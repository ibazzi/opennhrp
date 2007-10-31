/* nhrp_packet.c - NHRP packet marshalling and tranceiving
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include "nhrp_packet.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"
#include "nhrp_common.h"

#define MAX_PDU_SIZE 1500

TAILQ_HEAD(nhrp_packet_list_head, nhrp_packet);

static uint32_t request_id = 0;
static struct nhrp_packet_list_head pending_requests =
	TAILQ_HEAD_INITIALIZER(pending_requests);

static uint16_t nhrp_calculate_checksum(uint8_t *pdu, uint16_t len)
{
	uint16_t *pdu16 = (uint16_t *) pdu;
	uint32_t csum = 0;
	int i;

	for (i = 0; i < len / 2; i++)
		csum += pdu16[i];
	if (len & 1)
		csum += htons(pdu[len - 1]);

	while (csum & 0xffff0000)
		csum = (csum & 0xffff) + (csum >> 16);

	return (~csum) & 0xffff;
}

struct nhrp_buffer *nhrp_buffer_alloc(uint32_t size)
{
	struct nhrp_buffer *buf;

	buf = malloc(sizeof(struct nhrp_buffer) + size);
	buf->length = size;

	return buf;
}

void nhrp_buffer_free(struct nhrp_buffer *buffer)
{
	free(buffer);
}

struct nhrp_cie *nhrp_cie_alloc(void)
{
	return calloc(1, sizeof(struct nhrp_cie));
}

void nhrp_cie_free(struct nhrp_cie *cie)
{
	free(cie);
}

void nhrp_payload_set_type(struct nhrp_payload *payload, int type)
{
	if (payload->payload_type == type)
		return;

	payload->payload_type = type;
	switch (type) {
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		TAILQ_INIT(&payload->u.cie_list_head);
		break;
	default:
		payload->u.raw = NULL;
		break;
	}
}

void nhrp_payload_set_raw(struct nhrp_payload *payload, struct nhrp_buffer *raw)
{
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_RAW);
	payload->u.raw = raw;
}

void nhrp_payload_add_cie(struct nhrp_payload *payload, struct nhrp_cie *cie)
{
	if (payload->payload_type != NHRP_PAYLOAD_TYPE_CIE_LIST)
		return;

	TAILQ_INSERT_TAIL(&payload->u.cie_list_head, cie, cie_list_entry);
}

struct nhrp_packet *nhrp_packet_alloc(void)
{
	return calloc(1, sizeof(struct nhrp_packet));
}

struct nhrp_payload *nhrp_packet_payload(struct nhrp_packet *packet)
{
	return nhrp_packet_extension(packet, NHRP_EXTENSION_PAYLOAD);
}

struct nhrp_payload *nhrp_packet_extension(struct nhrp_packet *packet,
					   uint16_t extension)
{
	struct nhrp_payload *p;

	if (packet->extension_by_type[extension & 0x7fff] != NULL)
		return packet->extension_by_type[extension & 0x7fff];

	p = &packet->extension_by_order[packet->num_extensions++];
	p->extension_type = extension;
	packet->extension_by_type[extension & 0x7fff] = p;

	return p;
}

void nhrp_packet_free(struct nhrp_packet *packet)
{
	if (packet->handler)
		TAILQ_REMOVE(&pending_requests, packet, request_list_entry);
	free(packet);
}

static int nhrp_handle_traffic_indication(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_protocol_address dst;
	struct iphdr *iph;
	struct nhrp_payload *pl;

        pl = nhrp_packet_payload(packet);
	switch (packet->hdr.protocol_type) {
	case ETHP_IP:
		if (pl == NULL || pl->u.raw->length < sizeof(struct iphdr))
			return FALSE;

		iph = (struct iphdr *) pl->u.raw->data;
		nhrp_protocol_address_set(&dst, 4, (uint8_t *) &iph->daddr);
		break;
	default:
		return FALSE;
	}

	nhrp_info("Traffic Indication from proto src %s; make direct tunnel to %s",
		nhrp_protocol_address_format(
			packet->hdr.protocol_type,
			&packet->src_protocol_address,
			sizeof(tmp), tmp),
		nhrp_protocol_address_format(
			packet->hdr.protocol_type,
			&dst, sizeof(tmp2), tmp2));

	return FALSE;
}

struct {
	uint16_t payload_type;
	int reply;
	int (*handler)(struct nhrp_packet *packet);
} packet_types[] = {
	[NHRP_PACKET_RESOLUTION_REQUEST] = {
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_RESOLUTION_REPLY] = {
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
		.reply = TRUE,
	},
	[NHRP_PACKET_REGISTRATION_REQUEST] = {
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_REGISTRATION_REPLY] = {
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
		.reply = TRUE,
	},
	[NHRP_PACKET_PURGE_REQUEST] = {
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_PURGE_REPLY] = {
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
		.reply = TRUE,
	},
	[NHRP_PACKET_ERROR_INDICATION] = {
		.payload_type = NHRP_PAYLOAD_TYPE_RAW,
	},
	[NHRP_PACKET_TRAFFIC_INDICATION] = {
		.handler = nhrp_handle_traffic_indication,
		.payload_type = NHRP_PAYLOAD_TYPE_RAW,
	}
};

static int unmarshall_binary(uint8_t **pdu, size_t *pduleft, size_t size, void *raw)
{
	if (*pduleft < size)
		return FALSE;

	memcpy(raw, *pdu, size);
	*pdu += size;
	*pduleft -= size;
	return TRUE;
}

static inline int unmarshall_protocol_address(uint8_t **pdu, size_t *pduleft, struct nhrp_protocol_address *pa)
{
	if (*pduleft < pa->addr_len)
		return FALSE;

	if (!nhrp_protocol_address_set(pa, pa->addr_len, *pdu))
		return FALSE;

	*pdu += pa->addr_len;
	*pduleft -= pa->addr_len;
	return TRUE;
}

static inline int unmarshall_nbma_address(uint8_t **pdu, size_t *pduleft, struct nhrp_nbma_address *na)
{
	if (*pduleft < na->addr_len + na->subaddr_len)
		return FALSE;

	if (!nhrp_nbma_address_set(na,
				   na->addr_len, *pdu,
				   na->subaddr_len, *pdu + na->addr_len))
		return FALSE;

	*pdu += na->addr_len + na->subaddr_len;
	*pduleft -= na->addr_len + na->subaddr_len;
	return TRUE;
}

static int unmarshall_payload(uint8_t **pdu, size_t *pduleft,
			      int type, size_t size,
			      struct nhrp_payload *p)
{
	if (*pduleft < size)
		return FALSE;

	nhrp_payload_set_type(p, type);
	switch (p->payload_type) {
	case NHRP_PAYLOAD_TYPE_NONE:
		*pdu += size;
		*pduleft -= size;
		return TRUE;
	case NHRP_PAYLOAD_TYPE_RAW:
		p->u.raw = nhrp_buffer_alloc(size);
		return unmarshall_binary(pdu, pduleft, size, p->u.raw->data);
	default:
		return FALSE;
	}
}

static int unmarshall_packet(uint8_t *pdu, size_t pduleft, struct nhrp_packet *packet)
{
	uint8_t *pos = pdu;
	int size;
	struct nhrp_packet_header *phdr = (struct nhrp_packet_header *) pdu;

	if (!unmarshall_binary(&pos, &pduleft, sizeof(packet->hdr), &packet->hdr))
		return FALSE;

	if (packet->hdr.type >= ARRAY_SIZE(packet_types))
		return FALSE;

	packet->src_nbma_address.addr_len = phdr->src_nbma_address_len;
	packet->src_nbma_address.subaddr_len = phdr->src_nbma_subaddress_len;
	packet->src_protocol_address.addr_len = phdr->src_protocol_address_len;
	packet->dst_protocol_address.addr_len = phdr->dst_protocol_address_len;

	if (!unmarshall_nbma_address(&pos, &pduleft, &packet->src_nbma_address))
		return FALSE;
	if (!unmarshall_protocol_address(&pos, &pduleft, &packet->src_protocol_address))
		return FALSE;
	if (!unmarshall_protocol_address(&pos, &pduleft, &packet->dst_protocol_address))
		return FALSE;

	if (ntohs(packet->hdr.extension_offset) == 0) {
		/* No extensions; rest of data is payload */
		size = pduleft;
	} else {
		/* Extensions present; exclude those from payload */
		size = ntohs(packet->hdr.extension_offset) -
			(pos - pdu);
		if (size < 0 || size > pduleft)
			return FALSE;
	}

	if (!unmarshall_payload(&pos, &pduleft,
				packet_types[packet->hdr.type].payload_type,
				size, nhrp_packet_payload(packet)))
		return -1;

#if 0
	phdr->extension_offset = htons((int)(pos - pdu));
	for (i = 1; i < packet->num_extensions; i++) {
		struct nhrp_extension_header *eh = (struct nhrp_extension_header *) pos;

		if (packet->extension_by_order[i].payload_type == NHRP_PAYLOAD_TYPE_NONE)
			continue;

		neh.type = htons(packet->extension_by_order[i].extension_type);
		neh.length = 0;

		if (!marshall_binary(&pos, &pduleft, sizeof(neh), &neh))
			return -1;
		if (!marshall_payload(&pos, &pduleft, &packet->extension_by_order[i]))
			return -1;
		eh->length = htons((pos - (uint8_t *) eh) - sizeof(neh));
	}
	neh.type = htons(NHRP_EXTENSION_END | NHRP_EXTENSION_FLAG_COMPULSORY);
	neh.length = 0;
	if (!marshall_binary(&pos, &pduleft, sizeof(neh), &neh))
		return -1;

	size = (int)(pos - pdu);
	phdr->packet_size = htons(size);
	phdr->checksum = 0;
	phdr->checksum = nhrp_calculate_checksum(pdu, size);
#endif

	return TRUE;
}
static int nhrp_packet_forward(struct nhrp_packet *packet, struct nhrp_nbma_address *from)
{
	char tmp[64], tmp2[64], tmp3[64];

	nhrp_info("Packet nbma src %s, proto src %s, proto dst %s needs to be forwarded",
		nhrp_nbma_address_format(packet->hdr.afnum,
					 &packet->src_nbma_address,
					 sizeof(tmp), tmp),
		nhrp_protocol_address_format(packet->hdr.protocol_type,
					     &packet->src_protocol_address,
					     sizeof(tmp2), tmp2),
		nhrp_protocol_address_format(packet->hdr.protocol_type,
					     &packet->dst_protocol_address,
					     sizeof(tmp3), tmp3));

	return FALSE;
}

static int nhrp_packet_receive_local(struct nhrp_packet *packet, struct nhrp_nbma_address *from)
{
	struct nhrp_packet *req;

	/* FIXME: Check authentication extension first */

	if (packet_types[packet->hdr.type].reply) {
		TAILQ_FOREACH(req, &pending_requests, request_list_entry) {
			if (packet->hdr.u.request_id != req->hdr.u.request_id)
				continue;
			if (nhrp_nbma_address_cmp(&packet->src_nbma_address,
						  &req->src_nbma_address))
				continue;
			if (nhrp_protocol_address_cmp(&packet->src_protocol_address,
						      &req->src_protocol_address))
				continue;

			nhrp_task_cancel(&req->timeout);
			req->handler(req->handler_ctx, packet);
			nhrp_packet_free(req);

			return TRUE;
		}

		return FALSE;
	}

	if (packet_types[packet->hdr.type].handler == NULL) {
		char tmp[64], tmp2[64], tmp3[64];

		nhrp_info("Packet type %d from nbma src %s, proto src %s, proto dst %s not supported",
			  packet->hdr.type,
			  nhrp_nbma_address_format(packet->hdr.afnum,
						   &packet->src_nbma_address,
						   sizeof(tmp), tmp),
			  nhrp_protocol_address_format(packet->hdr.protocol_type,
						       &packet->src_protocol_address,
						       sizeof(tmp2), tmp2),
			  nhrp_protocol_address_format(packet->hdr.protocol_type,
						       &packet->dst_protocol_address,
						       sizeof(tmp3), tmp3));
		return FALSE;
	}

	return packet_types[packet->hdr.type].handler(packet);
}

int nhrp_packet_receive(uint8_t *pdu, size_t pdulen,
			struct nhrp_interface *iface,
			struct nhrp_nbma_address *from)
{
	char tmp[64];
	struct nhrp_packet *packet;
	struct nhrp_protocol_address *dest;
	struct nhrp_peer *peer;
	int ret = FALSE;

	if (nhrp_calculate_checksum(pdu, pdulen) != 0) {
		nhrp_error("Bad checksum in packet from %s",
			   nhrp_nbma_address_format(iface->afnum, from,
						    sizeof(tmp), tmp));
		return FALSE;
	}

	packet = nhrp_packet_alloc();
	if (packet == NULL)
		return FALSE;

	if (!unmarshall_packet(pdu, pdulen, packet)) {
		nhrp_error("Failed to unmarshall packet from %s",
			   nhrp_nbma_address_format(iface->afnum, from,
						    sizeof(tmp), tmp));
		goto error;
	}

	if (packet_types[packet->hdr.type].reply)
		dest = &packet->src_protocol_address;
	else
		dest = &packet->dst_protocol_address;

	peer = nhrp_peer_find(packet->hdr.protocol_type, dest, 0xff);
	if (peer == NULL || peer->type != NHRP_PEER_TYPE_LOCAL)
		ret = nhrp_packet_forward(packet, from);
	else
		ret = nhrp_packet_receive_local(packet, from);

error:
	nhrp_packet_free(packet);
	return ret;
}

static int marshall_binary(uint8_t **pdu, size_t *pduleft, size_t size, void *raw)
{
	if (*pduleft < size)
		return FALSE;

	memcpy(*pdu, raw, size);
	*pdu += size;
	*pduleft -= size;

	return TRUE;
}

static inline int marshall_protocol_address(uint8_t **pdu, size_t *pduleft, struct nhrp_protocol_address *pa)
{
	return marshall_binary(pdu, pduleft, pa->addr_len, pa->addr);
}

static inline int marshall_nbma_address(uint8_t **pdu, size_t *pduleft, struct nhrp_nbma_address *na)
{
	if (!marshall_binary(pdu, pduleft, na->addr_len, na->addr))
		return FALSE;

	return marshall_binary(pdu, pduleft, na->subaddr_len, na->subaddr);
}

static int marshall_cie(uint8_t **pdu, size_t *pduleft, struct nhrp_cie *cie)
{
	cie->hdr.nbma_address_len = cie->nbma_address.addr_len;
	cie->hdr.nbma_subaddress_len = cie->nbma_address.subaddr_len;
	cie->hdr.protocol_address_len = cie->protocol_address.addr_len;

	if (!marshall_binary(pdu, pduleft, sizeof(struct nhrp_cie_header), &cie->hdr))
		return FALSE;
	if (!marshall_nbma_address(pdu, pduleft, &cie->nbma_address))
		return FALSE;
	return marshall_protocol_address(pdu, pduleft, &cie->protocol_address);
}

static int marshall_payload(uint8_t **pdu, size_t *pduleft, struct nhrp_payload *p)
{
	struct nhrp_cie *cie;

	switch (p->payload_type) {
	case NHRP_PAYLOAD_TYPE_NONE:
		return TRUE;
	case NHRP_PAYLOAD_TYPE_RAW:
		if (p->u.raw->length == 0)
			return TRUE;
		return marshall_binary(pdu, pduleft, p->u.raw->length, p->u.raw->data);
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		TAILQ_FOREACH(cie, &p->u.cie_list_head, cie_list_entry) {
			if (!marshall_cie(pdu, pduleft, cie))
				return FALSE;
		}
		return TRUE;
	default:
		return FALSE;
	}
}

static int marshall_packet(uint8_t *pdu, size_t pduleft, struct nhrp_packet *packet)
{
	uint8_t *pos = pdu;
	struct nhrp_packet_header *phdr = (struct nhrp_packet_header *) pdu;
	struct nhrp_extension_header neh;
	int i, size;

	if (!marshall_binary(&pos, &pduleft, sizeof(packet->hdr), &packet->hdr))
		return -1;
	if (!marshall_nbma_address(&pos, &pduleft, &packet->src_nbma_address))
		return -1;
	if (!marshall_protocol_address(&pos, &pduleft, &packet->src_protocol_address))
		return -1;
	if (!marshall_protocol_address(&pos, &pduleft, &packet->dst_protocol_address))
		return -1;
	if (!marshall_payload(&pos, &pduleft, nhrp_packet_payload(packet)))
		return -1;

	phdr->extension_offset = htons((int)(pos - pdu));
	for (i = 1; i < packet->num_extensions; i++) {
		struct nhrp_extension_header *eh = (struct nhrp_extension_header *) pos;

		if (packet->extension_by_order[i].payload_type == NHRP_PAYLOAD_TYPE_NONE)
			continue;

		neh.type = htons(packet->extension_by_order[i].extension_type);
		neh.length = 0;

		if (!marshall_binary(&pos, &pduleft, sizeof(neh), &neh))
			return -1;
		if (!marshall_payload(&pos, &pduleft, &packet->extension_by_order[i]))
			return -1;
		eh->length = htons((pos - (uint8_t *) eh) - sizeof(neh));
	}
	neh.type = htons(NHRP_EXTENSION_END | NHRP_EXTENSION_FLAG_COMPULSORY);
	neh.length = 0;
	if (!marshall_binary(&pos, &pduleft, sizeof(neh), &neh))
		return -1;

	size = (int)(pos - pdu);
	phdr->packet_size = htons(size);
	phdr->checksum = 0;
	phdr->src_nbma_address_len = packet->src_nbma_address.addr_len;
	phdr->src_nbma_subaddress_len = packet->src_nbma_address.subaddr_len;
	phdr->src_protocol_address_len = packet->src_protocol_address.addr_len;
	phdr->dst_protocol_address_len = packet->dst_protocol_address.addr_len;
	phdr->checksum = nhrp_calculate_checksum(pdu, size);

	return size;
}

int nhrp_packet_send(struct nhrp_packet *packet)
{
	struct nhrp_nbma_address nexthop;
	struct nhrp_interface *iface;
	struct nhrp_payload *payload;
	uint8_t pdu[MAX_PDU_SIZE];
	int size;

	if (!kernel_route(packet, &iface, &nexthop))
		return FALSE;

	if (packet->hdr.hop_count == 0)
		packet->hdr.hop_count = 16;

	payload = nhrp_packet_extension(packet, NHRP_EXTENSION_AUTHENTICATION | NHRP_EXTENSION_FLAG_COMPULSORY);
	if (payload->payload_type == NHRP_PAYLOAD_TYPE_NONE &&
	    iface->auth_token != NULL) {
		nhrp_payload_set_raw(payload, iface->auth_token);
	}

	size = marshall_packet(pdu, sizeof(pdu), packet);
	if (size < 0)
		return FALSE;

	return kernel_send(pdu, size, iface, &nexthop);
}

static void nhrp_packet_xmit_timeout(struct nhrp_task *task)
{
        struct nhrp_packet *packet = container_of(task, struct nhrp_packet, timeout);

	packet->handler(packet->handler_ctx, NULL);
	nhrp_packet_free(packet);
}

int nhrp_packet_send_request(struct nhrp_packet *packet,
			     void (*handler)(void *ctx, struct nhrp_packet *packet),
			     void *ctx)
{
	packet->hdr.u.request_id = request_id++;

	if (!nhrp_packet_send(packet))
		return FALSE;

	packet->handler = handler;
	packet->handler_ctx = ctx;
	TAILQ_INSERT_TAIL(&pending_requests, packet, request_list_entry);
	nhrp_task_schedule(&packet->timeout, 5000,
			   nhrp_packet_xmit_timeout);
	return TRUE;
}
