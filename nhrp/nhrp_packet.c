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

static int unmarshall_packet_header(uint8_t **pdu, size_t *pdusize, struct nhrp_packet *packet);

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

struct nhrp_buffer *nhrp_buffer_copy(struct nhrp_buffer *buffer)
{
	struct nhrp_buffer *copy;

	copy = nhrp_buffer_alloc(buffer->length);
	memcpy(copy->data, buffer->data, buffer->length);
	return copy;
}

int nhrp_buffer_cmp(struct nhrp_buffer *a, struct nhrp_buffer *b)
{
	if (a->length > b->length)
		return 1;
	if (a->length < b->length)
		return -1;
	return memcmp(a->data, b->data, a->length);
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

void nhrp_payload_free(struct nhrp_payload *payload)
{
	struct nhrp_cie *cie;

	switch (payload->payload_type) {
	case NHRP_PAYLOAD_TYPE_RAW:
		nhrp_buffer_free(payload->u.raw);
		break;
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		while (!TAILQ_EMPTY(&payload->u.cie_list_head)) {
			cie = TAILQ_FIRST(&payload->u.cie_list_head);
			TAILQ_REMOVE(&payload->u.cie_list_head, cie, cie_list_entry);
			nhrp_cie_free(cie);
		}
		break;
	}
	payload->payload_type = NHRP_PAYLOAD_TYPE_NONE;
}

void nhrp_payload_set_type(struct nhrp_payload *payload, int type)
{
	if (payload->payload_type == type)
		return;

	nhrp_payload_free(payload);
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

struct nhrp_cie *nhrp_payload_get_cie(struct nhrp_payload *payload, int index)
{
	struct nhrp_cie *cie;

	if (payload->payload_type != NHRP_PAYLOAD_TYPE_CIE_LIST)
		return NULL;

	for (cie = TAILQ_FIRST(&payload->u.cie_list_head);
	     cie != NULL && index > 1; index--) {
		cie = TAILQ_NEXT(cie, cie_list_entry);
	}

	return cie;
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
					   uint32_t extension)
{
	struct nhrp_payload *p;

	if (packet->extension_by_type[extension & 0x7fff] != NULL)
		return packet->extension_by_type[extension & 0x7fff];

	if (extension & NHRP_EXTENSION_FLAG_NOCREATE)
		return NULL;

	p = &packet->extension_by_order[packet->num_extensions++];
	p->extension_type = extension & 0xffff;
	packet->extension_by_type[extension & 0x7fff] = p;

	return p;
}

void nhrp_packet_free(struct nhrp_packet *packet)
{
	int i;

	for (i = 0; i < packet->num_extensions; i++)
		nhrp_payload_free(&packet->extension_by_order[i]);
	if (packet->handler)
		TAILQ_REMOVE(&pending_requests, packet, request_list_entry);
	free(packet);
}

static int nhrp_handle_resolution_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;

	nhrp_info("Received Resolution Request from proto src %s to %s",
		nhrp_address_format(&packet->src_protocol_address,
			sizeof(tmp), tmp),
		nhrp_address_format(&packet->dst_protocol_address,
			sizeof(tmp2), tmp2));

	packet->hdr.type = NHRP_PACKET_RESOLUTION_REPLY;
	packet->hdr.flags &= NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER |
			     NHRP_FLAG_RESOLUTION_SOURCE_STABLE |
			     NHRP_FLAG_RESOLUTION_UNIQUE |
			     NHRP_FLAG_RESOLUTION_NAT;
	packet->hdr.flags |= NHRP_FLAG_RESOLUTION_DESTINATION_STABLE |
			     NHRP_FLAG_RESOLUTION_AUTHORATIVE;
	packet->hdr.hop_count = 0;

	cie = nhrp_cie_alloc();
	if (cie == NULL)
		return FALSE;

	cie->hdr = (struct nhrp_cie_header) {
		.code = NHRP_CODE_SUCCESS,
		.prefix_length = packet->dst_peer->prefix_length,
		.holding_time = constant_htons(NHRP_HOLDING_TIME),
	};

	payload = nhrp_packet_payload(packet);
	nhrp_payload_free(payload);
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	if (!nhrp_packet_route(packet))
		return FALSE;

	cie->nbma_address = packet->my_nbma_address;
	cie->protocol_address = packet->my_protocol_address;

	return nhrp_packet_send(packet);
}

static int nhrp_handle_registration_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	struct nhrp_peer *peer, *p;

	nhrp_info("Received Registration Request from proto src %s to %s",
		nhrp_address_format(&packet->src_protocol_address,
			sizeof(tmp), tmp),
		nhrp_address_format(&packet->dst_protocol_address,
			sizeof(tmp2), tmp2));

	packet->hdr.type = NHRP_PACKET_REGISTRATION_REPLY;
	packet->hdr.flags &= NHRP_FLAG_REGISTRATION_UNIQUE;
	packet->hdr.hop_count = 0;

	payload = nhrp_packet_payload(packet);
	TAILQ_FOREACH(cie, &payload->u.cie_list_head, cie_list_entry) {
		peer = nhrp_peer_alloc();
		if (peer == NULL) {
			cie->hdr.code = NHRP_CODE_INSUFFICIENT_RESOURCES;
			continue;
		}

		peer->type = NHRP_PEER_TYPE_DYNAMIC;
		peer->afnum = packet->hdr.afnum;
		peer->protocol_type = packet->hdr.protocol_type;
		peer->interface = packet->src_iface;
		peer->expire_time = (ntohs(cie->hdr.holding_time) - 60) * 1000;
		if (cie->nbma_address.addr_len != 0)
			peer->nbma_address = cie->nbma_address;
		else
			peer->nbma_address = packet->src_nbma_address;
		if (cie->protocol_address.addr_len != 0)
			peer->protocol_address = cie->protocol_address;
		else
			peer->protocol_address = packet->src_protocol_address;
		peer->dst_protocol_address = peer->protocol_address;

		peer->prefix_length = cie->hdr.prefix_length;
		if (peer->prefix_length == 0xff)
			peer->prefix_length = peer->protocol_address.addr_len * 8;

		while ((p = nhrp_peer_find(&peer->dst_protocol_address,
					   peer->prefix_length,
					   NHRP_PEER_FIND_SUBNET_MATCH)) != NULL)
			nhrp_peer_remove(p);

		nhrp_peer_insert(peer);
		nhrp_peer_free(peer);

		cie->hdr.code = NHRP_CODE_SUCCESS;
	}

	return nhrp_packet_send(packet);
}

static int nhrp_handle_error_indication(struct nhrp_packet *error_packet)
{
	struct nhrp_packet *packet, *req;
	struct nhrp_payload *payload;
	uint8_t *pdu;
	size_t pduleft;

	packet = nhrp_packet_alloc();
	if (packet == NULL)
		return FALSE;

	payload = nhrp_packet_payload(error_packet);
	pdu = payload->u.raw->data;
	pduleft = payload->u.raw->length;

	if (!unmarshall_packet_header(&pdu, &pduleft, packet)) {
		nhrp_packet_free(packet);
		return FALSE;
	}

	TAILQ_FOREACH(req, &pending_requests, request_list_entry) {
		if (packet->hdr.u.request_id != req->hdr.u.request_id)
			continue;

		if (nhrp_address_cmp(&packet->src_nbma_address,
				     &req->src_nbma_address))
			continue;
		if (nhrp_address_cmp(&packet->src_protocol_address,
				     &req->src_protocol_address))
			continue;

		nhrp_task_cancel(&req->timeout);
		req->handler(req->handler_ctx, packet);
		nhrp_packet_free(req);

		nhrp_packet_free(packet);
		return TRUE;
	}

	nhrp_packet_free(packet);
	return FALSE;
}

static int nhrp_handle_traffic_indication(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_address dst;
	struct iphdr *iph;
	struct nhrp_payload *pl;
	struct nhrp_peer *peer;
	int pf;

	pf = nhrp_pf_from_protocol(packet->hdr.protocol_type);
	pl = nhrp_packet_payload(packet);
	switch (packet->hdr.protocol_type) {
	case ETHPROTO_IP:
		if (pl == NULL || pl->u.raw->length < sizeof(struct iphdr))
			return FALSE;

		iph = (struct iphdr *) pl->u.raw->data;
		nhrp_address_set(&dst, pf, 4, (uint8_t *) &iph->daddr);
		break;
	default:
		return FALSE;
	}

	nhrp_info("Traffic Indication from proto src %s; about packet to %s",
		nhrp_address_format(&packet->src_protocol_address,
				    sizeof(tmp), tmp),
		nhrp_address_format(&dst, sizeof(tmp2), tmp2));

	peer = nhrp_peer_find(&dst, 0xff, 0);
	if (peer != NULL &&
	    peer->prefix_length == peer->dst_protocol_address.addr_len * 8)
		return TRUE;

	if ((peer->interface != NULL) &&
	    !(peer->interface->flags & NHRP_INTERFACE_FLAG_SHORTCUT))
		return TRUE;

	peer = nhrp_peer_alloc();
	peer->type = NHRP_PEER_TYPE_INCOMPLETE;
	peer->afnum = packet->hdr.afnum;
	peer->protocol_type = packet->hdr.protocol_type;
	peer->dst_protocol_address = dst;
	peer->prefix_length = packet->dst_protocol_address.addr_len * 8;
	nhrp_peer_insert(peer);
	nhrp_peer_free(peer);

	return TRUE;
}

#define NHRP_TYPE_REQUEST	0
#define NHRP_TYPE_REPLY		1
#define NHRP_TYPE_INDICATION	2

static struct {
	int type;
	uint16_t payload_type;
	int (*handler)(struct nhrp_packet *packet);
} packet_types[] = {
	[NHRP_PACKET_RESOLUTION_REQUEST] = {
		.type = NHRP_TYPE_REQUEST,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
		.handler = nhrp_handle_resolution_request,
	},
	[NHRP_PACKET_RESOLUTION_REPLY] = {
		.type = NHRP_TYPE_REPLY,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_REGISTRATION_REQUEST] = {
		.type = NHRP_TYPE_REQUEST,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
		.handler = nhrp_handle_registration_request,
	},
	[NHRP_PACKET_REGISTRATION_REPLY] = {
		.type = NHRP_TYPE_REPLY,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_PURGE_REQUEST] = {
		.type = NHRP_TYPE_REQUEST,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_PURGE_REPLY] = {
		.type = NHRP_TYPE_REPLY,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_ERROR_INDICATION] = {
		.type = NHRP_TYPE_INDICATION,
		.payload_type = NHRP_PAYLOAD_TYPE_RAW,
		.handler = nhrp_handle_error_indication,
	},
	[NHRP_PACKET_TRAFFIC_INDICATION] = {
		.type = NHRP_TYPE_INDICATION,
		.payload_type = NHRP_PAYLOAD_TYPE_RAW,
		.handler = nhrp_handle_traffic_indication,
	}
};
static int extension_types[] = {
	[NHRP_EXTENSION_RESPONDER_ADDRESS] = NHRP_PAYLOAD_TYPE_CIE_LIST,
	[NHRP_EXTENSION_FORWARD_TRANSIT_NHS] = NHRP_PAYLOAD_TYPE_CIE_LIST,
	[NHRP_EXTENSION_REVERSE_TRANSIT_NHS] = NHRP_PAYLOAD_TYPE_CIE_LIST,
	[NHRP_EXTENSION_NAT_ADDRESS] = NHRP_PAYLOAD_TYPE_CIE_LIST
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

static inline int unmarshall_protocol_address(uint8_t **pdu, size_t *pduleft, struct nhrp_address *pa)
{
	if (*pduleft < pa->addr_len)
		return FALSE;

	if (!nhrp_address_set(pa, pa->type, pa->addr_len, *pdu))
		return FALSE;

	*pdu += pa->addr_len;
	*pduleft -= pa->addr_len;
	return TRUE;
}

static inline int unmarshall_nbma_address(uint8_t **pdu, size_t *pduleft, struct nhrp_address *na)
{
	if (*pduleft < na->addr_len + na->subaddr_len)
		return FALSE;

	if (!nhrp_address_set_full(na, na->type,
				   na->addr_len, *pdu,
				   na->subaddr_len, *pdu + na->addr_len))
		return FALSE;

	*pdu += na->addr_len + na->subaddr_len;
	*pduleft -= na->addr_len + na->subaddr_len;
	return TRUE;
}

static int unmarshall_cie(uint8_t **pdu, size_t *pduleft, struct nhrp_packet *p, struct nhrp_cie *cie)
{
	if (!unmarshall_binary(pdu, pduleft, sizeof(struct nhrp_cie_header), &cie->hdr))
		return FALSE;

	cie->nbma_address.type = nhrp_pf_from_afnum(p->hdr.afnum);
	cie->nbma_address.addr_len = cie->hdr.nbma_address_len;
	cie->nbma_address.subaddr_len = cie->hdr.nbma_subaddress_len;
	cie->protocol_address.type = nhrp_pf_from_protocol(p->hdr.protocol_type);
	cie->protocol_address.addr_len = cie->hdr.protocol_address_len;

	if (!unmarshall_nbma_address(pdu, pduleft, &cie->nbma_address))
		return FALSE;
	return unmarshall_protocol_address(pdu, pduleft, &cie->protocol_address);
}

static int unmarshall_payload(uint8_t **pdu, size_t *pduleft,
			      struct nhrp_packet *packet,
			      int type, size_t size,
			      struct nhrp_payload *p)
{
	struct nhrp_cie *cie;
	size_t cieleft;

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
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		cieleft = size;
		while (cieleft) {
			cie = nhrp_cie_alloc();
			TAILQ_INSERT_TAIL(&p->u.cie_list_head, cie, cie_list_entry);
			if (!unmarshall_cie(pdu, &cieleft, packet, cie))
				return FALSE;
		}
		*pduleft -= size;
		return TRUE;
	default:
		return FALSE;
	}
}

static int unmarshall_packet_header(uint8_t **pdu, size_t *pduleft, struct nhrp_packet *packet)
{
	struct nhrp_packet_header *phdr = (struct nhrp_packet_header *) *pdu;

	if (!unmarshall_binary(pdu, pduleft, sizeof(packet->hdr), &packet->hdr))
		return FALSE;

	if (packet->hdr.type >= ARRAY_SIZE(packet_types))
		return FALSE;

	packet->src_nbma_address.type = nhrp_pf_from_afnum(packet->hdr.afnum);
	packet->src_nbma_address.addr_len = phdr->src_nbma_address_len;
	packet->src_nbma_address.subaddr_len = phdr->src_nbma_subaddress_len;
	packet->src_protocol_address.type = nhrp_pf_from_protocol(packet->hdr.protocol_type);
	packet->src_protocol_address.addr_len = phdr->src_protocol_address_len;
	packet->dst_protocol_address.type = nhrp_pf_from_protocol(packet->hdr.protocol_type);
	packet->dst_protocol_address.addr_len = phdr->dst_protocol_address_len;

	if (!unmarshall_nbma_address(pdu, pduleft, &packet->src_nbma_address))
		return FALSE;
	if (!unmarshall_protocol_address(pdu, pduleft, &packet->src_protocol_address))
		return FALSE;
	return unmarshall_protocol_address(pdu, pduleft, &packet->dst_protocol_address);
}

static int unmarshall_packet(uint8_t *pdu, size_t pdusize, struct nhrp_packet *packet)
{
	size_t pduleft = pdusize;
	uint8_t *pos = pdu;
	int size, extension_offset;

	if (!unmarshall_packet_header(&pos, &pduleft, packet))
		return FALSE;

	extension_offset = ntohs(packet->hdr.extension_offset);
	if (extension_offset == 0) {
		/* No extensions; rest of data is payload */
		size = pduleft;
	} else {
		/* Extensions present; exclude those from payload */
		size = extension_offset - (pos - pdu);
		if (size < 0 || size > pduleft) {
			nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ERROR, pos - pdu);
			return FALSE;
		}
	}

	if (!unmarshall_payload(&pos, &pduleft, packet,
				packet_types[packet->hdr.type].payload_type,
				size, nhrp_packet_payload(packet))) {
		nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ERROR, pos - pdu);
		return FALSE;
	}

	if (extension_offset == 0)
		return TRUE;

	pos = &pdu[extension_offset];
	pduleft = pdusize - extension_offset;
	do {
		struct nhrp_extension_header eh;
		int extension_type, payload_type;

		if (!unmarshall_binary(&pos, &pduleft, sizeof(eh), &eh)) {
			nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ERROR, pos - pdu);
			return FALSE;
		}

		extension_type = ntohs(eh.type) & ~NHRP_EXTENSION_FLAG_COMPULSORY;
		if (extension_type == NHRP_EXTENSION_END)
			break;

		payload_type = NHRP_PAYLOAD_TYPE_NONE;
		if (extension_type < ARRAY_SIZE(extension_types))
			payload_type = extension_types[extension_type];
		if (payload_type == NHRP_PAYLOAD_TYPE_NONE)
			payload_type = NHRP_PAYLOAD_TYPE_RAW;
		if (payload_type == NHRP_PAYLOAD_TYPE_RAW &&
		    ntohs(eh.length) == 0)
			payload_type = NHRP_PAYLOAD_TYPE_NONE;

		if (!unmarshall_payload(&pos, &pduleft, packet,
					payload_type, ntohs(eh.length),
					nhrp_packet_extension(packet, ntohs(eh.type)))) {
			nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ERROR, pos - pdu);
			return FALSE;
		}
	} while (1);

	return TRUE;
}

static int nhrp_packet_forward(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64], tmp3[64];
	struct nhrp_payload *p = NULL;

	nhrp_info("Forwarding packet from nbma src %s, proto src %s to proto dst %s, hop count %d",
		nhrp_address_format(&packet->src_nbma_address,
				    sizeof(tmp), tmp),
		nhrp_address_format(&packet->src_protocol_address,
				    sizeof(tmp2), tmp2),
		nhrp_address_format(&packet->dst_protocol_address,
				    sizeof(tmp3), tmp3),
		packet->hdr.hop_count);

	if (packet->hdr.hop_count == 0) {
		nhrp_packet_send_error(packet, NHRP_ERROR_HOP_COUNT_EXCEEDED, 0);
		return TRUE;
	}
	packet->hdr.hop_count--;

	if (!nhrp_packet_route(packet)) {
		nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE, 0);
		return FALSE;
	}

	switch (packet_types[packet->hdr.type].type) {
	case NHRP_TYPE_REQUEST:
		p = nhrp_packet_extension(packet, NHRP_EXTENSION_FORWARD_TRANSIT_NHS | NHRP_EXTENSION_FLAG_NOCREATE);
		break;
	case NHRP_TYPE_REPLY:
		p = nhrp_packet_extension(packet, NHRP_EXTENSION_REVERSE_TRANSIT_NHS | NHRP_EXTENSION_FLAG_NOCREATE);
		break;
	}
	if (p != NULL) {
		struct nhrp_cie *cie;

		TAILQ_FOREACH(cie, &p->u.cie_list_head, cie_list_entry) {
			if (nhrp_address_cmp(&cie->nbma_address, &packet->my_nbma_address) == 0 &&
			    nhrp_address_cmp(&cie->protocol_address, &packet->my_protocol_address) == 0) {
				nhrp_packet_send_error(packet, NHRP_ERROR_LOOP_DETECTED, 0);
				return FALSE;
			}
		}

		cie = nhrp_cie_alloc();
		if (cie != NULL) {
			cie->hdr = (struct nhrp_cie_header) {
				.code = NHRP_CODE_SUCCESS,
				.holding_time = NHRP_HOLDING_TIME,
			};
			cie->nbma_address = packet->my_nbma_address;
			cie->protocol_address = packet->my_protocol_address;
			nhrp_payload_add_cie(p, cie);
		}
	}

	return nhrp_packet_send(packet);
}

static int nhrp_packet_receive_local(struct nhrp_packet *packet)
{
	struct nhrp_packet *req;

	if (packet_types[packet->hdr.type].type == NHRP_TYPE_REPLY) {
		TAILQ_FOREACH(req, &pending_requests, request_list_entry) {
			if (packet->hdr.u.request_id != req->hdr.u.request_id)
				continue;
			if (nhrp_address_cmp(&packet->src_nbma_address,
					     &req->src_nbma_address))
				continue;
			if (nhrp_address_cmp(&packet->src_protocol_address,
					     &req->src_protocol_address))
				continue;

			nhrp_task_cancel(&req->timeout);
			req->handler(req->handler_ctx, packet);
			nhrp_packet_free(req);

			return TRUE;
		}

		/* Reply to unsent request? */
		nhrp_packet_send_error(packet, NHRP_ERROR_INVALID_RESOLUTION_REPLY, 0);
		return FALSE;
	}

	if (packet_types[packet->hdr.type].handler == NULL) {
		char tmp[64], tmp2[64], tmp3[64];

		nhrp_info("Packet type %d from nbma src %s, proto src %s, proto dst %s not supported",
			  packet->hdr.type,
			  nhrp_address_format(&packet->src_nbma_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp2), tmp2),
			  nhrp_address_format(&packet->dst_protocol_address,
					      sizeof(tmp3), tmp3));
		return FALSE;
	}

	return packet_types[packet->hdr.type].handler(packet);
}

int nhrp_packet_receive(uint8_t *pdu, size_t pdulen,
			struct nhrp_interface *iface,
			struct nhrp_address *from)
{
	char tmp[64];
	struct nhrp_packet *packet;
	struct nhrp_address *dest;
	struct nhrp_peer *peer;
	int ret = FALSE;

	if (nhrp_calculate_checksum(pdu, pdulen) != 0) {
		nhrp_error("Bad checksum in packet from %s",
			   nhrp_address_format(from, sizeof(tmp), tmp));
		return FALSE;
	}

	packet = nhrp_packet_alloc();
	if (packet == NULL)
		return FALSE;

	if (!unmarshall_packet(pdu, pdulen, packet)) {
		nhrp_error("Failed to unmarshall packet from %s",
			   nhrp_address_format(from, sizeof(tmp), tmp));
		goto error;
	}

	packet->req_pdu = pdu;
	packet->req_pdulen = pdulen;

	if (packet_types[packet->hdr.type].type == NHRP_TYPE_REPLY)
		dest = &packet->src_protocol_address;
	else
		dest = &packet->dst_protocol_address;

	peer = nhrp_peer_find(dest, 0xff, NHRP_PEER_FIND_COMPLETE);
	packet->src_linklayer_address = *from;
	packet->src_iface = iface;
	packet->dst_peer = peer;

	/* RFC2332 5.3.4 - Authentication is always done pairwise on an NHRP
	 * hop-by-hop basis; i.e. regenerated at each hop. */
	if (packet->src_iface->auth_token &&
	    (packet->hdr.type != NHRP_PACKET_ERROR_INDICATION ||
	     packet->hdr.u.error.code != NHRP_ERROR_AUTHENTICATION_FAILURE)) {
		struct nhrp_payload *p;
		p = nhrp_packet_extension(packet, NHRP_EXTENSION_AUTHENTICATION | NHRP_EXTENSION_FLAG_NOCREATE);
		if (p == NULL ||
		    nhrp_buffer_cmp(packet->src_iface->auth_token, p->u.raw) != 0) {
			nhrp_error("Dropping packet from %s with bad authentication",
				nhrp_address_format(from, sizeof(tmp), tmp));
			nhrp_packet_send_error(packet, NHRP_ERROR_AUTHENTICATION_FAILURE, 0);
			goto error;
		}
	}

	if (peer == NULL || peer->type != NHRP_PEER_TYPE_LOCAL)
		ret = nhrp_packet_forward(packet);
	else
		ret = nhrp_packet_receive_local(packet);

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

static inline int marshall_protocol_address(uint8_t **pdu, size_t *pduleft, struct nhrp_address *pa)
{
	if (pa->subaddr_len != 0)
		return FALSE;
	return marshall_binary(pdu, pduleft, pa->addr_len, pa->addr);
}

static inline int marshall_nbma_address(uint8_t **pdu, size_t *pduleft, struct nhrp_address *na)
{
	return marshall_binary(pdu, pduleft, na->addr_len + na->subaddr_len, na->addr);
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

static int marshall_packet_header(uint8_t **pdu, size_t *pduleft, struct nhrp_packet *packet)
{
	if (!marshall_binary(pdu, pduleft, sizeof(packet->hdr), &packet->hdr))
		return FALSE;
	if (!marshall_nbma_address(pdu, pduleft, &packet->src_nbma_address))
		return FALSE;
	if (!marshall_protocol_address(pdu, pduleft, &packet->src_protocol_address))
		return FALSE;
	return marshall_protocol_address(pdu, pduleft, &packet->dst_protocol_address);
}

static int marshall_packet(uint8_t *pdu, size_t pduleft, struct nhrp_packet *packet)
{
	uint8_t *pos = pdu;
	struct nhrp_packet_header *phdr = (struct nhrp_packet_header *) pdu;
	struct nhrp_extension_header neh;
	int i, size;

	if (!marshall_packet_header(&pos, &pduleft, packet))
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

	/* Cisco is seriously brain damaged. It needs some extra garbage
         * at the end of error indication or it'll barf out spurious errors. */
	if (packet->hdr.type == NHRP_PACKET_ERROR_INDICATION &&
	    pduleft >= 0x10) {
		memset(pos, 0, 0x10);
		pos += 0x10;
		pduleft -= 0x10;
	}

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

int nhrp_packet_route(struct nhrp_packet *packet)
{
	struct nhrp_address proto_nexthop, *dest;
	char tmp[64];
	int r, ifindex = -1;

	if (packet_types[packet->hdr.type].type == NHRP_TYPE_REPLY)
		dest = &packet->src_protocol_address;
	else
		dest = &packet->dst_protocol_address;

	r = kernel_route(dest, &packet->my_protocol_address,
			 &proto_nexthop, &ifindex);
	if (!r) {
		nhrp_error("No route to protocol address %s",
			nhrp_address_format( dest, sizeof(tmp), tmp));
		return FALSE;
	}

	if (packet->dst_iface == NULL)
		packet->dst_iface = nhrp_interface_get_by_index(ifindex, FALSE);
	if (packet->dst_iface == NULL) {
		nhrp_error("Protocol address %s routed to non-NHRP interface",
			nhrp_address_format(dest, sizeof(tmp), tmp));
		return FALSE;
	}
	packet->my_nbma_address = packet->dst_iface->nbma_address;

	packet->dst_peer = nhrp_peer_find(&proto_nexthop, 0xff,
					  NHRP_PEER_FIND_COMPLETE);
	if (packet->dst_peer == NULL) {
		nhrp_error("No peer entry for protocol address %s",
			nhrp_address_format(&proto_nexthop, sizeof(tmp), tmp));
		return FALSE;
	}

	if (packet->my_nbma_address.type == PF_UNSPEC) {
		r = kernel_route(&packet->dst_peer->nbma_address,
				 &packet->my_nbma_address, NULL, NULL);
		if (!r) {
			nhrp_error("No route to NBMA address %s",
				nhrp_address_format(
					&packet->dst_peer->nbma_address,
					sizeof(tmp), tmp));
			return FALSE;
		}
	}

	return TRUE;
}

int nhrp_packet_send(struct nhrp_packet *packet)
{
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	uint8_t pdu[MAX_PDU_SIZE];
	char tmp[64];
	int size;

	if (packet->dst_peer == NULL ||
	    packet->dst_iface == NULL ||
	    packet->my_nbma_address.addr_len == 0 ||
	    packet->my_protocol_address.addr_len == 0) {
		if (!nhrp_packet_route(packet))
			return FALSE;
	}

	if (packet->src_nbma_address.addr_len == 0)
		packet->src_nbma_address = packet->my_nbma_address;
	if (packet->src_protocol_address.addr_len == 0)
		packet->src_protocol_address = packet->my_protocol_address;
	if (packet->hdr.hop_count == 0)
		packet->hdr.hop_count = 16;

	/* RFC2332 5.3.1 */
	payload = nhrp_packet_extension(
		packet, NHRP_EXTENSION_RESPONDER_ADDRESS |
		NHRP_EXTENSION_FLAG_COMPULSORY | NHRP_EXTENSION_FLAG_NOCREATE);
	if (packet_types[packet->hdr.type].type == NHRP_TYPE_REPLY &&
	    (payload != NULL && TAILQ_EMPTY(&payload->u.cie_list_head))) {
		struct nhrp_cie *cie;

		cie = nhrp_cie_alloc();
		if (cie == NULL)
			return FALSE;

		cie->hdr.holding_time = htons(NHRP_HOLDING_TIME);
		cie->nbma_address = packet->my_nbma_address;
		cie->protocol_address = packet->my_protocol_address;
		nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
		nhrp_payload_add_cie(payload, cie);
	}

	/* RFC2332 5.3.4 - Authentication is always done pairwise on an NHRP
	 * hop-by-hop basis; i.e. regenerated at each hop. */
	payload = nhrp_packet_extension(packet, NHRP_EXTENSION_AUTHENTICATION | NHRP_EXTENSION_FLAG_COMPULSORY);
	nhrp_payload_free(payload);
	if (packet->dst_iface->auth_token != NULL)
		nhrp_payload_set_raw(payload,
			nhrp_buffer_copy(packet->dst_iface->auth_token));

	/* Cisco NAT extension CIE */
	if (packet_types[packet->hdr.type].type != NHRP_TYPE_INDICATION &&
	    (packet->hdr.flags & NHRP_FLAG_REGISTRATION_NAT)) {
		payload = nhrp_packet_extension(packet, NHRP_EXTENSION_NAT_ADDRESS);
		nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);

		if (packet->dst_iface->nat_cie.nbma_address.addr_len &&
		    TAILQ_EMPTY(&payload->u.cie_list_head)) {
			cie = nhrp_cie_alloc();
			if (cie != NULL) {
				*cie = packet->dst_iface->nat_cie;
				nhrp_payload_add_cie(payload, cie);
			}
		}
	}

	nhrp_info("Sending packet %d to nbma %s",
		packet->hdr.type,
		nhrp_address_format(&packet->dst_peer->nbma_address, sizeof(tmp), tmp));

	size = marshall_packet(pdu, sizeof(pdu), packet);
	if (size < 0)
		return FALSE;

	return kernel_send(pdu, size, packet->dst_iface,
			   &packet->dst_peer->nbma_address);
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
	nhrp_task_schedule(&packet->timeout, 5000, nhrp_packet_xmit_timeout);
	return TRUE;
}

int nhrp_packet_send_error(struct nhrp_packet *error_packet,
			   uint16_t indication_code, uint16_t offset)
{
	struct nhrp_packet *p;
	struct nhrp_payload *pl;
	int r;

	/* RFC2332 5.2.7 Never generate errors about errors */
	if (error_packet->hdr.type == NHRP_PACKET_ERROR_INDICATION)
		return TRUE;

	p = nhrp_packet_alloc();
	p->hdr = error_packet->hdr;
	p->hdr.hop_count = 0;
	p->hdr.type = NHRP_PACKET_ERROR_INDICATION;
	p->hdr.u.error.code = indication_code;
	p->hdr.u.error.offset = htons(offset);

	if (packet_types[error_packet->hdr.type].type == NHRP_TYPE_REPLY)
		p->dst_protocol_address = error_packet->dst_protocol_address;
	else
		p->dst_protocol_address = error_packet->src_protocol_address;

	pl = nhrp_packet_payload(p);
	nhrp_payload_set_type(pl, NHRP_PAYLOAD_TYPE_RAW);
	pl->u.raw = nhrp_buffer_alloc(error_packet->req_pdulen);
	memcpy(pl->u.raw->data, error_packet->req_pdu, error_packet->req_pdulen);

	r = nhrp_packet_send(p);
	nhrp_packet_free(p);

	return r;
}
