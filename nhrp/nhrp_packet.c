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
#include "nhrp_packet.h"
#include "nhrp_common.h"

#define MAX_PDU_SIZE 1500

static uint16_t nhrp_calculate_checksum(uint8_t *pdu, uint16_t len)
{
	uint16_t *pdu16 = (uint16_t *) pdu;
	uint32_t csum = 0;
	int i;

	for (i = 0; i < len / 2; i++)
		csum += pdu16[i];

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

void nhrp_payload_set_type(struct nhrp_payload *payload, int type)
{
	if (payload->type == type)
		return;

	payload->type = type;
	switch (type) {
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		TAILQ_INIT(&payload->u.cie_list_head);
		break;
	}
}

void nhrp_payload_set_raw(struct nhrp_payload *payload, struct nhrp_buffer *raw)
{
}

void nhrp_payload_add_cie(struct nhrp_payload *payload, struct nhrp_cie *cie)
{
	if (payload->type != NHRP_PAYLOAD_TYPE_CIE_LIST)
		return;

	TAILQ_INSERT_TAIL(&payload->u.cie_list_head, cie, cie_list_entry);
}

struct nhrp_packet *nhrp_packet_alloc(void)
{
	return calloc(1, sizeof(struct nhrp_packet));
}

void nhrp_packet_free(struct nhrp_packet *packet)
{
	free(packet);
}

int nhrp_packet_receive(uint8_t *pdu, size_t pdulen,
			struct nhrp_interface *iface,
			struct nhrp_nbma_address *from)
{
	char tmp[64];

	nhrp_info("NHRP packet from NBMA %s",
		  nhrp_format_nbma_address(iface->afnum, from,
					   sizeof(tmp), tmp));
	nhrp_hex_dump("nhrp packet", pdu, pdulen);

	return FALSE;
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

	switch (p->type) {
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
	if (!marshall_payload(&pos, &pduleft, &packet->extension[NHRP_EXTENSION_PAYLOAD]))
		return -1;

	phdr->extension_offset = htons((int)(pos - pdu));
	for (i = 1; i < ARRAY_SIZE(packet->extension); i++) {
		struct nhrp_extension_header *eh = (struct nhrp_extension_header *) pos;

		if (packet->extension[i].type == NHRP_PAYLOAD_TYPE_NONE)
			continue;

		neh.type = htons(i);
		if (packet->extension[i].flags & NHRP_PAYLOAD_FLAG_COMPULSORY)
			neh.type |= NHRP_EXTENSION_FLAG_COMPULSORY;
		neh.length = 0;

		if (!marshall_binary(&pos, &pduleft, sizeof(neh), &neh))
			return -1;
		if (!marshall_payload(&pos, &pduleft, &packet->extension[i]))
			return -1;
		eh->length = htons((pos - (uint8_t *) eh) - sizeof(neh));
	}
	neh.type = htons(NHRP_EXTENSION_END) | NHRP_EXTENSION_FLAG_COMPULSORY;
	neh.length = 0;
	if (!marshall_binary(&pos, &pduleft, sizeof(neh), &neh))
		return -1;
	if (((uintptr_t) pos) & 1)
		*pos = 0;

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
	uint8_t pdu[MAX_PDU_SIZE];
	int size;

	if (!kernel_route(packet, &iface, &nexthop))
		return FALSE;

	if (packet->hdr.hop_count == 0)
		packet->hdr.hop_count = 16;
	if (packet->extension[NHRP_EXTENSION_AUTHENTICATION].type == NHRP_PAYLOAD_TYPE_NONE &&
	    iface->auth_token != NULL) {
		packet->extension[NHRP_EXTENSION_AUTHENTICATION].type = NHRP_PAYLOAD_TYPE_RAW;
		packet->extension[NHRP_EXTENSION_AUTHENTICATION].flags = NHRP_PAYLOAD_FLAG_COMPULSORY;
		packet->extension[NHRP_EXTENSION_AUTHENTICATION].u.raw = iface->auth_token;
	}

	size = marshall_packet(pdu, sizeof(pdu), packet);
	if (size < 0)
		return FALSE;

	nhrp_hex_dump("packet", pdu, size);

	return kernel_send(pdu, size, iface, &nexthop);
}

