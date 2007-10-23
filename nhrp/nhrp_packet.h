/* nhrp_packet.h - In-memory NHRP packet definitions
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#ifndef NHRP_PACKET_H
#define NHRP_PACKET_H

#include <sys/queue.h>
#include "nhrp_protocol.h"

#define NHRP_MAX_ADDRESS_LEN		8
#define NHRP_MAX_SUBADDRESS_LEN		4
#define NHRP_MAX_EXTENSIONS		10

struct nhrp_buffer {
	uint32_t length;
	uint8_t data[];
};

struct nhrp_nbma_address {
	uint8_t addr_len;
	uint8_t subaddr_len;
	uint8_t addr[NHRP_MAX_ADDRESS_LEN];
	uint8_t subadd[NHRP_MAX_SUBADDRESS_LEN];
};

struct nhrp_protocol_address {
	uint8_t addr_len;
	uint8_t addr[NHRP_MAX_ADDRESS_LEN];
};

struct nhrp_cie {
	TAILQ_ENTRY(nhrp_cie)		cie_list_entry;
	struct nhrp_cie_header		hdr;
	struct nhrp_nbma_address	nbma_address;
	struct nhrp_protocol_address	protocol_address;
};

TAILQ_HEAD(nhrp_cie_list_head, nhrp_cie);

#define NHRP_PAYLOAD_NONE		0
#define NHRP_PAYLOAD_RAW		1
#define NHRP_PAYLOAD_CIE_LIST		2

struct nhrp_payload {
	uint16_t type;
	uint16_t extension_type;
	union {
		struct nhrp_buffer *raw;
		struct nhrp_cie_list_head cie_list_head;
	} u;
};

struct nhrp_packet {
	struct nhrp_packet_header	hdr;
	struct nhrp_nbma_address	src_nbma_address;
	struct nhrp_protocol_address	src_protocol_address;
	struct nhrp_protocol_address	dst_protocol_address;
	struct nhrp_payload		payload;
	struct nhrp_payload		extension[NHRP_MAX_EXTENSIONS];
};

struct nhrp_buffer *nhrp_buffer_alloc(uint32_t size);
void nhrp_buffer_free(struct nhrp_buffer *buffer);

struct nhrp_packet *nhrp_packet_alloc(void);
void nhrp_packet_free(struct nhrp_packet *packet);
int nhrp_packet_recv(struct nhrp_packet *packet);
int nhrp_packet_send(struct nhrp_packet *packet);

#endif
