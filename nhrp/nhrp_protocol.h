/* nhrp_protocol.h - NHRP protocol definitions
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#ifndef NHRP_PROTOCOL_H
#define NHRP_PROTOCOL_H

#include <stdint.h>
#include "afnum.h"

/* NHRP Version */
#define NHRP_VERSION_RFC2332			1

/* NHRP Packet Types */
#define NHRP_PACKET_RESOLUTION_REQUEST		1
#define NHRP_PACKET_RESOLUTION_REPLY		2
#define NHRP_PACKET_REGISTRATION_REQUEST	3
#define NHRP_PACKET_REGISTRATION_REPLY		4
#define NHRP_PACKET_PURGE_REQUEST		5
#define NHRP_PACKET_PURGE_REPLY			6
#define NHRP_PACKET_ERROR_INDICATION		7
#define NHRP_PACKET_TRAFFIC_INDICATION		8

/* NHRP Extension Types */
#define NHRP_EXTENSION_COMPULSORY		constant_htons(0x8000)
#define NHRP_EXTENSION_END			constant_htons(0)
#define NHRP_EXTENSION_PAYLOAD			constant_htons(0)
#define NHRP_EXTENSION_RESPONDER_ADDRESS	constant_htons(3)
#define NHRP_EXTENSION_FORWARD_TRANSIT_NHS	constant_htons(4)
#define NHRP_EXTENSION_REVERSE_TRANSIT_NHS	constant_htons(5)
#define NHRP_EXTENSION_AUTHENTICATION		constant_htons(7)
#define NHRP_EXTENSION_VENDOR			constant_htons(8)
#define NHRP_EXTENSION_CISCO_NAT		constant_htons(9)

/* NHRP Error Indication Codes */
#define NHRP_ERROR_UNRECOGNIZED_EXTENSION	1
#define NHRP_ERROR_LOOP_DETECTED		2
#define NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE	6
#define NHRP_ERROR_PROTOCOL_ERROR		7
#define NHRP_ERROR_SDU_SIZE_EXCEEDED		8
#define NHRP_ERROR_INVALID_EXTENSION		9
#define NHRP_ERROR_INVALID_RESOLUTION_REPLY	10
#define NHRP_ERROR_AUTHENTICATION_FAILURE	11
#define NHRP_ERROR_HOP_COUNT_EXCEEDED		15

/* NHRP CIE Codes */
#define NHRP_CODE_SUCCESS			0
#define NHRP_CODE_ADMINISTRATIVELY_PROHIBITED	4
#define NHRP_CODE_INSUFFICIENT_RESOURCES	5
#define NHRP_CODE_NO_BINDING_EXISTS		11
#define NHRP_CODE_BINDING_NON_UNIQUE		13
#define NHRP_CODE_UNIQUE_ADDRESS_REGISTERED     14

/* NHRP Flags for Resolution request/reply */
#define NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER	constant_htons(0x0001)
#define NHRP_FLAG_RESOLUTION_AUTHORATIVE	constant_htons(0x0002)
#define NHRP_FLAG_RESOLUTION_DESTINATION_STABLE	constant_htons(0x0004)
#define NHRP_FLAG_RESOLUTION_UNIQUE		constant_htons(0x0008)
#define NHRP_FLAG_RESOLUTION_SOURCE_STABLE	constant_htons(0x0010)

/* NHRP Flags for Registration request/reply */
#define NHRP_FLAG_REGISTRATION_UNIQUE		constant_htons(0x0001)

/* NHRP Flags for Purge request/reply */
#define NHRP_FLAG_PURGE_NO_REPLY		constant_htons(0x0001)

/* NHRP Packet Structures */
struct nhrp_packet_header {
	/* Fixed header */
	uint16_t	afnum;
	uint16_t	protocol_type;
	uint8_t		snap[5];
	uint8_t		hop_count;
	uint16_t	packet_size;
	uint16_t	checksum;
	uint16_t	extension_offset;
	uint8_t		version;
	uint8_t		type;
	uint8_t		src_nbma_address_len;
	uint8_t		src_nbma_subaddress_len;

	/* Mandatory header */
	uint8_t		src_protocol_address_len;
	uint8_t		dst_protocol_address_len;
	uint16_t	flags;
	union {
		uint32_t		request_id;
		struct {
			uint16_t	code;
			uint16_t	offset;
		} error;
	} u;
};

struct nhrp_cie_header {
	uint8_t		code;
	uint8_t		prefix_length;
	uint16_t	unused;
	uint16_t	mtu;
	uint16_t	holding_time;
	uint8_t		nbma_address_len;
	uint8_t		nbma_subaddress_len;
	uint8_t		protocol_address_len;
	uint8_t		preference;
};

struct nhrp_extension_header {
	uint16_t	type;
	uint16_t	length;
};

#endif
