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

#define <stdint.h>
#include "afnum.h"

/* NHRP Link layer related defines */
#define ETH_P_NHRP				0x2001
#define IPPROTO_NHRP				54

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
#define NHRP_EXTENSION_COMPULSORY		0x8000
#define NHRP_EXTENSION_END			(0 | NHRP_EXTENSION_COMPULSORY)
#define NHRP_EXTENSION_RESPONDER_ADDRESS	(3 | NHRP_EXTENSION_COMPULSORY)
#define NHRP_EXTENSION_FORWARD_TRANSIT_NHS	(4 | NHRP_EXTENSION_COMPULSORY)
#define NHRP_EXTENSION_REVERSE_TRANSIT_NHS	(5 | NHRP_EXTENSION_COMPULSORY)
#define NHRP_EXTENSION_AUTHENTICATION		(7 | NHRP_EXTENSION_COMPULSORY)
#define NHRP_EXTENSION_VENDOR			(8)
#define NHRP_EXTENSION_CISCO_NAT		(9)

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
#define NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER	0x0001
#define NHRP_FLAG_RESOLUTION_AUTHORATIVE	0x0002
#define NHRP_FLAG_RESOLUTION_DESTINATION_STABLE	0x0004
#define NHRP_FLAG_RESOLUTION_UNIQUE		0x0008
#define NHRP_FLAG_RESOLUTION_SOURCE_STABLE	0x0010

/* NHRP Flags for Registration request/reply */
#define NHRP_FLAG_REGISTRATION_UNIQUE		0x0001

/* NHRP Flags for Purge request/reply */
#define NHRP_FLAG_PURGE_NO_REPLY		0x0001

/* NHRP Packet Structures */
struct nhrp_packet_header {
	uint16		ar_afn;
	uint16		ar_pro_type;
	uint8		ar_snap[5];
	uint8		ar_hopcnt;
	uint16		ar_pktsz;
	uint16		ar_chksum;
	uint16		ar_extoff;
	uint16		ar_op_version;
	uint16		ar_op_type;
	uint16		ar_shtl;
	uint16		ar_sstl;
};

struct nhrp_packet_mandatory_part {
	uint8		src_proto_len;
	uint8		dst_proto_len;
	uint16		flags;
	uint32		request_id;
};

struct nhrp_cie_header {
	uint8		code;
	uint8		prefix_length;
	uint16		unused;
	uint16		mtu;
	uint16		holding_time;
	uint8		cli_nbma_address_len;
	uint8		cli_nbma_subaddress_len;
	uint8		cli_protocol_len;
	uint8		preference;
};

struct nhrp_extension_header {
	uint16		type;
	uint16		length;
};

#endif
