/* nhrp_peer.h - NHRP peer cache definitions
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#ifndef NHRP_PEER_H
#define NHRP_PEER_H

#include <sys/queue.h>

#define NHRP_PEER_TYPE_PERMANENT	0x00	/* Learned from interface config */
#define NHRP_PEER_TYPE_STATIC		0x01	/* Static mapping from config file */
#define NHRP_PEER_TYPE_DYNAMIC		0x02	/* NHC registration */
#define NHRP_PEER_TYPE_CACHED		0x03	/* Received/relayed resolution reply */

CIRCLEQ_HEAD(nhrp_peer_list, nhrp_peer);

struct nhrp_peer {
	CIRCLEQ_ENTRY(nhrp_peer) entry;
	uint8_t type;
	uint8_t prefix_length;
	uint16_t flags;
	uint16_t afnum;
	uint16_t mtu;
	uint32_t expire_time;
	uint8_t nbma_address[NHRP_MAX_ADDRESS_LEN];
	uint8_t nbma_subaddress[NHRP_MAX_SUBADDRESS_LEN];
	uint8_t protocol_address[NHRP_MAX_ADDRESS_LEN];
	uint8_t dst_protocol_address[NHRP_MAX_ADDRESS_LEN];
};

#endif
