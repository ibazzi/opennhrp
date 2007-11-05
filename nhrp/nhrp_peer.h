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

#include <stdint.h>
#include <sys/queue.h>
#include "nhrp_packet.h"

#define NHRP_PEER_TYPE_LOCAL		0x00	/* Learned from interface config */
#define NHRP_PEER_TYPE_STATIC		0x01	/* Static mapping from config file */
#define NHRP_PEER_TYPE_DYNAMIC		0x02	/* NHC registration */
#define NHRP_PEER_TYPE_INCOMPLITE	0x03	/* Resolution request sent */
#define NHRP_PEER_TYPE_CACHED		0x04	/* Received/relayed resolution reply */

CIRCLEQ_HEAD(nhrp_peer_list, nhrp_peer);

struct nhrp_peer {
	CIRCLEQ_ENTRY(nhrp_peer) peer_list;
	struct nhrp_task task;
	pid_t script_pid;
	void (*script_callback)(struct nhrp_peer *peer);
	uint8_t type;
	uint8_t prefix_length;
	uint16_t afnum;
	uint16_t protocol_type;
	uint16_t mtu;
	uint32_t expire_time;
	struct nhrp_address nbma_address;
	struct nhrp_address protocol_address;
	struct nhrp_address dst_protocol_address;
	struct nhrp_interface *interface;
};

int nhrp_peer_init(void);
void nhrp_peer_insert(struct nhrp_peer *peer);
void nhrp_peer_remove(struct nhrp_peer *peer);
struct nhrp_peer *nhrp_peer_find(struct nhrp_address *dest, int min_prefix);

#endif
