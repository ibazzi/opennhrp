/* nhrp_peer.c - NHRP peer cache implementation
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include "nhrp_common.h"
#include "nhrp_peer.h"

static struct nhrp_peer_list peer_cache = CIRCLEQ_HEAD_INITIALIZER(peer_cache);

static void nhrp_peer_register(struct nhrp_task *task)
{
	nhrp_info("Sending NHRP-Register");
}

void nhrp_peer_insert(struct nhrp_peer *peer)
{
	CIRCLEQ_INSERT_HEAD(&peer_cache, peer, peer_list);

	if (peer->type == NHRP_PEER_TYPE_STATIC) {
		/* Schedule registration */
		nhrp_task_schedule(&peer->task, 5000, nhrp_peer_register);
	}

	switch (peer->protocol_type) {
	case ETH_P_IP:
		nhrp_info("Peer %d.%d.%d.%d/%d learned",
			peer->dst_protocol_address.addr[0],
			peer->dst_protocol_address.addr[1],
			peer->dst_protocol_address.addr[2],
			peer->dst_protocol_address.addr[3],
			peer->prefix_length);
		break;
	}
}

void nhrp_peer_remove(struct nhrp_peer *peer)
{
	CIRCLEQ_REMOVE(&peer_cache, peer, peer_list);
}

struct nhrp_peer *nhrp_peer_find(struct nhrp_protocol_address *dest, int min_prefix)
{
	struct nhrp_peer *p;

	CIRCLEQ_FOREACH(p, &peer_cache, peer_list) {
	}

	return NULL;
}
