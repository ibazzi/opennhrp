/* nhrp_peer.c - NHRP peer cache implementation
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <string.h>
#include "nhrp_common.h"
#include "nhrp_peer.h"

static struct nhrp_peer_list peer_cache = CIRCLEQ_HEAD_INITIALIZER(peer_cache);

static void nhrp_peer_register(struct nhrp_task *task);

static void nhrp_peer_handle_registration_reply(void *ctx, struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;
	char dst[64];

	if (reply == NULL ||
	    reply->hdr.type != NHRP_PACKET_REGISTRATION_REPLY) {
		nhrp_info("Failed to register to %s",
			  nhrp_protocol_address_format(peer->protocol_type,
				  		       &peer->dst_protocol_address,
						       sizeof(dst), dst));
		nhrp_task_schedule(&peer->task, 10000, nhrp_peer_register);
		return;
	}

	nhrp_info("Received Registration Reply from %s",
		  nhrp_protocol_address_format(peer->protocol_type,
					       &peer->dst_protocol_address,
					       sizeof(dst), dst));

	/* Re-register after holding time expires */
	nhrp_task_schedule(&peer->task, (NHRP_HOLDING_TIME - 60) * 1000,
			   nhrp_peer_register);
}

static void nhrp_peer_register(struct nhrp_task *task)
{
	struct nhrp_peer *peer = container_of(task, struct nhrp_peer, task);
	char dst[64];
	struct nhrp_packet *packet;
	struct nhrp_cie *cie;
	struct nhrp_payload *payload;
	int sent = FALSE;

	packet = nhrp_packet_alloc();
	if (packet == NULL)
		goto error;

	*packet = (struct nhrp_packet) {
		.hdr.afnum = peer->afnum,
		.hdr.protocol_type = peer->protocol_type,
		.hdr.version = NHRP_VERSION_RFC2332,
		.hdr.type = NHRP_PACKET_REGISTRATION_REQUEST,
		.hdr.flags = NHRP_FLAG_REGISTRATION_UNIQUE,
		.dst_protocol_address = peer->dst_protocol_address,
	};

	cie = nhrp_cie_alloc();
	if (cie == NULL)
		goto error;

        *cie = (struct nhrp_cie) {
		.hdr.code = NHRP_CODE_SUCCESS,
		.hdr.prefix_length = 0xff,
		.hdr.mtu = 0,
		.hdr.holding_time = constant_htons(NHRP_HOLDING_TIME),
		.hdr.preference = 0,
	};

	payload = nhrp_packet_payload(packet);
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	nhrp_info("Sending Registration Request to %s",
		  nhrp_protocol_address_format(peer->protocol_type,
					       &peer->dst_protocol_address,
					       sizeof(dst), dst));

	sent = nhrp_packet_send_request(packet,
		nhrp_peer_handle_registration_reply, peer);

error:
	if (!sent) {
		nhrp_packet_free(packet);
		/* Try again later */
		nhrp_task_schedule(&peer->task, 10000, nhrp_peer_register);
	}
}

void nhrp_peer_insert(struct nhrp_peer *peer)
{
	char dst[64], nbma[64];

	CIRCLEQ_INSERT_HEAD(&peer_cache, peer, peer_list);

	if (peer->type == NHRP_PEER_TYPE_STATIC) {
		/* Schedule registration */
		nhrp_task_schedule(&peer->task, 1000, nhrp_peer_register);
	}

	nhrp_info("Peer %s/%d learned at NBMA address %s",
		nhrp_protocol_address_format(peer->protocol_type,
			&peer->dst_protocol_address, sizeof(dst), dst),
		peer->prefix_length,
		nhrp_nbma_address_format(peer->afnum, &peer->nbma_address,
			sizeof(nbma), nbma));
}

void nhrp_peer_remove(struct nhrp_peer *peer)
{
	CIRCLEQ_REMOVE(&peer_cache, peer, peer_list);
}

struct nhrp_peer *nhrp_peer_find(uint16_t protocol_type,
				 struct nhrp_protocol_address *dest,
				 int min_prefix)
{
	struct nhrp_peer *p;
	int prefix;

	if (min_prefix == 0xff)
		min_prefix = dest->addr_len * 8;

	CIRCLEQ_FOREACH(p, &peer_cache, peer_list) {
		if (protocol_type != p->protocol_type)
			continue;

		if (min_prefix < p->prefix_length)
			continue;

		prefix = min_prefix;
		if (p->prefix_length < min_prefix)
			prefix = p->prefix_length;

		if (memcmp(dest->addr, p->dst_protocol_address.addr,
			   prefix / 8) != 0)
			continue;

		/* FIXME: Check remaining bits of address */
		return p;
	}

	return NULL;
}
