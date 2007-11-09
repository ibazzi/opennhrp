/* nhrp_peer.c - NHRP peer cache implementation
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"

#define NHRP_NEGATIVE_CACHE_TIME	(3*60*1000)

static struct nhrp_peer_list peer_cache = CIRCLEQ_HEAD_INITIALIZER(peer_cache);

static const char * const peer_type[] = {
	[NHRP_PEER_TYPE_INCOMPLETE]	= "incomplete",
	[NHRP_PEER_TYPE_NEGATIVE]	= "negative",
	[NHRP_PEER_TYPE_CACHED]		= "cached",
	[NHRP_PEER_TYPE_CACHED_ROUTE]	= "route",
	[NHRP_PEER_TYPE_DYNAMIC]	= "dynamic",
	[NHRP_PEER_TYPE_LOCAL]		= "local",
	[NHRP_PEER_TYPE_STATIC]		= "static",
};

static void nhrp_peer_register_task(struct nhrp_task *task);
static void nhrp_peer_register(struct nhrp_peer *peer);

struct nhrp_peer *nhrp_peer_alloc(void)
{
	struct nhrp_peer *p;
	p = calloc(1, sizeof(struct nhrp_peer));
	p->ref_count = 1;
	return p;
}

struct nhrp_peer *nhrp_peer_dup(struct nhrp_peer *peer)
{
	peer->ref_count++;
	return peer;
}

int nhrp_peer_free(struct nhrp_peer *peer)
{
	peer->ref_count--;
	if (peer->ref_count > 0)
		return FALSE;
	nhrp_task_cancel(&peer->task);
	free(peer);
	return TRUE;
}

static char *nhrp_peer_format(struct nhrp_peer *peer, size_t len, char *buf)
{
	char tmp[64];
	int i = 0;

	if (peer == NULL) {
		snprintf(buf, len, "(null)");
		return buf;
	}

	i += snprintf(&buf[i], len - i, "%s/%d",
		nhrp_address_format(&peer->protocol_address, sizeof(tmp), tmp),
		peer->prefix_length);

	if (peer->next_hop_address.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, " %s %s",
			peer->type == NHRP_PEER_TYPE_CACHED_ROUTE ? "nexthop" : "nbma",
			nhrp_address_format(&peer->next_hop_address, sizeof(tmp), tmp));
	}
	if (peer->interface != NULL) {
		i += snprintf(&buf[i], len - i, " dev %s",
			      peer->interface->name);
	}

	return buf;
}

static void nhrp_peer_prune(struct nhrp_peer *peer)
{
	char tmp[64];

	if (peer->script_pid) {
		kill(SIGINT, peer->script_pid);
		peer->script_pid = -1;
	}

	nhrp_info("Pruning peer %s", nhrp_peer_format(peer, sizeof(tmp), tmp));
	nhrp_peer_remove(peer);
}

static void nhrp_peer_prune_task(struct nhrp_task *task)
{
	return nhrp_peer_prune(container_of(task, struct nhrp_peer, task));
}

static void nhrp_peer_reinsert(struct nhrp_peer *peer, int type)
{
	struct nhrp_peer *dup;

	dup = nhrp_peer_dup(peer);
	nhrp_peer_remove(peer);

	dup->type = type;
	nhrp_peer_insert(dup);
	nhrp_peer_free(dup);
}

static char *env(const char *key, const char *value)
{
	char *buf;
	buf = malloc(strlen(key)+strlen(value)+2);
	if (buf == NULL)
		return NULL;
	sprintf(buf, "%s=%s", key, value);
	return buf;
}

static int nhrp_peer_run_script(struct nhrp_peer *peer, char *action, void (*cb)(struct nhrp_peer *))
{
	char *argv[] = { "./peer-updown", action, NULL };
	char *envp[32];
	char tmp[64];
	pid_t pid;
	int i = 0;

	pid = fork();
	if (pid == -1)
		return FALSE;
	if (pid > 0) {
		peer->script_pid = pid;
		peer->script_callback = cb;
		return TRUE;
	}

	envp[i++] = env("NHRP_DESTADDR", nhrp_address_format(&peer->protocol_address, sizeof(tmp), tmp));
	sprintf(tmp, "%d", peer->prefix_length);
	envp[i++] = env("NHRP_DESTPREFIX", tmp);

	switch (peer->type) {
	case NHRP_PEER_TYPE_CACHED:
	case NHRP_PEER_TYPE_LOCAL:
	case NHRP_PEER_TYPE_STATIC:
		envp[i++] = env("NHRP_DESTNBMA",
			nhrp_address_format(&peer->next_hop_address, sizeof(tmp), tmp));
		break;
	case NHRP_PEER_TYPE_CACHED_ROUTE:
		envp[i++] = env("NHRP_NEXTHOP",
			nhrp_address_format(&peer->next_hop_address, sizeof(tmp), tmp));
		break;
	}
	if (peer->interface != NULL)
		envp[i++] = env("NHRP_DESTIFACE", peer->interface->name);

	envp[i++] = NULL;

	execve("peer-updown", argv, envp);
	exit(1);
}

static void nhrp_peer_handle_registration_reply(void *ctx, struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	char tmp[64];

	if (nhrp_peer_free(peer))
		return;

	if (reply == NULL ||
	    reply->hdr.type != NHRP_PACKET_REGISTRATION_REPLY) {
		nhrp_info("Failed to register to %s",
			  nhrp_address_format(&peer->protocol_address,
					      sizeof(tmp), tmp));
		nhrp_task_schedule(&peer->task, 10000, nhrp_peer_register_task);
		return;
	}

	nhrp_info("Received Registration Reply from %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(tmp), tmp));

	/* Check for NAT */
	payload = nhrp_packet_extension(reply, NHRP_EXTENSION_NAT_ADDRESS | NHRP_EXTENSION_FLAG_NOCREATE);
	if (payload != NULL) {
		cie = nhrp_payload_get_cie(payload, 2);
		if (cie != NULL) {
			nhrp_info("NAT detected: our real NBMA address is %s",
				  nhrp_address_format(&cie->nbma_address, sizeof(tmp), tmp));
			peer->interface->nat_cie = *cie;
		}
	}

	/* Re-register after holding time expires */
	nhrp_task_schedule(&peer->task, (NHRP_HOLDING_TIME - 60) * 1000,
			   nhrp_peer_register_task);
}

static void nhrp_peer_register_task(struct nhrp_task *task)
{
	nhrp_peer_register(container_of(task, struct nhrp_peer, task));
}

static void nhrp_peer_register(struct nhrp_peer *peer)
{
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
		.hdr.flags = NHRP_FLAG_REGISTRATION_UNIQUE |
			     NHRP_FLAG_REGISTRATION_NAT,
		.dst_protocol_address = peer->protocol_address,
	};

	/* Payload CIE */
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

	/* Cisco NAT extension CIE */
	cie = nhrp_cie_alloc();
	if (cie == NULL)
		goto error;

        *cie = (struct nhrp_cie) {
		.hdr.code = NHRP_CODE_SUCCESS,
		.hdr.prefix_length = peer->protocol_address.addr_len * 8,
		.hdr.preference = 0,
		.nbma_address = peer->next_hop_address,
		.protocol_address = peer->protocol_address,
	};

	payload = nhrp_packet_extension(packet, NHRP_EXTENSION_NAT_ADDRESS);
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	nhrp_info("Sending Registration Request to %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(dst), dst));

	sent = nhrp_packet_send_request(packet,
					nhrp_peer_handle_registration_reply,
					nhrp_peer_dup(peer));
	peer->interface = packet->dst_iface;

error:
	if (!sent) {
		nhrp_packet_free(packet);
		/* Try again later */
		nhrp_task_schedule(&peer->task, 10000, nhrp_peer_register_task);
	}
}

static void nhrp_peer_dynamic_up(struct nhrp_peer *peer)
{
	kernel_inject_neighbor(&peer->protocol_address, peer);
}

static void nhrp_peer_handle_resolution_reply(void *ctx, struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx, *np;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	struct nhrp_interface *iface;
	char dst[64], tmp[64], nbma[64];

	if (nhrp_peer_free(peer))
		return;

	if (reply == NULL ||
	    reply->hdr.type != NHRP_PACKET_RESOLUTION_REPLY) {
		nhrp_info("Failed to resolve %s",
			  nhrp_address_format(&peer->protocol_address,
				  	      sizeof(dst), dst));

		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_NEGATIVE);
		return;
	}

	payload = nhrp_packet_payload(reply);
	if (payload->payload_type != NHRP_PAYLOAD_TYPE_CIE_LIST)
		return;

	cie = TAILQ_FIRST(&payload->u.cie_list_head);

	nhrp_info("Received Resolution Reply %s/%d is at proto %s nbma %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(dst), dst),
		  cie->hdr.prefix_length,
		  nhrp_address_format(&cie->protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&cie->nbma_address,
				      sizeof(nbma), nbma));


	if (nhrp_address_cmp(&peer->protocol_address, &cie->protocol_address) == 0) {
		/* Destination is within NBMA network; update cache */
		peer->prefix_length = cie->hdr.prefix_length;
		peer->next_hop_address = cie->nbma_address;
		peer->expire_time = (ntohs(cie->hdr.holding_time) - 60) * 1000;
		nhrp_address_mask(&peer->protocol_address, peer->prefix_length);
		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_CACHED);
		return;
	}

	/* Update the received NBMA address to nexthop */
	iface = peer->interface;
	np = nhrp_peer_alloc();
	np->type = NHRP_PEER_TYPE_CACHED;
	np->afnum = reply->hdr.afnum;
	np->protocol_type = reply->hdr.protocol_type;
	np->protocol_address = cie->protocol_address;
	np->next_hop_address = cie->nbma_address;
	np->prefix_length = cie->protocol_address.addr_len * 8;
	np->interface = iface;
	nhrp_peer_insert(np);
	nhrp_peer_free(np);

	/* Off NBMA destination; a shortcut route */
	peer->prefix_length = cie->hdr.prefix_length;
	peer->next_hop_address = cie->protocol_address;
	peer->expire_time = (ntohs(cie->hdr.holding_time) - 60) * 1000;
	nhrp_address_mask(&peer->protocol_address, peer->prefix_length);
	nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_CACHED_ROUTE);
}

static void nhrp_peer_resolve(struct nhrp_peer *peer)
{
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
		.hdr.type = NHRP_PACKET_RESOLUTION_REQUEST,
		.hdr.flags = NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER |
			     NHRP_FLAG_RESOLUTION_AUTHORATIVE |
			     NHRP_FLAG_RESOLUTION_NAT,
		.dst_protocol_address = peer->protocol_address,
	};

	/* Payload CIE */
	cie = nhrp_cie_alloc();
	if (cie == NULL)
		goto error;

        *cie = (struct nhrp_cie) {
		.hdr.code = NHRP_CODE_SUCCESS,
		.hdr.prefix_length = 0,
		.hdr.mtu = 0,
		.hdr.holding_time = constant_htons(NHRP_HOLDING_TIME),
	};

	payload = nhrp_packet_payload(packet);
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	nhrp_info("Sending Resolution Request to %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(dst), dst));

	sent = nhrp_packet_send_request(packet,
					nhrp_peer_handle_resolution_reply,
					nhrp_peer_dup(peer));
	peer->interface = packet->dst_iface;

error:
	if (!sent) {
		nhrp_packet_free(packet);
	}
}

void nhrp_peer_insert(struct nhrp_peer *ins)
{
	char tmp[128];
	struct nhrp_peer *peer;

	/* First, prune all duplicates */
	while ((peer = nhrp_peer_find(&ins->protocol_address,
				      ins->prefix_length,
				      NHRP_PEER_FIND_SUBNET_MATCH)) != NULL)
		nhrp_peer_prune(peer);

	peer = nhrp_peer_dup(ins);
	CIRCLEQ_INSERT_HEAD(&peer_cache, peer, peer_list);

	switch (peer->type) {
	case NHRP_PEER_TYPE_STATIC:
		nhrp_peer_run_script(peer, "peer-up", nhrp_peer_register);
		break;
	case NHRP_PEER_TYPE_INCOMPLETE:
		nhrp_peer_resolve(peer);
		break;
	case NHRP_PEER_TYPE_CACHED:
	case NHRP_PEER_TYPE_DYNAMIC:
		nhrp_peer_run_script(peer, "peer-up", nhrp_peer_dynamic_up);
		break;
	case NHRP_PEER_TYPE_CACHED_ROUTE:
		nhrp_peer_run_script(peer, "route-up", NULL);
		nhrp_task_schedule(&peer->task, peer->expire_time,
				   nhrp_peer_prune_task);
		break;
	case NHRP_PEER_TYPE_NEGATIVE:
		kernel_inject_neighbor(&peer->protocol_address, peer);
		nhrp_task_schedule(&peer->task, NHRP_NEGATIVE_CACHE_TIME,
				   nhrp_peer_prune_task);
		break;
	}

	nhrp_info("Adding %s %s",
		  peer_type[peer->type],
		  nhrp_peer_format(peer, sizeof(tmp), tmp));
}

void nhrp_peer_remove(struct nhrp_peer *peer)
{
	CIRCLEQ_REMOVE(&peer_cache, peer, peer_list);
	nhrp_peer_free(peer);
}

struct nhrp_peer *nhrp_peer_find(struct nhrp_address *dest,
				 int min_prefix, int flags)
{
	struct nhrp_peer *found_peer = NULL;
	struct nhrp_peer *p;
	int prefix;

	if (min_prefix == 0xff)
		min_prefix = dest->addr_len * 8;

	CIRCLEQ_FOREACH(p, &peer_cache, peer_list) {
		if (dest->type != p->protocol_address.type)
			continue;

		if (flags & NHRP_PEER_FIND_SUBNET_MATCH) {
			if (min_prefix > p->prefix_length)
				continue;
			prefix = min_prefix;
		} else {
			if (min_prefix < p->prefix_length)
				continue;
			prefix = p->prefix_length;
		}

		if ((flags & NHRP_PEER_FIND_COMPLETE) &&
		     (p->type == NHRP_PEER_TYPE_INCOMPLETE))
			continue;

		if (memcmp(dest->addr, p->protocol_address.addr,
			   prefix / 8) != 0)
			continue;

		/* FIXME: Check remaining bits of address */

		if (found_peer != NULL &&
		    found_peer->prefix_length > p->prefix_length)
			continue;

		/* Best match so far */
		found_peer = p;
	}

	return found_peer;
}

void nhrp_peer_reap_pid(pid_t pid)
{
	struct nhrp_peer *p;

	CIRCLEQ_FOREACH(p, &peer_cache, peer_list) {
		if (p->script_pid != pid)
			continue;

		p->script_pid = -1;
		if (p->script_callback) {
			void (*cb)(struct nhrp_peer *);
			cb = p->script_callback;
			p->script_callback = NULL;
			cb(p);
		}
	}
}

void nhrp_peer_dump_cache(void)
{
	struct nhrp_peer *peer;
	int num_total = 0;
	char tmp[64];

	nhrp_info("Peer cache dump:");
	CIRCLEQ_FOREACH(peer, &peer_cache, peer_list) {
		nhrp_info("%s %s",
			peer_type[peer->type],
			nhrp_peer_format(peer, sizeof(tmp), tmp));
		num_total++;
	}
	nhrp_info("Total %d peer cache entries", num_total);
}
