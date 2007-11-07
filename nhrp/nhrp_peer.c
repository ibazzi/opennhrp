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
	[NHRP_PEER_TYPE_LOCAL] = "local address",
	[NHRP_PEER_TYPE_STATIC] = "statically mapped",
	[NHRP_PEER_TYPE_DYNAMIC] = "dynamically registered",
	[NHRP_PEER_TYPE_INCOMPLETE] = "incomplete",
	[NHRP_PEER_TYPE_CACHED] = "cached",
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
		nhrp_address_format(&peer->dst_protocol_address, sizeof(tmp), tmp),
		peer->prefix_length);

	if (peer->nbma_address.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, " (at NBMA %s)",
			nhrp_address_format(&peer->nbma_address, sizeof(tmp), tmp));
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
	struct nhrp_peer *p, *dup;

	dup = nhrp_peer_dup(peer);
	nhrp_peer_remove(peer);

	while ((p = nhrp_peer_find(&dup->dst_protocol_address,
				   dup->prefix_length,
				   NHRP_PEER_FIND_SUBNET_MATCH)) != NULL)
		nhrp_peer_prune(p);

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

	envp[i++] = env("NHRP_PEER_PROTOCOL_ADDRESS", nhrp_address_format(&peer->protocol_address, sizeof(tmp), tmp));
	envp[i++] = env("NHRP_PEER_NBMA_ADDRESS", nhrp_address_format(&peer->nbma_address, sizeof(tmp), tmp));
	if (peer->interface != NULL)
		envp[i++] = env("NHRP_PEER_INTERFACE", peer->interface->name);

	envp[i++] = env("NHRP_ROUTE_DEST", nhrp_address_format(&peer->dst_protocol_address, sizeof(tmp), tmp));
	sprintf(tmp, "%d", peer->prefix_length);
	envp[i++] = env("NHRP_ROUTE_PREFIX", tmp);

	envp[i++] = NULL;

	execve("peer-updown", argv, envp);
	exit(1);
}

static void nhrp_peer_handle_registration_reply(void *ctx, struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;
	char dst[64];

	if (nhrp_peer_free(peer))
		return;

	if (reply == NULL ||
	    reply->hdr.type != NHRP_PACKET_REGISTRATION_REPLY) {
		nhrp_info("Failed to register to %s",
			  nhrp_address_format(&peer->dst_protocol_address,
					      sizeof(dst), dst));
		nhrp_task_schedule(&peer->task, 10000, nhrp_peer_register_task);
		return;
	}

	nhrp_info("Received Registration Reply from %s",
		  nhrp_address_format(&peer->dst_protocol_address,
				      sizeof(dst), dst));

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
		  nhrp_address_format(&peer->dst_protocol_address,
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

static void nhrp_peer_route_up(struct nhrp_peer *peer)
{
	if (nhrp_address_cmp(&peer->protocol_address, &peer->dst_protocol_address) != 0)
		nhrp_peer_run_script(peer, "route-up", NULL);
}

static void nhrp_peer_handle_resolution_reply(void *ctx, struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	char dst[64], tmp[64], nbma[64];

	if (nhrp_peer_free(peer))
		return;

	if (reply == NULL ||
	    reply->hdr.type != NHRP_PACKET_RESOLUTION_REPLY) {
		nhrp_info("Failed to resolve %s",
			  nhrp_address_format(&peer->dst_protocol_address,
				  	      sizeof(dst), dst));

		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_NEGATIVE);
		return;
	}

	payload = nhrp_packet_payload(reply);
	if (payload->payload_type != NHRP_PAYLOAD_TYPE_CIE_LIST)
		return;

	cie = TAILQ_FIRST(&payload->u.cie_list_head);

	peer->prefix_length = cie->hdr.prefix_length;
	peer->nbma_address = cie->nbma_address;
	peer->protocol_address = cie->protocol_address;
	peer->expire_time = (ntohs(cie->hdr.holding_time) - 60) * 1000;
	nhrp_address_mask(&peer->dst_protocol_address, peer->prefix_length);

	nhrp_info("Received Resolution Reply %s/%d is at proto %s nbma %s",
		  nhrp_address_format(&peer->dst_protocol_address,
				      sizeof(dst), dst),
		  peer->prefix_length,
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&peer->nbma_address,
			  	      sizeof(nbma), nbma));

	nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_CACHED);
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
		.hdr.flags =
			NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER |
			NHRP_FLAG_RESOLUTION_AUTHORATIVE,
		.dst_protocol_address = peer->dst_protocol_address,
	};

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
		  nhrp_address_format(&peer->dst_protocol_address,
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
		nhrp_peer_run_script(peer, "peer-up", nhrp_peer_route_up);
		nhrp_task_schedule(&peer->task, peer->expire_time,
				   nhrp_peer_prune_task);
		break;
	case NHRP_PEER_TYPE_NEGATIVE:
		nhrp_task_schedule(&peer->task, NHRP_NEGATIVE_CACHE_TIME,
				   nhrp_peer_prune_task);
		break;
	}

	nhrp_info("Peer %s, %s",
		  nhrp_peer_format(peer, sizeof(tmp), tmp),
		  peer_type[peer->type]);
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
	char tmp[64], tmp2[64];
	int prefix;

	if (min_prefix == 0xff)
		min_prefix = dest->addr_len * 8;

	CIRCLEQ_FOREACH(p, &peer_cache, peer_list) {
		if (dest->type != p->dst_protocol_address.type)
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
		     (p->type == NHRP_PEER_TYPE_INCOMPLETE ||
		      p->type == NHRP_PEER_TYPE_NEGATIVE))
			continue;

		if (memcmp(dest->addr, p->dst_protocol_address.addr,
			   prefix / 8) != 0)
			continue;

		/* FIXME: Check remaining bits of address */

		if (found_peer != NULL &&
		    found_peer->prefix_length > p->prefix_length)
			continue;

		/* Best match so far */
		found_peer = p;
	}

	nhrp_info("nhrp_peer_find(%s): returning %s",
		nhrp_address_format(dest, sizeof(tmp), tmp),
		nhrp_peer_format(found_peer, sizeof(tmp2), tmp2));

	return found_peer;
}

static int signal_pipe[2];

static void signal_handler(int sig)
{
	send(signal_pipe[1], &sig, sizeof(sig), MSG_DONTWAIT);
}

static void reap_children(void *ctx, int fd, short events)
{
	struct nhrp_peer *p;
	pid_t pid;
	int status, sig;

	read(fd, &sig, sizeof(sig));
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
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
}

int nhrp_peer_init(void)
{
	socketpair(AF_UNIX, SOCK_STREAM, 0, signal_pipe);
	signal(SIGCHLD, signal_handler);
	return nhrp_task_poll_fd(signal_pipe[0], POLLIN, reap_children, NULL);
}
