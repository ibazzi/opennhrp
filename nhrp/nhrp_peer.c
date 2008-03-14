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

#define NHRP_PEER_FORMAT_LEN		128
#define NHRP_NEGATIVE_CACHE_TIME	(3*60)
#define NHRP_RENEW_TIME			(2*60)
#define NHRP_RETRY_REGISTER_TIME	(60)

#define NHRP_PEER_FLAG_PRUNE_PENDING	0x00010000

const char * const nhrp_peer_type[] = {
	[NHRP_PEER_TYPE_INCOMPLETE]	= "incomplete",
	[NHRP_PEER_TYPE_NEGATIVE]	= "negative",
	[NHRP_PEER_TYPE_CACHED]		= "cached",
	[NHRP_PEER_TYPE_CACHED_ROUTE]	= "route",
	[NHRP_PEER_TYPE_DYNAMIC]	= "dynamic",
	[NHRP_PEER_TYPE_LOCAL]		= "local",
	[NHRP_PEER_TYPE_STATIC]		= "static",
};

static void nhrp_run_up_script_task(struct nhrp_task *task);
static void nhrp_peer_register_task(struct nhrp_task *task);
static void nhrp_peer_register(struct nhrp_peer *peer);
static void nhrp_peer_up(struct nhrp_peer *peer);

static int bitcmp(uint8_t *a, uint8_t *b, int len)
{
	int bytes, bits, mask, r;

	bytes = len / 8;
	bits  = len % 8;

	if (bytes != 0) {
		r = memcmp(a, b, bytes);
		if (r != 0)
			return r;
	}
	if (bits != 0) {
		mask = (0xff << (8 - bits)) & 0xff;
		return ((int) (a[bytes] & mask)) - ((int) (b[bytes] & mask));
	}
	return 0;
}

static const char *nhrp_error_indication_text(int ei)
{
	switch (ei) {
	case -1:
		return "timeout";
	case NHRP_ERROR_UNRECOGNIZED_EXTENSION:
		return "unrecognized extension";
	case NHRP_ERROR_LOOP_DETECTED:
		return "loop detected";
	case NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE:
		return "protocol address unreachable";
	case NHRP_ERROR_PROTOCOL_ERROR:
		return "protocol error";
	case NHRP_ERROR_SDU_SIZE_EXCEEDED:
		return "SDU size exceeded";
	case NHRP_ERROR_INVALID_EXTENSION:
		return "invalid extension";
	case NHRP_ERROR_INVALID_RESOLUTION_REPLY:
		return "unexpected resolution reply";
	case NHRP_ERROR_AUTHENTICATION_FAILURE:
		return "authentication failure";
	case NHRP_ERROR_HOP_COUNT_EXCEEDED:
		return "hop count exceeded";
	}
	return "unknown";
}

static char *nhrp_peer_format(struct nhrp_peer *peer, size_t len, char *buf)
{
	char tmp[NHRP_PEER_FORMAT_LEN];
	int i = 0;

	if (peer == NULL) {
		snprintf(buf, len, "(null)");
		return buf;
	}

	i += snprintf(&buf[i], len - i, "%s/%d",
		nhrp_address_format(&peer->protocol_address, sizeof(tmp), tmp),
		peer->prefix_length);

	if (peer->next_hop_address.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, " %s",
			peer->type == NHRP_PEER_TYPE_CACHED_ROUTE ? "nexthop" : "nbma");

		if (peer->nbma_hostname != NULL) {
			i += snprintf(&buf[i], len - i, " %s[%s]",
				peer->nbma_hostname,
				nhrp_address_format(&peer->next_hop_address,
						    sizeof(tmp), tmp));
		} else {
			i += snprintf(&buf[i], len - i, " %s",
				nhrp_address_format(&peer->next_hop_address,
						    sizeof(tmp), tmp));
		}
	}
	if (peer->next_hop_nat_oa.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, " nbma-nat-oa %s",
			nhrp_address_format(&peer->next_hop_nat_oa, sizeof(tmp), tmp));
	}
	i += snprintf(&buf[i], len - i, " dev %s",
		      peer->interface->name);
	if (peer->flags & NHRP_PEER_FLAG_USED)
		i += snprintf(&buf[i], len - i, " used");
	if (peer->flags & NHRP_PEER_FLAG_UNIQUE)
		i += snprintf(&buf[i], len - i, " unique");
	if (peer->flags & NHRP_PEER_FLAG_UP)
		i += snprintf(&buf[i], len - i, " up");
	if (peer->expire_time) {
		int rel = peer->expire_time - time(NULL);
		if (rel >= 0) {
			i += snprintf(&buf[i], len - i, " expires_in %d:%02d",
				      rel / 60, rel % 60);
		} else {
			i += snprintf(&buf[i], len - i, " expired");
		}
	}

	return buf;
}

static void nhrp_peer_prune_task(struct nhrp_task *task)
{
	return nhrp_peer_remove(container_of(task, struct nhrp_peer, task));
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

static int nhrp_peer_run_script(struct nhrp_peer *peer, char *action, void (*cb)(struct nhrp_peer *, int))
{
	struct nhrp_interface *iface = peer->interface;
	const char *argv[] = { nhrp_script_file, action, NULL };
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

	envp[i++] = env("NHRP_TYPE", nhrp_peer_type[peer->type]);
	if (iface->protocol_address.type != AF_UNSPEC)
		envp[i++] = env("NHRP_SRCADDR",
				nhrp_address_format(&iface->protocol_address,
						    sizeof(tmp), tmp));
	if (peer->my_nbma_address.type != AF_UNSPEC)
		envp[i++] = env("NHRP_SRCNBMA",
				nhrp_address_format(&peer->my_nbma_address,
						    sizeof(tmp), tmp));
	envp[i++] = env("NHRP_DESTADDR",
			nhrp_address_format(&peer->protocol_address,
					    sizeof(tmp), tmp));
	sprintf(tmp, "%d", peer->prefix_length);
	envp[i++] = env("NHRP_DESTPREFIX", tmp);

	switch (peer->type) {
	case NHRP_PEER_TYPE_CACHED:
	case NHRP_PEER_TYPE_LOCAL:
	case NHRP_PEER_TYPE_STATIC:
	case NHRP_PEER_TYPE_DYNAMIC:
		envp[i++] = env("NHRP_DESTNBMA",
			nhrp_address_format(&peer->next_hop_address,
					    sizeof(tmp), tmp));
		if (peer->next_hop_nat_oa.type != PF_UNSPEC)
			envp[i++] = env("NHRP_DESTNBMA_NAT_OA",
				nhrp_address_format(&peer->next_hop_nat_oa,
						    sizeof(tmp), tmp));
		break;
	case NHRP_PEER_TYPE_CACHED_ROUTE:
		envp[i++] = env("NHRP_NEXTHOP",
			nhrp_address_format(&peer->next_hop_address, sizeof(tmp), tmp));
		break;
	}
	envp[i++] = env("NHRP_DESTIFACE", peer->interface->name);
	envp[i++] = NULL;

	execve(nhrp_script_file, (char **) argv, envp);
	exit(1);
}

static void nhrp_peer_static_up(struct nhrp_peer *peer, int status)
{
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		nhrp_peer_up(peer);

		if (peer->flags & NHRP_PEER_FLAG_REGISTER)
			nhrp_peer_register(peer);
	} else {
		nhrp_task_schedule(&peer->task, 10000, nhrp_run_up_script_task);
	}
}

static void nhrp_peer_static_down(struct nhrp_peer *peer, int status)
{
	nhrp_task_schedule(&peer->task, 5000, nhrp_run_up_script_task);
}

static void nhrp_peer_dynamic_up(struct nhrp_peer *peer, int status)
{
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		nhrp_peer_up(peer);
		kernel_inject_neighbor(&peer->protocol_address,
				       &peer->next_hop_address,
				       peer->interface);
	} else {
		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_NEGATIVE);
	}
}

static void nhrp_peer_route_up(struct nhrp_peer *peer, int status)
{
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		peer->flags |= NHRP_PEER_FLAG_UP;
	} else {
		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_NEGATIVE);
	}
}

static void nhrp_run_up_script_task(struct nhrp_task *task)
{
	struct nhrp_peer *peer = container_of(task, struct nhrp_peer, task);

	if (peer->nbma_hostname) {
		char host[64];

		if (!nhrp_address_resolve(peer->nbma_hostname, &peer->next_hop_address)) {
			nhrp_task_schedule(&peer->task, 5000, nhrp_run_up_script_task);
			return;
		}

		nhrp_info("Resolved '%s' as %s",
			peer->nbma_hostname,
			nhrp_address_format(&peer->next_hop_address,
					    sizeof(host), host));
	}

	nhrp_peer_run_script(peer, "peer-up", nhrp_peer_static_up);
}

static void nhrp_peer_up(struct nhrp_peer *peer)
{
	struct nhrp_interface *iface = peer->interface;
	struct nhrp_peer *p;

	peer->flags |= NHRP_PEER_FLAG_UP;

	/* Check if there are routes using this peer as next-hop*/
	CIRCLEQ_FOREACH(p, &iface->peer_cache, peer_list) {
		if (p->type != NHRP_PEER_TYPE_CACHED_ROUTE)
			continue;

		if (p->flags & NHRP_PEER_FLAG_UP)
			continue;

		if (nhrp_address_cmp(&p->next_hop_address,
				     &peer->protocol_address) != 0)
			continue;

		nhrp_peer_run_script(p, "route-up", nhrp_peer_route_up);
	}

	if (peer->queued_packet != NULL) {
		nhrp_packet_marshall_and_send(peer->queued_packet);
		nhrp_packet_free(peer->queued_packet);
		peer->queued_packet = NULL;
	}
}

static void nhrp_peer_handle_registration_reply(void *ctx, struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	char tmp[NHRP_PEER_FORMAT_LEN];
	int ec;

	if (nhrp_peer_free(peer))
		return;

	if (reply == NULL ||
	    reply->hdr.type != NHRP_PACKET_REGISTRATION_REPLY) {
		ec = reply ? reply->hdr.u.error.code : -1;
		nhrp_info("Failed to register to %s: %s (%d)",
			  nhrp_address_format(&peer->protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_error_indication_text(ec), ntohs(ec));
		nhrp_task_schedule(&peer->task, NHRP_RETRY_REGISTER_TIME * 1000,
				   nhrp_peer_register_task);
		return;
	}

	nhrp_info("Received Registration Reply from %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(tmp), tmp));

	/* Check for NAT */
	payload = nhrp_packet_extension(reply,
					NHRP_EXTENSION_NAT_ADDRESS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (payload != NULL) {
		cie = nhrp_payload_get_cie(payload, 2);
		if (cie != NULL) {
			nhrp_info("NAT detected: our real NBMA address is %s",
				  nhrp_address_format(&cie->nbma_address, sizeof(tmp), tmp));
			peer->interface->nat_cie = *cie;
		}
	}

	/* Re-register after holding time expires */
	nhrp_task_schedule(&peer->task,
			   (NHRP_HOLDING_TIME - NHRP_RENEW_TIME) * 1000,
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

	packet->hdr = (struct nhrp_packet_header) {
		.afnum = peer->afnum,
		.protocol_type = peer->protocol_type,
		.version = NHRP_VERSION_RFC2332,
		.type = NHRP_PACKET_REGISTRATION_REQUEST,
		.flags = NHRP_FLAG_REGISTRATION_UNIQUE |
			 NHRP_FLAG_REGISTRATION_NAT
	};
        packet->dst_protocol_address = peer->protocol_address;

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

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	/* Standard extensions */
	nhrp_packet_extension(packet,
			      NHRP_EXTENSION_FORWARD_TRANSIT_NHS |
			      NHRP_EXTENSION_FLAG_COMPULSORY,
			      NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_packet_extension(packet,
			      NHRP_EXTENSION_REVERSE_TRANSIT_NHS |
			      NHRP_EXTENSION_FLAG_COMPULSORY,
			      NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_packet_extension(packet,
			      NHRP_EXTENSION_RESPONDER_ADDRESS |
			      NHRP_EXTENSION_FLAG_COMPULSORY,
			      NHRP_PAYLOAD_TYPE_CIE_LIST);

	/* Cisco NAT extension CIE */
	cie = nhrp_cie_alloc();
	if (cie == NULL)
		goto error_free_packet;

        *cie = (struct nhrp_cie) {
		.hdr.code = NHRP_CODE_SUCCESS,
		.hdr.prefix_length = peer->protocol_address.addr_len * 8,
		.hdr.preference = 0,
		.nbma_address = peer->next_hop_address,
		.protocol_address = peer->protocol_address,
	};

	payload = nhrp_packet_extension(packet, NHRP_EXTENSION_NAT_ADDRESS,
					NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	nhrp_info("Sending Registration Request to %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(dst), dst));

	packet->dst_peer = peer;
	packet->dst_iface = peer->interface;
	sent = nhrp_packet_send_request(packet,
					nhrp_peer_handle_registration_reply,
					nhrp_peer_dup(peer));

error_free_packet:
	nhrp_packet_free(packet);
error:
	if (!sent) {
		/* Try again later */
		nhrp_task_schedule(&peer->task, NHRP_RETRY_REGISTER_TIME * 1000,
				   nhrp_peer_register_task);
	}
}

static void nhrp_peer_handle_resolution_reply(void *ctx, struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx, *np;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie, *natcie = NULL;
	struct nhrp_interface *iface;
	char dst[64], tmp[64], nbma[64];
	int ec;

	if (nhrp_peer_free(peer))
		return;

	if (reply == NULL ||
	    reply->hdr.type != NHRP_PACKET_RESOLUTION_REPLY) {
		ec = reply ? reply->hdr.u.error.code : -1;

		nhrp_info("Failed to resolve %s: %s (%d)",
			  nhrp_address_format(&peer->protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_error_indication_text(ec), ntohs(ec));

		/* Negative and up: no route what so ever - do not
		 * use static routes to send stuff to this address */
		peer->flags |= NHRP_PEER_FLAG_UP;

		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_NEGATIVE);
		return;
	}

	payload = nhrp_packet_payload(reply, NHRP_PAYLOAD_TYPE_CIE_LIST);
	cie = TAILQ_FIRST(&payload->u.cie_list_head);
	if (cie == NULL)
		return;

	nhrp_info("Received Resolution Reply %s/%d is at proto %s nbma %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(dst), dst),
		  cie->hdr.prefix_length,
		  nhrp_address_format(&cie->protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&cie->nbma_address,
				      sizeof(nbma), nbma));

	payload = nhrp_packet_extension(reply,
					NHRP_EXTENSION_NAT_ADDRESS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_CIE_LIST);
	if ((reply->hdr.flags & NHRP_FLAG_RESOLUTION_NAT) &&
	    (payload != NULL)) {
		natcie = TAILQ_FIRST(&payload->u.cie_list_head);
		if (natcie != NULL) {
			nhrp_info("NAT detected: really at proto %s nbma %s",
				nhrp_address_format(&natcie->protocol_address,
					sizeof(tmp), tmp),
				nhrp_address_format(&natcie->nbma_address,
					sizeof(nbma), nbma));
		}
	}
	if (natcie == NULL)
		natcie = cie;

	if (nhrp_address_cmp(&peer->protocol_address, &cie->protocol_address) == 0) {
		/* Destination is within NBMA network; update cache */
		peer->prefix_length = cie->hdr.prefix_length;
		peer->next_hop_address = natcie->nbma_address;
		peer->expire_time = time(NULL) + ntohs(cie->hdr.holding_time);
		nhrp_address_mask(&peer->protocol_address, peer->prefix_length);
		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_CACHED);
		return;
	}

	/* Update the received NBMA address to nexthop */
	iface = peer->interface;
	np = nhrp_peer_find(iface,
			    &cie->protocol_address,
			    cie->protocol_address.addr_len * 8,
			    NHRP_PEER_FIND_SUBNET);
	if (np == NULL) {
		np = nhrp_peer_alloc(iface);
		np->type = NHRP_PEER_TYPE_CACHED;
		np->afnum = reply->hdr.afnum;
		np->protocol_type = reply->hdr.protocol_type;
		np->protocol_address = cie->protocol_address;
		np->next_hop_address = natcie->nbma_address;
		np->prefix_length = cie->protocol_address.addr_len * 8;
		np->expire_time = time(NULL) + ntohs(cie->hdr.holding_time);
		nhrp_peer_insert(np);
		nhrp_peer_free(np);
	} else {
		np->next_hop_address = natcie->nbma_address;
		np->prefix_length = cie->protocol_address.addr_len * 8;
		np->expire_time = time(NULL) + ntohs(cie->hdr.holding_time);
		nhrp_peer_reinsert(np, NHRP_PEER_TYPE_CACHED);
	}

	/* Off NBMA destination; a shortcut route */
	peer->prefix_length = cie->hdr.prefix_length;
	peer->next_hop_address = cie->protocol_address;
	peer->expire_time = time(NULL) + ntohs(cie->hdr.holding_time);
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

	packet->hdr = (struct nhrp_packet_header) {
		.afnum = peer->afnum,
		.protocol_type = peer->protocol_type,
		.version = NHRP_VERSION_RFC2332,
		.type = NHRP_PACKET_RESOLUTION_REQUEST,
		.flags = NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER |
			 NHRP_FLAG_RESOLUTION_AUTHORATIVE |
			 NHRP_FLAG_RESOLUTION_NAT
	};
	packet->dst_protocol_address = peer->protocol_address;

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

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	nhrp_info("Sending Resolution Request to %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(dst), dst));

	/* Standard extensions */
	nhrp_packet_extension(packet,
			      NHRP_EXTENSION_FORWARD_TRANSIT_NHS |
			      NHRP_EXTENSION_FLAG_COMPULSORY,
			      NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_packet_extension(packet,
			      NHRP_EXTENSION_REVERSE_TRANSIT_NHS |
			      NHRP_EXTENSION_FLAG_COMPULSORY,
			      NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_packet_extension(packet,
			      NHRP_EXTENSION_RESPONDER_ADDRESS |
			      NHRP_EXTENSION_FLAG_COMPULSORY,
			      NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_packet_extension(packet,
			      NHRP_EXTENSION_NAT_ADDRESS,
			      NHRP_PAYLOAD_TYPE_CIE_LIST);

	packet->dst_iface = peer->interface;
	sent = nhrp_packet_send_request(packet,
					nhrp_peer_handle_resolution_reply,
					nhrp_peer_dup(peer));

error:
	if (!sent) {
		nhrp_packet_free(packet);
	}
}

static void nhrp_peer_renew(struct nhrp_peer *peer)
{
	struct nhrp_interface *iface = peer->interface;
	struct nhrp_peer *p;
	int num_routes = 0;

	/* Renew the cached information: all related routes
	 * or the peer itself */
	if (peer->type != NHRP_PEER_TYPE_CACHED_ROUTE) {
		CIRCLEQ_FOREACH(p, &iface->peer_cache, peer_list) {
			if (p->type != NHRP_PEER_TYPE_CACHED_ROUTE)
				continue;

			if (!(p->flags & NHRP_PEER_FLAG_UP))
				continue;

			if (nhrp_address_cmp(&p->next_hop_address,
					     &peer->protocol_address) != 0)
				continue;

			if (p->flags & NHRP_PEER_FLAG_PRUNE_PENDING) {
				p->flags &= ~NHRP_PEER_FLAG_PRUNE_PENDING;
				nhrp_task_cancel(&p->task);
				nhrp_peer_resolve(p);
				num_routes++;
			}
		}
	}

	if (peer->flags & NHRP_PEER_FLAG_PRUNE_PENDING) {
		peer->flags &= ~NHRP_PEER_FLAG_PRUNE_PENDING;
		nhrp_task_cancel(&peer->task);

		if (num_routes == 0)
			nhrp_peer_resolve(peer);
	}
}

static void nhrp_peer_check_renew_task(struct nhrp_task *task)
{
	struct nhrp_peer *peer = container_of(task, struct nhrp_peer, task);
	struct nhrp_peer *nexthop;

	if (peer->type == NHRP_PEER_TYPE_CACHED_ROUTE)
		nexthop = nhrp_peer_find(peer->interface,
					 &peer->next_hop_address, 0xff,
					 NHRP_PEER_FIND_ROUTE);
	else
		nexthop = peer;

	peer->flags |= NHRP_PEER_FLAG_PRUNE_PENDING;
	nhrp_task_schedule(&peer->task,
			   (peer->expire_time - time(NULL)) * 1000,
			   nhrp_peer_prune_task);

	if (nexthop->flags & NHRP_PEER_FLAG_USED)
		nhrp_peer_renew(peer);
}

struct nhrp_peer *nhrp_peer_alloc(struct nhrp_interface *iface)
{
	struct nhrp_peer *p;
	p = calloc(1, sizeof(struct nhrp_peer));
	p->ref_count = 1;
	p->interface = iface;
	return p;
}

struct nhrp_peer *nhrp_peer_dup(struct nhrp_peer *peer)
{
	peer->ref_count++;
	return peer;
}

int nhrp_peer_free(struct nhrp_peer *peer)
{
	struct nhrp_interface *iface = peer->interface;
	struct nhrp_peer *p, *next;

	peer->ref_count--;
	if (peer->ref_count > 0)
		return FALSE;

	switch (peer->type) {
	case NHRP_PEER_TYPE_CACHED_ROUTE:
		if ((peer->flags & NHRP_PEER_FLAG_UP) &&
		    !(peer->flags & NHRP_PEER_FLAG_REPLACED))
			nhrp_peer_run_script(peer, "route-down", NULL);
		break;
	case NHRP_PEER_TYPE_CACHED:
	case NHRP_PEER_TYPE_DYNAMIC:
	case NHRP_PEER_TYPE_STATIC:
		/* Remove cached routes using this entry as next-hop */
		for (p = CIRCLEQ_FIRST(&iface->peer_cache);
		     p != (void*) &iface->peer_cache; p = next) {
			next = CIRCLEQ_NEXT(p, peer_list);

			if (p->type != NHRP_PEER_TYPE_CACHED_ROUTE)
				continue;

			if (!(p->flags & NHRP_PEER_FLAG_UP))
				continue;

			if (nhrp_address_cmp(&p->next_hop_address,
					     &peer->protocol_address) != 0)
				continue;

			nhrp_peer_remove(p);
		}

		/* Execute peer-down */
		if (!(peer->flags & NHRP_PEER_FLAG_REPLACED)) {
			if (peer->flags & NHRP_PEER_FLAG_UP)
				nhrp_peer_run_script(peer, "peer-down", NULL);
		}

		/* Fall-through */
	case NHRP_PEER_TYPE_INCOMPLETE:
	case NHRP_PEER_TYPE_NEGATIVE:
		/* Remove from arp cache */
		if (!(peer->flags & NHRP_PEER_FLAG_REPLACED)) {
			if (peer->protocol_address.type != PF_UNSPEC)
				kernel_inject_neighbor(&peer->protocol_address,
						       NULL, peer->interface);
		}
		break;
	}

	if (peer->nbma_hostname) {
		free(peer->nbma_hostname);
		peer->nbma_hostname = NULL;
	}

	if (peer->script_pid) {
		kill(SIGINT, peer->script_pid);
		peer->script_pid = -1;
	}

	nhrp_task_cancel(&peer->task);

	free(peer);

	return TRUE;
}

static void nhrp_peer_resolve_nbma(struct nhrp_peer *peer)
{
	char tmp[64];
	int r;

	if (peer->interface->nbma_address.type == AF_UNSPEC) {
		r = kernel_route(NULL, &peer->next_hop_address,
				 &peer->my_nbma_address, NULL);
		if (!r) {
			nhrp_error("No route to next hop address %s",
				   nhrp_address_format(&peer->next_hop_address,
						       sizeof(tmp), tmp));
		}
	} else {
		peer->my_nbma_address = peer->interface->nbma_address;
	}
}

static void nhrp_peer_insert_task(struct nhrp_task *task)
{
	struct nhrp_peer *peer = container_of(task, struct nhrp_peer, task);
	struct nhrp_peer *nexthop;

	switch (peer->type) {
	case NHRP_PEER_TYPE_STATIC:
		nhrp_peer_resolve_nbma(peer);
		nhrp_run_up_script_task(task);
		break;
	case NHRP_PEER_TYPE_LOCAL:
		peer->flags |= NHRP_PEER_FLAG_UP;
		forward_local_addresses_changed();
		break;
	case NHRP_PEER_TYPE_INCOMPLETE:
		nhrp_peer_resolve(peer);
		break;
	case NHRP_PEER_TYPE_CACHED:
		nhrp_task_schedule(&peer->task,
				   (peer->expire_time - time(NULL) - NHRP_RENEW_TIME) * 1000,
				   nhrp_peer_check_renew_task);
		/* Fallthrough to bring peer up */
	case NHRP_PEER_TYPE_DYNAMIC:
		nhrp_peer_resolve_nbma(peer);
		if (!(peer->flags & NHRP_PEER_FLAG_UP))
			nhrp_peer_run_script(peer, "peer-up", nhrp_peer_dynamic_up);
		break;
	case NHRP_PEER_TYPE_CACHED_ROUTE:
		nexthop = nhrp_peer_find(peer->interface,
					 &peer->next_hop_address, 0xff,
					 NHRP_PEER_FIND_ROUTE | NHRP_PEER_FIND_NEXTHOP);
		if ((nexthop->flags & NHRP_PEER_FLAG_UP) &&
		    !(peer->flags & NHRP_PEER_FLAG_UP))
			nhrp_peer_run_script(peer, "route-up",
					     nhrp_peer_route_up);
		nhrp_task_schedule(&peer->task,
				   (peer->expire_time - time(NULL) - NHRP_RENEW_TIME - 1) * 1000,
				   nhrp_peer_check_renew_task);
		break;
	case NHRP_PEER_TYPE_NEGATIVE:
		peer->expire_time = time(NULL) + NHRP_NEGATIVE_CACHE_TIME;
		if (peer->flags & NHRP_PEER_FLAG_UP)
			kernel_inject_neighbor(&peer->protocol_address,
					       NULL, peer->interface);
		nhrp_task_schedule(&peer->task,
				   NHRP_NEGATIVE_CACHE_TIME * 1000,
				   nhrp_peer_prune_task);
		break;
	}
}

void nhrp_peer_insert(struct nhrp_peer *ins)
{
	struct nhrp_interface *iface = ins->interface;
	struct nhrp_peer *peer;
	char tmp[NHRP_PEER_FORMAT_LEN];

	/* First, prune all duplicates */
	while ((peer = nhrp_peer_find(iface,
				      &ins->protocol_address,
				      ins->prefix_length,
				      NHRP_PEER_FIND_SUBNET |
				      NHRP_PEER_FIND_REMOVABLE)) != NULL)
		nhrp_peer_remove(peer);

	peer = nhrp_peer_dup(ins);
	CIRCLEQ_INSERT_HEAD(&iface->peer_cache, peer, peer_list);

	nhrp_info("Adding %s %s",
		  nhrp_peer_type[peer->type],
		  nhrp_peer_format(peer, sizeof(tmp), tmp));

	if (nhrp_running || peer->type == NHRP_PEER_TYPE_LOCAL)
		nhrp_peer_insert_task(&peer->task);
	else
		nhrp_task_schedule(&peer->task, 0, nhrp_peer_insert_task);
}

void nhrp_peer_purge(struct nhrp_peer *peer)
{
	switch (peer->type) {
	case NHRP_PEER_TYPE_STATIC:
		peer->flags &= ~NHRP_PEER_FLAG_UP;
		nhrp_task_cancel(&peer->task);
		nhrp_peer_run_script(peer, "peer-down", nhrp_peer_static_down);
		break;
	default:
		nhrp_peer_remove(peer);
		break;
	}
}

void nhrp_peer_remove(struct nhrp_peer *peer)
{
	struct nhrp_interface *iface = peer->interface;

	CIRCLEQ_REMOVE(&iface->peer_cache, peer, peer_list);
	nhrp_peer_free(peer);
}

void nhrp_peer_set_used(struct nhrp_interface *iface,
			struct nhrp_address *peer_address,
			int used)
{
	struct nhrp_peer *p;

	CIRCLEQ_FOREACH(p, &iface->peer_cache, peer_list) {
		if (peer_address->type != p->protocol_address.type)
			continue;

		if (p->prefix_length != peer_address->addr_len * 8)
			continue;

		if (nhrp_address_cmp(peer_address, &p->protocol_address) != 0)
			continue;

		if (used) {
			p->flags |= NHRP_PEER_FLAG_USED;
			nhrp_peer_renew(p);
		} else
			p->flags &= ~NHRP_PEER_FLAG_USED;
	}
}

struct enum_interface_peers_ctx {
	nhrp_peer_enumerator enumerator;
	void *ctx;
};

static int enum_interface_peers(void *ctx, struct nhrp_interface *iface)
{
	struct enum_interface_peers_ctx *ectx =
		(struct enum_interface_peers_ctx *) ctx;
	struct nhrp_peer *p;
	int rc;

	CIRCLEQ_FOREACH(p, &iface->peer_cache, peer_list) {
		rc = ectx->enumerator(ectx->ctx, p);
		if (rc != 0)
			return rc;
	}
	return 0;
}

int nhrp_peer_foreach(nhrp_peer_enumerator e, void *ctx)
{
	struct enum_interface_peers_ctx ectx = { e, ctx };

	return nhrp_interface_foreach(enum_interface_peers, &ectx);
}

struct nhrp_peer *nhrp_peer_find_full(struct nhrp_interface *iface,
				      struct nhrp_address *dest,
				      int min_prefix, int flags,
				      struct nhrp_cie_list_head *cielist)
{
	struct nhrp_peer *found_peer = NULL;
	struct nhrp_peer *p;
	struct nhrp_address *addr;
	int prefix, exact, found_exact = 0;

	if (min_prefix == 0xff)
		min_prefix = dest->addr_len * 8;
	if (min_prefix == 0 && (flags & NHRP_PEER_FIND_EXACT))
		min_prefix = dest->addr_len * 8;

	CIRCLEQ_FOREACH(p, &iface->peer_cache, peer_list) {
		if (dest != NULL &&
		    dest->type != p->protocol_address.type)
			continue;

		if (flags & NHRP_PEER_FIND_NBMA) {
			prefix = min_prefix;
			if (p->type == NHRP_PEER_TYPE_CACHED_ROUTE)
				continue;
		} else if (flags & NHRP_PEER_FIND_SUBNET) {
			if (min_prefix > p->prefix_length)
				continue;
			prefix = min_prefix;
		} else if (flags & NHRP_PEER_FIND_ROUTE) {
			if (min_prefix < p->prefix_length)
				continue;
			prefix = p->prefix_length;
		} else if (flags & NHRP_PEER_FIND_EXACT) {
			if (min_prefix != p->prefix_length)
				continue;
			prefix = min_prefix;
		} else
			return NULL;

		if (flags & NHRP_PEER_FIND_NBMA)
			addr = &p->next_hop_address;
		else
			addr = &p->protocol_address;

		if (dest != NULL &&
		    p->type == NHRP_PEER_TYPE_STATIC &&
		    min_prefix == dest->addr_len * 8 &&
		    memcmp(dest->addr, addr->addr, dest->addr_len) == 0)
			exact = 1;
		else
			exact = 0;

		if (found_exact > exact)
			continue;

		if ((flags & NHRP_PEER_FIND_COMPLETE) &&
		    p->type == NHRP_PEER_TYPE_INCOMPLETE)
			continue;
		if ((flags & NHRP_PEER_FIND_UP) &&
		    !(p->flags & NHRP_PEER_FLAG_UP) && !exact)
			continue;

		if ((flags & NHRP_PEER_FIND_REMOVABLE) &&
		    (p->type == NHRP_PEER_TYPE_LOCAL ||
		     p->type == NHRP_PEER_TYPE_STATIC))
			continue;

		if ((flags & NHRP_PEER_FIND_PURGEABLE) &&
		    (p->type == NHRP_PEER_TYPE_LOCAL ||
		     (p->type == NHRP_PEER_TYPE_STATIC &&
		      !(p->flags & NHRP_PEER_FLAG_UP))))
			continue;

		if (p->type != NHRP_PEER_TYPE_CACHED_ROUTE &&
		    cielist != NULL &&
		    nhrp_address_match_cie_list(&p->next_hop_address,
						&p->protocol_address,
						cielist))
			continue;

		if (dest != NULL && bitcmp(dest->addr, addr->addr, prefix) != 0)
			continue;

		if (found_peer != NULL &&
		    found_peer->prefix_length > p->prefix_length)
			continue;

		if (found_peer != NULL && found_exact == exact &&
		    found_peer->prefix_length == p->prefix_length &&
		    found_peer->last_used < p->last_used)
			continue;

		/* Best match so far */
		found_peer = p;
		found_exact = exact;
	}

	if (found_peer != NULL)
		time(&found_peer->last_used);

	return found_peer;
}

void nhrp_peer_traffic_indication(struct nhrp_interface *iface,
				  uint16_t afnum, struct nhrp_address *dst)
{
	struct nhrp_peer *peer;

	/* Are we already doing something for this destination? */
	peer = nhrp_peer_find(iface, dst, 0xff, NHRP_PEER_FIND_EXACT);
	if (peer != NULL)
		return;

	/* Get the route */
	peer = nhrp_peer_find(iface, dst, 0xff, NHRP_PEER_FIND_ROUTE);
	if (peer != NULL) {
		/* Is this routed to somewhere already? */
		if (peer->type == NHRP_PEER_TYPE_CACHED_ROUTE)
			return;

		/* Are shortcuts allowed? */
		if (!(peer->interface->flags & NHRP_INTERFACE_FLAG_SHORTCUT))
			return;
	}

	peer = nhrp_peer_alloc(iface);
	peer->type = NHRP_PEER_TYPE_INCOMPLETE;
	peer->afnum = afnum;
	peer->protocol_type = nhrp_protocol_from_pf(dst->type);
	peer->protocol_address = *dst;
	peer->prefix_length = dst->addr_len * 8;
	nhrp_peer_insert(peer);
	nhrp_peer_free(peer);
}

struct reap_ctx {
	pid_t pid;
	int status;
};

static int reap_pid(void *ctx, struct nhrp_peer *p)
{
	struct reap_ctx *r = (struct reap_ctx *) ctx;

	if (p->script_pid == r->pid) {
		p->script_pid = -1;
		if (p->script_callback) {
			void (*cb)(struct nhrp_peer *, int);
			cb = p->script_callback;
			p->script_callback = NULL;
			cb(p, r->status);
		}
	}

	return 0;
}

void nhrp_peer_reap_pid(pid_t pid, int status)
{
	struct reap_ctx ctx = { pid, status };

	nhrp_peer_foreach(reap_pid, &ctx);
}

static int dump_peer(void *ctx, struct nhrp_peer *peer)
{
	int *num_total = (int *) ctx;
	char tmp[NHRP_PEER_FORMAT_LEN];

	nhrp_info("%s %s",
		  nhrp_peer_type[peer->type],
		  nhrp_peer_format(peer, sizeof(tmp), tmp));
	(*num_total)++;
	return 0;
}

void nhrp_peer_dump_cache(void)
{
	int num_total = 0;

	nhrp_info("Peer cache dump:");
	nhrp_peer_foreach(dump_peer, &num_total);
	nhrp_info("Total %d peer cache entries", num_total);
}
