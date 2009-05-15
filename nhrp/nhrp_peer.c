/* nhrp_peer.c - NHRP peer cache implementation
 *
 * Copyright (C) 2007-2009 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or later as
 * published by the Free Software Foundation.
 *
 * See http://www.gnu.org/ for details.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"

#define NHRP_PEER_FORMAT_LEN		128
#define NHRP_NEGATIVE_CACHE_TIME	(3*60)
#define NHRP_EXPIRY_TIME		(5*60)
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

static struct nhrp_peer_list local_peer_cache =
	CIRCLEQ_HEAD_INITIALIZER(local_peer_cache);

/* Peer entrys life, pending callbacks and their call order are listed
 * here.
 *
 * Generally everything starts from nhrp_peer_insert() call which schedules
 * (during startup) or directly invokes nhrp_peer_insert_cb().
 *
 * INCOMPLETE:
 * 1. nhrp_peer_insert_cb: send resolution request
 * 2. nhrp_peer_handle_resolution_reply: entry deleted or reinserted NEGATIVE
 *
 * NEGATIVE:
 * 1. nhrp_peer_insert_cb: schedule task remove
 *
 * CACHED, STATIC, DYNAMIC:
 * 1. nhrp_peer_insert_cb: calls nhrp_peer_restart_cb
 * 2. nhrp_peer_restart_cb: resolves dns name, or calls nhrp_run_up_script()
 * 3. nhrp_peer_address_query_callback: calls nhrp_peer_run_up_script()
 * 4. nhrp_peer_run_up_script: spawns script, or goes to nhrp_peer_lower_is_up()
 * 5. nhrp_peer_script_peer_up_done: calls nhrp_peer_lower_is_up()
 * 6. nhrp_peer_lower_is_up: sends registration, or goes to nhrp_peer_is_up()
 * 7. nhrp_peer_handle_registration_reply:
 *	a. on success: calls nhrp_peer_is_up()
 *	b. on error reply: calls nhrp_peer_send_purge_protocol()
 *	   nhrp_peer_handle_purge_protocol_reply: sends new registration
 * 8. nhrp_peer_is_up: schedules re-register, expire or deletion
 *
 * ON EXPIRE:
 *	schedule remove
 *	nhrp_peer_renew is called if peer has USED flag set or becomes set,
 *	while the peer is expired
 * ON RENEW: calls sends resolution request, schedule EXPIRE
 *
 * ON ERROR for CACHED: reinsert as NEGATIVE
 * ON ERROR for STATIC: fork peer-down script (if was lower up)
 *			schedule task request link
 * ON ERROR for DYNAMIC: fork peer-down script (if was lower up)
 *			 delete peer
 *
 * CACHED_ROUTE:
 * 1. nhrp_peer_insert_cb: spawns route-up script, or schedules EXPIRE
 *
 * LOCAL:
 * nothing, only netlink code modifies these
 */

static void nhrp_peer_reinsert(struct nhrp_peer *peer, int type);
static void nhrp_peer_restart_cb(struct ev_timer *w, int revents);
static void nhrp_peer_remove_cb(struct ev_timer *w, int revents);
static void nhrp_peer_send_resolve(struct nhrp_peer *peer);
static void nhrp_peer_send_register_cb(struct ev_timer *w, int revents);

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

static const char *nhrp_cie_code_text(int ct)
{
	switch (ct) {
	case NHRP_CODE_SUCCESS:
		return "success";
	case NHRP_CODE_ADMINISTRATIVELY_PROHIBITED:
		return "administratively prohibited";
	case NHRP_CODE_INSUFFICIENT_RESOURCES:
		return "insufficient resources";
	case NHRP_CODE_NO_BINDING_EXISTS:
		return "no binding exists";
	case NHRP_CODE_BINDING_NON_UNIQUE:
		return "binding non-unique";
	case NHRP_CODE_UNIQUE_ADDRESS_REGISTERED:
		return "unique address already registered";
	}
	return "unknown";
}

static inline void nhrp_peer_debug_refcount(const char *func,
					    struct nhrp_peer *peer)
{
#if 0
	char tmp[NHRP_PEER_FORMAT_LEN];
	nhrp_debug("%s(%s %s) ref=%d",
		   func, nhrp_peer_type[peer->type],
		   nhrp_peer_format(peer, sizeof(tmp), tmp),
		   peer->ref);
#endif
}

static char *nhrp_peer_format_full(struct nhrp_peer *peer, size_t len,
				   char *buf, int full)
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
			peer->type == NHRP_PEER_TYPE_CACHED_ROUTE ?
			"nexthop" : "nbma");

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
			      nhrp_address_format(&peer->next_hop_nat_oa,
						  sizeof(tmp), tmp));
	}
	i += snprintf(&buf[i], len - i, " dev %s",
		      peer->interface->name);
	if (peer->mtu)
		i += snprintf(&buf[i], len - i, " mtu %d", peer->mtu);

	if (!full)
		return buf;

	if (peer->flags & NHRP_PEER_FLAG_USED)
		i += snprintf(&buf[i], len - i, " used");
	if (peer->flags & NHRP_PEER_FLAG_UNIQUE)
		i += snprintf(&buf[i], len - i, " unique");
	if (peer->flags & NHRP_PEER_FLAG_UP)
		i += snprintf(&buf[i], len - i, " up");
	else if (peer->flags & NHRP_PEER_FLAG_LOWER_UP)
		i += snprintf(&buf[i], len - i, " lower-up");
	if (peer->expire_time != 0.0) {
		int rel;

		rel = peer->expire_time - ev_now();
		if (rel >= 0) {
			i += snprintf(&buf[i], len - i, " expires_in %d:%02d",
				      rel / 60, rel % 60);
		} else {
			i += snprintf(&buf[i], len - i, " expired");
		}
	}
	if (peer->flags & NHRP_PEER_FLAG_PRUNE_PENDING)
		i += snprintf(&buf[i], len - i, " dying");

	return buf;
}

static inline char *nhrp_peer_format(struct nhrp_peer *peer,
				     size_t len, char *buf)
{
	return nhrp_peer_format_full(peer, len, buf, TRUE);
}

static void nhrp_peer_resolve_nbma(struct nhrp_peer *peer)
{
	char tmp[64];
	int r;

	if (peer->interface->nbma_address.type == PF_UNSPEC) {
		r = kernel_route(NULL, &peer->next_hop_address,
				 &peer->my_nbma_address, NULL,
				 &peer->my_nbma_mtu);
		if (!r) {
			nhrp_error("No route to next hop address %s",
				   nhrp_address_format(&peer->next_hop_address,
						       sizeof(tmp), tmp));
		}
	} else {
		peer->my_nbma_address = peer->interface->nbma_address;
		peer->my_nbma_mtu = peer->interface->nbma_mtu;
	}
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

void nhrp_peer_run_script(struct nhrp_peer *peer, char *action,
			  void (*cb)(struct ev_child *, int),
			  struct ev_child *child)
{
	struct nhrp_interface *iface = peer->interface;
	const char *argv[] = { nhrp_script_file, action, NULL };
	char *envp[32];
	char tmp[64];
	pid_t pid;
	int i = 0;

	if (child == NULL)
		child = &peer->child;

	/* Resolve own NBMA address before forking if required
	 * since it requires traversing peer cache and can trigger
	 * logging and other stuff. */
	if (peer->my_nbma_address.type == PF_UNSPEC)
		nhrp_peer_resolve_nbma(peer);

	/* Fork and execute script */
	pid = fork();
	if (pid == -1) {
		if (cb != NULL)
			cb(child, -1);
		return;
	} else if (pid > 0) {
		if (cb != NULL) {
			ev_child_stop(child);
			ev_child_init(child, cb, pid, 0);
			ev_child_start(child);
		}
		return;
	}

	envp[i++] = env("NHRP_TYPE", nhrp_peer_type[peer->type]);
	if (iface->protocol_address.type != PF_UNSPEC)
		envp[i++] = env("NHRP_SRCADDR",
				nhrp_address_format(&iface->protocol_address,
						    sizeof(tmp), tmp));
	if (peer->my_nbma_address.type != PF_UNSPEC)
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
		if (peer->mtu) {
			sprintf(tmp, "%d", peer->mtu);
			envp[i++] = env("NHRP_DESTMTU", tmp);
		}
		if (peer->next_hop_nat_oa.type != PF_UNSPEC)
			envp[i++] = env("NHRP_DESTNBMA_NAT_OA",
				nhrp_address_format(&peer->next_hop_nat_oa,
						    sizeof(tmp), tmp));
		break;
	case NHRP_PEER_TYPE_CACHED_ROUTE:
		envp[i++] = env("NHRP_NEXTHOP",
			nhrp_address_format(&peer->next_hop_address,
					    sizeof(tmp), tmp));
		break;
	}
	envp[i++] = env("NHRP_INTERFACE", peer->interface->name);
	envp[i++] = NULL;

	execve(nhrp_script_file, (char **) argv, envp);
	exit(1);
}

static void nhrp_peer_cancel_async(struct nhrp_peer *peer)
{
	nhrp_address_resolve_cancel(&peer->address_query);
	ev_timer_stop(&peer->timer);
	if (ev_is_active(&peer->child)) {
		kill(SIGINT, peer->child.pid);
		ev_child_stop(&peer->child);
	}
}

static void nhrp_peer_schedule(struct nhrp_peer *peer, ev_tstamp timeout,
			       void (*cb)(struct ev_timer *w, int revents))
{
	ev_timer_stop(&peer->timer);
	ev_timer_init(&peer->timer, cb, timeout, 0.);
	ev_timer_start(&peer->timer);
}

static void nhrp_peer_restart_error(struct nhrp_peer *peer)
{
	if (peer->type == NHRP_PEER_TYPE_STATIC)
		nhrp_peer_schedule(peer, 10, nhrp_peer_restart_cb);
	else
		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_NEGATIVE);
}

static void nhrp_peer_script_route_up_done(struct ev_child *w, int revents)
{
	struct nhrp_peer *peer = container_of(w, struct nhrp_peer, child);
	int status = 0;
	char tmp[64];

	if (revents)
		status = w->rstatus;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		nhrp_debug("[%s] Route up script succesfully executed",
			   nhrp_address_format(&peer->protocol_address,
					       sizeof(tmp), tmp));

		peer->flags |= NHRP_PEER_FLAG_UP;
	} else {
		nhrp_info("[%s] Route up script failed with status %x;"
			  "adding negative cached entry",
			  nhrp_address_format(&peer->protocol_address,
					      sizeof(tmp), tmp),
			  status);

		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_NEGATIVE);
	}
}

static int nhrp_peer_routes_up(void *ctx, struct nhrp_peer *peer)
{
	if (!(peer->flags & NHRP_PEER_FLAG_UP))
		nhrp_peer_run_script(peer, "route-up",
				     nhrp_peer_script_route_up_done, NULL);

	return 0;
}

static int nhrp_peer_routes_renew(void *ctx, struct nhrp_peer *peer)
{
	int *num_routes = (int *) ctx;

	if (peer->flags & NHRP_PEER_FLAG_PRUNE_PENDING) {
		peer->flags &= ~NHRP_PEER_FLAG_PRUNE_PENDING;
		nhrp_peer_cancel_async(peer);
		nhrp_peer_send_resolve(peer);
		(*num_routes)++;
	}

	return 0;
}

static void nhrp_peer_renew(struct nhrp_peer *peer)
{
	struct nhrp_interface *iface = peer->interface;
	struct nhrp_peer_selector sel;
	int num_routes = 0;

	/* Renew the cached information: all related routes
	 * or the peer itself */
	if (peer->type != NHRP_PEER_TYPE_CACHED_ROUTE) {
		memset(&sel, 0, sizeof(sel));
		sel.flags = NHRP_PEER_FIND_UP;
		sel.type_mask = BIT(NHRP_PEER_TYPE_CACHED_ROUTE);
		sel.interface = iface;
		sel.next_hop_address = peer->protocol_address;
		nhrp_peer_foreach(nhrp_peer_routes_renew, &num_routes, &sel);
	}

	if (peer->flags & NHRP_PEER_FLAG_PRUNE_PENDING) {
		peer->flags &= ~NHRP_PEER_FLAG_PRUNE_PENDING;
		nhrp_peer_cancel_async(peer);
		nhrp_peer_send_resolve(peer);
	}
}

static int is_used(void *ctx, struct nhrp_peer *peer)
{
	if (peer->flags & NHRP_PEER_FLAG_USED)
		return 1;

	return 0;
}

static void nhrp_peer_expire_cb(struct ev_timer *w, int revents)
{
	struct nhrp_peer *peer = container_of(w, struct nhrp_peer, timer);
	struct nhrp_peer_selector sel;
	int used;

	peer->flags |= NHRP_PEER_FLAG_PRUNE_PENDING;
	nhrp_peer_schedule(peer, peer->expire_time - ev_now(),
			   nhrp_peer_remove_cb);

	if (peer->type == NHRP_PEER_TYPE_CACHED_ROUTE) {
		memset(&sel, 0, sizeof(sel));
		sel.interface = peer->interface;
		sel.protocol_address = peer->next_hop_address;
		used = nhrp_peer_foreach(is_used, NULL, &sel);
	} else
		used = peer->flags & NHRP_PEER_FLAG_USED;

	if (used)
		nhrp_peer_renew(peer);
}

static void nhrp_peer_is_up(struct nhrp_peer *peer)
{
	struct nhrp_interface *iface = peer->interface;
	struct nhrp_peer_selector sel;

	peer->flags |= NHRP_PEER_FLAG_UP | NHRP_PEER_FLAG_LOWER_UP;

	/* Check if there are routes using this peer as next-hop*/
	memset(&sel, 0, sizeof(sel));
	sel.type_mask = BIT(NHRP_PEER_TYPE_CACHED_ROUTE);
	sel.interface = iface;
	sel.next_hop_address = peer->protocol_address;
	nhrp_peer_foreach(nhrp_peer_routes_up, NULL, &sel);

	if (peer->queued_packet != NULL) {
		nhrp_packet_marshall_and_send(peer->queued_packet);
		nhrp_packet_put(peer->queued_packet);
		peer->queued_packet = NULL;
	}

	/* Schedule expiry or renewal */
	switch (peer->type) {
	case NHRP_PEER_TYPE_DYNAMIC:
		nhrp_peer_schedule(peer, peer->expire_time - ev_now(),
				   nhrp_peer_remove_cb);
		break;
	case NHRP_PEER_TYPE_CACHED:
		nhrp_peer_schedule(
			peer,
			peer->expire_time - NHRP_EXPIRY_TIME - ev_now(),
			nhrp_peer_expire_cb);
		break;
	case NHRP_PEER_TYPE_STATIC:
		if (peer->flags & NHRP_PEER_FLAG_REGISTER) {
			nhrp_peer_schedule(
				peer, iface->holding_time - NHRP_EXPIRY_TIME,
				nhrp_peer_send_register_cb);
		}
		break;
	}
}

static void nhrp_peer_lower_is_up(struct nhrp_peer *peer)
{
	peer->flags |= NHRP_PEER_FLAG_LOWER_UP;

	if (peer->flags & NHRP_PEER_FLAG_REGISTER)
		nhrp_peer_send_register_cb(&peer->timer, 0);
	else
		nhrp_peer_is_up(peer);
}

static void nhrp_peer_script_peer_up_done(struct ev_child *w, int revents)
{
	struct nhrp_peer *peer = container_of(w, struct nhrp_peer, child);
	int status = 0;
	char tmp[64];

	if (revents)
		status = w->rstatus;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		nhrp_debug("[%s] Peer up script succesfully executed",
			   nhrp_address_format(&peer->protocol_address,
					       sizeof(tmp), tmp));

		kernel_inject_neighbor(&peer->protocol_address,
				       &peer->next_hop_address,
				       peer->interface);
		nhrp_peer_lower_is_up(peer);
	} else {
		nhrp_error("[%s] Peer up script failed with status %x",
			   nhrp_address_format(&peer->protocol_address,
					       sizeof(tmp), tmp),
			   status);
		nhrp_peer_restart_error(peer);
	}
}

static void nhrp_peer_run_up_script(struct nhrp_peer *peer)
{
	nhrp_peer_run_script(peer, "peer-up",
			     nhrp_peer_script_peer_up_done, NULL);
}

static void nhrp_peer_address_query_callback(struct nhrp_address_query *query,
					     struct nhrp_address *result)
{
	struct nhrp_peer *peer = container_of(query, struct nhrp_peer,
					      address_query);
	char host[64];

	if (result->type != AF_UNSPEC) {
		nhrp_info("Resolved '%s' as %s",
			  peer->nbma_hostname,
			  nhrp_address_format(result, sizeof(host), host));
		peer->next_hop_address = *result;
		peer->afnum = nhrp_afnum_from_pf(peer->next_hop_address.type);
		nhrp_peer_run_up_script(peer);
	} else {
		nhrp_error("Failed to resolve '%s'", peer->nbma_hostname);
		nhrp_peer_restart_error(peer);
	}
}

static void nhrp_peer_restart_cb(struct ev_timer *w, int revents)
{
	struct nhrp_peer *peer = container_of(w, struct nhrp_peer, timer);

	if (peer->nbma_hostname != NULL) {
		nhrp_address_resolve(&peer->address_query,
				     peer->nbma_hostname,
				     nhrp_peer_address_query_callback);
	} else {
		nhrp_peer_resolve_nbma(peer);

		if (!(peer->flags & NHRP_PEER_FLAG_LOWER_UP))
			nhrp_peer_run_up_script(peer);
		else
			nhrp_peer_script_peer_up_done(&peer->child, 0);
	}
}

static void nhrp_peer_send_protocol_purge(struct nhrp_peer *peer)
{
	char tmp[64];
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
		.type = NHRP_PACKET_PURGE_REQUEST,
		.flags = NHRP_FLAG_PURGE_NO_REPLY,
	};
	if (peer->flags & NHRP_PEER_FLAG_CISCO) {
		/* Cisco IOS seems to require reqistration and purge
		 * request id to match, so we need to used a fixed
		 * value. This is in violation of RFC, though. */
		packet->hdr.u.request_id =
			nhrp_address_hash(&peer->interface->protocol_address);
	}
	packet->dst_protocol_address = peer->protocol_address;

	/* Payload CIE */
	cie = nhrp_cie_alloc();
	if (cie == NULL)
		goto error_free_packet;

	*cie = (struct nhrp_cie) {
		.hdr.code = NHRP_CODE_SUCCESS,
		.hdr.mtu = 0,
		.hdr.preference = 0,
		.hdr.prefix_length = 0xff,
	};
	cie->protocol_address = peer->interface->protocol_address;

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	nhrp_info("Sending Purge Request (of protocol address) to %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(tmp), tmp));

	packet->dst_peer = nhrp_peer_get(peer);
	packet->dst_iface = peer->interface;
	sent = nhrp_packet_send(packet);
error_free_packet:
	nhrp_packet_put(packet);
error:
	if (sent)
		nhrp_peer_schedule(peer, 2, nhrp_peer_send_register_cb);
	else
		nhrp_peer_restart_error(peer);
}

static int nhrp_add_local_route_cie(void *ctx, struct nhrp_peer *route)
{
	struct nhrp_packet *packet = (struct nhrp_packet *) ctx;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;

	if (!(route->interface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST))
		return 0;

	cie = nhrp_cie_alloc();
	if (cie == NULL)
		return 0;

	*cie = (struct nhrp_cie) {
		.hdr.code = 0,
		.hdr.prefix_length = route->prefix_length,
		.protocol_address = route->protocol_address,
	};

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	return 0;
}

static void nhrp_peer_handle_registration_reply(void *ctx,
						struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	struct nhrp_packet *packet;
	char tmp[NHRP_PEER_FORMAT_LEN];
	int ec = -1;

	if (peer->flags & NHRP_PEER_FLAG_REMOVED)
		goto ret;

	if (reply == NULL ||
	    reply->hdr.type != NHRP_PACKET_REGISTRATION_REPLY) {
		ec = reply ? reply->hdr.u.error.code : -1;
		nhrp_info("Failed to register to %s: %s (%d)",
			  nhrp_address_format(&peer->protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_error_indication_text(ec), ntohs(ec));

		if (reply != NULL) {
			nhrp_peer_schedule(peer, NHRP_RETRY_REGISTER_TIME,
					   nhrp_peer_send_register_cb);
		} else {
			nhrp_peer_restart_error(peer);
		}
		goto ret;
	}

	/* Check result */
	payload = nhrp_packet_payload(reply, NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (payload != NULL) {
		cie = nhrp_payload_get_cie(payload, 1);
		if (cie != NULL)
			ec = cie->hdr.code;
	}

	nhrp_info("Received Registration Reply from %s: %s",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_cie_code_text(ec));

	switch (ec) {
	case NHRP_CODE_SUCCESS:
		break;
	case NHRP_CODE_UNIQUE_ADDRESS_REGISTERED:
		nhrp_peer_send_protocol_purge(peer);
		goto ret;
	default:
		nhrp_peer_schedule(peer, NHRP_RETRY_REGISTER_TIME,
				   nhrp_peer_send_register_cb);
		goto ret;
	}

	/* Check for NAT */
	payload = nhrp_packet_extension(reply,
					NHRP_EXTENSION_NAT_ADDRESS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (payload != NULL) {
		cie = nhrp_payload_get_cie(payload, 2);
		if (cie != NULL) {
			nhrp_info("NAT detected: our real NBMA address is %s",
				  nhrp_address_format(&cie->nbma_address,
						      sizeof(tmp), tmp));
			peer->interface->nat_cie = *cie;
		}
	}

	/* If not re-registration, send a purge request for each subnet
	 * we accept shortcuts to, to clear server redirection cache. */
	if (!(peer->flags & NHRP_PEER_FLAG_UP) &&
	    (packet = nhrp_packet_alloc()) != NULL) {
		struct nhrp_peer_selector sel;

		packet->hdr = (struct nhrp_packet_header) {
			.afnum = peer->afnum,
			.protocol_type = peer->protocol_type,
			.version = NHRP_VERSION_RFC2332,
			.type = NHRP_PACKET_PURGE_REQUEST
		};
		packet->dst_protocol_address = peer->protocol_address;

		memset(&sel, 0, sizeof(sel));
		sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL);
		nhrp_peer_foreach(nhrp_add_local_route_cie, packet, &sel);

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

		nhrp_info("Sending Purge Request (of local routes) to %s",
			  nhrp_address_format(&peer->protocol_address,
					      sizeof(tmp), tmp));

		packet->dst_peer = nhrp_peer_get(peer);
		packet->dst_iface = peer->interface;
		nhrp_packet_send_request(packet, NULL, NULL);
		nhrp_packet_put(packet);
	}

	/* Re-register after holding time expires */
	nhrp_peer_is_up(peer);
ret:
	nhrp_peer_put(peer);
}

static void nhrp_peer_send_register_cb(struct ev_timer *w, int revents)
{
	struct nhrp_peer *peer = container_of(w, struct nhrp_peer, timer);
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
	if (peer->flags & NHRP_PEER_FLAG_CISCO) {
		/* Cisco IOS seems to require reqistration and purge
		 * request id to match, so we need to used a fixed
		 * value. This is in violation of RFC, though. */
		packet->hdr.u.request_id =
			nhrp_address_hash(&peer->interface->protocol_address);
	}
	packet->dst_protocol_address = peer->protocol_address;

	/* Payload CIE */
	cie = nhrp_cie_alloc();
	if (cie == NULL)
		goto error;

        *cie = (struct nhrp_cie) {
		.hdr.code = NHRP_CODE_SUCCESS,
		.hdr.prefix_length = 0xff,
		.hdr.mtu = htons(peer->my_nbma_mtu),
		.hdr.holding_time = htons(peer->interface->holding_time),
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

	nhrp_info("Sending Registration Request to %s (my mtu=%d)",
		  nhrp_address_format(&peer->protocol_address,
				      sizeof(dst), dst),
		  peer->my_nbma_mtu);

	packet->dst_peer = nhrp_peer_get(peer);
	packet->dst_iface = peer->interface;
	sent = nhrp_packet_send_request(packet,
					nhrp_peer_handle_registration_reply,
					nhrp_peer_get(peer));

error_free_packet:
	nhrp_packet_put(packet);
error:
	if (!sent)
		nhrp_peer_restart_error(peer);
}

static int error_on_matching(void *ctx, struct nhrp_peer *peer)
{
	return 1;
}

static void nhrp_peer_handle_resolution_reply(void *ctx,
					      struct nhrp_packet *reply)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx, *np;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie, *natcie = NULL, *natoacie = NULL;
	struct nhrp_interface *iface;
	struct nhrp_peer_selector sel;
	char dst[64], tmp[64], nbma[64];
	int ec;

	if (peer->flags & NHRP_PEER_FLAG_REMOVED)
		goto ret;

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
		goto ret;
	}

	payload = nhrp_packet_payload(reply, NHRP_PAYLOAD_TYPE_CIE_LIST);
	cie = TAILQ_FIRST(&payload->u.cie_list_head);
	if (cie == NULL)
		goto ret;

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
			natoacie = cie;
			nhrp_info("NAT detected: really at proto %s nbma %s",
				nhrp_address_format(&natcie->protocol_address,
					sizeof(tmp), tmp),
				nhrp_address_format(&natcie->nbma_address,
					sizeof(nbma), nbma));
		}
	}
	if (natcie == NULL)
		natcie = cie;

	if (nhrp_address_cmp(&peer->protocol_address, &cie->protocol_address)
	    == 0) {
		/* Destination is within NBMA network; update cache */
		peer->mtu = ntohs(cie->hdr.mtu);
		peer->prefix_length = cie->hdr.prefix_length;
		peer->next_hop_address = natcie->nbma_address;
		if (natoacie != NULL)
			peer->next_hop_nat_oa = natoacie->nbma_address;
		peer->expire_time = ev_now() + ntohs(cie->hdr.holding_time);
		nhrp_address_mask(&peer->protocol_address, peer->prefix_length);
		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_CACHED);
		goto ret;
	}

	/* Check that we won't replace a local route */
	sel = (struct nhrp_peer_selector) {
		.flags = NHRP_PEER_FIND_EXACT,
		.type_mask = BIT(NHRP_PEER_TYPE_LOCAL),
		.protocol_address = peer->protocol_address,
		.prefix_length = cie->hdr.prefix_length,
	};
	if (nhrp_peer_foreach(error_on_matching, NULL, &sel)) {
		nhrp_error("Local route %s/%d exists: not replacing "
			   "with shortcut",
			   nhrp_address_format(&peer->protocol_address,
					       sizeof(tmp), tmp),
			   cie->hdr.prefix_length);
		peer->flags |= NHRP_PEER_FLAG_UP;
		nhrp_peer_reinsert(peer, NHRP_PEER_TYPE_NEGATIVE);
		goto ret;
	}

	/* Update the received NBMA address to nexthop */
	iface = peer->interface;
	np = nhrp_peer_route(iface, &cie->protocol_address,
			     NHRP_PEER_FIND_EXACT, 0);
	if (np == NULL) {
		np = nhrp_peer_alloc(iface);
		np->type = NHRP_PEER_TYPE_CACHED;
		np->afnum = reply->hdr.afnum;
		np->protocol_type = reply->hdr.protocol_type;
		np->protocol_address = cie->protocol_address;
		np->next_hop_address = natcie->nbma_address;
		if (natoacie != NULL)
			np->next_hop_nat_oa = natoacie->nbma_address;
		np->mtu = ntohs(cie->hdr.mtu);
		np->prefix_length = cie->protocol_address.addr_len * 8;
		np->expire_time = ev_now() + ntohs(cie->hdr.holding_time);
		nhrp_peer_insert(np);
		nhrp_peer_put(np);
	}

	/* Off NBMA destination; a shortcut route */
	np = nhrp_peer_alloc(iface);
	np->type = NHRP_PEER_TYPE_CACHED_ROUTE;
	np->afnum = reply->hdr.afnum;
	np->protocol_type = reply->hdr.protocol_type;
	np->protocol_address = peer->protocol_address;
	np->prefix_length = cie->hdr.prefix_length;
	np->next_hop_address = cie->protocol_address;
	np->expire_time = ev_now() + ntohs(cie->hdr.holding_time);
	nhrp_address_mask(&np->protocol_address, np->prefix_length);
	nhrp_peer_insert(np);
	nhrp_peer_put(np);

	/* Delete the incomplete entry */
	nhrp_peer_remove(peer);
ret:
	nhrp_peer_put(peer);
}

static void nhrp_peer_send_resolve(struct nhrp_peer *peer)
{
	char dst[64];
	struct nhrp_packet *packet;
	struct nhrp_cie *cie;
	struct nhrp_payload *payload;

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
		.hdr.holding_time = htons(peer->interface->holding_time),
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
	nhrp_packet_send_request(packet,
				 nhrp_peer_handle_resolution_reply,
				 nhrp_peer_get(peer));

error:
	nhrp_packet_put(packet);
}

struct nhrp_peer *nhrp_peer_alloc(struct nhrp_interface *iface)
{
	struct nhrp_peer *p;

	p = calloc(1, sizeof(struct nhrp_peer));
	p->ref = 1;
	p->interface = iface;
	ev_timer_init(&p->timer, NULL, 0., 0.);
	ev_child_init(&p->child, NULL, 0, 0);

	return p;
}

struct nhrp_peer *nhrp_peer_get(struct nhrp_peer *peer)
{
	if (peer == NULL)
		return NULL;

	peer->ref++;
	nhrp_peer_debug_refcount(__FUNCTION__, peer);

	return peer;
}

static void nhrp_peer_release(struct nhrp_peer *peer)
{
	struct nhrp_interface *iface = peer->interface;
	struct nhrp_peer_selector sel;

	nhrp_peer_cancel_async(peer);

	switch (peer->type) {
	case NHRP_PEER_TYPE_CACHED_ROUTE:
		if ((peer->flags & NHRP_PEER_FLAG_UP) &&
		    !(peer->flags & NHRP_PEER_FLAG_REPLACED))
			nhrp_peer_run_script(peer, "route-down", NULL, NULL);
		break;
	case NHRP_PEER_TYPE_CACHED:
	case NHRP_PEER_TYPE_DYNAMIC:
	case NHRP_PEER_TYPE_STATIC:
		if (!(peer->flags & NHRP_PEER_FLAG_REPLACED)) {
			/* Remove cached routes using this entry as next-hop */
			memset(&sel, 0, sizeof(sel));
			sel.type_mask = BIT(NHRP_PEER_TYPE_CACHED_ROUTE);
			sel.interface = iface;
			sel.next_hop_address = peer->protocol_address;
			nhrp_peer_foreach(nhrp_peer_remove_matching, NULL,
					  &sel);

			/* Execute peer-down */
			if (peer->flags & NHRP_PEER_FLAG_UP)
				nhrp_peer_run_script(peer, "peer-down",
						     NULL, NULL);
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

	free(peer);
}

int nhrp_peer_put(struct nhrp_peer *peer)
{
	NHRP_BUG_ON(peer->ref == 0);

	peer->ref--;
	nhrp_peer_debug_refcount(__FUNCTION__, peer);

	if (peer->ref > 0)
		return FALSE;

	nhrp_peer_release(peer);

	return TRUE;
}

static void nhrp_peer_insert_cb(struct ev_timer *w, int revents)
{
	struct nhrp_peer *peer = container_of(w, struct nhrp_peer, timer);

	nhrp_peer_cancel_async(peer);
	switch (peer->type) {
	case NHRP_PEER_TYPE_LOCAL:
		peer->flags |= NHRP_PEER_FLAG_UP;
		forward_local_addresses_changed();
		break;
	case NHRP_PEER_TYPE_INCOMPLETE:
		nhrp_peer_send_resolve(peer);
		break;
	case NHRP_PEER_TYPE_CACHED:
	case NHRP_PEER_TYPE_DYNAMIC:
	case NHRP_PEER_TYPE_STATIC:
		nhrp_peer_restart_cb(w, 0);
		break;
	case NHRP_PEER_TYPE_CACHED_ROUTE:
		if (!(peer->flags & NHRP_PEER_FLAG_UP) &&
		    nhrp_peer_route(peer->interface,
				    &peer->next_hop_address,
				    NHRP_PEER_FIND_UP | NHRP_PEER_FIND_EXACT,
				    NHRP_PEER_TYPEMASK_ADJACENT) != NULL)
			nhrp_peer_run_script(peer, "route-up",
					     nhrp_peer_script_route_up_done,
					     NULL);

		nhrp_peer_schedule(peer, peer->expire_time - NHRP_EXPIRY_TIME
				   - 1 - ev_now(), nhrp_peer_expire_cb);
		break;
	case NHRP_PEER_TYPE_NEGATIVE:
		peer->expire_time = ev_now() + NHRP_NEGATIVE_CACHE_TIME;

		if (peer->flags & NHRP_PEER_FLAG_UP)
			kernel_inject_neighbor(&peer->protocol_address,
					       NULL, peer->interface);
		nhrp_peer_schedule(peer, NHRP_NEGATIVE_CACHE_TIME,
				   nhrp_peer_remove_cb);
		break;
	}
}

static void nhrp_peer_reinsert(struct nhrp_peer *peer, int type)
{
	NHRP_BUG_ON((peer->type == NHRP_PEER_TYPE_LOCAL) !=
		    (type == NHRP_PEER_TYPE_LOCAL));

	peer->flags &= ~NHRP_PEER_FLAG_REMOVED;
	peer->type = type;
	nhrp_peer_insert_cb(&peer->timer, 0);
}

void nhrp_peer_insert(struct nhrp_peer *peer)
{
	struct nhrp_peer_selector sel;
	char tmp[NHRP_PEER_FORMAT_LEN];

	/* First, prune all duplicates */
	memset(&sel, 0, sizeof(sel));
	if (peer->type == NHRP_PEER_TYPE_CACHED_ROUTE) {
		/* remove all existing shortcuts with same nexthop */
		sel.flags = NHRP_PEER_FIND_SUBNET;
		sel.next_hop_address = peer->next_hop_address;
	} else {
		/* remove exact nbma protocol address matches */
		sel.flags = NHRP_PEER_FIND_EXACT;
	}
	sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
	sel.interface = peer->interface;
	sel.protocol_address = peer->protocol_address;
	sel.prefix_length = peer->prefix_length;
	nhrp_peer_foreach(nhrp_peer_remove_matching, NULL, &sel);

	/* Keep a reference as long as we are on the list */
	peer = nhrp_peer_get(peer);
	nhrp_debug("Adding %s %s",
		   nhrp_peer_type[peer->type],
		   nhrp_peer_format(peer, sizeof(tmp), tmp));

	if (peer->type == NHRP_PEER_TYPE_LOCAL)
		CIRCLEQ_INSERT_HEAD(&local_peer_cache, peer, peer_list);
	else
		CIRCLEQ_INSERT_HEAD(&peer->interface->peer_cache,
				    peer, peer_list);

	/* Start peers life */
	if (nhrp_running || peer->type == NHRP_PEER_TYPE_LOCAL)
		nhrp_peer_insert_cb(&peer->timer, 0);
	else
		nhrp_peer_schedule(peer, 0, &nhrp_peer_insert_cb);
}

static void nhrp_peer_script_peer_down_done(struct ev_child *w, int revents)
{
	struct nhrp_peer *peer = container_of(w, struct nhrp_peer, child);

	nhrp_peer_schedule(peer, 5, nhrp_peer_restart_cb);
}

void nhrp_peer_purge(struct nhrp_peer *peer)
{
	switch (peer->type) {
	case NHRP_PEER_TYPE_STATIC:
		peer->flags &= ~(NHRP_PEER_FLAG_LOWER_UP | NHRP_PEER_FLAG_UP);
		nhrp_peer_cancel_async(peer);
		nhrp_peer_run_script(peer, "peer-down",
				     nhrp_peer_script_peer_down_done, NULL);
		nhrp_address_set_type(&peer->my_nbma_address, PF_UNSPEC);
		break;
	default:
		nhrp_peer_remove(peer);
		break;
	}
}

int nhrp_peer_purge_matching(void *ctx, struct nhrp_peer *peer)
{
	int *count = (int *) ctx;

	nhrp_peer_purge(peer);
	if (count != NULL)
		(*count)++;

	return 0;
}

static void nhrp_peer_remove_cb(struct ev_timer *w, int revents)
{
	struct nhrp_peer *peer = container_of(w, struct nhrp_peer, timer);
	struct nhrp_interface *iface = peer->interface;
	int type;

	peer->flags |= NHRP_PEER_FLAG_REMOVED;
	if (peer->type == NHRP_PEER_TYPE_LOCAL)
		CIRCLEQ_REMOVE(&local_peer_cache, peer, peer_list);
	else
		CIRCLEQ_REMOVE(&iface->peer_cache, peer, peer_list);

	type = peer->type;
	nhrp_peer_put(peer);

	if (type == NHRP_PEER_TYPE_LOCAL)
		forward_local_addresses_changed();
}

void nhrp_peer_remove(struct nhrp_peer *peer)
{
	char tmp[NHRP_PEER_FORMAT_LEN];

	if (peer->flags & NHRP_PEER_FLAG_REMOVED)
		return;

	nhrp_debug("Removing %s %s",
		   nhrp_peer_type[peer->type],
		   nhrp_peer_format(peer, sizeof(tmp), tmp));

	peer->flags |= NHRP_PEER_FLAG_REMOVED;
	nhrp_peer_cancel_async(peer);
	nhrp_peer_schedule(peer, 0, nhrp_peer_remove_cb);
}

int nhrp_peer_remove_matching(void *ctx, struct nhrp_peer *peer)
{
	int *count = (int *) ctx;

	nhrp_peer_remove(peer);
	if (count != NULL)
		(*count)++;

	return 0;
}

int nhrp_peer_set_used_matching(void *ctx, struct nhrp_peer *peer)
{
	int used = (int) ctx;

	if (used) {
		peer->flags |= NHRP_PEER_FLAG_USED;
		nhrp_peer_renew(peer);
	} else {
		peer->flags &= ~NHRP_PEER_FLAG_USED;
	}
	return 0;
}

int nhrp_peer_match(struct nhrp_peer *p, struct nhrp_peer_selector *sel)
{
	if (sel->type_mask && !(sel->type_mask & BIT(p->type)))
		return FALSE;

	if ((sel->flags & NHRP_PEER_FIND_UP) &&
	    !(p->flags & NHRP_PEER_FLAG_UP))
		return FALSE;

	if (sel->interface != NULL &&
	    p->type != NHRP_PEER_TYPE_LOCAL &&
	    p->interface != sel->interface)
		return FALSE;

	if (sel->protocol_address.type != PF_UNSPEC) {
		if (sel->prefix_length == 0)
			sel->prefix_length = sel->protocol_address.addr_len * 8;

		if (sel->flags & NHRP_PEER_FIND_EXACT) {
			if (nhrp_address_cmp(&p->protocol_address,
					     &sel->protocol_address) != 0)
				return FALSE;

			if (p->prefix_length != sel->prefix_length &&
			    p->type != NHRP_PEER_TYPE_STATIC)
				return FALSE;
		} else if (sel->flags & NHRP_PEER_FIND_ROUTE) {
			if (nhrp_address_prefix_cmp(&p->protocol_address,
						    &sel->protocol_address,
						    p->prefix_length) != 0)
				return FALSE;
		} else {
			if (p->prefix_length < sel->prefix_length)
				return FALSE;

			if (nhrp_address_prefix_cmp(&p->protocol_address,
						    &sel->protocol_address,
						    sel->prefix_length) != 0)
				return FALSE;
		}
	}

	if (sel->next_hop_address.type != PF_UNSPEC) {
		if (nhrp_address_cmp(&p->next_hop_address,
				     &sel->next_hop_address) != 0)
			return FALSE;
	}

	return TRUE;
}

struct enum_interface_peers_ctx {
	nhrp_peer_enumerator enumerator;
	void *ctx;
	struct nhrp_peer_selector *sel;
};

static int enumerate_peer_cache(struct nhrp_peer_list *peer_cache,
				nhrp_peer_enumerator e, void *ctx,
				struct nhrp_peer_selector *sel)
{
	struct nhrp_peer *p;
	int rc = 0;

	CIRCLEQ_FOREACH(p, peer_cache, peer_list) {
		if (p->flags & NHRP_PEER_FLAG_REMOVED)
			continue;

		if (sel == NULL || nhrp_peer_match(p, sel)) {
			rc = e(ctx, p);
			if (rc != 0)
				break;
		}
	}

	return rc;
}

static int enum_interface_peers(void *ctx, struct nhrp_interface *iface)
{
	struct enum_interface_peers_ctx *ectx =
		(struct enum_interface_peers_ctx *) ctx;

	return enumerate_peer_cache(&iface->peer_cache,
				    ectx->enumerator, ectx->ctx,
				    ectx->sel);
}

int nhrp_peer_foreach(nhrp_peer_enumerator e, void *ctx,
		      struct nhrp_peer_selector *sel)
{
	struct nhrp_interface *iface = NULL;
	struct enum_interface_peers_ctx ectx = { e, ctx, sel };
	int rc;

	if (sel != NULL)
		iface = sel->interface;

	rc = enumerate_peer_cache(&local_peer_cache, e, ctx, sel);
	if (rc != 0)
		return rc;

	/* Speed optimization: TYPE_LOCAL peers cannot be found from
	 * other places */
	if (sel != NULL && sel->type_mask == BIT(NHRP_PEER_TYPE_LOCAL))
		return 0;

	if (iface == NULL)
		rc = nhrp_interface_foreach(enum_interface_peers, &ectx);
	else
		rc = enumerate_peer_cache(&iface->peer_cache, e, ctx, sel);

	return rc;
}

struct route_decision {
	struct nhrp_peer_selector sel;
	struct nhrp_cie_list_head *exclude;
	struct nhrp_peer *best_found;
	struct nhrp_address *src;
	int found_exact, found_up;
};

static int decide_route(void *ctx, struct nhrp_peer *peer)
{
	struct route_decision *rd = (struct route_decision *) ctx;
	int exact;

	if (peer->type != NHRP_PEER_TYPE_CACHED_ROUTE) {
		/* Exclude addresses from CIE from routing decision
		 * to avoid routing loops within NHS clusters. */
		if (rd->exclude != NULL &&
		    nhrp_address_match_cie_list(&peer->next_hop_address,
						&peer->protocol_address,
						rd->exclude))
			return 0;

		/* Exclude also source address, we don't want to
		 * forward questions back to who's asking. */
		if (rd->src != NULL &&
		    nhrp_address_cmp(rd->src, &peer->protocol_address) == 0)
			return 0;
	} else {
		/* Exclude routes that point back to the sender
		 * of the packet */
		if (rd->src != NULL &&
		    nhrp_address_cmp(rd->src, &peer->next_hop_address) == 0)
			return 0;
	}

	exact = (peer->type >= NHRP_PEER_TYPE_STATIC) &&
		(nhrp_address_cmp(&peer->protocol_address,
				  &rd->sel.protocol_address) == 0);
	if (rd->found_exact > exact)
		return 0;

	if (rd->found_up && !(peer->flags & NHRP_PEER_FLAG_UP))
		return 0;

	if (rd->best_found != NULL &&
	    rd->found_exact == exact &&
	    rd->found_up == (peer->flags & NHRP_PEER_FLAG_UP)) {
		if (rd->best_found->prefix_length > peer->prefix_length)
			return 0;

		if (rd->best_found->prefix_length == peer->prefix_length &&
		    rd->best_found->last_used < peer->last_used)
			return 0;
	}

	rd->best_found = peer;
	rd->found_exact = exact;
	rd->found_up = peer->flags & NHRP_PEER_FLAG_UP;
	return 0;
}

struct nhrp_peer *nhrp_peer_route_full(struct nhrp_interface *interface,
				       struct nhrp_address *dst,
				       int flags, int type_mask,
				       struct nhrp_address *src,
				       struct nhrp_cie_list_head *exclude)
{
	struct route_decision rd;

	memset(&rd, 0, sizeof(rd));
	rd.sel.flags = flags & ~NHRP_PEER_FIND_UP;
	if ((flags & (NHRP_PEER_FIND_ROUTE | NHRP_PEER_FIND_EXACT |
		      NHRP_PEER_FIND_SUBNET)) == 0)
		rd.sel.flags |= NHRP_PEER_FIND_ROUTE;
	rd.sel.type_mask = type_mask;
	rd.sel.interface = interface;
	rd.sel.protocol_address = *dst;
	rd.exclude = exclude;
	rd.src = src;
	nhrp_peer_foreach(decide_route, &rd, &rd.sel);

	if (rd.best_found == NULL)
		return NULL;

	if ((flags & NHRP_PEER_FIND_UP) &&
	    !(rd.best_found->flags & NHRP_PEER_FLAG_UP))
		return NULL;

	rd.best_found->last_used = ev_now();
	return rd.best_found;
}

void nhrp_peer_traffic_indication(struct nhrp_interface *iface,
				  uint16_t afnum, struct nhrp_address *dst)
{
	struct nhrp_peer *peer;
	int type;

	/* For off-NBMA destinations, we consider all shortcut routes,
	 * but NBMA destinations should be exact because we want to drop
	 * NHS from the path. */
	if (nhrp_address_prefix_cmp(dst, &iface->protocol_address,
				    iface->protocol_address_prefix) != 0)
		type = NHRP_PEER_FIND_ROUTE;
	else
		type = NHRP_PEER_FIND_EXACT;

	/* Have we done something for this destination already? */
	peer = nhrp_peer_route(iface, dst, type, 0);
	if (peer != NULL)
		return;

	/* Initiate resolution */
	peer = nhrp_peer_alloc(iface);
	peer->type = NHRP_PEER_TYPE_INCOMPLETE;
	peer->afnum = afnum;
	peer->protocol_type = nhrp_protocol_from_pf(dst->type);
	peer->protocol_address = *dst;
	peer->prefix_length = dst->addr_len * 8;
	nhrp_peer_insert(peer);
	nhrp_peer_put(peer);
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
	nhrp_peer_foreach(dump_peer, &num_total, NULL);
	nhrp_info("Total %d peer cache entries", num_total);
}
