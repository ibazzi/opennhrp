/* nhrp_packet.c - NHRP packet marshalling and tranceiving
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>
#include "nhrp_packet.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"
#include "nhrp_common.h"

#define PACKET_RETRIES			6
#define PACKET_RETRY_INTERVAL		5000
#define RATE_LIMIT_HASH_SIZE		256
#define RATE_LIMIT_MAX_TOKENS		4
#define RATE_LIMIT_SEND_INTERVAL	5
#define RATE_LIMIT_SILENCE		360
#define RATE_LIMIT_PURGE_INTERVAL	600
#define MAX_PDU_SIZE			1500

struct nhrp_rate_limit {
	LIST_ENTRY(nhrp_rate_limit) hash_entry;
	struct nhrp_address src;
	struct nhrp_address dst;
	struct timeval rate_last;
	int rate_tokens;
};

LIST_HEAD(nhrp_rate_limit_list_head, nhrp_rate_limit);
TAILQ_HEAD(nhrp_packet_list_head, nhrp_packet);

static uint32_t request_id = 0;
static struct nhrp_packet_list_head pending_requests =
	TAILQ_HEAD_INITIALIZER(pending_requests);

static struct nhrp_rate_limit_list_head rate_limit_hash[RATE_LIMIT_HASH_SIZE];
static struct nhrp_task rate_limit_task;
static int num_rate_limit_entries = 0;

static int unmarshall_packet_header(uint8_t **pdu, size_t *pdusize, struct nhrp_packet *packet);

NHRP_TASK(prune_rate_limit_entries);

static void nhrp_rate_limit_delete(struct nhrp_rate_limit *rl)
{
	LIST_REMOVE(rl, hash_entry);
	free(rl);
	num_rate_limit_entries--;
}

void nhrp_rate_limit_clear(struct nhrp_address *a, int pref)
{
	struct nhrp_rate_limit *rl, *next;
	int i;

	for (i = 0; i < RATE_LIMIT_HASH_SIZE; i++) {
		for (rl = LIST_FIRST(&rate_limit_hash[i]);
		     rl != NULL; rl = next) {
			next = LIST_NEXT(rl, hash_entry);

			if (nhrp_address_prefix_cmp(a, &rl->src, pref) == 0 ||
			    nhrp_address_prefix_cmp(a, &rl->dst, pref) == 0)
				nhrp_rate_limit_delete(rl);
		}
	}

	if (num_rate_limit_entries == 0)
		nhrp_task_cancel(&rate_limit_task);
}

static void prune_rate_limit_entries_callback(struct nhrp_task *task)
{
	struct nhrp_rate_limit *rl, *next;
	struct timeval now, tv;
	int i;

	gettimeofday(&now, NULL);
	for (i = 0; i < RATE_LIMIT_HASH_SIZE; i++) {
		for (rl = LIST_FIRST(&rate_limit_hash[i]);
		     rl != NULL; rl = next) {
			next = LIST_NEXT(rl, hash_entry);

			tv = rl->rate_last;
			tv.tv_sec += 2 * RATE_LIMIT_SILENCE;
			if (timercmp(&now, &tv, >))
				nhrp_rate_limit_delete(rl);
		}
	}

	if (num_rate_limit_entries)
		nhrp_task_schedule(&rate_limit_task,
				   RATE_LIMIT_PURGE_INTERVAL * 1000,
				   &prune_rate_limit_entries);
}

static char *prune_rate_limit_entries_describe(struct nhrp_task *task, size_t buflen, char *buf)
{
	snprintf(buf, buflen, "Prune rate limit tokens");
	return buf;
}

static struct nhrp_rate_limit *get_rate_limit(struct nhrp_address *src, struct nhrp_address *dst)
{
	unsigned int key;
	struct nhrp_rate_limit *e;

	key = nhrp_address_hash(src) ^ nhrp_address_hash(dst);
	key %= RATE_LIMIT_HASH_SIZE;

	LIST_FOREACH(e, &rate_limit_hash[key], hash_entry) {
		if (nhrp_address_cmp(&e->src, src) == 0 &&
		    nhrp_address_cmp(&e->dst, dst) == 0)
			return e;
	}

	e = calloc(1, sizeof(struct nhrp_rate_limit));
	e->src = *src;
	e->dst = *dst;
	LIST_INSERT_HEAD(&rate_limit_hash[key], e, hash_entry);

	if (num_rate_limit_entries == 0)
		nhrp_task_schedule(&rate_limit_task,
				   RATE_LIMIT_PURGE_INTERVAL * 1000,
				   &prune_rate_limit_entries);
	num_rate_limit_entries++;

	return e;
}

static uint16_t nhrp_calculate_checksum(uint8_t *pdu, uint16_t len)
{
	uint16_t *pdu16 = (uint16_t *) pdu;
	uint32_t csum = 0;
	int i;

	for (i = 0; i < len / 2; i++)
		csum += pdu16[i];
	if (len & 1)
		csum += htons(pdu[len - 1]);

	while (csum & 0xffff0000)
		csum = (csum & 0xffff) + (csum >> 16);

	return (~csum) & 0xffff;
}

struct nhrp_buffer *nhrp_buffer_alloc(uint32_t size)
{
	struct nhrp_buffer *buf;

	buf = malloc(sizeof(struct nhrp_buffer) + size);
	buf->length = size;

	return buf;
}

struct nhrp_buffer *nhrp_buffer_copy(struct nhrp_buffer *buffer)
{
	struct nhrp_buffer *copy;

	copy = nhrp_buffer_alloc(buffer->length);
	memcpy(copy->data, buffer->data, buffer->length);
	return copy;
}

int nhrp_buffer_cmp(struct nhrp_buffer *a, struct nhrp_buffer *b)
{
	if (a->length > b->length)
		return 1;
	if (a->length < b->length)
		return -1;
	return memcmp(a->data, b->data, a->length);
}

void nhrp_buffer_free(struct nhrp_buffer *buffer)
{
	free(buffer);
}

struct nhrp_cie *nhrp_cie_alloc(void)
{
	return calloc(1, sizeof(struct nhrp_cie));
}

void nhrp_cie_free(struct nhrp_cie *cie)
{
	free(cie);
}

void nhrp_cie_reset(struct nhrp_cie *cie)
{
	memset(&cie->cie_list_entry, 0, sizeof(cie->cie_list_entry));
}

void nhrp_payload_free(struct nhrp_payload *payload)
{
	struct nhrp_cie *cie;

	switch (payload->payload_type) {
	case NHRP_PAYLOAD_TYPE_RAW:
		nhrp_buffer_free(payload->u.raw);
		break;
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		while (!TAILQ_EMPTY(&payload->u.cie_list_head)) {
			cie = TAILQ_FIRST(&payload->u.cie_list_head);
			TAILQ_REMOVE(&payload->u.cie_list_head, cie, cie_list_entry);
			nhrp_cie_free(cie);
		}
		break;
	}
	payload->payload_type = NHRP_PAYLOAD_TYPE_NONE;
}

void nhrp_payload_set_type(struct nhrp_payload *payload, int type)
{
	if (payload->payload_type == type)
		return;

	nhrp_payload_free(payload);
	payload->payload_type = type;
	switch (type) {
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		TAILQ_INIT(&payload->u.cie_list_head);
		break;
	default:
		payload->u.raw = NULL;
		break;
	}
}

void nhrp_payload_set_raw(struct nhrp_payload *payload, struct nhrp_buffer *raw)
{
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_RAW);
	payload->u.raw = raw;
}

void nhrp_payload_add_cie(struct nhrp_payload *payload, struct nhrp_cie *cie)
{
	if (payload->payload_type != NHRP_PAYLOAD_TYPE_CIE_LIST)
		return;

	TAILQ_INSERT_TAIL(&payload->u.cie_list_head, cie, cie_list_entry);
}

struct nhrp_cie *nhrp_payload_get_cie(struct nhrp_payload *payload, int index)
{
	struct nhrp_cie *cie;

	if (payload->payload_type != NHRP_PAYLOAD_TYPE_CIE_LIST)
		return NULL;

	for (cie = TAILQ_FIRST(&payload->u.cie_list_head);
	     cie != NULL && index > 1; index--) {
		cie = TAILQ_NEXT(cie, cie_list_entry);
	}

	return cie;
}

struct nhrp_packet *nhrp_packet_alloc(void)
{
	struct nhrp_packet *packet;
	packet = calloc(1, sizeof(struct nhrp_packet));
	packet->ref = 1;
	return packet;
}

struct nhrp_packet *nhrp_packet_dup(struct nhrp_packet *packet)
{
	packet->ref++;
	return packet;
}

struct nhrp_payload *nhrp_packet_payload(struct nhrp_packet *packet, int payload_type)
{
	return nhrp_packet_extension(packet, NHRP_EXTENSION_PAYLOAD, payload_type);
}

struct nhrp_payload *nhrp_packet_extension(struct nhrp_packet *packet,
					   uint32_t extension, int payload_type)
{
	struct nhrp_payload *p;

	p = packet->extension_by_type[extension & 0x7fff];
	if (p != NULL) {
		if (payload_type == NHRP_PAYLOAD_TYPE_ANY ||
		    payload_type == p->payload_type)
			return p;
		if (extension & NHRP_EXTENSION_FLAG_NOCREATE)
			return NULL;
		nhrp_payload_set_type(p, payload_type);
		return p;
	}

	if (extension & NHRP_EXTENSION_FLAG_NOCREATE)
		return NULL;

	p = &packet->extension_by_order[packet->num_extensions++];
	p->extension_type = extension & 0xffff;
	packet->extension_by_type[extension & 0x7fff] = p;
	if (payload_type != NHRP_PAYLOAD_TYPE_ANY)
		nhrp_payload_set_type(p, payload_type);

	return p;
}

void nhrp_packet_free(struct nhrp_packet *packet)
{
	int i;

	packet->ref--;
	if (packet->ref > 0)
		return;

	if (packet->dst_peer != NULL)
		nhrp_peer_free(packet->dst_peer);
	for (i = 0; i < packet->num_extensions; i++)
		nhrp_payload_free(&packet->extension_by_order[i]);
	free(packet);
}

static int nhrp_packet_reroute(struct nhrp_packet *packet,
			       struct nhrp_peer *dst_peer)
{
	packet->dst_iface = packet->src_iface;
	if (packet->dst_peer != NULL)
		nhrp_peer_free(packet->dst_peer);
	packet->dst_peer = nhrp_peer_dup(dst_peer);
	return nhrp_packet_route(packet);
}

static void nhrp_packet_dequeue(struct nhrp_packet *packet)
{
	nhrp_task_cancel(&packet->timeout);
	TAILQ_REMOVE(&pending_requests, packet, request_list_entry);
	nhrp_packet_free(packet);
}

static int nhrp_handle_resolution_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;

	nhrp_info("Received Resolution Request from proto src %s to %s",
		nhrp_address_format(&packet->src_protocol_address,
			sizeof(tmp), tmp),
		nhrp_address_format(&packet->dst_protocol_address,
			sizeof(tmp2), tmp2));

	packet->hdr.type = NHRP_PACKET_RESOLUTION_REPLY;
	packet->hdr.flags &= NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER |
			     NHRP_FLAG_RESOLUTION_SOURCE_STABLE |
			     NHRP_FLAG_RESOLUTION_UNIQUE |
			     NHRP_FLAG_RESOLUTION_NAT;
	packet->hdr.flags |= NHRP_FLAG_RESOLUTION_DESTINATION_STABLE |
			     NHRP_FLAG_RESOLUTION_AUTHORATIVE;
	packet->hdr.hop_count = 0;

	cie = nhrp_cie_alloc();
	if (cie == NULL)
		return FALSE;

	cie->hdr = (struct nhrp_cie_header) {
		.code = NHRP_CODE_SUCCESS,
		.prefix_length = packet->dst_peer->prefix_length,
		.holding_time = constant_htons(NHRP_HOLDING_TIME),
	};

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_ANY);
	nhrp_payload_free(payload);
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	if (!nhrp_packet_reroute(packet, FALSE))
		return FALSE;

	cie->nbma_address = packet->dst_peer->my_nbma_address;
	cie->protocol_address = packet->dst_iface->protocol_address;

	nhrp_info("Sending Resolution Reply %s is-at %s",
		nhrp_address_format(&cie->protocol_address,
			sizeof(tmp), tmp),
		nhrp_address_format(&cie->nbma_address,
			sizeof(tmp2), tmp2));

	/* Reset NAT header to regenerate it for reply */
	payload = nhrp_packet_extension(packet,
					NHRP_EXTENSION_NAT_ADDRESS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_ANY);
	if (payload != NULL) {
		nhrp_payload_free(payload);
		nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	}

	return nhrp_packet_send(packet);
}

static int find_one(void *ctx, struct nhrp_peer *p)
{
	return 1;
}

static int remove_old_registrations(void *ctx, struct nhrp_peer *p)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;

	/* If re-registration, mark the new connection up */
	if (nhrp_address_cmp(&peer->protocol_address, &p->protocol_address) == 0 &&
	    nhrp_address_cmp(&peer->next_hop_address, &p->next_hop_address) == 0 &&
	    peer->prefix_length == p->prefix_length)
		peer->flags |= p->flags & (NHRP_PEER_FLAG_UP |
					   NHRP_PEER_FLAG_LOWER_UP);

	p->flags |= NHRP_PEER_FLAG_REPLACED;
	nhrp_peer_remove(p);
	return 0;
}

static int nhrp_handle_registration_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	struct nhrp_peer *peer, *rpeer = NULL;
	struct nhrp_peer_selector sel;
	int natted = 0;

	nhrp_info("Received Registration Request from proto src %s to %s",
		nhrp_address_format(&packet->src_protocol_address,
			sizeof(tmp), tmp),
		nhrp_address_format(&packet->dst_protocol_address,
			sizeof(tmp2), tmp2));

	/* Cisco NAT extension, CIE added IF all of the following is true:
	 * 1. We are the first hop registration server
	 *    (=no entries in forward transit CIE list)
	 * 2. NAT is detected (link layer address != announced address)
	 * 3. NAT extension is requested */
	payload = nhrp_packet_extension(packet,
					NHRP_EXTENSION_FORWARD_TRANSIT_NHS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (payload != NULL && TAILQ_EMPTY(&payload->u.cie_list_head) &&
	    packet->src_linklayer_address.type != PF_UNSPEC &&
	    nhrp_address_cmp(&packet->src_nbma_address, &packet->src_linklayer_address) != 0) {
		natted = 1;
		payload = nhrp_packet_extension(packet,
						NHRP_EXTENSION_NAT_ADDRESS |
						NHRP_EXTENSION_FLAG_NOCREATE,
						NHRP_PAYLOAD_TYPE_CIE_LIST);
		if (payload != NULL) {
			cie = nhrp_cie_alloc();
			if (cie != NULL) {
				cie->nbma_address = packet->src_linklayer_address;
				cie->protocol_address = packet->src_protocol_address;
				nhrp_payload_add_cie(payload, cie);
			}
		}
	}

	packet->hdr.type = NHRP_PACKET_REGISTRATION_REPLY;
	packet->hdr.flags &= NHRP_FLAG_REGISTRATION_UNIQUE |
			     NHRP_FLAG_REGISTRATION_NAT;
	packet->hdr.hop_count = 0;

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	TAILQ_FOREACH(cie, &payload->u.cie_list_head, cie_list_entry) {
		peer = nhrp_peer_alloc(packet->src_iface);
		if (peer == NULL) {
			cie->hdr.code = NHRP_CODE_INSUFFICIENT_RESOURCES;
			continue;
		}

		peer->type = NHRP_PEER_TYPE_DYNAMIC;
		peer->afnum = packet->hdr.afnum;
		peer->protocol_type = packet->hdr.protocol_type;
		peer->expire_time = time(NULL) + ntohs(cie->hdr.holding_time);

		if (cie->nbma_address.addr_len != 0)
			peer->next_hop_address = cie->nbma_address;
		else
			peer->next_hop_address = packet->src_nbma_address;

		if (natted) {
			peer->next_hop_nat_oa  = peer->next_hop_address;
			peer->next_hop_address = packet->src_linklayer_address;
		}

		if (cie->protocol_address.addr_len != 0)
			peer->protocol_address = cie->protocol_address;
		else
			peer->protocol_address = packet->src_protocol_address;

		peer->prefix_length = cie->hdr.prefix_length;
		if (peer->prefix_length == 0xff)
			peer->prefix_length = peer->protocol_address.addr_len * 8;

		memset(&sel, 0, sizeof(sel));
		sel.flags = NHRP_PEER_FIND_EXACT;
		sel.type_mask = ~NHRP_PEER_TYPEMASK_REMOVABLE;
		sel.interface = packet->src_iface;
		sel.protocol_address = peer->protocol_address;
		sel.prefix_length = peer->prefix_length;

		/* Check that there is no conflicting peers and
		 * that the script allows this registration. */
		if (nhrp_peer_foreach(find_one, peer, &sel) == 0 &&
		    nhrp_peer_authorize_registration(peer)) {
			/* Remove all old stuff and accept registration */
			memset(&sel, 0, sizeof(sel));
			sel.flags = NHRP_PEER_FIND_EXACT;
			sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
			sel.interface = packet->src_iface;
			sel.protocol_address = peer->protocol_address;
			sel.prefix_length = peer->prefix_length;
			nhrp_peer_foreach(remove_old_registrations, peer, &sel);

			cie->hdr.code = NHRP_CODE_SUCCESS;
			nhrp_peer_insert(peer);

			if (rpeer == NULL)
				rpeer = nhrp_peer_dup(peer);
		} else {
			/* Non-removable binding already exists */
			cie->hdr.code = NHRP_CODE_ADMINISTRATIVELY_PROHIBITED;
			peer->flags |= NHRP_PEER_FLAG_REPLACED;
		}
		nhrp_peer_free(peer);
	}

	if (!nhrp_packet_reroute(packet, rpeer)) {
		if (rpeer != NULL)
			nhrp_peer_free(rpeer);

		nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE, 0);
		return FALSE;
	}
	if (rpeer != NULL)
		nhrp_peer_free(rpeer);

	return nhrp_packet_send(packet);
}

static int nhrp_handle_purge_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_peer_selector sel;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	int ret = TRUE;

	nhrp_info("Received Purge Request from proto src %s to %s",
		nhrp_address_format(&packet->src_protocol_address,
			sizeof(tmp), tmp),
		nhrp_address_format(&packet->dst_protocol_address,
			sizeof(tmp2), tmp2));

	packet->hdr.type = NHRP_PACKET_PURGE_REPLY;
	packet->hdr.flags = 0;
	packet->hdr.hop_count = 0;

	if (!(packet->hdr.flags & NHRP_FLAG_PURGE_NO_REPLY))
		ret = nhrp_packet_send(packet);

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	TAILQ_FOREACH(cie, &payload->u.cie_list_head, cie_list_entry) {
		nhrp_info("Purge proto %s/%d nbma %s",
			nhrp_address_format(&cie->protocol_address,
					    sizeof(tmp), tmp),
			cie->hdr.prefix_length,
			nhrp_address_format(&cie->nbma_address,
					    sizeof(tmp), tmp));

		memset(&sel, 0, sizeof(sel));
		sel.flags = NHRP_PEER_FIND_EXACT;
		sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
		sel.interface = packet->src_iface;
		sel.protocol_address = cie->protocol_address;
		sel.prefix_length = cie->hdr.prefix_length;
		nhrp_peer_foreach(nhrp_peer_remove_matching, NULL, &sel);
		nhrp_rate_limit_clear(&cie->protocol_address,
				      cie->hdr.prefix_length);
	}

	return ret;
}

static int nhrp_do_handle_error_indication(struct nhrp_packet *error_pkt,
					   struct nhrp_packet *orig_pkt)
{
	struct nhrp_packet *req;

	TAILQ_FOREACH(req, &pending_requests, request_list_entry) {
		if (orig_pkt->hdr.u.request_id != req->hdr.u.request_id)
			continue;

		if (nhrp_address_cmp(&orig_pkt->src_nbma_address,
				     &req->src_nbma_address))
			continue;
		if (nhrp_address_cmp(&orig_pkt->src_protocol_address,
				     &req->src_protocol_address))
			continue;

		req->handler(req->handler_ctx, error_pkt);
		nhrp_packet_dequeue(req);

		return TRUE;
	}

	return FALSE;
}

static int nhrp_handle_error_indication(struct nhrp_packet *error_packet)
{
	struct nhrp_packet *packet;
	struct nhrp_payload *payload;
	uint8_t *pdu;
	size_t pduleft;
	int r;

	packet = nhrp_packet_alloc();
	if (packet == NULL)
		return FALSE;

	payload = nhrp_packet_payload(error_packet, NHRP_PAYLOAD_TYPE_RAW);
	pdu = payload->u.raw->data;
	pduleft = payload->u.raw->length;

	if (!unmarshall_packet_header(&pdu, &pduleft, packet)) {
		nhrp_packet_free(packet);
		return FALSE;
	}

	r = nhrp_do_handle_error_indication(error_packet, packet);
	nhrp_packet_free(packet);

	return r;
}

static int nhrp_handle_traffic_indication(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_address dst;
	struct nhrp_payload *pl;

	pl = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_RAW);
	if (pl == NULL)
		return FALSE;

	if (!nhrp_address_parse_packet(packet->hdr.protocol_type,
				       pl->u.raw->length, pl->u.raw->data,
				       NULL, &dst))
		return FALSE;

	/* Shortcuts enabled? */
	if (packet->src_iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT) {
		nhrp_info("Traffic Indication from proto src %s; "
			  "about packet to %s",
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&dst, sizeof(tmp2), tmp2));

		nhrp_peer_traffic_indication(packet->src_iface,
					     packet->hdr.afnum,
					     &dst);
	} else {
		nhrp_info("Traffic Indication ignored from proto src %s; "
			  "about packet to %s",
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&dst, sizeof(tmp2), tmp2));
	}

	return TRUE;
}

#define NHRP_TYPE_REQUEST	0
#define NHRP_TYPE_REPLY		1
#define NHRP_TYPE_INDICATION	2

static struct {
	int type;
	uint16_t payload_type;
	int (*handler)(struct nhrp_packet *packet);
} packet_types[] = {
	[NHRP_PACKET_RESOLUTION_REQUEST] = {
		.type = NHRP_TYPE_REQUEST,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
		.handler = nhrp_handle_resolution_request,
	},
	[NHRP_PACKET_RESOLUTION_REPLY] = {
		.type = NHRP_TYPE_REPLY,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_REGISTRATION_REQUEST] = {
		.type = NHRP_TYPE_REQUEST,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
		.handler = nhrp_handle_registration_request,
	},
	[NHRP_PACKET_REGISTRATION_REPLY] = {
		.type = NHRP_TYPE_REPLY,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_PURGE_REQUEST] = {
		.type = NHRP_TYPE_REQUEST,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
		.handler = nhrp_handle_purge_request,
	},
	[NHRP_PACKET_PURGE_REPLY] = {
		.type = NHRP_TYPE_REPLY,
		.payload_type = NHRP_PAYLOAD_TYPE_CIE_LIST,
	},
	[NHRP_PACKET_ERROR_INDICATION] = {
		.type = NHRP_TYPE_INDICATION,
		.payload_type = NHRP_PAYLOAD_TYPE_RAW,
		.handler = nhrp_handle_error_indication,
	},
	[NHRP_PACKET_TRAFFIC_INDICATION] = {
		.type = NHRP_TYPE_INDICATION,
		.payload_type = NHRP_PAYLOAD_TYPE_RAW,
		.handler = nhrp_handle_traffic_indication,
	}
};
static int extension_types[] = {
	[NHRP_EXTENSION_RESPONDER_ADDRESS] = NHRP_PAYLOAD_TYPE_CIE_LIST,
	[NHRP_EXTENSION_FORWARD_TRANSIT_NHS] = NHRP_PAYLOAD_TYPE_CIE_LIST,
	[NHRP_EXTENSION_REVERSE_TRANSIT_NHS] = NHRP_PAYLOAD_TYPE_CIE_LIST,
	[NHRP_EXTENSION_NAT_ADDRESS] = NHRP_PAYLOAD_TYPE_CIE_LIST
};

static int unmarshall_binary(uint8_t **pdu, size_t *pduleft, size_t size, void *raw)
{
	if (*pduleft < size)
		return FALSE;

	memcpy(raw, *pdu, size);
	*pdu += size;
	*pduleft -= size;
	return TRUE;
}

static inline int unmarshall_protocol_address(uint8_t **pdu, size_t *pduleft, struct nhrp_address *pa)
{
	if (*pduleft < pa->addr_len)
		return FALSE;

	if (!nhrp_address_set(pa, pa->type, pa->addr_len, *pdu))
		return FALSE;

	*pdu += pa->addr_len;
	*pduleft -= pa->addr_len;
	return TRUE;
}

static inline int unmarshall_nbma_address(uint8_t **pdu, size_t *pduleft, struct nhrp_address *na)
{
	if (*pduleft < na->addr_len + na->subaddr_len)
		return FALSE;

	if (!nhrp_address_set_full(na, na->type,
				   na->addr_len, *pdu,
				   na->subaddr_len, *pdu + na->addr_len))
		return FALSE;

	*pdu += na->addr_len + na->subaddr_len;
	*pduleft -= na->addr_len + na->subaddr_len;
	return TRUE;
}

static int unmarshall_cie(uint8_t **pdu, size_t *pduleft, struct nhrp_packet *p, struct nhrp_cie *cie)
{
	if (!unmarshall_binary(pdu, pduleft, sizeof(struct nhrp_cie_header), &cie->hdr))
		return FALSE;

	cie->nbma_address.type = nhrp_pf_from_afnum(p->hdr.afnum);
	cie->nbma_address.addr_len = cie->hdr.nbma_address_len;
	cie->nbma_address.subaddr_len = cie->hdr.nbma_subaddress_len;
	cie->protocol_address.type = nhrp_pf_from_protocol(p->hdr.protocol_type);
	cie->protocol_address.addr_len = cie->hdr.protocol_address_len;

	if (!unmarshall_nbma_address(pdu, pduleft, &cie->nbma_address))
		return FALSE;
	return unmarshall_protocol_address(pdu, pduleft, &cie->protocol_address);
}

static int unmarshall_payload(uint8_t **pdu, size_t *pduleft,
			      struct nhrp_packet *packet,
			      int type, size_t size,
			      struct nhrp_payload *p)
{
	struct nhrp_cie *cie;
	size_t cieleft;

	if (*pduleft < size)
		return FALSE;

	nhrp_payload_set_type(p, type);
	switch (p->payload_type) {
	case NHRP_PAYLOAD_TYPE_NONE:
		*pdu += size;
		*pduleft -= size;
		return TRUE;
	case NHRP_PAYLOAD_TYPE_RAW:
		p->u.raw = nhrp_buffer_alloc(size);
		return unmarshall_binary(pdu, pduleft, size, p->u.raw->data);
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		cieleft = size;
		while (cieleft) {
			cie = nhrp_cie_alloc();
			TAILQ_INSERT_TAIL(&p->u.cie_list_head, cie, cie_list_entry);
			if (!unmarshall_cie(pdu, &cieleft, packet, cie))
				return FALSE;
		}
		*pduleft -= size;
		return TRUE;
	default:
		return FALSE;
	}
}

static int unmarshall_packet_header(uint8_t **pdu, size_t *pduleft, struct nhrp_packet *packet)
{
	struct nhrp_packet_header *phdr = (struct nhrp_packet_header *) *pdu;

	if (!unmarshall_binary(pdu, pduleft, sizeof(packet->hdr), &packet->hdr))
		return FALSE;

	if (packet->hdr.type >= ARRAY_SIZE(packet_types))
		return FALSE;

	packet->src_nbma_address.type = nhrp_pf_from_afnum(packet->hdr.afnum);
	packet->src_nbma_address.addr_len = phdr->src_nbma_address_len;
	packet->src_nbma_address.subaddr_len = phdr->src_nbma_subaddress_len;
	packet->src_protocol_address.type = nhrp_pf_from_protocol(packet->hdr.protocol_type);
	packet->src_protocol_address.addr_len = phdr->src_protocol_address_len;
	packet->dst_protocol_address.type = nhrp_pf_from_protocol(packet->hdr.protocol_type);
	packet->dst_protocol_address.addr_len = phdr->dst_protocol_address_len;

	if (!unmarshall_nbma_address(pdu, pduleft, &packet->src_nbma_address))
		return FALSE;
	if (!unmarshall_protocol_address(pdu, pduleft, &packet->src_protocol_address))
		return FALSE;
	return unmarshall_protocol_address(pdu, pduleft, &packet->dst_protocol_address);
}

static int unmarshall_packet(uint8_t *pdu, size_t pdusize, struct nhrp_packet *packet)
{
	size_t pduleft = pdusize;
	uint8_t *pos = pdu;
	int size, extension_offset;

	if (!unmarshall_packet_header(&pos, &pduleft, packet))
		return FALSE;

	extension_offset = ntohs(packet->hdr.extension_offset);
	if (extension_offset == 0) {
		/* No extensions; rest of data is payload */
		size = pduleft;
	} else {
		/* Extensions present; exclude those from payload */
		size = extension_offset - (pos - pdu);
		if (size < 0 || size > pduleft) {
			nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ERROR, pos - pdu);
			return FALSE;
		}
	}

	if (!unmarshall_payload(&pos, &pduleft, packet,
				packet_types[packet->hdr.type].payload_type,
				size, nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_ANY))) {
		nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ERROR, pos - pdu);
		return FALSE;
	}

	if (extension_offset == 0)
		return TRUE;

	pos = &pdu[extension_offset];
	pduleft = pdusize - extension_offset;
	do {
		struct nhrp_extension_header eh;
		int extension_type, payload_type;

		if (!unmarshall_binary(&pos, &pduleft, sizeof(eh), &eh)) {
			nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ERROR, pos - pdu);
			return FALSE;
		}

		extension_type = ntohs(eh.type) & ~NHRP_EXTENSION_FLAG_COMPULSORY;
		if (extension_type == NHRP_EXTENSION_END)
			break;

		payload_type = NHRP_PAYLOAD_TYPE_NONE;
		if (extension_type < ARRAY_SIZE(extension_types))
			payload_type = extension_types[extension_type];
		if (payload_type == NHRP_PAYLOAD_TYPE_NONE)
			payload_type = NHRP_PAYLOAD_TYPE_RAW;
		if (payload_type == NHRP_PAYLOAD_TYPE_RAW &&
		    ntohs(eh.length) == 0)
			payload_type = NHRP_PAYLOAD_TYPE_NONE;

		if (!unmarshall_payload(&pos, &pduleft, packet,
					payload_type, ntohs(eh.length),
					nhrp_packet_extension(packet, ntohs(eh.type), NHRP_PAYLOAD_TYPE_ANY))) {
			nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ERROR, pos - pdu);
			return FALSE;
		}
	} while (1);

	return TRUE;
}

static int nhrp_packet_forward(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64], tmp3[64];
	struct nhrp_payload *p = NULL;

	nhrp_info("Forwarding packet from nbma src %s, proto src %s to proto dst %s, hop count %d",
		nhrp_address_format(&packet->src_nbma_address,
				    sizeof(tmp), tmp),
		nhrp_address_format(&packet->src_protocol_address,
				    sizeof(tmp2), tmp2),
		nhrp_address_format(&packet->dst_protocol_address,
				    sizeof(tmp3), tmp3),
		packet->hdr.hop_count);

	if (packet->hdr.hop_count == 0) {
		nhrp_packet_send_error(packet, NHRP_ERROR_HOP_COUNT_EXCEEDED, 0);
		return TRUE;
	}
	packet->hdr.hop_count--;

	if (!nhrp_packet_reroute(packet, FALSE)) {
		nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE, 0);
		return FALSE;
	}

	switch (packet_types[packet->hdr.type].type) {
	case NHRP_TYPE_REQUEST:
		p = nhrp_packet_extension(packet,
					  NHRP_EXTENSION_FORWARD_TRANSIT_NHS |
					  NHRP_EXTENSION_FLAG_NOCREATE,
					  NHRP_PAYLOAD_TYPE_CIE_LIST);
		break;
	case NHRP_TYPE_REPLY:
		p = nhrp_packet_extension(packet,
					  NHRP_EXTENSION_REVERSE_TRANSIT_NHS |
					  NHRP_EXTENSION_FLAG_NOCREATE,
					  NHRP_PAYLOAD_TYPE_CIE_LIST);
		break;
	}
	if (p != NULL) {
		struct nhrp_cie *cie;

		if (nhrp_address_match_cie_list(&packet->dst_peer->my_nbma_address,
						&packet->dst_iface->protocol_address,
						&p->u.cie_list_head)) {
			nhrp_packet_send_error(packet, NHRP_ERROR_LOOP_DETECTED, 0);
			return FALSE;
		}

		cie = nhrp_cie_alloc();
		if (cie != NULL) {
			cie->hdr = (struct nhrp_cie_header) {
				.code = NHRP_CODE_SUCCESS,
				.holding_time = NHRP_HOLDING_TIME,
			};
			cie->nbma_address = packet->dst_peer->my_nbma_address;
			cie->protocol_address = packet->dst_iface->protocol_address;
			nhrp_payload_add_cie(p, cie);
		}
	}

	return nhrp_packet_route_and_send(packet);
}

static int nhrp_packet_receive_local(struct nhrp_packet *packet)
{
	struct nhrp_packet *req;

	if (packet_types[packet->hdr.type].type == NHRP_TYPE_REPLY) {
		TAILQ_FOREACH(req, &pending_requests, request_list_entry) {
			if (packet->hdr.u.request_id != req->hdr.u.request_id)
				continue;
			if (nhrp_address_cmp(&packet->src_nbma_address,
					     &req->src_nbma_address))
				continue;
			if (nhrp_address_cmp(&packet->src_protocol_address,
					     &req->src_protocol_address))
				continue;

			req->handler(req->handler_ctx, packet);
			nhrp_packet_dequeue(req);

			return TRUE;
		}

		/* Reply to unsent request? */
		nhrp_packet_send_error(packet, NHRP_ERROR_INVALID_RESOLUTION_REPLY, 0);
		return TRUE;
	}

	if (packet_types[packet->hdr.type].handler == NULL) {
		char tmp[64], tmp2[64], tmp3[64];

		nhrp_info("Packet type %d from nbma src %s, proto src %s, proto dst %s not supported",
			  packet->hdr.type,
			  nhrp_address_format(&packet->src_nbma_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp2), tmp2),
			  nhrp_address_format(&packet->dst_protocol_address,
					      sizeof(tmp3), tmp3));
		return FALSE;
	}

	return packet_types[packet->hdr.type].handler(packet);
}

int nhrp_packet_receive(uint8_t *pdu, size_t pdulen,
			struct nhrp_interface *iface,
			struct nhrp_address *from)
{
	char tmp[64];
	struct nhrp_packet *packet;
	struct nhrp_address *dest;
	struct nhrp_peer *peer;
	int ret = FALSE;

	if (nhrp_calculate_checksum(pdu, pdulen) != 0) {
		nhrp_error("Bad checksum in packet from %s",
			   nhrp_address_format(from, sizeof(tmp), tmp));
		return FALSE;
	}

	packet = nhrp_packet_alloc();
	if (packet == NULL)
		return FALSE;

	if (!unmarshall_packet(pdu, pdulen, packet)) {
		nhrp_error("Failed to unmarshall packet from %s",
			   nhrp_address_format(from, sizeof(tmp), tmp));
		goto error;
	}

	packet->req_pdu = pdu;
	packet->req_pdulen = pdulen;

	if (packet_types[packet->hdr.type].type == NHRP_TYPE_REPLY)
		dest = &packet->src_protocol_address;
	else
		dest = &packet->dst_protocol_address;

	peer = nhrp_peer_route(iface, dest, 0,
			       BIT(NHRP_PEER_TYPE_LOCAL), NULL);
	packet->src_linklayer_address = *from;
	packet->src_iface = iface;
	packet->dst_peer = nhrp_peer_dup(peer);

	/* RFC2332 5.3.4 - Authentication is always done pairwise on an NHRP
	 * hop-by-hop basis; i.e. regenerated at each hop. */
	if (packet->src_iface->auth_token &&
	    (packet->hdr.type != NHRP_PACKET_ERROR_INDICATION ||
	     packet->hdr.u.error.code != NHRP_ERROR_AUTHENTICATION_FAILURE)) {
		struct nhrp_payload *p;
		p = nhrp_packet_extension(packet,
					  NHRP_EXTENSION_AUTHENTICATION |
					  NHRP_EXTENSION_FLAG_NOCREATE,
					  NHRP_PAYLOAD_TYPE_RAW);
		if (p == NULL ||
		    nhrp_buffer_cmp(packet->src_iface->auth_token, p->u.raw) != 0) {
			nhrp_error("Dropping packet from %s with bad authentication",
				nhrp_address_format(from, sizeof(tmp), tmp));
			nhrp_packet_send_error(packet, NHRP_ERROR_AUTHENTICATION_FAILURE, 0);
			goto error;
		}
	}

	if (peer != NULL && peer->type == NHRP_PEER_TYPE_LOCAL)
		ret = nhrp_packet_receive_local(packet);
	else
		ret = nhrp_packet_forward(packet);

error:
	nhrp_packet_free(packet);
	return ret;
}

static int marshall_binary(uint8_t **pdu, size_t *pduleft, size_t size, void *raw)
{
	if (*pduleft < size)
		return FALSE;

	memcpy(*pdu, raw, size);
	*pdu += size;
	*pduleft -= size;

	return TRUE;
}

static inline int marshall_protocol_address(uint8_t **pdu, size_t *pduleft, struct nhrp_address *pa)
{
	if (pa->subaddr_len != 0)
		return FALSE;
	return marshall_binary(pdu, pduleft, pa->addr_len, pa->addr);
}

static inline int marshall_nbma_address(uint8_t **pdu, size_t *pduleft, struct nhrp_address *na)
{
	return marshall_binary(pdu, pduleft, na->addr_len + na->subaddr_len, na->addr);
}

static int marshall_cie(uint8_t **pdu, size_t *pduleft, struct nhrp_cie *cie)
{
	cie->hdr.nbma_address_len = cie->nbma_address.addr_len;
	cie->hdr.nbma_subaddress_len = cie->nbma_address.subaddr_len;
	cie->hdr.protocol_address_len = cie->protocol_address.addr_len;

	if (!marshall_binary(pdu, pduleft, sizeof(struct nhrp_cie_header), &cie->hdr))
		return FALSE;
	if (!marshall_nbma_address(pdu, pduleft, &cie->nbma_address))
		return FALSE;
	return marshall_protocol_address(pdu, pduleft, &cie->protocol_address);
}

static int marshall_payload(uint8_t **pdu, size_t *pduleft, struct nhrp_payload *p)
{
	struct nhrp_cie *cie;

	switch (p->payload_type) {
	case NHRP_PAYLOAD_TYPE_NONE:
		return TRUE;
	case NHRP_PAYLOAD_TYPE_RAW:
		if (p->u.raw->length == 0)
			return TRUE;
		return marshall_binary(pdu, pduleft, p->u.raw->length, p->u.raw->data);
	case NHRP_PAYLOAD_TYPE_CIE_LIST:
		TAILQ_FOREACH(cie, &p->u.cie_list_head, cie_list_entry) {
			if (!marshall_cie(pdu, pduleft, cie))
				return FALSE;
		}
		return TRUE;
	default:
		return FALSE;
	}
}

static int marshall_packet_header(uint8_t **pdu, size_t *pduleft, struct nhrp_packet *packet)
{
	if (!marshall_binary(pdu, pduleft, sizeof(packet->hdr), &packet->hdr))
		return FALSE;
	if (!marshall_nbma_address(pdu, pduleft, &packet->src_nbma_address))
		return FALSE;
	if (!marshall_protocol_address(pdu, pduleft, &packet->src_protocol_address))
		return FALSE;
	return marshall_protocol_address(pdu, pduleft, &packet->dst_protocol_address);
}

static int marshall_packet(uint8_t *pdu, size_t pduleft, struct nhrp_packet *packet)
{
	uint8_t *pos = pdu;
	struct nhrp_packet_header *phdr = (struct nhrp_packet_header *) pdu;
	struct nhrp_extension_header neh;
	int i, size;

	if (!marshall_packet_header(&pos, &pduleft, packet))
		return -1;
	if (!marshall_payload(&pos, &pduleft, nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_ANY)))
		return -1;

	phdr->extension_offset = htons((int)(pos - pdu));
	for (i = 1; i < packet->num_extensions; i++) {
		struct nhrp_extension_header *eh = (struct nhrp_extension_header *) pos;

		if (packet->extension_by_order[i].payload_type == NHRP_PAYLOAD_TYPE_NONE)
			continue;

		neh.type = htons(packet->extension_by_order[i].extension_type);
		neh.length = 0;

		if (!marshall_binary(&pos, &pduleft, sizeof(neh), &neh))
			return -1;
		if (!marshall_payload(&pos, &pduleft, &packet->extension_by_order[i]))
			return -1;
		eh->length = htons((pos - (uint8_t *) eh) - sizeof(neh));
	}
	neh.type = htons(NHRP_EXTENSION_END | NHRP_EXTENSION_FLAG_COMPULSORY);
	neh.length = 0;
	if (!marshall_binary(&pos, &pduleft, sizeof(neh), &neh))
		return -1;

	/* Cisco is seriously brain damaged. It needs some extra garbage
         * at the end of error indication or it'll barf out spurious errors. */
	if (packet->hdr.type == NHRP_PACKET_ERROR_INDICATION &&
	    pduleft >= 0x10) {
		memset(pos, 0, 0x10);
		pos += 0x10;
		pduleft -= 0x10;
	}

	size = (int)(pos - pdu);
	phdr->packet_size = htons(size);
	phdr->checksum = 0;
	phdr->src_nbma_address_len = packet->src_nbma_address.addr_len;
	phdr->src_nbma_subaddress_len = packet->src_nbma_address.subaddr_len;
	phdr->src_protocol_address_len = packet->src_protocol_address.addr_len;
	phdr->dst_protocol_address_len = packet->dst_protocol_address.addr_len;
	phdr->checksum = nhrp_calculate_checksum(pdu, size);

	return size;
}

int nhrp_packet_route(struct nhrp_packet *packet)
{
	struct nhrp_address proto_nexthop, *dest;
	struct nhrp_cie_list_head *cielist = NULL;
	struct nhrp_payload *payload;
	struct nhrp_peer *peer;
	char tmp[64];
	int r;

	if (packet->dst_iface == NULL) {
		nhrp_error("nhrp_packet_route called without destination interface");
		return FALSE;
	}

	if (packet_types[packet->hdr.type].type == NHRP_TYPE_REPLY) {
		dest = &packet->src_protocol_address;
		r = NHRP_EXTENSION_REVERSE_TRANSIT_NHS;
	} else {
		dest = &packet->dst_protocol_address;
		r = NHRP_EXTENSION_FORWARD_TRANSIT_NHS;
	}
	payload = nhrp_packet_extension(packet,
					r | NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (payload != NULL)
		cielist = &payload->u.cie_list_head;

	if (packet->dst_peer != NULL) {
		proto_nexthop = packet->dst_peer->next_hop_address;
	} else {
		r = kernel_route(packet->dst_iface, dest,
				 &packet->dst_iface->protocol_address,
				 &proto_nexthop);
		if (!r) {
			nhrp_error("No route to protocol address %s",
				nhrp_address_format(dest, sizeof(tmp), tmp));
			return FALSE;
		}

		peer = nhrp_peer_route(packet->dst_iface,
				       &proto_nexthop,
				       0,
				       ~(BIT(NHRP_PEER_TYPE_CACHED_ROUTE) |
					 BIT(NHRP_PEER_TYPE_INCOMPLETE)),
				       cielist);
		if (peer == NULL || peer->type == NHRP_PEER_TYPE_NEGATIVE) {
			nhrp_error("No peer entry for protocol address %s",
				   nhrp_address_format(&proto_nexthop,
						       sizeof(tmp), tmp));
			return FALSE;
		}
		packet->dst_peer = nhrp_peer_dup(peer);
	}

	return TRUE;
}

int nhrp_packet_marshall_and_send(struct nhrp_packet *packet)
{
	uint8_t pdu[MAX_PDU_SIZE];
	char tmp[4][64];
	int size;

	nhrp_debug("Sending packet %d, from: %s (nbma %s), to: %s (nbma %s)",
		   packet->hdr.type,
		   nhrp_address_format(&packet->src_protocol_address,
				       sizeof(tmp[0]), tmp[0]),
		   nhrp_address_format(&packet->src_nbma_address,
				       sizeof(tmp[1]), tmp[1]),
		   nhrp_address_format(&packet->dst_protocol_address,
				       sizeof(tmp[2]), tmp[2]),
		   nhrp_address_format(&packet->dst_peer->next_hop_address,
				       sizeof(tmp[3]), tmp[3]));

	size = marshall_packet(pdu, sizeof(pdu), packet);
	if (size < 0)
		return FALSE;

	if (!kernel_send(pdu, size, packet->dst_iface,
			 &packet->dst_peer->next_hop_address))
		return FALSE;

	return TRUE;
}

int nhrp_packet_route_and_send(struct nhrp_packet *packet)
{
	struct nhrp_payload *payload;

	if (packet->dst_peer == NULL || packet->dst_iface == NULL) {
		if (!nhrp_packet_route(packet)) {
			nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE, 0);
			return TRUE;
		}
	}

	if (packet->src_nbma_address.addr_len == 0)
		packet->src_nbma_address = packet->dst_peer->my_nbma_address;
	if (packet->src_protocol_address.addr_len == 0)
		packet->src_protocol_address = packet->dst_iface->protocol_address;
	if (packet->hdr.afnum == AFNUM_RESERVED)
		packet->hdr.afnum = packet->dst_peer->afnum;
	if (packet->hdr.hop_count == 0)
		packet->hdr.hop_count = 16;

	/* RFC2332 5.3.1 */
	payload = nhrp_packet_extension(
		packet, NHRP_EXTENSION_RESPONDER_ADDRESS |
		NHRP_EXTENSION_FLAG_COMPULSORY | NHRP_EXTENSION_FLAG_NOCREATE,
		NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (packet_types[packet->hdr.type].type == NHRP_TYPE_REPLY &&
	    (payload != NULL && TAILQ_EMPTY(&payload->u.cie_list_head))) {
		struct nhrp_cie *cie;

		cie = nhrp_cie_alloc();
		if (cie == NULL)
			return FALSE;

		cie->hdr.holding_time = htons(NHRP_HOLDING_TIME);
		cie->nbma_address = packet->dst_peer->my_nbma_address;
		cie->protocol_address = packet->dst_iface->protocol_address;
		nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
		nhrp_payload_add_cie(payload, cie);
	}

	/* RFC2332 5.3.4 - Authentication is always done pairwise on an NHRP
	 * hop-by-hop basis; i.e. regenerated at each hop. */
	payload = nhrp_packet_extension(packet,
					NHRP_EXTENSION_AUTHENTICATION |
					NHRP_EXTENSION_FLAG_COMPULSORY,
					NHRP_PAYLOAD_TYPE_RAW);
	nhrp_payload_free(payload);
	if (packet->dst_iface->auth_token != NULL)
		nhrp_payload_set_raw(payload,
			nhrp_buffer_copy(packet->dst_iface->auth_token));

        if (packet->dst_peer->type == NHRP_PEER_TYPE_LOCAL)
		return nhrp_packet_receive_local(packet);

	if (packet->dst_peer->flags & (NHRP_PEER_FLAG_UP |
				       NHRP_PEER_FLAG_LOWER_UP))
		return nhrp_packet_marshall_and_send(packet);

	if (packet->dst_peer->queued_packet != NULL)
		nhrp_packet_free(packet->dst_peer->queued_packet);
	packet->dst_peer->queued_packet = nhrp_packet_dup(packet);

	return TRUE;
}

int nhrp_packet_send(struct nhrp_packet *packet)
{
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;

	if (packet->dst_iface == NULL) {
		if (!nhrp_packet_route(packet)) {
			nhrp_packet_send_error(packet, NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE, 0);
			return TRUE;
		}
	}

	/* Cisco NAT extension CIE */
	if (packet_types[packet->hdr.type].type != NHRP_TYPE_INDICATION &&
	    (packet->hdr.flags & NHRP_FLAG_REGISTRATION_NAT)) {
		payload = nhrp_packet_extension(packet, NHRP_EXTENSION_NAT_ADDRESS,
						NHRP_PAYLOAD_TYPE_CIE_LIST);

		if (packet->dst_iface->nat_cie.nbma_address.addr_len &&
		    payload != NULL && TAILQ_EMPTY(&payload->u.cie_list_head)) {
			cie = nhrp_cie_alloc();
			if (cie != NULL) {
				*cie = packet->dst_iface->nat_cie;
				nhrp_cie_reset(cie);
				nhrp_payload_add_cie(payload, cie);
			}
		}
	}

	return nhrp_packet_route_and_send(packet);
}

NHRP_TASK(nhrp_packet_xmit_timeout);

static void nhrp_packet_xmit_timeout_callback(struct nhrp_task *task)
{
	struct nhrp_packet *packet = container_of(task, struct nhrp_packet, timeout);

	TAILQ_REMOVE(&pending_requests, packet, request_list_entry);

	if (packet->dst_peer != NULL &&
	    ++packet->retry < PACKET_RETRIES) {
		nhrp_packet_marshall_and_send(packet);

		TAILQ_INSERT_TAIL(&pending_requests, packet,
				  request_list_entry);
		nhrp_task_schedule(&packet->timeout, PACKET_RETRY_INTERVAL,
				   &nhrp_packet_xmit_timeout);
	} else {
		if (packet->dst_peer == NULL)
			nhrp_error("nhrp_packet_xmit_timeout: no destination peer!");
		packet->handler(packet->handler_ctx, NULL);
		nhrp_packet_dequeue(packet);
	}
}

static char *nhrp_packet_xmit_timeout_describe(struct nhrp_task *task, size_t buflen, char *buf)
{
	struct nhrp_packet *packet = container_of(task, struct nhrp_packet, timeout);
	char to[64];

	snprintf(buf, buflen, "Timeout handler: packet %d (to %s)",
		 packet->hdr.type,
		 nhrp_address_format(&packet->dst_protocol_address, sizeof(to), to));
	return buf;
}

int nhrp_packet_send_request(struct nhrp_packet *pkt,
			     void (*handler)(void *ctx, struct nhrp_packet *packet),
			     void *ctx)
{
	struct nhrp_packet *packet;

	packet = nhrp_packet_dup(pkt);

	packet->retry = 0;
	request_id++;
	packet->hdr.u.request_id = htonl(request_id);

	packet->handler = handler;
	packet->handler_ctx = ctx;
	TAILQ_INSERT_TAIL(&pending_requests, packet, request_list_entry);
	nhrp_task_schedule(&packet->timeout, 5000, &nhrp_packet_xmit_timeout);

	return nhrp_packet_send(packet);
}

int nhrp_packet_send_error(struct nhrp_packet *error_packet,
			   uint16_t indication_code, uint16_t offset)
{
	struct nhrp_packet *p;
	struct nhrp_payload *pl;
	int r;

	/* RFC2332 5.2.7 Never generate errors about errors */
	if (error_packet->hdr.type == NHRP_PACKET_ERROR_INDICATION)
		return TRUE;

	p = nhrp_packet_alloc();
	p->hdr = error_packet->hdr;
	p->hdr.hop_count = 0;
	p->hdr.type = NHRP_PACKET_ERROR_INDICATION;
	p->hdr.u.error.code = indication_code;
	p->hdr.u.error.offset = htons(offset);
	p->dst_iface = error_packet->src_iface;

	if (packet_types[error_packet->hdr.type].type == NHRP_TYPE_REPLY)
		p->dst_protocol_address = error_packet->dst_protocol_address;
	else
		p->dst_protocol_address = error_packet->src_protocol_address;

	pl = nhrp_packet_payload(p, NHRP_PAYLOAD_TYPE_RAW);
	pl->u.raw = nhrp_buffer_alloc(error_packet->req_pdulen);
	memcpy(pl->u.raw->data, error_packet->req_pdu, error_packet->req_pdulen);

	if (p->dst_protocol_address.type == PF_UNSPEC)
		r = nhrp_do_handle_error_indication(p, error_packet);
	else
		r = nhrp_packet_send(p);

	nhrp_packet_free(p);

	return r;
}

int nhrp_packet_send_traffic(struct nhrp_interface *iface, int protocol_type,
			     uint8_t *pdu, size_t pdulen)
{
	struct nhrp_rate_limit *rl;
	struct nhrp_packet *p;
	struct nhrp_payload *pl;
	struct nhrp_address src, dst;
	char tmp1[64], tmp2[64];
	int r;
	struct timeval now, tv;

	if (!nhrp_address_parse_packet(protocol_type, pdulen, pdu, &src, &dst))
		return FALSE;

	rl = get_rate_limit(&src, &dst);
	if (rl == NULL)
		return FALSE;

	gettimeofday(&now, NULL);
	tv = rl->rate_last;
	tv.tv_sec += RATE_LIMIT_SILENCE;

	/* If silence period has elapsed, reset algorithm */
	if (timercmp(&now, &tv, >))
		rl->rate_tokens = 0;

	/* Too many ignored redirects; just update time of last packet */
	if (rl->rate_tokens >= RATE_LIMIT_MAX_TOKENS) {
		rl->rate_last = now;
		return FALSE;
	}

	/* Check for load limit; set rate_last to last sent redirect */
	tv = rl->rate_last;
	tv.tv_sec += RATE_LIMIT_SEND_INTERVAL;
	if (rl->rate_tokens != 0 && timercmp(&now, &tv, <))
		return FALSE;

	rl->rate_tokens++;
	rl->rate_last = now;

	p = nhrp_packet_alloc();
	p->hdr = (struct nhrp_packet_header) {
		.protocol_type = protocol_type,
		.version = NHRP_VERSION_RFC2332,
		.type = NHRP_PACKET_TRAFFIC_INDICATION,
		.hop_count = 1,
	};
	p->dst_protocol_address = src;

	pl = nhrp_packet_payload(p, NHRP_PAYLOAD_TYPE_RAW);
	pl->u.raw = nhrp_buffer_alloc(pdulen);
	memcpy(pl->u.raw->data, pdu, pdulen);

	nhrp_info("Sending Traffic Indication about packet from %s to %s",
		nhrp_address_format(&src, sizeof(tmp1), tmp1),
		nhrp_address_format(&dst, sizeof(tmp2), tmp2));

	p->dst_iface = iface;
	r = nhrp_packet_send(p);
	nhrp_packet_free(p);

	return r;
}
