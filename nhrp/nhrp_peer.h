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

#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/queue.h>
#include "nhrp_address.h"

#define NHRP_PEER_TYPE_INCOMPLETE	0x00	/* Resolution request sent */
#define NHRP_PEER_TYPE_NEGATIVE		0x01	/* Negative cached */
#define NHRP_PEER_TYPE_CACHED		0x02	/* Received/relayed resolution reply */
#define NHRP_PEER_TYPE_CACHED_ROUTE	0x03	/* Received/relayed resolution for route */
#define NHRP_PEER_TYPE_DYNAMIC		0x04	/* NHC registration */
#define NHRP_PEER_TYPE_STATIC		0x05	/* Static mapping from config file */
#define NHRP_PEER_TYPE_LOCAL		0x06	/* Learned from interface config */
#define NHRP_PEER_TYPE_MAX		0x07

#define NHRP_PEER_FLAG_UNIQUE		0x01	/* Peer is unique; see RFC2332 */
#define NHRP_PEER_FLAG_REGISTER		0x02	/* For TYPE_STATIC: send registration */
#define NHRP_PEER_FLAG_USED		0x10	/* Peer is in kernel ARP table */
#define NHRP_PEER_FLAG_LOWER_UP		0x20	/* Script executed succesfully */
#define NHRP_PEER_FLAG_UP		0x40	/* Can send all packets (registration ok) */
#define NHRP_PEER_FLAG_REPLACED		0x80	/* Peer has been replaced */

#define NHRP_PEER_FIND_ROUTE		0x01
#define NHRP_PEER_FIND_EXACT		0x02
#define NHRP_PEER_FIND_SUBNET		0x04
#define NHRP_PEER_FIND_COMPLETE		0x10
#define NHRP_PEER_FIND_UP		0x20
#define NHRP_PEER_FIND_REMOVABLE	0x40
#define NHRP_PEER_FIND_PURGEABLE	0x80

CIRCLEQ_HEAD(nhrp_peer_list, nhrp_peer);

struct nhrp_interface;
struct nhrp_packet;
struct nhrp_cie_list_head;

struct nhrp_peer {
	int ref_count;
	CIRCLEQ_ENTRY(nhrp_peer) peer_list;
	struct nhrp_task task;
	struct nhrp_interface *interface;
	pid_t script_pid;
	void (*script_callback)(struct nhrp_peer *peer, int status);

	int flags;
	uint8_t type;
	uint8_t prefix_length;
	uint16_t afnum;
	uint16_t protocol_type;
	uint16_t mtu;
	time_t expire_time;
	time_t last_used;
	struct nhrp_address my_nbma_address;
	struct nhrp_address protocol_address;

	char *nbma_hostname;
	/* NHRP_PEER_TYPE_ROUTE: protocol addr., others: NBMA addr. */
	struct nhrp_address next_hop_address;
	struct nhrp_address next_hop_nat_oa;

	struct nhrp_packet *queued_packet;
};

struct nhrp_peer_selector {
	int flags; /* NHRP_PEER_FIND_xxx */

	struct nhrp_interface *interface;

	int prefix_length;
	struct nhrp_address protocol_address;

	struct nhrp_address nbma_address;
};

const char * const nhrp_peer_type[NHRP_PEER_TYPE_MAX];
typedef int (*nhrp_peer_enumerator)(void *ctx, struct nhrp_peer *peer);

void nhrp_peer_reap_pid(pid_t pid, int status);

struct nhrp_peer *nhrp_peer_alloc(struct nhrp_interface *iface);
struct nhrp_peer *nhrp_peer_dup(struct nhrp_peer *peer);
int nhrp_peer_free(struct nhrp_peer *peer);

void nhrp_peer_insert(struct nhrp_peer *peer);
void nhrp_peer_remove(struct nhrp_peer *peer);
void nhrp_peer_purge(struct nhrp_peer *peer);

void nhrp_peer_set_used(struct nhrp_interface *iface,
			struct nhrp_address *peer_address,
			int used);

int nhrp_peer_match(struct nhrp_peer *peer, struct nhrp_peer_selector *sel);

int nhrp_peer_foreach(nhrp_peer_enumerator e, void *ctx,
		      struct nhrp_peer_selector *sel);

struct nhrp_peer *nhrp_peer_route(struct nhrp_interface *iface,
				  struct nhrp_address *dest,
				  int flags,
				  struct nhrp_cie_list_head *exclude);

void nhrp_peer_traffic_indication(struct nhrp_interface *iface,
				  uint16_t afnum, struct nhrp_address *dst);
void nhrp_peer_dump_cache(void);

#endif
