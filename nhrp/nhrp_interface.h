/* nhrp_interface.h - NHRP configuration per interface definitions
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#ifndef NHRP_INTERFACE_H
#define NHRP_INTERFACE_H

#include <sys/queue.h>
#include "nhrp_packet.h"
#include "nhrp_peer.h"

#define NHRP_INTERFACE_FLAG_NON_CACHING		0x0001	/* Do not cache entries */
#define NHRP_INTERFACE_FLAG_SHORTCUT		0x0002	/* Create shortcut routes */
#define NHRP_INTERFACE_FLAG_REDIRECT		0x0004	/* Send redirects */
#define NHRP_INTERFACE_FLAG_SHORTCUT_DEST	0x0008	/* Advertise routes */

struct nhrp_interface {
	LIST_ENTRY(nhrp_interface) name_list;
	LIST_ENTRY(nhrp_interface) index_list;

	/* Configured information */
	char name[16];
	unsigned int flags;
	struct nhrp_buffer *auth_token;

	/* Cached from kernel interface */
	unsigned int index;
	uint16_t afnum;
	struct nhrp_address nbma_address;
	struct nhrp_cie nat_cie;

	/* Actually, we should have list of protocol addresses;
	 * we might have multiple address and multiple protocol types */
	struct nhrp_address protocol_address;

        /* Peer cache is interface specific */
	struct nhrp_peer_list peer_cache;
};

typedef int (*nhrp_interface_enumerator)(void *ctx, struct nhrp_interface *iface);

void nhrp_interface_hash(struct nhrp_interface *iface);
int nhrp_interface_foreach(nhrp_interface_enumerator enumerator, void *ctx);
struct nhrp_interface *nhrp_interface_get_by_name(const char *name, int create);
struct nhrp_interface *nhrp_interface_get_by_index(unsigned int index, int create);
struct nhrp_interface *nhrp_interface_get_by_nbma(struct nhrp_address *addr);
struct nhrp_interface *nhrp_interface_get_by_protocol(struct nhrp_address *addr);

#endif
