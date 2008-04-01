/* nhrp_interface.c - NHRP configuration per interface
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <stddef.h>
#include <string.h>
#include <malloc.h>
#include "nhrp_interface.h"

#define INDEX_HASH_SIZE (1 << 4)

LIST_HEAD(nhrp_interface_list, nhrp_interface);

static struct nhrp_interface_list name_list;
static struct nhrp_interface_list index_hash[INDEX_HASH_SIZE];

void nhrp_interface_hash(struct nhrp_interface *iface)
{
	int iidx = iface->index & (INDEX_HASH_SIZE - 1);

	LIST_REMOVE(iface, name_list);
	LIST_REMOVE(iface, index_list);

	LIST_INSERT_HEAD(&name_list, iface, name_list);
	LIST_INSERT_HEAD(&index_hash[iidx], iface, index_list);
}

int nhrp_interface_foreach(nhrp_interface_enumerator enumerator, void *ctx)
{
	struct nhrp_interface *iface;
	int rc;

	LIST_FOREACH(iface, &name_list, name_list) {
		rc = enumerator(ctx, iface);
		if (rc != 0)
			return rc;
	}
	return 0;
}

struct nhrp_interface *nhrp_interface_get_by_name(const char *name, int create)
{
	struct nhrp_interface *iface;

	LIST_FOREACH(iface, &name_list, name_list) {
		if (strcmp(iface->name, name) == 0)
			return iface;
	}

	if (!create)
		return NULL;

	iface = calloc(1, sizeof(struct nhrp_interface));
	strncpy(iface->name, name, sizeof(iface->name));
	CIRCLEQ_INIT(&iface->peer_cache);

	LIST_INSERT_HEAD(&name_list, iface, name_list);
	LIST_INSERT_HEAD(&index_hash[0], iface, index_list);

	return iface;
}

struct nhrp_interface *nhrp_interface_get_by_index(unsigned int index, int create)
{
	struct nhrp_interface *iface;
	int iidx = index & (INDEX_HASH_SIZE - 1);

	LIST_FOREACH(iface, &index_hash[iidx], index_list) {
		if (iface->index == index)
			return iface;
	}

	return NULL;
}

struct nhrp_interface *nhrp_interface_get_by_nbma(struct nhrp_address *addr)
{
	struct nhrp_interface *iface;

	LIST_FOREACH(iface, &name_list, name_list) {
		if (nhrp_address_cmp(addr, &iface->nbma_address) == 0)
			return iface;

		if (iface->link_index == -1 &&
		    iface->nbma_address.type == PF_UNKNOWN)
			return iface;
	}

	return NULL;
}

struct nhrp_interface *nhrp_interface_get_by_protocol(struct nhrp_address *addr)
{
	struct nhrp_interface *iface;

	LIST_FOREACH(iface, &name_list, name_list) {
		if (nhrp_address_cmp(addr, &iface->protocol_address) == 0)
			return iface;
	}

	return NULL;
}
