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
	struct nhrp_buffer *cisco_authentication;

	/* Cached from kernel interface */
	unsigned int index;
	struct nhrp_nbma_address nbma_address;
};

void nhrp_interface_hash(struct nhrp_interface *iface);
struct nhrp_interface *nhrp_interface_get_by_name(const char *name, int create);
struct nhrp_interface *nhrp_interface_get_by_index(unsigned int index, int create);

#endif
