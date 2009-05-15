/* nhrp_common.h - Generic helper functions
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

#ifndef NHRP_COMMON_H
#define NHRP_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <linux/if_ether.h>

struct nhrp_interface;
struct nhrp_address;

extern const char *nhrp_config_file, *nhrp_script_file;
extern int nhrp_running, nhrp_verbose;

/* Logging */
void nhrp_debug(const char *format, ...);
void nhrp_info(const char *format, ...);
void nhrp_error(const char *format, ...);
void nhrp_perror(const char *message);
void nhrp_hex_dump(const char *name, const uint8_t *buf, int bytes);

#define NHRP_BUG_ON(cond) if (cond) { \
	nhrp_error("BUG: failure at %s:%d/%s(): %s!", \
		__FILE__, __LINE__, __func__, #cond); \
	abort(); \
}

/* Initializers for system dependant stuff */
int forward_init(void);
int forward_local_addresses_changed(void);

int kernel_init(void);
int kernel_route(struct nhrp_interface *out_iface,
		 struct nhrp_address *dest,
		 struct nhrp_address *default_source,
		 struct nhrp_address *next_hop,
		 u_int16_t *mtu);
int kernel_send(uint8_t *packet, size_t bytes, struct nhrp_interface *out,
		struct nhrp_address *to);
int kernel_inject_neighbor(struct nhrp_address *neighbor,
			   struct nhrp_address *hwaddr,
			   struct nhrp_interface *dev);

int log_init(void);
int admin_init(const char *socket);
void server_init(void);

#endif
