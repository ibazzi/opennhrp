/* nhrp_task.h - File descriptor polling and task scheduling
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#ifndef NHRP_COMMON_H
#define NHRP_COMMON_H

#include <stdint.h>
#include <poll.h>
#include <sys/time.h>
#include <linux/if_ether.h>

#include "nhrp_packet.h"
#include "nhrp_interface.h"

/* Mainloop and timed tasks */
struct nhrp_task {
	LIST_ENTRY(nhrp_task) task_list;
	struct timeval execute_time;
	void (*callback)(struct nhrp_task *task);
};

int nhrp_task_poll_fd(int fd, short events, void (*callback)(void *ctx, short events),
		      void *ctx);
void nhrp_task_unpoll_fd(int fd);
void nhrp_task_run(void);
void nhrp_task_schedule(struct nhrp_task *task, int timeout, void (*callback)(struct nhrp_task *task));

/* Logging */
void nhrp_info(const char *format, ...);
void nhrp_error(const char *format, ...);
void nhrp_perror(const char *message);
void nhrp_hex_dump(const char *name, const uint8_t *buf, int bytes);

/* Initializers for system dependant stuff */
int kernel_init(void);
int kernel_route(struct nhrp_packet *p, struct nhrp_interface **iface,
		 struct nhrp_nbma_address *next_hop_nbma);
int kernel_send(uint8_t *packet, size_t bytes, struct nhrp_interface *out,
		struct nhrp_nbma_address *to);

int log_init(void);

#endif
