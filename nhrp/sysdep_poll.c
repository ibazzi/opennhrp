/* sysdep_poll.c - poll(2) compliant mainloop
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include "nhrp_common.h"

#define MAX_FDS 8

struct pollctx {
	void (*callback)(void *ctx, short events);
	void *ctx;
};

static int numfds = 0;
static struct pollfd gfds[MAX_FDS];
static struct pollctx gctx[MAX_FDS];

int nhrp_task_poll_fd(int fd, short events, void (*callback)(void *ctx, short events),
		      void *ctx)
{
	if (numfds >= MAX_FDS) {
		nhrp_error("Poll table full. Increase MAX_FDS in sysdep_poll.c.");
		return 0;
	}

	gctx[numfds].callback = callback;
	gctx[numfds].ctx = ctx;
	gfds[numfds].fd = fd;
	gfds[numfds].events = events;
	numfds++;

	return 1;
}

void nhrp_task_unpoll_fd(int fd)
{
	int i;

	for (i = 0; i < numfds; i++)
		if (gfds[i].fd == fd)
			break;
	if (i >= numfds)
		return;

	gfds[i] = gfds[numfds - 1];
	gctx[i] = gctx[numfds - 1];
	numfds--;
}

void nhrp_task_run(void)
{
	int i;

	do {
		if (numfds == 0)
			break;

		poll(gfds, numfds, -1);

		for (i = 0; i < numfds; i++) {
			if (gfds[i].revents)
				gctx[i].callback(gctx[i].ctx, gfds[i].revents);
		}
	} while (1);
}
