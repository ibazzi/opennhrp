/* sysdep_poll.c - poll(2) compliant mainloop
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <poll.h>
#include "nhrp_defines.h"
#include "nhrp_common.h"

#define MAX_FDS 8

LIST_HEAD(nhrp_task_list, nhrp_task);

struct pollctx {
	void (*callback)(void *ctx, short events);
	void *ctx;
};

static int numfds = 0;
static struct pollfd gfds[MAX_FDS];
static struct pollctx gctx[MAX_FDS];
static struct nhrp_task_list tasks;

int nhrp_task_poll_fd(int fd, short events, void (*callback)(void *ctx, short events),
		      void *ctx)
{
	if (numfds >= MAX_FDS) {
		nhrp_error("Poll table full. Increase MAX_FDS in sysdep_poll.c.");
		return FALSE;
	}

	gctx[numfds].callback = callback;
	gctx[numfds].ctx = ctx;
	gfds[numfds].fd = fd;
	gfds[numfds].events = events;
	numfds++;

	return TRUE;
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

void nhrp_task_schedule(struct nhrp_task *task, int timeout, void (*callback)(struct nhrp_task *task))
{
	struct nhrp_task *after = NULL, *next;

	gettimeofday(&task->execute_time, NULL);
	task->callback = callback;
	task->execute_time.tv_usec += (timeout % 1000) * 1000;
	task->execute_time.tv_sec += timeout / 1000 +
		(task->execute_time.tv_usec / 1000000);
	task->execute_time.tv_usec %= 1000000;

	for (next = LIST_FIRST(&tasks);
	     next != NULL && timercmp(&task->execute_time, &next->execute_time, >);
	     next = LIST_NEXT(next, task_list))
		after = next;

	if (after != NULL)
		LIST_INSERT_AFTER(after, task, task_list);
	else
		LIST_INSERT_HEAD(&tasks, task, task_list);
}

void nhrp_task_cancel(struct nhrp_task *task)
{
	LIST_REMOVE(task, task_list);
}

void nhrp_task_run(void)
{
	struct timeval now;
	struct nhrp_task *task;
	int i, timeout;

	do {
		if (numfds == 0 && LIST_EMPTY(&tasks))
			break;

		gettimeofday(&now, NULL);
		while (!LIST_EMPTY(&tasks) && timercmp(&LIST_FIRST(&tasks)->execute_time, &now, <=)) {
			task = LIST_FIRST(&tasks);

			LIST_REMOVE(task, task_list);
			task->callback(task);
		}

		if (!LIST_EMPTY(&tasks)) {
			task = LIST_FIRST(&tasks);

			timeout = task->execute_time.tv_sec - now.tv_sec;
			timeout *= 1000;
			timeout += (task->execute_time.tv_usec - now.tv_usec) / 1000;
		} else {
			timeout = -1;
		}

		poll(gfds, numfds, timeout);

		for (i = 0; i < numfds; i++) {
			if (gfds[i].revents)
				gctx[i].callback(gctx[i].ctx, gfds[i].revents);
		}
	} while (1);
}
