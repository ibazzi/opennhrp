/* sysdep_poll.c - poll(2) compliant mainloop
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or later as
 * published by the Free Software Foundation.
 *
 * See http://www.gnu.org/ for details.
 */

#include <poll.h>
#include <time.h>
#include <unistd.h>

#include <ares.h>

#include "nhrp_defines.h"
#include "nhrp_common.h"

#define MAX_FDS 8

struct pollctx {
	int (*callback)(void *ctx, int fd, short events);
	void *ctx;
};

extern ares_channel nhrp_ares_resolver;

int nhrp_running = 0;
struct nhrp_task_list nhrp_all_tasks;

static int numfds = 0;
static struct pollfd gfds[MAX_FDS];
static struct pollctx gctx[MAX_FDS];

void nhrp_time_monotonic(struct timeval *tv)
{
#if defined(_POSIX_MONOTONIC_CLOCK) || defined(CLOCK_MONOTONIC)
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
#else
	gettimeofday(tv, NULL);
#endif
}

int nhrp_task_poll_fd(int fd, short events,
		      int (*callback)(void *ctx, int fd, short events),
		      void *ctx)
{
	int i;

	for (i = 0; i < numfds; i++) {
		if (gfds[i].fd == fd) {
			gctx[i].callback = callback;
			gctx[i].ctx = ctx;
			gfds[i].events = events;
			return TRUE;
		}
	}

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

static void nhrp_task_unpoll_index(int i)
{
	gfds[i] = gfds[numfds - 1];
	gctx[i] = gctx[numfds - 1];
	numfds--;
}

void nhrp_task_unpoll_fd(int fd)
{
	int i;

	for (i = 0; i < numfds; i++)
		if (gfds[i].fd == fd)
			break;

	if (i < numfds)
		nhrp_task_unpoll_index(i);
}

void nhrp_task_schedule(struct nhrp_task *task, int timeout,
			const struct nhrp_task_ops *ops)
{
	struct timeval now;

	nhrp_time_monotonic(&now);
	nhrp_task_schedule_relative(task, &now, timeout, ops);
}

void nhrp_task_schedule_relative(struct nhrp_task *task,
				 struct timeval *when,
				 int rel_ms,
				 const struct nhrp_task_ops *ops)
{
	struct nhrp_task *after = NULL, *next;
	struct timeval rel;

	nhrp_task_cancel(task);

	task->ops = ops;
	if (rel_ms < 0) {
		rel.tv_sec = (-rel_ms) / 1000;
		rel.tv_usec = (-rel_ms) % 1000;
		timersub(when, &rel, &task->execute_time);
	} else {
		rel.tv_sec = rel_ms / 1000;
		rel.tv_usec = rel_ms % 1000;
		timeradd(when, &rel, &task->execute_time);
	}

	for (next = LIST_FIRST(&nhrp_all_tasks);
	     next != NULL && timercmp(&task->execute_time, &next->execute_time, >);
	     next = LIST_NEXT(next, task_list))
		after = next;

	if (after != NULL)
		LIST_INSERT_AFTER(after, task, task_list);
	else
		LIST_INSERT_HEAD(&nhrp_all_tasks, task, task_list);
}

void nhrp_task_schedule_relative(struct nhrp_task *task, struct timeval *tv,
				 int rel_ms, const struct nhrp_task_ops *ops);


void nhrp_task_cancel(struct nhrp_task *task)
{
	if (task->ops != NULL) {
		LIST_REMOVE(task, task_list);
		task->ops = NULL;
	}
}

void nhrp_task_run(void)
{
	struct timeval now, ares, *t;
	struct nhrp_task *task;
	int i, timeout;

	nhrp_running = TRUE;
	do {
		if (numfds == 0 && LIST_EMPTY(&nhrp_all_tasks))
			break;

		/* execute pending tasks */
		nhrp_time_monotonic(&now);
		while (!LIST_EMPTY(&nhrp_all_tasks) &&
		       timercmp(&LIST_FIRST(&nhrp_all_tasks)->execute_time,
				&now, <)) {
			const struct nhrp_task_ops *ops;

			task = LIST_FIRST(&nhrp_all_tasks);
			ops = task->ops;

			nhrp_task_cancel(task);
			ops->callback(task);
		}

		/* figure out timeout from scheduled tasks and c-ares */
		if (!LIST_EMPTY(&nhrp_all_tasks)) {
			timersub(&LIST_FIRST(&nhrp_all_tasks)->execute_time,
				 &now, &now);
			t = &now;
		} else
			t = NULL;
		t = ares_timeout(nhrp_ares_resolver, t, &ares);

		/* convert timeout to milliseconds */
		if (t != NULL)
			timeout = (t->tv_sec * 1000) + (t->tv_usec / 1000);
		else
			timeout = -1;

		i = poll(gfds, numfds, timeout);

		/* process c-ares timeouts */
		if ((i == 0 || timeout == 0) && (t == &ares))
			ares_process(nhrp_ares_resolver, NULL, NULL);

		/* process file descriptors */
		for (i = 0; i < numfds; i++) {
			if (gfds[i].revents) {
				if (gctx[i].callback(gctx[i].ctx, gfds[i].fd,
						     gfds[i].revents))
					nhrp_task_unpoll_index(i);
			}
		}
	} while (nhrp_running);
}

void nhrp_task_stop(void)
{
	nhrp_running = FALSE;
}
