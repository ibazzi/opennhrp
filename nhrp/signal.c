/* signal.c - Signal handling for NHRP daemon
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include "nhrp_common.h"
#include "nhrp_peer.h"

static int signal_pipe[2];

static void signal_handler(int sig)
{
	send(signal_pipe[1], &sig, sizeof(sig), MSG_DONTWAIT);
}

static void reap_children(void *ctx, int fd, short events)
{
	pid_t pid;
	int status, sig;

	if (read(fd, &sig, sizeof(sig)) != sizeof(sig))
		return;

	switch (sig) {
	case SIGCHLD:
		while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
			nhrp_peer_reap_pid(pid, status);
		}
		break;
	case SIGUSR1:
		nhrp_peer_dump_cache();
		break;
	case SIGINT:
	case SIGTERM:
		nhrp_task_stop();
		break;
	}
}

int signal_init(void)
{
	socketpair(AF_UNIX, SOCK_STREAM, 0, signal_pipe);

	signal(SIGCHLD, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	return nhrp_task_poll_fd(signal_pipe[0], POLLIN, reap_children, NULL);
}
