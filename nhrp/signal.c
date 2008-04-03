/* signal.c - Signal handling for NHRP daemon
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"

static int signal_pipe[2];

static void signal_handler(int sig)
{
	send(signal_pipe[1], &sig, sizeof(sig), MSG_DONTWAIT);
}

static int reap_children(void *ctx, int fd, short events)
{
	struct nhrp_peer_selector sel;
	pid_t pid;
	int status, sig;

	if (read(fd, &sig, sizeof(sig)) != sizeof(sig))
		return 0;

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
	case SIGHUP:
		memset(&sel, 0, sizeof(sel));
		sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
		nhrp_peer_foreach(nhrp_peer_remove_matching, NULL, &sel);
		break;
	}
	return 0;
}

int signal_init(void)
{
	socketpair(AF_UNIX, SOCK_STREAM, 0, signal_pipe);

	signal(SIGCHLD, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	return nhrp_task_poll_fd(signal_pipe[0], POLLIN, reap_children, NULL);
}
