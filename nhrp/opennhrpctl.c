/* opennhrpctl.c - OpenNHRP command line control utility
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

static int admin_init(const char *opennhrp_socket)
{
	struct sockaddr_un sun;
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, opennhrp_socket, sizeof(sun.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static void admin_close(int fd)
{
	close(fd);
}

static int admin_send(int fd, const char *str)
{
	write(fd, str, strlen(str));
	return 0;
}

static int admin_receive(int fd)
{
	char msg[512];
	size_t len;

	while ((len = recv(fd, msg, sizeof(msg), MSG_DONTWAIT)) > 0)
		write(fileno(stdout), msg, len);

	return 0;
}

static int usage(const char *prog)
{
	fprintf(stderr, "usage: %s [-a admin-socket] <command>\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	const char *socket = OPENNHRP_ADMIN_SOCKET;
	char cmd[1024] = "", *pos = cmd;
	int i, fd;

	for (i = 1; i < argc; i++) {
		if (strlen(argv[i]) != 2 || argv[i][0] != '-') {
			pos += snprintf(pos, &cmd[sizeof(cmd)-1]-pos,
					" %s", argv[i]);
			continue;
		}

		switch (argv[i][1]) {
		case 's':
			if (++i >= argc)
				return usage(argv[0]);
			socket = argv[i];
			break;
		default:
			return usage(argv[0]);
		}
	}
	if (cmd == pos)
		usage(argv[0]);

	fd = admin_init(socket);
	if (fd < 0) {
		fprintf(stderr,
			"Failed to connect to opennhrp daemon [%s]: %s.\n\n",
			socket, strerror(errno));
		return 1;
	}

	if (admin_send(fd, &cmd[1]) < 0 ||
	    admin_receive(fd) < 0) {
		fprintf(stderr, "Failed to send request: %s.\n",
			strerror(errno));
		return 2;
	}

	admin_close(fd);
	return 0;
}