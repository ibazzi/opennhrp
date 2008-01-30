/* admin.c - OpenNHRP administrative interface implementation
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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"

static void admin_write(void *fd, const char *format, ...)
{
	char msg[1024];
	va_list ap;
	size_t len;

	va_start(ap, format);
	len = vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);

	write((int) fd, msg, len);
}

static int admin_show_one_peer(void *ctx, struct nhrp_peer *peer)
{
	char buf[512], tmp[32];
	size_t len = sizeof(buf);
	int i = 0;

	i += snprintf(&buf[i], len - i, "Protocol-Address: %s/%d\n",
		nhrp_address_format(&peer->protocol_address, sizeof(tmp), tmp),
		peer->prefix_length);

	if (peer->next_hop_address.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, "%s: %s\n",
			peer->type == NHRP_PEER_TYPE_CACHED_ROUTE ?
			"Next-hop-Address" : "NBMA-Address",
			nhrp_address_format(&peer->next_hop_address, sizeof(tmp), tmp));
	}
	if (peer->next_hop_nat_oa.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, "NBMA-NAT-OA-Address: %s\n",
			nhrp_address_format(&peer->next_hop_nat_oa, sizeof(tmp), tmp));
	}
	if (peer->interface != NULL) {
		i += snprintf(&buf[i], len - i, "Interface: %s\n",
			      peer->interface->name);
	}
	if (peer->flags & (NHRP_PEER_FLAG_USED | NHRP_PEER_FLAG_UNIQUE |
			   NHRP_PEER_FLAG_UP)) {
		i += snprintf(&buf[i], len - i, "Flags:");
		if (peer->flags & NHRP_PEER_FLAG_USED)
			i += snprintf(&buf[i], len - i, " used");
		if (peer->flags & NHRP_PEER_FLAG_UNIQUE)
			i += snprintf(&buf[i], len - i, " unique");
		if (peer->flags & NHRP_PEER_FLAG_UP)
			i += snprintf(&buf[i], len - i, " up");
		i += snprintf(&buf[i], len - i, "\n");
	}
	if (peer->expire_time)
		i += snprintf(&buf[i], len - i, "Expires-At: %s\n",
			      ctime(&peer->expire_time));

	admin_write(ctx, "%s\n", buf);
	return 0;
}

static void admin_show(int fd, const char *cmd)
{
	nhrp_peer_enumerate(admin_show_one_peer, (void *) fd);
}

static struct {
	const char *command;
	void (*handler)(int fd, const char *cmd);
} admin_handler[] = {
	{ "show", admin_show },
};

static int admin_receive(void *ctx, int fd, short events)
{
	char buf[1024];
	size_t len;
	int i;

	len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (len < 0)
		goto err;

	for (i = 0; i < ARRAY_SIZE(admin_handler); i++) {
		if (strncasecmp(buf, admin_handler[i].command,
				strlen(admin_handler[i].command)) == 0) {
			admin_handler[i].handler(fd, buf);
		}
	}

err:
	close(fd);
	return -1;
}

static int admin_accept(void *ctx, int fd, short events)
{
	struct sockaddr_storage from;
	size_t fromlen = sizeof(from);
	int cnx;

	cnx = accept(fd, (struct sockaddr *) &from, &fromlen);
	if (cnx < 0)
		return 0;

	if (!nhrp_task_poll_fd(cnx, POLLIN, admin_receive, NULL))
		close(cnx);

	return 0;
}

int admin_init(const char *opennhrp_socket)
{
	struct sockaddr_un sun;
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, opennhrp_socket, sizeof(sun.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return 0;

	unlink(opennhrp_socket);
	if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) != 0)
		goto err_close;

	if (listen(fd, 5) != 0)
		goto err_close;

	if (!nhrp_task_poll_fd(fd, POLLIN, admin_accept, NULL))
		goto err_close;

	return 1;

err_close:
	nhrp_error("Failed initialize admin socket [%s]: %s",
		   opennhrp_socket, strerror(errno));
	close(fd);
	return 0;
}
