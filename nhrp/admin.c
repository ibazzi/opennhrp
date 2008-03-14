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
#include <malloc.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_address.h"
#include "nhrp_interface.h"

struct admin_remote {
	int			fd;
	struct nhrp_task	timeout;
};

static void admin_write(void *ctx, const char *format, ...)
{
	struct admin_remote *rmt = (struct admin_remote *) ctx;
	char msg[1024];
	va_list ap;
	size_t len;

	va_start(ap, format);
	len = vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);

	write(rmt->fd, msg, len);
}

static int admin_show_one_peer(void *ctx, struct nhrp_peer *peer)
{
	char buf[512], tmp[32];
	size_t len = sizeof(buf);
	int i = 0;

	i += snprintf(&buf[i], len - i,
		"Type: %s\n"
		"Protocol-Address: %s/%d\n",
		nhrp_peer_type[peer->type],
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
	i += snprintf(&buf[i], len - i, "Interface: %s\n",
		      peer->interface->name);

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
		i += snprintf(&buf[i], len - i, "Expires-At: %s",
			      ctime(&peer->expire_time));

	admin_write(ctx, "%s\n", buf);
	return 0;
}

static void admin_show(void *ctx, const char *cmd)
{
	nhrp_peer_foreach(admin_show_one_peer, ctx);
}

static int flush_all(void *ctx, struct nhrp_interface *iface)
{
	struct nhrp_peer *peer;
	int *count = (int *) ctx;

	while ((peer = nhrp_peer_find(iface, NULL, 0,
				      NHRP_PEER_FIND_SUBNET |
				      NHRP_PEER_FIND_REMOVABLE)) != NULL) {
		nhrp_peer_remove(peer);
		(*count)++;
	}

	return 0;
}

static void admin_flush(void *ctx, const char *cmd)
{
	int count = 0;

	nhrp_info("Admin: flushing entries");
	nhrp_interface_foreach(flush_all, &count);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

struct purge_ctx {
	struct nhrp_address address;
	uint8_t prefix_length;
	int count;
};

static int purge_protocol(void *ctx, struct nhrp_interface *iface)
{
	struct nhrp_peer *peer;
	struct purge_ctx *pp = (struct purge_ctx *) ctx;

	while ((peer = nhrp_peer_find(iface,
				      &pp->address,
				      pp->prefix_length,
				      NHRP_PEER_FIND_EXACT |
				      NHRP_PEER_FIND_REMOVABLE)) != NULL) {
		nhrp_peer_remove(peer);
		pp->count++;
	}

	return 0;
}

static void admin_purge_protocol(void *ctx, const char *cmd)
{
	struct purge_ctx pp;
	char tmp[64];

	pp.count = 0;
	if (!nhrp_address_parse(cmd, &pp.address, &pp.prefix_length)) {
		admin_write(ctx,
			    "Status: failed\n"
			    "Reason: bad-address-format\n");
		return;
	}

	nhrp_info("Admin: purge protocol address %s/%d",
		  nhrp_address_format(&pp.address, sizeof(tmp), tmp),
		  pp.prefix_length);

	nhrp_interface_foreach(purge_protocol, &pp);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    pp.count);
}

static int purge_nbma(void *ctx, struct nhrp_interface *iface)
{
	struct nhrp_peer *peer;
	struct purge_ctx *pp = (struct purge_ctx *) ctx;

	while ((peer = nhrp_peer_find_nbma(iface,
					   &pp->address,
					   NHRP_PEER_FIND_PURGEABLE)) != NULL) {
		nhrp_peer_purge(peer);
		pp->count++;
	}

	return 0;
}

static void admin_purge_nbma(void *ctx, const char *cmd)
{
	char tmp[64];
	struct purge_ctx pp;

	pp.count = 0;
	if (!nhrp_address_parse(cmd, &pp.address, NULL)) {
		admin_write(ctx,
			    "Status: failed\n"
			    "Reason: bad-address-format\n");
		return;
	}

	nhrp_info("Admin: purge nbma address %s",
		  nhrp_address_format(&pp.address, sizeof(tmp), tmp));

	nhrp_interface_foreach(purge_nbma, &pp);

        admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Purged: %d\n",
		    pp.count);
}

static struct {
	const char *command;
	void (*handler)(void *ctx, const char *cmd);
} admin_handler[] = {
	{ "show",		admin_show },
	{ "flush",		admin_flush },
	{ "purge protocol",	admin_purge_protocol },
	{ "purge nbma",		admin_purge_nbma },
};

static int admin_receive(void *ctx, int fd, short events)
{
	struct admin_remote *rm = (struct admin_remote *) ctx;
	char buf[1024];
	ssize_t len;
	int i, cmdlen;

	len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (len < 0 && errno == EAGAIN)
		return 0;
	if (len <= 0)
		goto err;

	for (i = 0; i < ARRAY_SIZE(admin_handler); i++) {
		cmdlen = strlen(admin_handler[i].command);
		if (len >= cmdlen &&
		    strncasecmp(buf, admin_handler[i].command, cmdlen) == 0) {
			admin_handler[i].handler(ctx, &buf[cmdlen]);
			break;
		}
	}
	if (i >= ARRAY_SIZE(admin_handler)) {
		admin_write(ctx,
			    "Status: failed\n"
			    "Reason: unrecognized command\n");
	}

err:
	nhrp_task_cancel(&rm->timeout);
	shutdown(fd, SHUT_RDWR);
	close(fd);
	free(rm);

	return -1;
}

static void admin_timeout(struct nhrp_task *task)
{
	struct admin_remote *rm = container_of(task, struct admin_remote, timeout);

	nhrp_task_unpoll_fd(rm->fd);
	close(rm->fd);
	free(rm);
}

static int admin_accept(void *ctx, int fd, short events)
{
	struct admin_remote *rm;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	int cnx;

	cnx = accept(fd, (struct sockaddr *) &from, &fromlen);
	if (cnx < 0)
		return 0;

	rm = calloc(1, sizeof(struct admin_remote));
	rm->fd = cnx;

	if (!nhrp_task_poll_fd(cnx, POLLIN, admin_receive, rm))
		close(cnx);

	nhrp_task_schedule(&rm->timeout, 10000, admin_timeout);

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
