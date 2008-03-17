/* admin.c - OpenNHRP administrative interface implementation
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
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

	int                     num_read;
	char                    cmd[512];
};

static int parse_word(const char **bufptr, size_t len, char *word)
{
	const char *buf = *bufptr;
	int i, pos = 0;

	while (isspace(buf[pos]) && buf[pos] != '\n' && buf[pos])
		pos++;

	if (buf[pos] == '\n' || buf[pos] == 0)
		return FALSE;

	for (i = 0; i < len-1 && !isspace(buf[pos+i]); i++)
		word[i] = buf[pos+i];
	word[i] = 0;

	*bufptr += i + pos;
	return TRUE;
}


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

struct selector_action_ctx {
	void *ctx;
	struct nhrp_peer_selector sel;
	int (*action)(void *ctx, struct nhrp_peer *peer);
	int count;
};

static int admin_show_peer(void *ctx, struct nhrp_peer *peer)
{
	struct selector_action_ctx *sa = (struct selector_action_ctx *) ctx;
	char buf[512], tmp[32];
	size_t len = sizeof(buf);
	int i = 0;

	i += snprintf(&buf[i], len - i,
		"Interface: %s\n"
		"Type: %s\n"
		"Protocol-Address: %s/%d\n",
		peer->interface->name,
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

	admin_write(sa->ctx, "%s\n", buf);
	return 0;
}

static int admin_purge_peer(void *ctx, struct nhrp_peer *peer)
{
	struct selector_action_ctx *sa = (struct selector_action_ctx *) ctx;
	nhrp_peer_purge(peer);
	sa->count++;
	return 0;
}

static int admin_remove_peer(void *ctx, struct nhrp_peer *peer)
{
	struct selector_action_ctx *sa = (struct selector_action_ctx *) ctx;
	nhrp_peer_remove(peer);
	sa->count++;
	return 0;
}

static void admin_selector_action(struct selector_action_ctx *sa,
				  const char *cmd)
{
	char keyword[64], tmp[64];
	struct nhrp_address address;
	uint8_t prefix_length;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(tmp), tmp)) {
			admin_write(sa->ctx,
				    "Status: failed\n"
				    "Reason: missing-argument\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return;
		}

		if (strcmp(keyword, "interface") == 0 ||
		    strcmp(keyword, "iface") == 0 ||
		    strcmp(keyword, "dev") == 0) {
			if (sa->sel.iface != NULL)
				goto err_conflict;
			sa->sel.iface = nhrp_interface_get_by_name(tmp, FALSE);
			if (sa->sel.iface == NULL)
				goto err_noiface;
			continue;
		}

		if (!nhrp_address_parse(tmp, &address, &prefix_length)) {
			admin_write(sa->ctx,
				    "Status: failed\n"
				    "Reason: invalid-address\n"
				    "Near-Keyword: '%s'\n",
				   keyword);
			return;
		}

		if (strcmp(keyword, "protocol") == 0) {
			sa->sel.protocol_address = address;
			sa->sel.prefix_length = prefix_length;
		} else if (strcmp(keyword, "nbma") == 0) {
			sa->sel.nbma_address = address;
		} else if (strcmp(keyword, "local-protocol") == 0) {
			if (sa->sel.iface != NULL)
				goto err_conflict;
			sa->sel.iface = nhrp_interface_get_by_protocol(&address);
			if (sa->sel.iface == NULL)
				goto err_noiface;
		} else if (strcmp(keyword, "local-nbma") == 0) {
			if (sa->sel.iface != NULL)
				goto err_conflict;
			sa->sel.iface = nhrp_interface_get_by_nbma(&address);
			if (sa->sel.iface == NULL)
				goto err_noiface;
		} else {
			admin_write(sa->ctx,
				    "Status: failed\n"
				    "Reason: syntax-error\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return;
		}
	}
	nhrp_peer_foreach(sa->action, sa, &sa->sel);

	admin_write(sa->ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    sa->count);
	return;

err_conflict:
	admin_write(sa->ctx,
		    "Status: failed\n"
		    "Reason: conflicting-keyword\n"
		    "Near-Keyword: '%s'\n",
		    keyword);
	return;
err_noiface:
	admin_write(sa->ctx,
		    "Status: failed\n"
		    "Reason: interface-not-found\n"
		    "Near-Keyword: '%s'\n"
		    "Argument: '%s'\n",
		    keyword, tmp);
	return;
}

static void admin_show(void *ctx, const char *cmd)
{
	struct selector_action_ctx sa;

	memset(&sa, 0, sizeof(sa));
	sa.ctx = ctx;
	sa.action = admin_show_peer;

	admin_selector_action(&sa, cmd);
}

static void admin_purge(void *ctx, const char *cmd)
{
	struct selector_action_ctx sa;

	memset(&sa, 0, sizeof(sa));
	sa.ctx = ctx;
	sa.sel.flags = NHRP_PEER_FIND_PURGEABLE;
	sa.action = admin_purge_peer;

	admin_selector_action(&sa, cmd);
}

static void admin_flush(void *ctx, const char *cmd)
{
	struct selector_action_ctx sa;

	memset(&sa, 0, sizeof(sa));
	sa.ctx = ctx;
	sa.sel.flags = NHRP_PEER_FIND_REMOVABLE;
	sa.action = admin_remove_peer;

	admin_selector_action(&sa, cmd);
}

static struct {
	const char *command;
	void (*handler)(void *ctx, const char *cmd);
} admin_handler[] = {
	{ "show",		admin_show },
	{ "flush",		admin_flush },
	{ "purge",		admin_purge },
};

static int admin_receive(void *ctx, int fd, short events)
{
	struct admin_remote *rm = (struct admin_remote *) ctx;
	ssize_t len;
	int i, cmdlen;

	len = recv(fd, rm->cmd, sizeof(rm->cmd) - rm->num_read, MSG_DONTWAIT);
	if (len < 0 && errno == EAGAIN)
		return 0;
	if (len <= 0)
		goto err;

	rm->num_read += len;
	if (rm->num_read >= sizeof(rm->cmd))
		goto err;

	if (rm->cmd[rm->num_read-1] != '\n')
		return 0;

	for (i = 0; i < ARRAY_SIZE(admin_handler); i++) {
		cmdlen = strlen(admin_handler[i].command);
		if (rm->num_read >= cmdlen &&
		    strncasecmp(rm->cmd, admin_handler[i].command, cmdlen) == 0) {
			admin_handler[i].handler(ctx, &rm->cmd[cmdlen]);
			break;
		}
	}
	if (i >= ARRAY_SIZE(admin_handler)) {
		admin_write(ctx,
			    "Status: error\n"
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
	shutdown(rm->fd, SHUT_RDWR);
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
	fcntl(cnx, F_SETFD, FD_CLOEXEC);

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

	fcntl(fd, F_SETFD, FD_CLOEXEC);
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
