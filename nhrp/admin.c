/* admin.c - OpenNHRP administrative interface implementation
 *
 * Copyright (C) 2007-2009 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or later as
 * published by the Free Software Foundation.
 *
 * See http://www.gnu.org/ for details.
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

static struct ev_io accept_io;

struct admin_remote {
	struct ev_timer timeout;
	struct ev_io io;
	int num_read;
	char cmd[512];
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

	if (write(rmt->io.fd, msg, len) != len) {
	}
}

static void admin_free_remote(struct admin_remote *rm)
{
	int fd = rm->io.fd;

	ev_io_stop(&rm->io);
	ev_timer_stop(&rm->timeout);
	shutdown(fd, SHUT_RDWR);
	close(fd);
	free(rm);
}

static int admin_show_peer(void *ctx, struct nhrp_peer *peer)
{
	char buf[512], tmp[32];
	size_t len = sizeof(buf);
	int i = 0, rel;

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
			peer->type == NHRP_PEER_TYPE_CACHED_ROUTE ? "Next-hop-Address" :
			peer->type == NHRP_PEER_TYPE_LOCAL ? "Alias-Address" :
			"NBMA-Address",
			nhrp_address_format(&peer->next_hop_address,
					    sizeof(tmp), tmp));
	}
	if (peer->nbma_hostname) {
		i += snprintf(&buf[i], len - i, "Hostname: %s\n",
			      peer->nbma_hostname);
	}
	if (peer->next_hop_nat_oa.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, "NBMA-NAT-OA-Address: %s\n",
			nhrp_address_format(&peer->next_hop_nat_oa,
					    sizeof(tmp), tmp));
	}
	if (peer->flags & (NHRP_PEER_FLAG_USED | NHRP_PEER_FLAG_UNIQUE |
			   NHRP_PEER_FLAG_UP | NHRP_PEER_FLAG_LOWER_UP)) {
		i += snprintf(&buf[i], len - i, "Flags:");
		if (peer->flags & NHRP_PEER_FLAG_UNIQUE)
			i += snprintf(&buf[i], len - i, " unique");

		if (peer->flags & NHRP_PEER_FLAG_USED)
			i += snprintf(&buf[i], len - i, " used");
		if (peer->flags & NHRP_PEER_FLAG_UP)
			i += snprintf(&buf[i], len - i, " up");
		else if (peer->flags & NHRP_PEER_FLAG_LOWER_UP)
			i += snprintf(&buf[i], len - i, " lower-up");
		i += snprintf(&buf[i], len - i, "\n");
	}
	if (peer->expire_time) {
		rel = (int) (peer->expire_time - ev_now());
		if (rel >= 0) {
			i += snprintf(&buf[i], len - i, "Expires-In: %d:%02d\n",
				      rel / 60, rel % 60);
		}
	}

	admin_write(ctx, "%s\n", buf);
	return 0;
}

static int admin_parse_selector(void *ctx, const char *cmd,
				struct nhrp_peer_selector *sel)
{
	char keyword[64], tmp[64];
	struct nhrp_address address;
	uint8_t prefix_length;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(tmp), tmp)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: missing-argument\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return FALSE;
		}

		if (strcmp(keyword, "interface") == 0 ||
		    strcmp(keyword, "iface") == 0 ||
		    strcmp(keyword, "dev") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->interface = nhrp_interface_get_by_name(tmp, FALSE);
			if (sel->interface == NULL)
				goto err_noiface;
			continue;
		}

		if (!nhrp_address_parse(tmp, &address, &prefix_length)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: invalid-address\n"
				    "Near-Keyword: '%s'\n",
				   keyword);
			return FALSE;
		}

		if (strcmp(keyword, "protocol") == 0) {
			if (sel->protocol_address.type != AF_UNSPEC)
				goto err_conflict;
			sel->protocol_address = address;
			sel->prefix_length = prefix_length;
		} else if (strcmp(keyword, "nbma") == 0) {
			if (sel->next_hop_address.type != AF_UNSPEC)
				goto err_conflict;
			sel->type_mask &= ~BIT(NHRP_PEER_TYPE_CACHED_ROUTE);
			sel->next_hop_address = address;
		} else if (strcmp(keyword, "local-protocol") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->interface = nhrp_interface_get_by_protocol(&address);
			if (sel->interface == NULL)
				goto err_noiface;
		} else if (strcmp(keyword, "local-nbma") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->interface = nhrp_interface_get_by_nbma(&address);
			if (sel->interface == NULL)
				goto err_noiface;
		} else {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: syntax-error\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return FALSE;
		}
	}
	return TRUE;

err_conflict:
	admin_write(ctx,
		    "Status: failed\n"
		    "Reason: conflicting-keyword\n"
		    "Near-Keyword: '%s'\n",
		    keyword);
	return FALSE;
err_noiface:
	admin_write(ctx,
		    "Status: failed\n"
		    "Reason: interface-not-found\n"
		    "Near-Keyword: '%s'\n"
		    "Argument: '%s'\n",
		    keyword, tmp);
	return FALSE;
}

static void admin_cache_show(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_ALL;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	admin_write(ctx, "Status: ok\n\n");
	nhrp_peer_foreach(admin_show_peer, ctx, &sel);
}

static void admin_cache_purge(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_PURGEABLE;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_purge_matching, &count, &sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static void admin_cache_flush(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_remove_matching, &count, &sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static void admin_redirect_purge(void *ctx, const char *cmd)
{
	char keyword[64];
	struct nhrp_address addr;
	uint8_t prefix;
	int count;

	nhrp_address_set_type(&addr, PF_UNSPEC);

	if (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!nhrp_address_parse(keyword, &addr, &prefix)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: invalid-address\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return;
		}
	}

	count = nhrp_rate_limit_clear(&addr, prefix);
	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static struct {
	const char *command;
	void (*handler)(void *ctx, const char *cmd);
} admin_handler[] = {
	{ "show",		admin_cache_show },
	{ "cache show",		admin_cache_show },
	{ "flush",		admin_cache_flush },
	{ "cache flush",	admin_cache_flush },
	{ "purge",		admin_cache_purge },
	{ "cache purge",	admin_cache_purge },
	{ "redirect purge",	admin_redirect_purge },
};

static void admin_receive_cb(struct ev_io *w, int revents)
{
	struct admin_remote *rm = container_of(w, struct admin_remote, io);
	int fd = rm->io.fd;
	ssize_t len;
	int i, cmdlen;

	len = recv(fd, rm->cmd, sizeof(rm->cmd) - rm->num_read, MSG_DONTWAIT);
	if (len < 0 && errno == EAGAIN)
		return;
	if (len <= 0)
		goto err;

	rm->num_read += len;
	if (rm->num_read >= sizeof(rm->cmd))
		goto err;

	if (rm->cmd[rm->num_read-1] != '\n')
		return;
	rm->cmd[--rm->num_read] = 0;

	for (i = 0; i < ARRAY_SIZE(admin_handler); i++) {
		cmdlen = strlen(admin_handler[i].command);
		if (rm->num_read >= cmdlen &&
		    strncasecmp(rm->cmd, admin_handler[i].command, cmdlen) == 0) {
			nhrp_debug("Admin: %s", rm->cmd);
			admin_handler[i].handler(rm, &rm->cmd[cmdlen]);
			break;
		}
	}
	if (i >= ARRAY_SIZE(admin_handler)) {
		admin_write(rm,
			    "Status: error\n"
			    "Reason: unrecognized command\n");
	}

err:
	admin_free_remote(rm);
}

static void admin_timeout_cb(struct ev_timer *t, int revents)
{
	admin_free_remote(container_of(t, struct admin_remote, timeout));
}

static void admin_accept_cb(ev_io *w, int revents)
{
	struct admin_remote *rm;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	int cnx;

	cnx = accept(w->fd, (struct sockaddr *) &from, &fromlen);
	if (cnx < 0)
		return;
	fcntl(cnx, F_SETFD, FD_CLOEXEC);

	rm = calloc(1, sizeof(struct admin_remote));

	ev_io_init(&rm->io, admin_receive_cb, cnx, EV_READ);
	ev_io_start(&rm->io);
	ev_timer_init(&rm->timeout, admin_timeout_cb, 10.0, 0.);
	ev_timer_start(&rm->timeout);
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

	ev_io_init(&accept_io, admin_accept_cb, fd, EV_READ);
	ev_io_start(&accept_io);

	return 1;

err_close:
	nhrp_error("Failed initialize admin socket [%s]: %s",
		   opennhrp_socket, strerror(errno));
	close(fd);
	return 0;
}
