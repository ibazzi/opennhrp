/* sysdep_netlink.c - Linux netlink glue
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "nhrp_common.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

typedef void (*netlink_dispatch_f)(struct nlmsghdr *msg);

struct netlink_fd {
	int fd;
	__u32 seq;

	int dispatch_size;
	const netlink_dispatch_f *dispatch;
};


static struct netlink_fd netlink_fd;

static int protocol_to_pf(uint16_t protocol)
{
	switch (protocol) {
	case ETHP_IP:
		return AF_INET;
	}
	return AF_UNSPEC;
}

static void netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
}

static int netlink_add_rtattr_l(struct nlmsghdr *n, int maxlen, int type,
				const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return FALSE;

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return TRUE;
}

static int netlink_receive(struct netlink_fd *fd, struct nlmsghdr *reply)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int got_reply = FALSE;
	char buf[16*1024];

	iov.iov_base = buf;
	while (!got_reply) {
		int status;
		struct nlmsghdr *h;

		iov.iov_len = sizeof(buf);
		status = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return reply == NULL;
			nhrp_perror("Netlink overrun");
			continue;
		}

		if (status == 0) {
			nhrp_error("Netlink returned EOF");
			return FALSE;
		}

		h = (struct nlmsghdr *) buf;
		while (NLMSG_OK(h, status)) {
			if (reply != NULL &&
			    h->nlmsg_seq == reply->nlmsg_seq) {
				memcpy(reply, h, reply->nlmsg_len);
				got_reply = TRUE;
			} else if (h->nlmsg_type <= fd->dispatch_size &&
				fd->dispatch[h->nlmsg_type] != NULL) {
				fd->dispatch[h->nlmsg_type](h);
			} else if (h->nlmsg_type != NLMSG_DONE) {
				nhrp_info("Unknown NLmsg: 0x%08x, len %d",
					h->nlmsg_type, h->nlmsg_len);
			}
			h = NLMSG_NEXT(h, status);
		}
	}

	return TRUE;
}

int netlink_talk(struct netlink_fd *fd, struct nlmsghdr *req,
		 size_t replysize, struct nlmsghdr *reply)
{
	int status;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = (void*) req,
		.iov_len = req->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	req->nlmsg_seq = ++fd->seq;
	if (reply == NULL)
		req->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(fd->fd, &msg, 0);
	if (status < 0) {
		nhrp_perror("Cannot talk to rtnetlink");
		return FALSE;
	}

	if (reply == NULL)
		return TRUE;

	reply->nlmsg_len = replysize;
	return netlink_receive(fd, reply);
}

int netlink_enumerate(struct netlink_fd *fd, int family, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	struct sockaddr_nl addr;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = ++fd->seq;
	req.g.rtgen_family = family;

	return sendto(fd->fd, (void *) &req, sizeof(req), 0,
		      (struct sockaddr *) &addr, sizeof(addr)) >= 0;
}

static void netlink_link_update(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct ifinfomsg *ifi = NLMSG_DATA(msg);
	struct rtattr *rta[IFLA_MAX+1];
	const char *ifname;

	netlink_parse_rtattr(rta, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(msg));
	if (rta[IFLA_IFNAME] == NULL)
		return;

	ifname = RTA_DATA(rta[IFLA_IFNAME]);
	iface = nhrp_interface_get_by_name(ifname, FALSE);
	if (iface == NULL)
		return;

	nhrp_info("Interface '%s' configuration changed", ifname);
	iface->index = ifi->ifi_index;
	nhrp_interface_hash(iface);
}

static void netlink_addr_update(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct ifaddrmsg *ifa = NLMSG_DATA(msg);
	struct rtattr *rta[IFA_MAX+1];

	netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(msg));
	iface = nhrp_interface_get_by_index(ifa->ifa_index, FALSE);
	if (iface == NULL)
		return;

	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST) {
		struct nhrp_peer *peer;

		peer = calloc(1, sizeof(struct nhrp_peer));
		peer->type = NHRP_PEER_TYPE_LOCAL;
		peer->afnum = AFNUM_RESERVED;
		switch (ifa->ifa_family) {
		case PF_INET:
			peer->protocol_type = ETHP_IP;
			peer->prefix_length = ifa->ifa_prefixlen;
			peer->dst_protocol_address.addr_len = RTA_PAYLOAD(rta[IFA_LOCAL]);
			memcpy(peer->dst_protocol_address.addr,
			       RTA_DATA(rta[IFA_LOCAL]), RTA_PAYLOAD(rta[IFA_LOCAL]));
			nhrp_peer_insert(peer);
			break;
		default:
			free(peer);
			peer = NULL;
			break;
		}
	}
}

static const netlink_dispatch_f route_dispatch[RTM_MAX] = {
	[RTM_NEWLINK] = netlink_link_update,
	[RTM_DELLINK] = netlink_link_update,
	[RTM_NEWADDR] = netlink_addr_update,
	[RTM_DELADDR] = netlink_addr_update,
};

static void netlink_read(void *ctx, short events)
{
	struct netlink_fd *fd = (struct netlink_fd *) ctx;

	if (events & POLLIN)
		netlink_receive(fd, NULL);
}

static void netlink_close(struct netlink_fd *fd)
{
	if (fd->fd >= 0) {
		nhrp_task_unpoll_fd(fd->fd);
		close(fd->fd);
		fd->fd = 0;
	}
}

static int netlink_open(struct netlink_fd *fd, int protocol, int groups)
{
	struct sockaddr_nl addr;
	int buf = 16 * 1024;

	fd->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	fd->seq = time(NULL);
	if (fd->fd < 0) {
		nhrp_perror("Cannot open netlink socket");
		return FALSE;
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) < 0) {
		nhrp_perror("SO_SNDBUF");
		goto error;
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) < 0) {
		nhrp_perror("SO_RCVBUF");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = groups;
	if (bind(fd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		nhrp_perror("Cannot bind netlink socket");
		goto error;
	}

	return TRUE;

error:
	netlink_close(fd);
	return FALSE;
}

int kernel_init(void)
{
	const int groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

	if (!netlink_open(&netlink_fd, NETLINK_ROUTE, groups))
		return FALSE;

	netlink_fd.dispatch_size = sizeof(route_dispatch) / sizeof(route_dispatch[0]);
	netlink_fd.dispatch = route_dispatch;

	if (!nhrp_task_poll_fd(netlink_fd.fd, POLLIN, netlink_read, &netlink_fd)) {
		netlink_close(&netlink_fd);
		return FALSE;
	}

	netlink_enumerate(&netlink_fd, AF_UNSPEC, RTM_GETLINK);
	netlink_read(&netlink_fd, POLLIN);

	netlink_enumerate(&netlink_fd, AF_UNSPEC, RTM_GETADDR);
	netlink_read(&netlink_fd, POLLIN);

	return TRUE;
}

int kernel_route(uint16_t protocol,
		 struct nhrp_protocol_address *dest,
		 struct nhrp_protocol_address *default_source,
		 uint16_t *afnum, struct nhrp_nbma_address *next_hop)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	} req;
	struct rtmsg *r = NLMSG_DATA(&req.n);
	struct rtattr *rta[RTA_MAX+1];

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = protocol_to_pf(protocol);
	req.r.rtm_table = 0;
	req.r.rtm_protocol = 0;
	req.r.rtm_scope = 0;
	req.r.rtm_type = 0;
	req.r.rtm_src_len = 0;
	req.r.rtm_dst_len = 0;
	req.r.rtm_tos = 0;

	netlink_add_rtattr_l(&req.n, sizeof(req), RTA_DST, dest->addr, dest->addr_len);
	req.r.rtm_dst_len = dest->addr_len * 8;

	if (!netlink_talk(&netlink_fd, &req.n, sizeof(req), &req.n))
		return FALSE;

	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(r), RTM_PAYLOAD(&req.n));

	if (rta[RTA_DST])
		nhrp_hex_dump("to", RTA_DATA(rta[RTA_DST]), RTA_PAYLOAD(rta[RTA_DST]));
	if (rta[RTA_PREFSRC])
		nhrp_hex_dump("from", RTA_DATA(rta[RTA_PREFSRC]), RTA_PAYLOAD(rta[RTA_PREFSRC]));
	if (rta[RTA_GATEWAY])
		nhrp_hex_dump("via", RTA_DATA(rta[RTA_GATEWAY]), RTA_PAYLOAD(rta[RTA_GATEWAY]));


	return FALSE;
}

int kernel_get_nbma_source(uint16_t afnum, struct nhrp_nbma_address *dest,
			   struct nhrp_nbma_address *default_source)
{
	return FALSE;
}

