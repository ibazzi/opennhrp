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

typedef void (*netlink_dispatch_f)(struct nlmsghdr *msg);

struct netlink_fd {
	int fd;
	__u32 seq;

	int dispatch_size;
	const netlink_dispatch_f *dispatch;
};


static struct netlink_fd netlink_fd;

static void netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
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
			peer->protocol_type = ETH_P_IP;
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

	if (events & POLLIN) {
		struct sockaddr_nl nladdr;
		struct iovec iov;
		struct msghdr msg = {
			.msg_name = &nladdr,
			.msg_namelen = sizeof(nladdr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};
		char buf[16384];

		iov.iov_base = buf;
		while (1) {
			int status;
			struct nlmsghdr *h;

			iov.iov_len = sizeof(buf);
			status = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
			if (status < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					return;
				nhrp_perror("Netlink overrun");
				continue;
			}

			if (status == 0) {
				nhrp_error("Netlink returned EOF");
				return;
			}

			h = (struct nlmsghdr *) buf;
			while (NLMSG_OK(h, status)) {
				if (h->nlmsg_type <= fd->dispatch_size &&
				    fd->dispatch[h->nlmsg_type] != NULL) {
					fd->dispatch[h->nlmsg_type](h);
				} else if (h->nlmsg_type != NLMSG_DONE) {
					nhrp_info("Unknown NLmsg: 0x%08x, len %d",
						  h->nlmsg_type, h->nlmsg_len);
				}
				h = NLMSG_NEXT(h, status);
			}
		}
	}
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
		return 0;
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) < 0) {
		nhrp_perror("SO_SNDBUF");
		netlink_close(fd);
		return 0;
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) < 0) {
		nhrp_perror("SO_RCVBUF");
		netlink_close(fd);
		return 0;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = groups;
	if (bind(fd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		nhrp_perror("Cannot bind netlink socket");
		return 0;
	}

	return 1;
}

int kernel_init(void)
{
	const int groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

	if (!netlink_open(&netlink_fd, NETLINK_ROUTE, groups))
		return 0;

	netlink_fd.dispatch_size = sizeof(route_dispatch) / sizeof(route_dispatch[0]);
	netlink_fd.dispatch = route_dispatch;

	if (!nhrp_task_poll_fd(netlink_fd.fd, POLLIN, netlink_read, &netlink_fd)) {
		netlink_close(&netlink_fd);
		return 0;
	}

	netlink_enumerate(&netlink_fd, AF_UNSPEC, RTM_GETLINK);
	netlink_read(&netlink_fd, POLLIN);

	netlink_enumerate(&netlink_fd, AF_UNSPEC, RTM_GETADDR);
	netlink_read(&netlink_fd, POLLIN);

	return 1;
}
