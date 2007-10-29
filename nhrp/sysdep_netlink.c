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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>

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
static int packet_fd;

static int protocol_to_pf(uint16_t protocol)
{
	switch (protocol) {
	case ETHP_IP:
		return AF_INET;
	}
	return AF_UNSPEC;
}

static int afnum_to_pf(uint16_t afnum)
{
	switch (afnum) {
	case AFNUM_INET:
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
	int got_reply = FALSE, len;
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
				len = h->nlmsg_len;
				if (len > reply->nlmsg_len) {
					nhrp_error("Netlink message truncated");
					len = reply->nlmsg_len;
				}
				memcpy(reply, h, len);
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

static int do_get_ioctl(const char *basedev, struct ip_tunnel_parm *p)
{
	struct ifreq ifr;
	int fd;
	int err;

	strncpy(ifr.ifr_name, basedev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void *) p;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCGETTUNNEL, &ifr);
	if (err)
		nhrp_perror("ioctl");
	close(fd);
	return err;
}

static void netlink_link_update(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct ifinfomsg *ifi = NLMSG_DATA(msg);
	struct rtattr *rta[IFLA_MAX+1];
	const char *ifname;
	struct ip_tunnel_parm cfg;

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

	switch (ifi->ifi_type) {
	case ARPHRD_IPGRE:
		iface->afnum = AFNUM_INET;
		do_get_ioctl(ifname, &cfg);
		if (cfg.iph.saddr) {
			iface->nbma_address.addr_len = 4;
			memcpy(iface->nbma_address.addr, &cfg.iph.saddr, 4);
		}
		break;
	}
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

static void pfpacket_read(void *ctx, short events)
{
	int fd = (int) ctx;
	struct sockaddr_ll lladdr;
	struct nhrp_interface *iface;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	uint8_t buf[1500];
	struct nhrp_nbma_address from;

	iov.iov_base = buf;
	while (1) {
		int status;

		iov.iov_len = sizeof(buf);
		status = recvmsg(fd, &msg, MSG_DONTWAIT);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return;
			nhrp_perror("PF_PACKET overrun");
			continue;
		}

		if (status == 0) {
			nhrp_error("PF_PACKET returned EOF");
			return;
		}

		iface = nhrp_interface_get_by_index(lladdr.sll_ifindex, FALSE);
		if (iface == NULL)
			continue;

		from.addr_len = lladdr.sll_halen;
		from.subaddr_len = 0;
		memcpy(from.addr, lladdr.sll_addr, lladdr.sll_halen);

		nhrp_packet_receive(buf, status, iface, &from);
	}
}

int kernel_init(void)
{
	const int groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

	packet_fd = socket(PF_PACKET, SOCK_DGRAM, ETHP_NHRP);
	if (packet_fd < 0) {
		nhrp_error("Unable to create PF_PACKET socket");
		return FALSE;
	}
	if (!nhrp_task_poll_fd(packet_fd, POLLIN, pfpacket_read, (void*) packet_fd))
		goto err_close_packetfd;

	if (!netlink_open(&netlink_fd, NETLINK_ROUTE, groups))
		goto err_remove_packetfd;

	netlink_fd.dispatch_size = sizeof(route_dispatch) / sizeof(route_dispatch[0]);
	netlink_fd.dispatch = route_dispatch;

	if (!nhrp_task_poll_fd(netlink_fd.fd, POLLIN, netlink_read, &netlink_fd))
		goto err_close_netlink;

	netlink_enumerate(&netlink_fd, AF_UNSPEC, RTM_GETLINK);
	netlink_read(&netlink_fd, POLLIN);

	netlink_enumerate(&netlink_fd, AF_UNSPEC, RTM_GETADDR);
	netlink_read(&netlink_fd, POLLIN);

	return TRUE;

err_close_netlink:
	netlink_close(&netlink_fd);
err_remove_packetfd:
	nhrp_task_unpoll_fd(packet_fd);
err_close_packetfd:
	close(packet_fd);
	return FALSE;
}

int kernel_route(struct nhrp_packet *p,
		 struct nhrp_interface **outiface,
		 struct nhrp_nbma_address *next_hop_nbma)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	} req;
	struct rtmsg *r = NLMSG_DATA(&req.n);
	struct rtattr *rta[RTA_MAX+1];
	struct nhrp_interface *iface;
	struct nhrp_peer *peer;
	struct nhrp_protocol_address next_hop;
	char tmp[64];
	int *pindex;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = protocol_to_pf(p->hdr.protocol_type);
	req.r.rtm_table = 0;
	req.r.rtm_protocol = 0;
	req.r.rtm_scope = 0;
	req.r.rtm_type = 0;
	req.r.rtm_src_len = 0;
	req.r.rtm_dst_len = 0;
	req.r.rtm_tos = 0;

	netlink_add_rtattr_l(&req.n, sizeof(req), RTA_DST,
			     p->dst_protocol_address.addr,
			     p->dst_protocol_address.addr_len);
	req.r.rtm_dst_len = p->dst_protocol_address.addr_len * 8;

	if (!netlink_talk(&netlink_fd, &req.n, sizeof(req), &req.n))
		return FALSE;

	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(r), RTM_PAYLOAD(&req.n));

	if (rta[RTA_OIF] == NULL) {
		nhrp_error("Route to %s has no interface",
			   nhrp_format_protocol_address(p->hdr.protocol_type, &p->dst_protocol_address, sizeof(tmp), tmp));
		return FALSE;
	}

	pindex = (int *) RTA_DATA(rta[RTA_OIF]);
	iface = nhrp_interface_get_by_index(*pindex, FALSE);
	if (iface == NULL) {
		nhrp_error("Route to %s goes to interface %d which is not configured for NHRP",
			   nhrp_format_protocol_address(p->hdr.protocol_type, &p->dst_protocol_address, sizeof(tmp), tmp),
			   *pindex);
		return FALSE;
	}

	if (p->src_protocol_address.addr_len == 0) {
		if (rta[RTA_PREFSRC] == NULL) {
			nhrp_error("Route to %s does not have default source and it is needed",
				   nhrp_format_protocol_address(p->hdr.protocol_type, &p->dst_protocol_address, sizeof(tmp), tmp));
			return FALSE;
		}

		p->src_protocol_address.addr_len = RTA_PAYLOAD(rta[RTA_PREFSRC]);
		memcpy(p->src_protocol_address.addr,
		       RTA_DATA(rta[RTA_PREFSRC]),
		       RTA_PAYLOAD(rta[RTA_PREFSRC]));
	}

	if (rta[RTA_GATEWAY] != NULL) {
		next_hop.addr_len = RTA_PAYLOAD(rta[RTA_GATEWAY]);
		memcpy(next_hop.addr, RTA_DATA(rta[RTA_GATEWAY]),
		       next_hop.addr_len);
	} else {
		next_hop = p->dst_protocol_address;
	}

	peer = nhrp_peer_find(p->hdr.protocol_type, &next_hop, 0);
	if (peer == NULL) {
		nhrp_error("Route to %s goes via unknown hop",
			   nhrp_format_protocol_address(p->hdr.protocol_type, &p->dst_protocol_address, sizeof(tmp), tmp));
		return FALSE;
	}

	if (p->src_nbma_address.addr_len == 0) {
		if (iface->nbma_address.addr_len == 0) {
			memset(&req, 0, sizeof(req));
			req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
			req.n.nlmsg_flags = NLM_F_REQUEST;
			req.n.nlmsg_type = RTM_GETROUTE;
			req.r.rtm_family = afnum_to_pf(peer->afnum);
			req.r.rtm_table = 0;
			req.r.rtm_protocol = 0;
			req.r.rtm_scope = 0;
			req.r.rtm_type = 0;
			req.r.rtm_src_len = 0;
			req.r.rtm_dst_len = 0;
			req.r.rtm_tos = 0;

			netlink_add_rtattr_l(&req.n, sizeof(req), RTA_DST,
				peer->nbma_address.addr,
				peer->nbma_address.addr_len);
			req.r.rtm_dst_len = peer->nbma_address.addr_len * 8;

			if (!netlink_talk(&netlink_fd, &req.n, sizeof(req), &req.n))
				return FALSE;

			netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(r), RTM_PAYLOAD(&req.n));

			if (rta[RTA_PREFSRC] == NULL) {
				nhrp_error("NBMA route to %s does not have default source and it is needed",
					   nhrp_format_nbma_address(peer->afnum, &peer->nbma_address, sizeof(tmp), tmp));
				return FALSE;
			}

			p->src_nbma_address.addr_len = RTA_PAYLOAD(rta[RTA_PREFSRC]);
			memcpy(p->src_nbma_address.addr,
				RTA_DATA(rta[RTA_PREFSRC]),
				RTA_PAYLOAD(rta[RTA_PREFSRC]));
		} else
			p->src_nbma_address = iface->nbma_address;
	}

	*outiface = iface;
	*next_hop_nbma = peer->nbma_address;

	return TRUE;
}

int kernel_send(uint8_t *packet, size_t bytes, struct nhrp_interface *out,
		struct nhrp_nbma_address *to)
{
	struct sockaddr_ll lladdr;
	struct iovec iov = {
		.iov_base = (void*) packet,
		.iov_len = bytes
	};
	struct msghdr msg = {
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int status;

	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_protocol = ETHP_NHRP;
	lladdr.sll_ifindex = out->index;
	lladdr.sll_halen = to->addr_len;
	memcpy(lladdr.sll_addr, to->addr, to->addr_len);

	status = sendmsg(packet_fd, &msg, 0);
	if (status < 0) {
		nhrp_perror("Cannot send packet");
		return FALSE;
	}

	return TRUE;
}
