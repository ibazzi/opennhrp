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

#define NDA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))

typedef void (*netlink_dispatch_f)(struct nlmsghdr *msg);

struct netlink_fd {
	int fd;
	__u32 seq;

	int dispatch_size;
	const netlink_dispatch_f *dispatch;
};


static struct netlink_fd netlink_fd;
static int packet_fd;

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

static int netlink_add_nested_rtattr_u32(struct rtattr *rta, int maxlen,
					 int type, uint32_t value)
{
	int len = RTA_LENGTH(4);
	struct rtattr *subrta;

	if (RTA_ALIGN(rta->rta_len) + len > maxlen)
		return FALSE;

	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), &value, 4);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
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

static int netlink_send(struct netlink_fd *fd, struct nlmsghdr *req)
{
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
	int status;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	req->nlmsg_seq = ++fd->seq;

	status = sendmsg(fd->fd, &msg, 0);
	if (status < 0) {
		nhrp_perror("Cannot talk to rtnetlink");
		return FALSE;
	}
	return TRUE;
}

static int netlink_talk(struct netlink_fd *fd, struct nlmsghdr *req,
		 size_t replysize, struct nlmsghdr *reply)
{
	if (reply == NULL)
		req->nlmsg_flags |= NLM_F_ACK;

	if (!netlink_send(fd, req))
		return FALSE;

	if (reply == NULL)
		return TRUE;

	reply->nlmsg_len = replysize;
	return netlink_receive(fd, reply);
}

static int netlink_enumerate(struct netlink_fd *fd, int family, int type)
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

	strncpy(ifr.ifr_name, basedev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void *) p;
	if (ioctl(packet_fd, SIOCGETTUNNEL, &ifr)) {
		nhrp_perror("ioctl(SIOCGETTUNNEL)");
		return FALSE;
	}
	return TRUE;
}

static int netlink_configure_arp(struct nhrp_interface *iface, int pf)
{
	struct {
		struct nlmsghdr n;
		struct ndtmsg ndtm;
		char buf[256];
	} req;
	struct {
		struct rtattr rta;
		char buf[256];
	} parms;

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndtm, 0, sizeof(req.ndtm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
	req.n.nlmsg_type = RTM_SETNEIGHTBL;

	req.ndtm.ndtm_family = pf;

	netlink_add_rtattr_l(&req.n, sizeof(req), NDTA_NAME,
			     "arp_cache", 10);

	parms.rta.rta_type = NDTA_PARMS;
	parms.rta.rta_len = RTA_LENGTH(0);
	netlink_add_nested_rtattr_u32(&parms.rta, sizeof(parms),
				      NDTPA_IFINDEX, iface->index);
	netlink_add_nested_rtattr_u32(&parms.rta, sizeof(parms),
				      NDTPA_APP_PROBES, 1);
	netlink_add_nested_rtattr_u32(&parms.rta, sizeof(parms),
				      NDTPA_MCAST_PROBES, 0);
	netlink_add_nested_rtattr_u32(&parms.rta, sizeof(parms),
				      NDTPA_UCAST_PROBES, 0);

	netlink_add_rtattr_l(&req.n, sizeof(req), NDTA_PARMS,
			     parms.buf, parms.rta.rta_len);

	return netlink_send(&netlink_fd, &req.n);
}

static int netlink_link_arp_on(struct nhrp_interface *iface)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(packet_fd, SIOCGIFFLAGS, &ifr)) {
		nhrp_perror("ioctl(SIOCGIFFLAGS)");
		return FALSE;
	}
	if (ifr.ifr_flags & IFF_NOARP) {
		ifr.ifr_flags &= ~IFF_NOARP;
		if (ioctl(packet_fd, SIOCSIFFLAGS, &ifr)) {
			nhrp_perror("ioctl(SIOCSIFFLAGS)");
			return FALSE;
		}
	}
	return TRUE;
}

static void netlink_neigh_request(struct nlmsghdr *msg)
{
	struct ndmsg *ndm = NLMSG_DATA(msg);
	struct rtattr *rta[NDA_MAX+1];
	struct nhrp_peer *peer;
	struct nhrp_address addr;
	char tmp[64];

	netlink_parse_rtattr(rta, NDA_MAX, NDA_RTA(ndm), NDA_PAYLOAD(msg));
	if (rta[NDA_DST] == NULL)
		return;

	nhrp_address_set(&addr, ndm->ndm_family,
			 RTA_PAYLOAD(rta[NDA_DST]),
			 RTA_DATA(rta[NDA_DST]));

	nhrp_info("NL-ARP who-has %s",
		nhrp_address_format(&addr, sizeof(tmp), tmp));

	peer = nhrp_peer_find(&addr, 0xff, NHRP_PEER_FIND_COMPLETE);
	if (peer == NULL)
		return;

	kernel_inject_neighbor(&addr, peer);
}

static void netlink_neigh_update(struct nlmsghdr *msg)
{
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
			nhrp_address_set(&iface->nbma_address, PF_INET,
					 4, (uint8_t *) &cfg.iph.saddr);
		}
		break;
	}

	if (!(iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)) {
		netlink_configure_arp(iface, PF_INET);
		netlink_link_arp_on(iface);
	}
}

static void netlink_addr_update(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct nhrp_peer *peer;
	struct ifaddrmsg *ifa = NLMSG_DATA(msg);
	struct rtattr *rta[IFA_MAX+1];

	netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(msg));
	iface = nhrp_interface_get_by_index(ifa->ifa_index, FALSE);
	if (iface == NULL)
		return;

	peer = nhrp_peer_alloc();
	peer->type = NHRP_PEER_TYPE_LOCAL;
	peer->afnum = AFNUM_RESERVED;
	peer->interface = iface;
	nhrp_address_set(&peer->protocol_address,
			 ifa->ifa_family,
			 RTA_PAYLOAD(rta[IFA_LOCAL]),
			 RTA_DATA(rta[IFA_LOCAL]));
	switch (ifa->ifa_family) {
	case PF_INET:
		peer->protocol_type = ETHPROTO_IP;
		if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
			peer->prefix_length = ifa->ifa_prefixlen;
		else
			peer->prefix_length = peer->protocol_address.addr_len * 8;
		nhrp_peer_insert(peer);
		break;
	default:
		break;
	}
	nhrp_peer_free(peer);
}

static const netlink_dispatch_f route_dispatch[RTM_MAX] = {
	[RTM_GETNEIGH] = netlink_neigh_request,
	[RTM_NEWNEIGH] = netlink_neigh_update,
	[RTM_NEWLINK] = netlink_link_update,
	[RTM_DELLINK] = netlink_link_update,
	[RTM_NEWADDR] = netlink_addr_update,
	[RTM_DELADDR] = netlink_addr_update,
};

static void netlink_read(void *ctx, int fd, short events)
{
	struct netlink_fd *nfd = (struct netlink_fd *) ctx;

	if (events & POLLIN)
		netlink_receive(nfd, NULL);
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

static void pfpacket_read(void *ctx, int fd, short events)
{
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
	struct nhrp_address from;

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

		nhrp_address_set(&from, PF_INET, lladdr.sll_halen, lladdr.sll_addr);
		nhrp_packet_receive(buf, status, iface, &from);
	}
}

int kernel_init(void)
{
	const int groups = RTMGRP_NEIGH | RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

	packet_fd = socket(PF_PACKET, SOCK_DGRAM, ETHPROTO_NHRP);
	if (packet_fd < 0) {
		nhrp_error("Unable to create PF_PACKET socket");
		return FALSE;
	}
	if (!nhrp_task_poll_fd(packet_fd, POLLIN, pfpacket_read, NULL))
		goto err_close_packetfd;

	if (!netlink_open(&netlink_fd, NETLINK_ROUTE, groups))
		goto err_remove_packetfd;

	netlink_fd.dispatch_size = sizeof(route_dispatch) / sizeof(route_dispatch[0]);
	netlink_fd.dispatch = route_dispatch;

	if (!nhrp_task_poll_fd(netlink_fd.fd, POLLIN, netlink_read, &netlink_fd))
		goto err_close_netlink;

	netlink_enumerate(&netlink_fd, AF_UNSPEC, RTM_GETLINK);
	netlink_read(&netlink_fd, netlink_fd.fd, POLLIN);

	netlink_enumerate(&netlink_fd, AF_UNSPEC, RTM_GETADDR);
	netlink_read(&netlink_fd, netlink_fd.fd, POLLIN);

	return TRUE;

err_close_netlink:
	netlink_close(&netlink_fd);
err_remove_packetfd:
	nhrp_task_unpoll_fd(packet_fd);
err_close_packetfd:
	close(packet_fd);
	return FALSE;
}

int kernel_route(struct nhrp_address *dest,
		 struct nhrp_address *default_source,
		 struct nhrp_address *next_hop,
		 int *oif_index)
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
	req.r.rtm_family = dest->type;

	netlink_add_rtattr_l(&req.n, sizeof(req), RTA_DST,
			     dest->addr, dest->addr_len);
	req.r.rtm_dst_len = dest->addr_len * 8;

	if (!netlink_talk(&netlink_fd, &req.n, sizeof(req), &req.n))
		return FALSE;

	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(r), RTM_PAYLOAD(&req.n));

	if (oif_index != NULL && rta[RTA_OIF] != NULL)
		*oif_index = *(int *) RTA_DATA(rta[RTA_OIF]);

	if (default_source != NULL && rta[RTA_PREFSRC] != NULL) {
		nhrp_address_set(default_source, dest->type,
				 RTA_PAYLOAD(rta[RTA_PREFSRC]),
				 RTA_DATA(rta[RTA_PREFSRC]));
	}

	if (next_hop != NULL) {
		if (rta[RTA_GATEWAY] != NULL) {
			nhrp_address_set(next_hop, dest->type,
					 RTA_PAYLOAD(rta[RTA_GATEWAY]),
					 RTA_DATA(rta[RTA_GATEWAY]));
		} else {
			*next_hop = *dest;
		}
	}

	return TRUE;
}

int kernel_send(uint8_t *packet, size_t bytes, struct nhrp_interface *out,
		struct nhrp_address *to)
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

	if (to->addr_len > sizeof(lladdr.sll_addr)) {
		nhrp_error("Destination NBMA address too long");
		return FALSE;
	}

	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_protocol = ETHPROTO_NHRP;
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

int kernel_inject_neighbor(struct nhrp_address *neighbor, struct nhrp_peer *peer)
{
	struct {
		struct nlmsghdr 	n;
		struct ndmsg 		ndm;
		char   			buf[256];
	} req;
	char neigh[64], nbma[64];

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWNEIGH;
	req.ndm.ndm_family = peer->protocol_address.type;
	req.ndm.ndm_ifindex = peer->interface->index;
	req.ndm.ndm_type = RTN_UNICAST;

	netlink_add_rtattr_l(&req.n, sizeof(req), NDA_DST,
			     neighbor->addr, neighbor->addr_len);

	if (peer->type != NHRP_PEER_TYPE_NEGATIVE) {
		req.ndm.ndm_state = NUD_REACHABLE;

		netlink_add_rtattr_l(&req.n, sizeof(req), NDA_LLADDR,
				     peer->next_hop_address.addr,
				     peer->next_hop_address.addr_len);

		nhrp_info("NL-ARP %s is-at %s",
			nhrp_address_format(neighbor, sizeof(neigh), neigh),
			nhrp_address_format(&peer->next_hop_address, sizeof(nbma), nbma));
	} else {
		req.ndm.ndm_state = NUD_FAILED;

		nhrp_info("NL-ARP %s not-reachable",
			  nhrp_address_format(neighbor, sizeof(neigh), neigh));
	}

	return netlink_send(&netlink_fd, &req.n);
}

