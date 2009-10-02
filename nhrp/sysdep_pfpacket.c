/* sysdep_pfpacket.c - Tracing of forwarded packets using PF_PACKET
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>

#include "libev.h"
#include "nhrp_defines.h"
#include "nhrp_common.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

#define MAX_OPCODES 100

struct multicast_packet {
	struct nhrp_interface *iface;
	struct sockaddr_ll lladdr;
	unsigned int pdulen;
	unsigned char pdu[1500];
};

static struct ev_io packet_io;
static struct ev_timer install_filter_timer;
static struct ev_idle mcast_route;

static struct multicast_packet mcast_queue[16];
static int mcast_head = 0, mcast_tail = 0;


enum {
	LABEL_NEXT = 0,
	LABEL_SKIP1,
	LABEL_SKIPN,
	LABEL_DROP,
	LABEL_CHECK_MC,
	LABEL_CHECK_MC_DROP,
	LABEL_CHECK_IND,
	LABEL_ACCEPT_MC,
	LABEL_ACCEPT_IND,
	NUM_LABELS
};

struct filter {
	int pos[NUM_LABELS];
	int numops;
	struct sock_filter code[MAX_OPCODES];
};

static void emit_stmt(struct filter *f, __u16 code, __u32 k)
{
	if (f->numops < MAX_OPCODES) {
		f->code[f->numops].code = code;
		f->code[f->numops].jt = 0;
		f->code[f->numops].jf = 0;
		f->code[f->numops].k = k;
	}
	f->numops++;
}

static void emit_jump(struct filter *f, __u16 code, __u32 k, __u8 jt, __u8 jf)
{
	if (f->numops < MAX_OPCODES) {
		f->code[f->numops].code = code;
		f->code[f->numops].jt = jt;
		f->code[f->numops].jf = jf;
		f->code[f->numops].k = k;
	}
	f->numops++;
}

static void patch_jump(struct filter *f, int new_label)
{
	NHRP_BUG_ON(BPF_CLASS(f->code[f->numops-1].code) != BPF_JMP);

	if (f->code[f->numops-1].jf == LABEL_NEXT)
		f->code[f->numops-1].jf = new_label;
	if (f->code[f->numops-1].jt == LABEL_NEXT)
		f->code[f->numops-1].jt = new_label;
}

static void mark(struct filter *f, int label)
{
	f->pos[label] = f->numops;
}

static int check_interface(void *ctx, struct nhrp_interface *iface)
{
	struct filter *f = (struct filter *) ctx;

	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		return 0;
	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
		return 0;

	if (iface->mcast_mask || iface->mcast_numaddr)
		emit_jump(f, BPF_JMP|BPF_JEQ|BPF_K, iface->index,
			  LABEL_CHECK_MC, LABEL_NEXT);
	else
		emit_jump(f, BPF_JMP|BPF_JEQ|BPF_K, iface->index,
			  LABEL_CHECK_MC_DROP, LABEL_NEXT);

	return 0;
}

static int check_ipv4(void *ctx, struct nhrp_peer *peer)
{
	struct filter *f = (struct filter *) ctx;
	unsigned long addr, mask;

	if (peer->protocol_type != ETHPROTO_IP)
		return 0;

	addr = htonl(*((unsigned long *) peer->protocol_address.addr));
	if (peer->prefix_length != 32) {
		mask = 0xffffffff >> peer->prefix_length;
		emit_jump(f, BPF_JMP|BPF_JGE|BPF_K, addr & ~mask, LABEL_NEXT, LABEL_SKIP1);
		emit_jump(f, BPF_JMP|BPF_JGT|BPF_K, addr |  mask, LABEL_NEXT, LABEL_DROP);
	} else {
		emit_jump(f, BPF_JMP|BPF_JEQ|BPF_K, addr, LABEL_DROP, LABEL_NEXT);
	}
	return 0;
}

static void install_filter_cb(struct ev_timer *w, int revents)
{
	struct nhrp_peer_selector sel;
	struct sock_fprog prog;
	struct filter f;
	int i;

	memset(&f, 0, sizeof(f));

	/* First, we are interested only on outgoing stuff */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_PKTTYPE);
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K,   PACKET_OUTGOING, LABEL_NEXT, LABEL_DROP);

	/* Check for IPv4 */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_PROTOCOL);
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K,   ETH_P_IP, LABEL_NEXT, LABEL_DROP);

	/* Check for valid interface */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_IFINDEX);
	nhrp_interface_foreach(check_interface, &f);
	patch_jump(&f, LABEL_DROP);

	/* Check for multicast IPv4 destination - accept on match */
	mark(&f, LABEL_CHECK_MC);
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, offsetof(struct iphdr, daddr));
	emit_jump(&f, BPF_JMP|BPF_JGE|BPF_K, 0xe0000000, LABEL_NEXT, LABEL_CHECK_IND);
	emit_jump(&f, BPF_JMP|BPF_JGE|BPF_K, 0xf0000000, LABEL_CHECK_IND, LABEL_ACCEPT_MC);

	/* Check for multicast IPv4 destination - drop on match */
	mark(&f, LABEL_CHECK_MC_DROP);
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, offsetof(struct iphdr, daddr));
	emit_jump(&f, BPF_JMP|BPF_JGE|BPF_K, 0xe0000000, LABEL_NEXT, LABEL_CHECK_IND);
	emit_jump(&f, BPF_JMP|BPF_JGE|BPF_K, 0xf0000000, LABEL_CHECK_IND, LABEL_DROP);

	/* Check for non-local IPv4 source */
	mark(&f, LABEL_CHECK_IND);
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, offsetof(struct iphdr, saddr));

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL);
	nhrp_peer_foreach(check_ipv4, &f, &sel);

	/* A packet we send Traffic Indication about: snap only start */
	mark(&f, LABEL_ACCEPT_IND);
	emit_stmt(&f, BPF_RET|BPF_K, 68);

	/* Exit */
	mark(&f, LABEL_DROP);
	emit_stmt(&f, BPF_RET|BPF_K, 0);

	/* Multicast packets need to be captured fully as we resend them */
	mark(&f, LABEL_ACCEPT_MC);
	emit_stmt(&f, BPF_RET|BPF_K, 65535);

	/* All ok so far? */
	if (f.numops >= MAX_OPCODES) {
		nhrp_error("Filter code buffer too small (code actual length %d)",
			   f.numops);
		return;
	}

	/* Fixup jumps to be relative */
	for (i = 0; i < f.numops; i++) {
		if (BPF_CLASS(f.code[i].code) == BPF_JMP) {
			if (f.code[i].jt > LABEL_SKIPN)
				f.code[i].jt = f.pos[f.code[i].jt] - i - 1;
			if (f.code[i].jf > LABEL_SKIPN)
				f.code[i].jf = f.pos[f.code[i].jf] - i - 1;
		}
	}

	/* Attach filter */
	prog.len = f.numops;
	prog.filter = f.code;
	if (setsockopt(packet_io.fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &prog, sizeof(prog)))
		return;

	nhrp_info("Filter code installed (%d opcodes)", f.numops);
}

int forward_local_addresses_changed(void)
{
	if (install_filter_timer.cb != NULL)
		ev_timer_start(&install_filter_timer);
	return TRUE;
}

static void send_multicast(struct ev_idle *w, int revents)
{
	struct multicast_packet *pkt;
	struct nhrp_peer *peer;
	struct iovec iov;
	struct msghdr msg;

	if (mcast_head == mcast_tail) {
		ev_idle_stop(&mcast_route);
		return;
	}

	/* Pop a packet */
	pkt = &mcast_queue[mcast_tail];
	mcast_tail = (mcast_tail + 1) % ARRAY_SIZE(mcast_queue);

	/* And softroute it forward */
	iov.iov_base = pkt->pdu;
	iov.iov_len = pkt->pdulen;
	msg = (struct msghdr) {
		.msg_name = &pkt->lladdr,
		.msg_namelen = sizeof(pkt->lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	list_for_each_entry(peer, &pkt->iface->mcast_list, mcast_list_entry) {
		/* Update NBMA destination */
		pkt->lladdr.sll_halen = peer->next_hop_address.addr_len;
		memcpy(pkt->lladdr.sll_addr, peer->next_hop_address.addr,
		       pkt->lladdr.sll_halen);

		/* Best effort attempt to emulate multicast */
		(void) sendmsg(packet_io.fd, &msg, 0);
	}
}

static void pfp_read_cb(struct ev_io *w, int revents)
{
	struct nhrp_address src, dst;
	struct nhrp_interface *iface;
	struct sockaddr_ll *lladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char fr[32], to[32];
	int r, i, nbmaset, fd = w->fd;

	if (!(revents & EV_READ))
		return;

	while (TRUE) {
		/* Get a scracth buffer directly from mcast queue, so we do
		 * not need copy the data later. */
		msg.msg_name = &mcast_queue[mcast_head].lladdr;
		msg.msg_namelen = sizeof(mcast_queue[mcast_head].lladdr);
		iov.iov_base = mcast_queue[mcast_head].pdu;
		iov.iov_len = sizeof(mcast_queue[mcast_head].pdu);

		/* Receive */
		r = recvmsg(fd, &msg, MSG_DONTWAIT);
		mcast_queue[mcast_head].pdulen = r;

		/* Process */
		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return;
			nhrp_perror("PF_PACKET overrun");
			continue;
		}

		if (r == 0) {
			nhrp_error("PF_PACKET returned EOF");
			return;
		}

		lladdr = &mcast_queue[mcast_head].lladdr;
		if (lladdr->sll_pkttype != PACKET_OUTGOING)
			continue;

		iface = nhrp_interface_get_by_index(lladdr->sll_ifindex, FALSE);
		if (iface == NULL)
			continue;
		if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
			continue;

		if (!nhrp_address_parse_packet(lladdr->sll_protocol,
					       r, iov.iov_base,
					       &src, &dst))
			return;

		nbmaset = 0;
		for (i = 0; i < lladdr->sll_halen; i++)
			if (lladdr->sll_addr[i] != 0)
				nbmaset = 1;

		if (nhrp_address_is_multicast(&dst)) {
			if (nbmaset)
				continue;

			nhrp_debug("Multicast from %s to %s",
				   nhrp_address_format(&src, sizeof(fr), fr),
				   nhrp_address_format(&dst, sizeof(to), to));

			/* Queue packet for processing later (handle important
			 * stuff first) */
			mcast_queue[mcast_head].iface = iface;
			mcast_head = (mcast_head + 1) % ARRAY_SIZE(mcast_queue);

			/* Drop packets from queue tail, if we haven't processed
			 * them yet. */
			if (mcast_head == mcast_tail)
				mcast_tail = (mcast_tail + 1) %
					ARRAY_SIZE(mcast_queue);

			ev_idle_start(&mcast_route);
		} else {
			nhrp_packet_send_traffic(iface, lladdr->sll_protocol,
						 iov.iov_base, r);
		}
	}
}

int forward_init(void)
{
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM, ntohs(ETH_P_ALL));
	if (fd < 0) {
		nhrp_error("Unable to create PF_PACKET socket");
		return FALSE;
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);

	ev_io_init(&packet_io, pfp_read_cb, fd, EV_READ);
	ev_io_start(&packet_io);

	ev_timer_init(&install_filter_timer, install_filter_cb, .01, .0);
	install_filter_cb(&install_filter_timer, 0);

	ev_idle_init(&mcast_route, send_multicast);
	ev_set_priority(&mcast_route, -1);

	return TRUE;
}

