/* platform/sysdep_pfpacket.c - Tracing of forwarded packets using PF_PACKET
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libev.h"
#include "nhrp_common.h"
#include "nhrp_defines.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

struct multicast_packet {
  struct nhrp_interface *iface;
  struct sockaddr_ll lladdr;
  unsigned int pdulen;
  unsigned char pdu[65535];
};

static struct ev_io packet_io;
static struct ev_timer install_filter_timer;

enum {
  LABEL_NEXT = 0,
  LABEL_SKIP1,
  LABEL_SKIPN,
  LABEL_DROP,
  LABEL_ACCEPT_IPv4_MULTICAST,
  LABEL_UNICAST_IPv4,
  LABEL_CHECK_NON_LOCAL_ADDRESS,
  NUM_LABELS
};

struct filter {
  int pos[NUM_LABELS];
  int numops, numalloc;
  struct sock_filter *code;
};

static int checkfilter(struct filter *f) {
  if (f->numops < f->numalloc)
    return 1;

  if (f->numalloc < 0)
    return 0;

  if (f->numalloc)
    f->numalloc *= 2;
  else
    f->numalloc = 128;

  f->code = realloc(f->code, f->numalloc * sizeof(struct sock_filter));
  if (f->code == NULL) {
    f->numalloc = -1;
    return 0;
  }

  return 1;
}

static void emit_stmt(struct filter *f, __u16 code, __u32 k) {
  if (checkfilter(f)) {
    f->code[f->numops].code = code;
    f->code[f->numops].jt = 0;
    f->code[f->numops].jf = 0;
    f->code[f->numops].k = k;
  }
  f->numops++;
}

static void emit_jump(struct filter *f, __u16 code, __u32 k, __u8 jt, __u8 jf) {
  if (checkfilter(f)) {
    f->code[f->numops].code = code;
    f->code[f->numops].jt = jt;
    f->code[f->numops].jf = jf;
    f->code[f->numops].k = k;
  }
  f->numops++;
}

static void mark(struct filter *f, int label) { f->pos[label] = f->numops; }

static int check_interface_multicast(void *ctx, struct nhrp_interface *iface) {
  struct filter *f = (struct filter *)ctx;

  if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
    return 0;
  if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
    return 0;

  if (iface->mcast_mask || iface->mcast_numaddr)
    emit_jump(f, BPF_JMP | BPF_JEQ | BPF_K, iface->index,
              LABEL_ACCEPT_IPv4_MULTICAST, LABEL_NEXT);

  return 0;
}

static int drop_matching_address(void *ctx, struct nhrp_peer *peer) {
  struct filter *f = (struct filter *)ctx;
  unsigned long addr, mask;

  if (peer->protocol_type != ETHPROTO_IP)
    return 0;

  addr = htonl(*((unsigned long *)peer->protocol_address.addr));
  if (peer->prefix_length != 32) {
    mask = 0xffffffff >> peer->prefix_length;
    emit_jump(f, BPF_JMP | BPF_JGE | BPF_K, addr & ~mask, LABEL_NEXT,
              LABEL_SKIP1);
    emit_jump(f, BPF_JMP | BPF_JGT | BPF_K, addr | mask, LABEL_NEXT,
              LABEL_DROP);
  } else {
    emit_jump(f, BPF_JMP | BPF_JEQ | BPF_K, addr, LABEL_DROP, LABEL_NEXT);
  }

  return 0;
}

static int check_interface_traffic_indication(void *ctx,
                                              struct nhrp_interface *iface) {
  struct filter *f = (struct filter *)ctx;

  if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
    return 0;
  if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
    return 0;
  if (!(iface->flags & NHRP_INTERFACE_FLAG_REDIRECT))
    return 0;

  emit_jump(f, BPF_JMP | BPF_JEQ | BPF_K, iface->index,
            LABEL_CHECK_NON_LOCAL_ADDRESS, LABEL_NEXT);

  return 0;
}

static void install_filter_cb(struct ev_timer *w, int revents) {
  struct nhrp_peer_selector sel;
  struct sock_fprog prog;
  struct filter f;
  int i;

  memset(&prog, 0, sizeof(prog));
  memset(&f, 0, sizeof(f));

  /* Check for IPv4 */
  emit_stmt(&f, BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PROTOCOL);
  emit_jump(&f, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, LABEL_NEXT, LABEL_DROP);

  /* Check for multicast IPv4 destination */
  emit_stmt(&f, BPF_LD | BPF_W | BPF_ABS, offsetof(struct iphdr, daddr));
  emit_jump(&f, BPF_JMP | BPF_JGE | BPF_K, 0xe0000000, LABEL_NEXT,
            LABEL_UNICAST_IPv4);
  emit_jump(&f, BPF_JMP | BPF_JGE | BPF_K, 0xf0000000, LABEL_UNICAST_IPv4,
            LABEL_NEXT);

  /* MULTICAST */
  /* 1. Check that it is outgoing packet */
  emit_stmt(&f, BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE);
  emit_jump(&f, BPF_JMP | BPF_JEQ | BPF_K, PACKET_OUTGOING, LABEL_NEXT,
            LABEL_DROP);
  /* 2. Check that we are on multicast enabled interface */
  emit_stmt(&f, BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_IFINDEX);
  nhrp_interface_foreach(check_interface_multicast, &f);
  emit_stmt(&f, BPF_RET | BPF_K, 0);
  /* 3. Return the whole packet */
  mark(&f, LABEL_ACCEPT_IPv4_MULTICAST);
  emit_stmt(&f, BPF_RET | BPF_K, 65535);

  /* UNICAST */
  mark(&f, LABEL_UNICAST_IPv4);
  /* 1. Check that it is for us */
  emit_stmt(&f, BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE);
  emit_jump(&f, BPF_JMP | BPF_JEQ | BPF_K, PACKET_HOST, LABEL_NEXT, LABEL_DROP);
  /* 2. Check that traffic indication enabled for the interface */
  emit_stmt(&f, BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_IFINDEX);
  nhrp_interface_foreach(check_interface_traffic_indication, &f);
  emit_stmt(&f, BPF_RET | BPF_K, 0);
  /* 3. Check that it is a non-local IP address */
  mark(&f, LABEL_CHECK_NON_LOCAL_ADDRESS);
  memset(&sel, 0, sizeof(sel));
  sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL_ADDR);
  emit_stmt(&f, BPF_LD | BPF_W | BPF_ABS, offsetof(struct iphdr, daddr));
  nhrp_peer_foreach(drop_matching_address, &f, &sel);
  /* 4. Return the header for Traffic Indication packet */
  emit_stmt(&f, BPF_RET | BPF_K, 68);

  mark(&f, LABEL_DROP);
  emit_stmt(&f, BPF_RET | BPF_K, 0);

  /* All ok so far? */
  if (f.numalloc < 0) {
    nhrp_error("Unable to construct filter code: out of memory (code actual "
               "length %d)",
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
  if (setsockopt(packet_io.fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog,
                 sizeof(prog)))
    nhrp_perror("Failed to install filter code");
  else
    nhrp_info("Filter code installed (%d opcodes)", f.numops);

  free(f.code);
}

int forward_local_addresses_changed(void) {
  if (install_filter_timer.cb != NULL)
    ev_timer_start(&install_filter_timer);
  return TRUE;
}

static void multicast_error(const char *reason) {
  static ev_tstamp next_log;

  if (ev_now() >= next_log) {
    nhrp_error("Multicast forwarding failed: %s", reason);
    next_log = ev_now() + 5.0;
  }
}

static void send_multicast(struct multicast_packet *pkt) {
  struct nhrp_peer *peer;
  struct nhrp_address *nbma;
  struct iovec iov;
  struct msghdr msg;
  int r;

  /* And softroute it forward */
  iov.iov_base = pkt->pdu;
  iov.iov_len = pkt->pdulen;
  msg = (struct msghdr){
      .msg_name = &pkt->lladdr,
      .msg_namelen = sizeof(pkt->lladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  list_for_each_entry(peer, &pkt->iface->mcast_list, mcast_list_entry) {
    if (!(peer->flags & NHRP_PEER_FLAG_UP) ||
        (peer->flags & (NHRP_PEER_FLAG_HA_BOOTSTRAP | NHRP_PEER_FLAG_REMOVED)))
      continue;

    /* Update NBMA destination */
    nbma = nhrp_peer_active_nbma(peer);
    if (nbma->type != PF_INET || nbma->addr_len != 4) {
      multicast_error("invalid NBMA destination");
      continue;
    }
    pkt->lladdr.sll_halen = nbma->addr_len;
    memcpy(pkt->lladdr.sll_addr, nbma->addr, nbma->addr_len);

    /* Best effort attempt to emulate multicast */
    do {
      r = sendmsg(packet_io.fd, &msg, MSG_DONTWAIT);
    } while (r < 0 && errno == EINTR);
    if (r < 0)
      multicast_error(strerror(errno));
    else if (r != pkt->pdulen)
      multicast_error("short packet send");
  }
}

static int complete_multicast_checksum(struct multicast_packet *pkt) {
  struct iphdr *iph = (struct iphdr *)pkt->pdu;
  unsigned int header_len = iph->ihl * 4, len = pkt->pdulen - header_len;
  unsigned int offset, minimum;
  uint16_t checksum;

  if (ntohs(iph->frag_off) & (IP_MF | IP_OFFMASK))
    return FALSE;
  if (iph->protocol == IPPROTO_UDP) {
    offset = offsetof(struct udphdr, check);
    minimum = sizeof(struct udphdr);
  } else if (iph->protocol == IPPROTO_TCP) {
    offset = offsetof(struct tcphdr, check);
    minimum = sizeof(struct tcphdr);
  } else {
    return FALSE;
  }
  if (len < minimum)
    return FALSE;
  /* CHECKSUM_PARTIAL already stores the pseudo-header sum in the field. */
  checksum = nhrp_calculate_checksum(pkt->pdu + header_len, len);
  if (checksum == 0 && iph->protocol == IPPROTO_UDP)
    checksum = 0xffff;
  memcpy(pkt->pdu + header_len + offset, &checksum, sizeof(checksum));
  return TRUE;
}

static void pfp_read_cb(struct ev_io *w, int revents) {
  struct nhrp_address nbma_src, src, dst;
  struct nhrp_interface *iface;
  struct sockaddr_ll *lladdr;
  struct multicast_packet pkt;
  union {
    struct cmsghdr align;
    unsigned char data[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
  } control;
  struct cmsghdr *cmsg;
  struct iovec iov;
  struct msghdr msg = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };
  char fr[32], to[32];
  int r, count, partial_checksum, fd = w->fd;

  if (!(revents & EV_READ))
    return;

  /* Bound each read batch so control traffic also gets event-loop time. */
  for (count = 0; count < 16; count++) {
    msg.msg_name = &pkt.lladdr;
    msg.msg_namelen = sizeof(pkt.lladdr);
    msg.msg_control = control.data;
    msg.msg_controllen = sizeof(control.data);
    iov.iov_base = pkt.pdu;
    iov.iov_len = sizeof(pkt.pdu);

    /* Receive */
    r = recvmsg(fd, &msg, MSG_DONTWAIT);

    /* Process */
    if (r < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      nhrp_perror("PF_PACKET overrun");
      return;
    }

    if (r == 0) {
      nhrp_error("PF_PACKET returned EOF");
      return;
    }

    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
      multicast_error("truncated packet");
      continue;
    }

    lladdr = &pkt.lladdr;
    if (lladdr->sll_pkttype != PACKET_OUTGOING &&
        lladdr->sll_pkttype != PACKET_HOST)
      continue;

    iface = nhrp_interface_get_by_index(lladdr->sll_ifindex, FALSE);
    if (iface == NULL)
      continue;
    if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
      continue;

    if (!nhrp_address_parse_packet(lladdr->sll_protocol, r, iov.iov_base, &src,
                                   &dst))
      continue;

    if (nhrp_address_is_multicast(&dst)) {
      struct iphdr *iph = (struct iphdr *)pkt.pdu;

      if (lladdr->sll_pkttype != PACKET_OUTGOING)
        continue;
      if (iph->version != 4 || iph->ihl < 5 ||
          ntohs(iph->tot_len) < iph->ihl * 4 || ntohs(iph->tot_len) > r) {
        multicast_error("invalid IPv4 packet length");
        continue;
      }

      nhrp_debug("Multicast from %s to %s",
                 nhrp_address_format(&src, sizeof(fr), fr),
                 nhrp_address_format(&dst, sizeof(to), to));

      pkt.iface = iface;
      pkt.pdulen = ntohs(iph->tot_len);
      partial_checksum = FALSE;
      for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
           cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_PACKET &&
            cmsg->cmsg_type == PACKET_AUXDATA &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(struct tpacket_auxdata))) {
          struct tpacket_auxdata *aux = (void *)CMSG_DATA(cmsg);
          partial_checksum = aux->tp_status & TP_STATUS_CSUMNOTREADY;
        }
      }
      if (partial_checksum && !complete_multicast_checksum(&pkt)) {
        multicast_error("unsupported or invalid partial checksum");
        continue;
      }
      send_multicast(&pkt);
    } else {
      if (lladdr->sll_pkttype != PACKET_HOST)
        continue;

      nhrp_address_set(&nbma_src, PF_INET, lladdr->sll_halen, lladdr->sll_addr);
      nhrp_packet_send_traffic(iface, &nbma_src, &src, &dst,
                               lladdr->sll_protocol, iov.iov_base, r);
    }
  }
}

int forward_init(void) {
  int fd, enabled = 1;

  fd = socket(PF_PACKET, SOCK_DGRAM, ntohs(ETH_P_ALL));
  if (fd < 0) {
    if (errno == EPERM || errno == EACCES) {
      nhrp_info("Non-root environment: forward_init in test mode");
      return TRUE;
    }
    nhrp_error("Unable to create PF_PACKET socket");
    return FALSE;
  }

  fcntl(fd, F_SETFD, FD_CLOEXEC);
  if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &enabled, sizeof(enabled))) {
    nhrp_perror("Unable to enable packet checksum metadata");
    close(fd);
    return FALSE;
  }

  ev_io_init(&packet_io, pfp_read_cb, fd, EV_READ);
  ev_io_start(&packet_io);

  ev_timer_init(&install_filter_timer, install_filter_cb, .01, .0);
  install_filter_cb(&install_filter_timer, 0);

  return TRUE;
}

void forward_cleanup(void) {
  ev_io_stop(&packet_io);
  close(packet_io.fd);
  ev_timer_stop(&install_filter_timer);
}
