/* Exercise the production peer list and packet path without CAP_NET_RAW. */
#include <assert.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

static unsigned int sends, reads, failures, interrupt_send, block_send;
static unsigned char sent_destination[4], sent_packet[65535];
static size_t sent_length;
static int receive_flags;
static int partial_checksum;

static ssize_t test_sendmsg(int fd, const struct msghdr *msg, int flags) {
  const struct sockaddr_ll *addr = msg->msg_name;
  (void)fd;
  assert(flags & MSG_DONTWAIT);
  if (interrupt_send) {
    interrupt_send = 0;
    errno = EINTR;
    return -1;
  }
  sends++;
  if (block_send) {
    errno = EAGAIN;
    return -1;
  }
  assert(addr->sll_halen == 4);
  memcpy(sent_destination, addr->sll_addr, 4);
  sent_length = msg->msg_iov[0].iov_len;
  assert(sent_length <= sizeof(sent_packet));
  memcpy(sent_packet, msg->msg_iov[0].iov_base, sent_length);
  return sent_length;
}

static ssize_t test_recvmsg(int fd, struct msghdr *msg, int flags) {
  struct sockaddr_ll *addr = msg->msg_name;
  struct msghdr data = *msg;
  ssize_t n;
  reads++;
  data.msg_name = NULL;
  data.msg_namelen = 0;
  data.msg_control = NULL;
  data.msg_controllen = 0;
  n = recvmsg(fd, &data, flags);
  msg->msg_flags = data.msg_flags | receive_flags;
  if (partial_checksum) {
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
    struct tpacket_auxdata *aux = (void *)CMSG_DATA(cmsg);
    cmsg->cmsg_level = SOL_PACKET;
    cmsg->cmsg_type = PACKET_AUXDATA;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*aux));
    *aux = (struct tpacket_auxdata){.tp_status = TP_STATUS_CSUMNOTREADY};
    msg->msg_controllen = CMSG_SPACE(sizeof(*aux));
  } else {
    msg->msg_controllen = 0;
  }
  *addr = (struct sockaddr_ll){.sll_ifindex = 1,
                               .sll_protocol = htons(ETH_P_IP),
                               .sll_pkttype = PACKET_OUTGOING};
  return n;
}

#define sendmsg test_sendmsg
#define recvmsg test_recvmsg
#include "../nhrp/platform/sysdep_pfpacket.c"
#undef sendmsg
#undef recvmsg
#include "../nhrp/core/nhrp_peer.c"

static struct nhrp_interface iface;
int nhrp_verbose;

void nhrp_log(int level, const char *format, ...) {
  (void)format;
  if (level == NHRP_LOG_ERROR)
    failures++;
}
void nhrp_perror(const char *message) { assert(!message); }
struct nhrp_interface *nhrp_interface_get_by_index(unsigned int index,
                                                   int create) {
  (void)create;
  assert(index == 1);
  return &iface;
}
int __wrap_nhrp_packet_send_traffic(struct nhrp_interface *interface,
                                    struct nhrp_address *nbma_src,
                                    struct nhrp_address *src,
                                    struct nhrp_address *dst, int protocol,
                                    uint8_t *pdu, size_t len) {
  (void)interface;
  (void)nbma_src;
  (void)src;
  (void)dst;
  (void)protocol;
  (void)pdu;
  (void)len;
  assert(!"unexpected unicast traffic indication");
  return FALSE;
}

int main(void) {
  struct nhrp_peer anchor = {.interface = &iface,
                             .type = NHRP_PEER_TYPE_STATIC,
                             .flags = NHRP_PEER_FLAG_UP};
  struct nhrp_peer active = {.interface = &iface,
                             .type = NHRP_PEER_TYPE_HA_ACTIVE,
                             .flags = NHRP_PEER_FLAG_UP};
  struct multicast_packet pkt = {.iface = &iface, .pdulen = 20};
  struct iphdr *iph = (struct iphdr *)pkt.pdu;
  int fd[2];
  unsigned int before;

  ev_default_loop(0);
  iface.flags = NHRP_INTERFACE_FLAG_CONFIGURED;
  iface.mcast_mask = BIT(NHRP_PEER_TYPE_STATIC) | BIT(NHRP_PEER_TYPE_HA_ACTIVE);
  list_init(&iface.mcast_list);
  list_init(&anchor.mcast_list_entry);
  list_init(&active.mcast_list_entry);
  ev_timer_init(&anchor.timer, NULL, 0., 0.);
  assert(nhrp_address_parse("10.20.0.1", &anchor.protocol_address, NULL));
  active.protocol_address = anchor.protocol_address;
  assert(nhrp_address_parse("192.0.2.1", &anchor.next_hop_address, NULL));
  assert(nhrp_address_parse("192.0.2.2", &active.next_hop_address, NULL));
  assert(nhrp_address_parse("192.0.2.3", &active.local_connect_address, NULL));
  nhrp_peer_update_multicast(&anchor);
  assert(list_hashed(&anchor.mcast_list_entry));
  nhrp_peer_update_multicast(&active);
  suspend_static_cb(NULL, &anchor);
  assert(!list_hashed(&anchor.mcast_list_entry));
  nhrp_peer_update_multicast(&anchor); /* A late refresh cannot re-add it. */
  assert(!list_hashed(&anchor.mcast_list_entry));
  interrupt_send = 1;
  send_multicast(&pkt);
  assert(sends == 1 && !interrupt_send);
  assert(memcmp(sent_destination, active.local_connect_address.addr, 4) == 0);
  active.local_connect_address.type = PF_UNSPEC;
  active.next_hop_address = anchor.next_hop_address; /* Hub switch. */
  nhrp_peer_update_multicast(&active);
  send_multicast(&pkt);
  assert(sends == 2 &&
         memcmp(sent_destination, anchor.next_hop_address.addr, 4) == 0);
  /* Explicit destinations also select the active peer and exclude bootstrap. */
  iface.mcast_mask = 0;
  iface.mcast_numaddr = 1;
  iface.mcast_addr = &active.protocol_address;
  nhrp_peer_update_multicast(&active);
  assert(list_hashed(&active.mcast_list_entry));
  active.flags = 0;
  send_multicast(&pkt);
  assert(sends == 2);
  active.flags = NHRP_PEER_FLAG_UP | NHRP_PEER_FLAG_REMOVED;
  send_multicast(&pkt);
  assert(sends == 2);
  active.flags = NHRP_PEER_FLAG_UP;
  block_send = 1;
  send_multicast(&pkt);
  assert(sends == 3 && failures == 1);
  send_multicast(&pkt);
  assert(failures == 1); /* Failure logs are throttled. */
  block_send = 0;

  /* Real datagrams exercise the receive size and bounded callback. */
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fd) == 0);
  ev_io_init(&packet_io, pfp_read_cb, fd[1], EV_READ);
  *iph = (struct iphdr){.version = 4,
                        .ihl = 5,
                        .tot_len = htons(2000),
                        .daddr = htonl(0xef010101)};
  memset(pkt.pdu + sizeof(*iph), 0xa5, 2000 - sizeof(*iph));
  assert(send(fd[0], pkt.pdu, 2000, 0) == 2000);
  pfp_read_cb(&packet_io, EV_READ);
  assert(sent_length == 2000 && memcmp(sent_packet, pkt.pdu, 2000) == 0);
  before = sends;
  receive_flags = MSG_TRUNC;
  assert(send(fd[0], pkt.pdu, 2000, 0) == 2000);
  pfp_read_cb(&packet_io, EV_READ);
  assert(sends == before);
  receive_flags = 0;
  iph->tot_len = htons(2001);
  assert(send(fd[0], pkt.pdu, 2000, 0) == 2000);
  pfp_read_cb(&packet_io, EV_READ);
  assert(sends == before);
  iph->tot_len = htons(2000);
  for (int i = 0; i < 40; i++)
    assert(send(fd[0], pkt.pdu, 2000, 0) == 2000);
  reads = 0;
  pfp_read_cb(&packet_io, EV_READ);
  assert(reads == 16 && sends == before + 16);
  pfp_read_cb(&packet_io, EV_READ);
  pfp_read_cb(&packet_io, EV_READ);
  assert(sends == before + 40);

  /* Known wire checksums include odd payload lengths and the pseudo-header. */
  {
    uint8_t odd[] = {1, 2, 3};
    struct udphdr *udp = (void *)(pkt.pdu + sizeof(*iph));
    struct tcphdr *tcp = (void *)udp;
    assert(ntohs(nhrp_calculate_checksum(odd, sizeof(odd))) == 0xfbfd);
    iph->protocol = IPPROTO_UDP;
    iph->tot_len = htons(sizeof(*iph) + sizeof(*udp) + 9);
    *udp = (struct udphdr){.source = htons(12000),
                           .dest = htons(31020),
                           .len = htons(17),
                           .check = htons(0xf9f9)};
    memcpy(udp + 1, "multicast", 9);
    partial_checksum = 1;
    assert(send(fd[0], pkt.pdu, ntohs(iph->tot_len), 0) == ntohs(iph->tot_len));
    pfp_read_cb(&packet_io, EV_READ);
    assert(((struct udphdr *)(sent_packet + sizeof(*iph)))->check ==
           htons(0x4527));
    iph->protocol = IPPROTO_TCP;
    pkt.pdulen = sizeof(*iph) + sizeof(*tcp) + 1;
    memset(tcp, 0, sizeof(*tcp));
    tcp->source = htons(12000);
    tcp->dest = htons(31020);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(4096);
    tcp->check = htons(0xf9f2);
    *((uint8_t *)(tcp + 1)) = 'x';
    assert(complete_multicast_checksum(&pkt));
    assert(tcp->check == htons(0x85fd));
    iph->frag_off = htons(IP_MF);
    assert(!complete_multicast_checksum(&pkt));
  }
  close(fd[0]);
  close(fd[1]);
  ev_loop_destroy();
  puts("Multicast HA membership, addressing, packet size and bounded "
       "forwarding passed");
  return 0;
}
