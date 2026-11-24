/* Real request callbacks and timers, with allocation failure injection. */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

static void *test_calloc(size_t count, size_t size);
static void test_free(void *ptr);
#define calloc test_calloc
#define free test_free
#include "../nhrp/core/nhrp_peer.c"
#include "../nhrp/core/nhrp_packet.c"
#undef calloc
#undef free

static void *allocations[64];
static size_t live_allocations;
static unsigned int fail_cie, fail_packet;
static struct nhrp_interface iface;
static struct nhrp_peer *traffic_peer;
static struct nhrp_address neighbor_destination, registration_destination;
int nhrp_verbose, nhrp_running = 1;
const char *nhrp_script_file = "/bin/true";

static void *test_calloc(size_t count, size_t size) {
  void *ptr;
  size_t i;
  if (size == sizeof(struct nhrp_cie) && fail_cie && --fail_cie == 0) {
    errno = ENOMEM;
    return NULL;
  }
  if (size == sizeof(struct nhrp_packet) && fail_packet && --fail_packet == 0) {
    errno = ENOMEM;
    return NULL;
  }
  ptr = calloc(count, size);
  assert(ptr);
  for (i = 0; i < ARRAY_SIZE(allocations); i++) {
    if (allocations[i] != NULL)
      continue;
    allocations[i] = ptr;
    live_allocations++;
    return ptr;
  }
  assert(!"too many outstanding production allocations");
  return NULL;
}

static void test_free(void *ptr) {
  size_t i;
  for (i = 0; ptr && i < ARRAY_SIZE(allocations); i++) {
    if (allocations[i] != ptr)
      continue;
    allocations[i] = NULL;
    live_allocations--;
    break;
  }
  free(ptr);
}

void nhrp_log(int level, const char *format, ...) {
  (void)level;
  (void)format;
}
int nhrp_interface_foreach(nhrp_interface_enumerator cb, void *ctx) {
  return cb(ctx, &iface);
}
struct nhrp_peer *nhrp_interface_find_peer(struct nhrp_interface *interface,
                                            const struct nhrp_address *nbma) {
  assert(interface == &iface && traffic_peer);
  assert(nhrp_address_cmp(nbma, &traffic_peer->next_hop_address) == 0);
  return traffic_peer;
}
int nhrp_ha_prepare_outgoing(struct nhrp_packet *packet) {
  (void)packet;
  return TRUE;
}
int nhrp_ha_prepare_registration_discovery(struct nhrp_peer *peer,
                                           struct nhrp_packet *packet) {
  (void)peer;
  (void)packet;
  return TRUE;
}
int nhrp_ha_handle_registration_discovery(struct nhrp_peer *peer,
                                          struct nhrp_packet *packet) {
  (void)peer;
  (void)packet;
  return TRUE;
}
void nhrp_server_finish_request(struct nhrp_pending_request *request) {
  assert(!request);
}
void kernel_refresh_addresses(void) {}
int forward_local_addresses_changed(void) { return TRUE; }
int kernel_route(struct nhrp_interface *src, struct nhrp_address *dst,
                   struct nhrp_address *via, struct nhrp_address *address,
                   uint16_t *mtu) {
  (void)src;
  (void)dst;
  (void)via;
  (void)address;
  (void)mtu;
  return FALSE;
}
int kernel_inject_neighbor(struct nhrp_address *protocol,
                             struct nhrp_address *nbma,
                             struct nhrp_interface *interface) {
  (void)protocol;
  if (nbma != NULL)
    neighbor_destination = *nbma;
  (void)interface;
  return TRUE;
}
int kernel_send(uint8_t *pdu, size_t length, struct nhrp_interface *interface,
                  struct nhrp_address *address) {
  (void)pdu;
  (void)length;
  (void)interface;
  if (length >= sizeof(struct nhrp_packet_header) &&
      ((struct nhrp_packet_header *)pdu)->type == NHRP_PACKET_REGISTRATION_REQUEST)
    registration_destination = *address;
  return TRUE;
}
char *nhrp_env(const char *key, const char *value) {
  (void)key;
  (void)value;
  return NULL;
}
char *nhrp_envu32(const char *key, uint32_t value) {
  (void)key;
  (void)value;
  return NULL;
}

static struct nhrp_packet *pending_request(void) {
  assert(!list_empty(&pending_requests));
  return container_of(pending_requests.next, struct nhrp_packet,
                      request_list_entry);
}

static void test_nat_by_registration_source(void) {
  struct nhrp_interface tunnel = {0};
  struct nhrp_peer first = {.interface = &tunnel,
      .flags = NHRP_PEER_FLAG_REGISTER | NHRP_PEER_FLAG_UP};
  struct nhrp_peer second = first;
  struct nhrp_peer destination = {.interface = &tunnel};

  list_init(&tunnel.peer_list);
  list_add(&first.peer_list_entry, &tunnel.peer_list);
  list_add(&second.peer_list_entry, &tunnel.peer_list);
  assert(nhrp_address_parse("192.0.2.10", &first.my_nbma_address, NULL));
  assert(nhrp_address_parse("198.51.100.10", &second.my_nbma_address, NULL));
  assert(nhrp_address_parse("203.0.113.10", &first.nat_nbma_address, NULL));
  assert(nhrp_address_parse("203.0.113.11", &second.nat_nbma_address, NULL));
  first.nat_source_address = first.my_nbma_address;
  second.nat_source_address = second.my_nbma_address;

  assert(nhrp_peer_nat_nbma(&first) == &first.nat_nbma_address);
  assert(nhrp_peer_nat_nbma(&second) == &second.nat_nbma_address);
  destination.my_nbma_address = first.my_nbma_address;
  assert(nhrp_peer_nat_nbma(&destination) == &first.nat_nbma_address);
  destination.my_nbma_address = second.my_nbma_address;
  assert(nhrp_peer_nat_nbma(&destination) == &second.nat_nbma_address);

  second.my_nbma_address = first.my_nbma_address;
  assert(!nhrp_peer_nat_nbma(&second));
  second.nat_source_address = second.my_nbma_address;
  destination.my_nbma_address = first.my_nbma_address;
  assert(!nhrp_peer_nat_nbma(&destination));
  assert(nhrp_peer_nat_nbma(&first) == &first.nat_nbma_address);
  nhrp_address_set_type(&second.nat_nbma_address, AF_UNSPEC);
  assert(!nhrp_peer_nat_nbma(&second));
  assert(nhrp_peer_nat_nbma(&first) == &first.nat_nbma_address);
}

static void expire_peer(struct nhrp_peer *peer) {
  assert(ev_is_active(&peer->timer));
  ev_timer_stop(&peer->timer);
  ev_timer_set(&peer->timer, 0., 0.);
  ev_timer_start(&peer->timer);
  ev_run(EVRUN_NOWAIT);
}

int main(void) {
  struct nhrp_peer *nhs, *peer;
  struct nhrp_address dst;
  size_t baseline;
  int i;

  test_nat_by_registration_source();

  ev_default_loop(0);
  strcpy(iface.name, "test");
  list_init(&iface.peer_list);
  list_init(&iface.mcast_list);
  assert(nhrp_address_parse("10.0.0.1", &iface.protocol_address, NULL));
  assert(nhrp_address_parse("192.0.2.1", &iface.nbma_address, NULL));
  nhs = nhrp_peer_alloc(&iface);
  nhs->type = NHRP_PEER_TYPE_STATIC;
  nhs->flags = NHRP_PEER_FLAG_UP | NHRP_PEER_FLAG_LOWER_UP |
               NHRP_PEER_FLAG_REPLACED;
  assert(nhrp_address_parse("0.0.0.0", &nhs->protocol_address, NULL));
  assert(nhrp_address_parse("192.0.2.2", &nhs->next_hop_address, NULL));
  nhs->my_nbma_address = iface.nbma_address;
  nhs->afnum = AFNUM_INET;
  nhs->protocol_type = ETHPROTO_IP;
  list_add(&nhs->peer_list_entry, &iface.peer_list);
  list_add(&nhs->enumeration_entry, &enumeration_peers);
  baseline = live_allocations;

  for (i = 0; i < 1000; i++) {
    uint32_t raw = htonl(0x0b000001 + i);
    struct nhrp_packet *request, *reply;
    struct nhrp_cie *cie;
    nhrp_address_set(&dst, AF_INET, 4, (void *)&raw);
    nhrp_peer_traffic_indication(&iface, AFNUM_INET, &dst);
    request = pending_request();
    reply = nhrp_packet_alloc();
    reply->hdr.type = NHRP_PACKET_RESOLUTION_REPLY;
    reply->hdr.u.request_id = request->hdr.u.request_id;
    reply->src_nbma_address = request->src_nbma_address;
    reply->src_protocol_address = request->src_protocol_address;
    if (i % 2) {
      cie = nhrp_cie_alloc();
      cie->hdr.code = NHRP_CODE_NO_BINDING_EXISTS;
      nhrp_payload_add_cie(nhrp_packet_payload(reply, NHRP_PAYLOAD_TYPE_CIE_LIST),
                           cie);
    }
    assert(nhrp_packet_receive_local(reply));
    nhrp_packet_put(reply);
    assert(list_empty(&pending_requests));
    peer = nhrp_peer_route(&iface, &dst, NHRP_PEER_FIND_EXACT,
                            BIT(NHRP_PEER_TYPE_NEGATIVE));
    assert(peer && ev_is_active(&peer->timer));
    assert(peer->expire_time > ev_now() &&
           peer->expire_time <= ev_now() + NHRP_NEGATIVE_CACHE_TIME);
    nhrp_peer_traffic_indication(&iface, AFNUM_INET, &dst);
    assert(list_empty(&pending_requests)); /* Suppress retries until expiry. */
    expire_peer(peer);
    assert(live_allocations == baseline && nhrp_peer_num_total == 1);

    /* Expiry permits another request; its real timeout also frees the peer. */
    nhrp_peer_traffic_indication(&iface, AFNUM_INET, &dst);
    request = pending_request();
    request->max_retries = 1;
    nhrp_packet_xmit_timeout_cb(&request->timeout, EV_TIMER);
    ev_run(EVRUN_NOWAIT);
    assert(list_empty(&pending_requests));
    assert(live_allocations == baseline && nhrp_peer_num_total == 1);
  }

  /* A successful off-NBMA reply still replaces INCOMPLETE with a shortcut. */
  {
    struct nhrp_packet *request, *reply;
    struct nhrp_peer *shortcut;
    struct nhrp_cie *cie;
    nhrp_peer_traffic_indication(&iface, AFNUM_INET, &dst);
    request = pending_request();
    peer = nhrp_peer_route(&iface, &dst, NHRP_PEER_FIND_EXACT,
                            BIT(NHRP_PEER_TYPE_INCOMPLETE));
    assert(peer);
    reply = nhrp_packet_alloc();
    reply->hdr = request->hdr;
    reply->hdr.type = NHRP_PACKET_RESOLUTION_REPLY;
    reply->src_nbma_address = request->src_nbma_address;
    reply->src_protocol_address = request->src_protocol_address;
    cie = nhrp_cie_alloc();
    cie->hdr.prefix_length = 32;
    cie->hdr.holding_time = htons(60);
    cie->protocol_address = nhs->protocol_address;
    cie->nbma_address = nhs->next_hop_address;
    nhrp_payload_add_cie(nhrp_packet_payload(reply, NHRP_PAYLOAD_TYPE_CIE_LIST),
                           cie);
    nhrp_running = 0; /* Inspect the new route before its script is scheduled. */
    assert(nhrp_packet_receive_local(reply));
    nhrp_packet_put(reply);
    assert(list_empty(&pending_requests));
    assert(peer->flags & NHRP_PEER_FLAG_REMOVED);
    shortcut = nhrp_peer_route(&iface, &dst, NHRP_PEER_FIND_EXACT,
                                BIT(NHRP_PEER_TYPE_SHORTCUT_ROUTE));
    assert(shortcut && ev_is_active(&shortcut->timer));
    nhrp_peer_remove(shortcut);
    ev_run(EVRUN_NOWAIT);
    nhrp_running = 1;
    assert(live_allocations == baseline && nhrp_peer_num_total == 1);
  }

  /* Registration packet/CIE failures must release allocations and retry. */
  for (i = 0; i <= 2; i++) {
    fail_cie = i;
    fail_packet = i == 0;
    nhrp_peer_send_register_cb(&nhs->timer, 0);
    assert(!fail_cie && !fail_packet && live_allocations == baseline);
    assert(ev_is_active(&nhs->timer));
    assert(nhs->timer.cb == nhrp_peer_restart_cb);
    ev_timer_stop(&nhs->timer);
  }

  /* Failed resolution allocation must not leave an immortal cache entry. */
  for (i = 0; i < 2; i++) {
    fail_cie = i;
    fail_packet = i == 0;
    nhrp_peer_traffic_indication(&iface, AFNUM_INET, &dst);
    assert(!fail_cie && !fail_packet && list_empty(&pending_requests));
    peer = nhrp_peer_route(&iface, &dst, NHRP_PEER_FIND_EXACT,
                            BIT(NHRP_PEER_TYPE_NEGATIVE));
    assert(peer && ev_is_active(&peer->timer));
    expire_peer(peer);
    assert(live_allocations == baseline);
  }

  /* The remaining packet-allocation callers also accept a NULL result. */
  {
    struct nhrp_packet request = {.hdr.type = NHRP_PACKET_RESOLUTION_REQUEST};
    struct nhrp_address all = {0};
    fail_packet = 1;
    assert(!nhrp_packet_send_error(&request, NHRP_ERROR_PROTOCOL_ERROR, 0));
    assert(!fail_packet && live_allocations == baseline);
    traffic_peer = nhs;
    nhs->type = NHRP_PEER_TYPE_DYNAMIC;
    iface.flags |= NHRP_INTERFACE_FLAG_REDIRECT;
    fail_packet = 1;
    assert(!nhrp_packet_send_traffic(&iface, &nhs->next_hop_address,
                                      &iface.protocol_address, &dst,
                                      ETHPROTO_IP, NULL, 0));
    assert(!fail_packet);
    assert(nhrp_rate_limit_clear(&all, 0) == 1);
    assert(live_allocations == baseline);
    nhs->type = NHRP_PEER_TYPE_STATIC;
  }

  nhs->flags = NHRP_PEER_FLAG_DISCOVER_NHS | NHRP_PEER_FLAG_REGISTER |
               NHRP_PEER_FLAG_LOWER_UP | NHRP_PEER_FLAG_REPLACED;
  nhrp_address_set_type(&nhs->protocol_address, AF_UNSPEC);
  nhs->prefix_length = 32;
  assert(nhrp_address_parse("172.29.1.250", &nhs->forwarding_nbma, NULL));
  struct nhrp_address announcement, withdrawal = {0};
  assert(nhrp_address_parse("172.29.1.251", &announcement, NULL));
  for (i = 0; i < 4; i++) {
    struct nhrp_packet *request, *reply;
    struct nhrp_cie *cie;

    if (i == 1)
      nhs->forwarding_policy = NHRP_FORWARDING_ORDINARY;
    if (i == 2)
      nhrp_address_set_type(&nhs->forwarding_nbma, AF_UNSPEC);
    nhrp_peer_send_register_cb(&nhs->timer, 0);
    request = pending_request();
    assert((nhrp_packet_forwarding_payload(request, NHRP_EXTENSION_FORWARDING_NBMA) != NULL) ==
           (i > 0));
    assert(!nhrp_address_cmp(&registration_destination, &nhs->next_hop_address));
    assert(request->hdr.hop_count == 1);
    assert(!nhrp_address_cmp(&request->dst_protocol_address, &iface.protocol_address));
    reply = nhrp_packet_alloc();
    reply->hdr = request->hdr;
    reply->hdr.type = NHRP_PACKET_REGISTRATION_REPLY;
    reply->src_iface = &iface;
    reply->src_nbma_address = request->src_nbma_address;
    reply->src_protocol_address = request->src_protocol_address;
    assert(nhrp_address_parse(i ? "10.0.0.3" : "10.0.0.2",
                              &reply->dst_protocol_address, NULL));
    cie = nhrp_cie_alloc();
    cie->hdr.code = NHRP_CODE_SUCCESS;
    nhrp_payload_add_cie(nhrp_packet_payload(reply, NHRP_PAYLOAD_TYPE_CIE_LIST), cie);
    nhrp_packet_request_forwarding(reply, NHRP_EXTENSION_FORWARDING_NBMA);
    nhrp_packet_reply_forwarding(reply, NHRP_EXTENSION_FORWARDING_NBMA,
                                 i == 3 ? &withdrawal : &announcement);
    assert(nhrp_packet_receive_local(reply));
    assert(pending_request() == request); /* Ignore a reply from another NBMA. */
    reply->src_linklayer_address = nhs->next_hop_address;
    assert(nhrp_packet_receive_local(reply));
    assert(list_empty(&pending_requests));
    assert(!nhrp_address_cmp(&nhs->protocol_address, &reply->dst_protocol_address));
    assert(nhs->flags & NHRP_PEER_FLAG_UP);
    nhrp_peer_renew(nhs);
    assert(nhs->type == NHRP_PEER_TYPE_STATIC && list_empty(&pending_requests));
    assert(!nhrp_address_cmp(&neighbor_destination,
                             i < 2 ? &nhs->forwarding_nbma :
                             i == 2 ? &announcement : &nhs->next_hop_address));
    assert(nhs->advertised_forwarding_nbma.type ==
           (i == 1 || i == 2 ? AF_INET : AF_UNSPEC));
    nhrp_packet_put(reply);
  }
  nhrp_peer_send_register_cb(&nhs->timer, 0);
  pending_request()->max_retries = 1;
  nhrp_packet_xmit_timeout_cb(&pending_request()->timeout, EV_TIMER);
  assert(nhs->protocol_address.type == AF_UNSPEC && !(nhs->flags & NHRP_PEER_FLAG_UP));
  assert(live_allocations == baseline);
  nhrp_peer_remove(nhs);
  ev_run(EVRUN_NOWAIT);
  assert(list_empty(&iface.peer_list) && list_empty(&enumeration_peers));
  assert(nhrp_peer_num_total == 0 && live_allocations == 0);
  ev_loop_destroy();
  puts("Resolution reply, timeout and allocation-failure lifetime tests passed");
  return 0;
}
