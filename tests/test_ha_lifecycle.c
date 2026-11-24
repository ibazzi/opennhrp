/* Exercise candidate request ownership and configuration retirement. */
#include <stdlib.h>
static unsigned int allocation_failure;
static void *test_calloc(size_t count, size_t size) {
  if (allocation_failure != 0 && --allocation_failure == 0)
    return NULL;
  return calloc(count, size);
}
#define calloc test_calloc
#include "../nhrp/ha/nhrp_ha.c"
#undef calloc
#include "../nhrp/core/nhrp_packet.c"
#include <assert.h>

int nhrp_running, nhrp_verbose;
static struct nhrp_interface iface;
static kernel_neighbor_callback neighbor_callback;
static void *neighbor_ctx;
static unsigned int completed;
static struct nhrp_address sent_destination, route_destination, route_source;

void nhrp_log(int level, const char *format, ...) {}
void admin_ha_notify(struct nhrp_interface *interface) {}
struct nhrp_interface *nhrp_interface_get_by_name(const char *name, int create) {
  return &iface;
}
struct nhrp_peer *nhrp_peer_alloc(struct nhrp_interface *interface) {
  struct nhrp_peer *peer = calloc(1, sizeof(*peer));
  assert(peer != NULL);
  peer->interface = interface;
  return peer;
}
int nhrp_peer_put(struct nhrp_peer *peer) {
  free(peer);
  return 0;
}
struct nhrp_peer *nhrp_peer_get(struct nhrp_peer *peer) {
  assert(!"unexpected peer lookup");
  return peer;
}
struct nhrp_peer *nhrp_peer_route_full(struct nhrp_interface *interface,
                                       struct nhrp_address *dest, int flags,
                                       int type_mask,
                                       struct nhrp_address *source,
                                       struct list_head *exclude) {
  assert(!"unexpected peer route lookup");
  return NULL;
}
int kernel_route(struct nhrp_interface *out, struct nhrp_address *dest,
                 struct nhrp_address *source, struct nhrp_address *next,
                 uint16_t *mtu) {
  assert(nhrp_address_cmp(dest, &route_destination) == 0);
  *source = route_source;
  *mtu = 1492;
  return TRUE;
}
int kernel_inject_neighbor_async(struct nhrp_address *protocol,
                                 struct nhrp_address *nbma,
                                 struct nhrp_interface *interface,
                                 kernel_neighbor_callback callback, void *ctx) {
  assert(neighbor_callback == NULL);
  neighbor_callback = callback;
  neighbor_ctx = ctx;
  return TRUE;
}
struct nhrp_peer *nhrp_peer_ha_commit(struct nhrp_interface *interface,
                                      struct nhrp_address *protocol,
                                      uint8_t prefix,
                                      struct nhrp_address *nbma,
                                      struct nhrp_address *local) {
  struct nhrp_peer *peer = nhrp_peer_alloc(interface);
  peer->next_hop_address = *nbma;
  return peer;
}
void nhrp_peer_ha_suspend_static(struct nhrp_interface *interface,
                                struct nhrp_address *protocol) {}
void nhrp_peer_ha_resume_static(struct nhrp_interface *interface,
                                const struct nhrp_address *protocol) {}
void nhrp_peer_remove(struct nhrp_peer *peer) {}
void nhrp_peer_update_multicast(struct nhrp_peer *peer) {}
const struct nhrp_address *nhrp_peer_nat_nbma(const struct nhrp_peer *peer) {
  return NULL;
}
int kernel_send(uint8_t *data, size_t length, struct nhrp_interface *interface,
                struct nhrp_address *destination) {
  sent_destination = *destination;
  return TRUE;
}

static void test_candidate_connect_address(void) {
  struct nhrp_address protocol, public, local, override_address, expected;
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;
  struct nhrp_ha_local_override override = {.interface = &iface,
                                            .configured = TRUE};
  struct nhrp_packet *request, *reply;
  struct nhrp_payload *payload;
  struct nhrp_cie *cie;
  struct nhrp_peer *peer;
  unsigned int mode, invalid;

  assert(nhrp_address_parse("10.99.0.1", &protocol, NULL));
  assert(nhrp_address_parse("192.0.2.1", &public, NULL));
  assert(nhrp_address_parse("172.29.1.250", &local, NULL));
  assert(nhrp_address_parse("172.29.1.251", &override_address, NULL));
  assert(
      nhrp_ha_config_map(&iface, &protocol, 24, "connect-test", &public, 100));
  service = service_find(&iface, &protocol);
  candidate = candidate_find(service, "connect-test");
  service->active = candidate;
  strcpy(override.member_id, candidate->member_id);
  override.local_nbma = override_address;

  for (mode = 0; mode < 3; mode++) {
    expected = mode == 0 ? public : mode == 1 ? local : override_address;
    if (mode == 1)
      candidate->bootstrap_local_nbma = local;
    if (mode == 2)
      list_add(&override.list_entry, &local_overrides);

    registration_timer_cb(&candidate->registration_timer, 0);
    assert(nhrp_address_cmp(&sent_destination, &expected) == 0);
    request = list_entry(pending_requests.next, struct nhrp_packet,
                         request_list_entry);
    assert(nhrp_address_cmp(&request->dst_peer->next_hop_address, &public) ==
           0);
    reply = nhrp_packet_alloc();
    reply->hdr.type = NHRP_PACKET_REGISTRATION_REPLY;
    reply->src_linklayer_address = expected;
    payload =
        nhrp_packet_extension(reply, NHRP_EXTENSION_HA, NHRP_PAYLOAD_TYPE_RAW);
    nhrp_payload_set_raw(payload,
                         ha_member_payload(candidate->member_id,
                                           candidate->registration_generation));
    payload = nhrp_packet_payload(reply, NHRP_PAYLOAD_TYPE_CIE_LIST);
    cie = nhrp_cie_alloc();
    cie->hdr.code = NHRP_CODE_SUCCESS;
    nhrp_payload_add_cie(payload, cie);
    request->handler(request->handler_ctx, reply);
    nhrp_packet_dequeue(request);
    nhrp_packet_put(reply);
    assert(candidate->registered && candidate->pending_requests == 0);

    for (invalid = 0; invalid < 3; invalid++) {
      unsigned int samples = candidate->quality.samples;
      probe_timer_cb(&candidate->probe_timer, 0);
      assert(nhrp_address_cmp(&sent_destination, &expected) == 0);
      request = list_entry(pending_requests.next, struct nhrp_packet,
                           request_list_entry);
      reply = nhrp_packet_alloc();
      reply->hdr.type = NHRP_PACKET_RESOLUTION_REPLY;
      reply->src_linklayer_address = expected;
      if (invalid == 1)
        assert(nhrp_address_parse("198.51.100.99",
                                  &reply->src_linklayer_address, NULL));
      payload = nhrp_packet_extension(reply, NHRP_EXTENSION_HA,
                                      NHRP_PAYLOAD_TYPE_RAW);
      nhrp_payload_set_raw(
          payload, ha_probe_payload(
                       NHRP_HA_PROBE_REPLY, candidate->member_id,
                       candidate->probe_sequence, candidate->probe_generation,
                       candidate->probe_nonce + (invalid == 2), 0,
                       iface.protocol_address.addr_len * 8, TRUE, TRUE, 0, 0));
      /* An in-flight reply belongs to the address selected before reload. */
      if (mode == 2)
        override.local_nbma = public;
      else
        candidate->bootstrap_local_nbma = override_address;
      request->handler(request->handler_ctx, reply);
      override.local_nbma = override_address;
      candidate->bootstrap_local_nbma =
          mode == 0 ? (struct nhrp_address){0} : local;
      nhrp_packet_dequeue(request);
      nhrp_packet_put(reply);
      assert(candidate->pending_requests == 0 && !candidate->probe_pending);
      assert(candidate->quality.samples == samples + 1);
      assert(candidate->consecutive_misses == invalid);
    }
    assert(candidate_release_owner_token(service, candidate, 1, &public, TRUE));
    assert(nhrp_address_cmp(&sent_destination, &expected) == 0);
    if (mode == 2)
      list_del(&override.list_entry);
  }

  /* The connection address must also select the source required by IPsec. */
  struct nhrp_address saved_source = iface.nbma_address;
  nhrp_address_set_type(&iface.nbma_address, PF_UNSPEC);
  route_destination = local;
  assert(nhrp_address_parse("192.168.100.2", &route_source, NULL));
  peer = candidate_direct_peer(candidate, &public);
  assert(peer != NULL);
  assert(nhrp_address_cmp(&peer->my_nbma_address, &route_source) == 0);
  assert(nhrp_address_cmp(nhrp_peer_active_nbma(peer), &local) == 0);
  nhrp_peer_put(peer);
  iface.nbma_address = saved_source;
  /* Another Hub must not inherit this member's private destination. */
  struct nhrp_ha_candidate other = {.service = service};
  strcpy(other.member_id, "other-hub");
  peer = candidate_direct_peer(&other, &public);
  assert(peer != NULL);
  assert(nhrp_address_cmp(nhrp_peer_active_nbma(peer), &public) == 0);
  nhrp_peer_put(peer);
  assert(list_empty(&pending_requests));
}

static size_t candidate_count(struct nhrp_ha_service *service) {
  struct nhrp_ha_candidate *candidate;
  size_t count = 0;
  list_for_each_entry(candidate, &service->candidates, list_entry)
    count++;
  return count;
}

static size_t advertisement_count(struct nhrp_ha_advertisement *advertisement) {
  struct nhrp_ha_advertised_entry *entry;
  size_t count = 0;
  list_for_each_entry(entry, &advertisement->entries, list_entry)
    count++;
  return count;
}

static void test_hub_rotation(void) {
  struct nhrp_address protocol, nbma;
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *source, *previous, *current;
  struct nhrp_ha_hub_list list = {.entry_count = 1};
  size_t i;

  assert(nhrp_address_parse("10.0.0.1", &protocol, NULL));
  assert(nhrp_address_parse("192.0.2.1", &nbma, NULL));
  assert(nhrp_ha_config_map(&iface, &protocol, 24, "source", &nbma, 100));
  service = service_find(&iface, &protocol);
  source = candidate_find(service, "source");
  strcpy(list.source_member, "source");
  memcpy(list.entries[0].nbma, nbma.addr, 4);
  for (i = 1; i <= 1000; i++) {
    list.list_generation = i;
    snprintf(list.entries[0].member, sizeof(list.entries[0].member), "hub%zu", i);
    assert(hub_list_apply(source, &list));
    assert(candidate_count(service) == 2);
  }
  previous = candidate_find(service, "hub1000");
  assert(previous != NULL);
  /* The real timers create two independently owned callback contexts. */
  iface.index = 1;
  iface.nbma_address = nbma;
  iface.protocol_address = protocol;
  registration_timer_cb(&previous->registration_timer, 0);
  probe_timer_cb(&previous->probe_timer, 0);
  assert(previous->pending_requests == 2);
  list.list_generation++;
  strcpy(list.entries[0].member, "latest");
  assert(hub_list_apply(source, &list));
  assert(!previous->configured && candidate_count(service) == 3);
  /* Drive the production packet timeout, including packet/context teardown. */
  struct nhrp_packet *packet =
      list_entry(pending_requests.next, struct nhrp_packet, request_list_entry);
  ev_invoke((ev_watcher *)&packet->timeout, EV_TIMER);
  assert(previous->pending_requests == 1 && candidate_count(service) == 3);
  packet = list_entry(pending_requests.next, struct nhrp_packet, request_list_entry);
  ev_invoke((ev_watcher *)&packet->timeout, EV_TIMER);
  assert(list_empty(&pending_requests));
  assert(candidate_find(service, "hub1000") == NULL);
  assert(candidate_count(service) == 2);

  current = candidate_find(service, "latest");
  quality_record(&current->quality, 100.0, TRUE, 0.0);
  list.list_generation++;
  assert(hub_list_apply(source, &list));
  assert(candidate_find(service, "latest") == current);
  assert(current->quality.samples == 1 && current->quality.failures == 1);

  list.entry_count = 2;
  list.list_generation++;
  list.entries[1] = list.entries[0];
  strcpy(list.entries[1].member, "source");
  list.entries[1].priority = 99;
  for (i = 0; i < 100; i++) {
    snprintf(list.entries[0].member, sizeof(list.entries[0].member), "invalid%zu", i);
    assert(!hub_list_apply(source, &list));
    assert(candidate_count(service) == 2 && current->dynamically_discovered);
  }
  strcpy(list.entries[0].member, "first-allocation");
  strcpy(list.entries[1].member, "second-allocation");
  allocation_failure = 2;
  assert(!hub_list_apply(source, &list));
  assert(allocation_failure == 0);
  assert(candidate_count(service) == 2 && current->dynamically_discovered);
}

static void selection_done(void *ctx, int status, const char *reason,
                           uint32_t generation) {
  assert(status == -EHOSTDOWN);
  completed++;
}

static void test_configuration_retirement(void) {
  struct nhrp_address protocol, nbma;
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *source, *target;
  struct nhrp_ha_advertisement *advertisement;
  size_t i;

  assert(nhrp_address_parse("10.0.0.1", &protocol, NULL));
  assert(nhrp_address_parse("192.0.2.1", &nbma, NULL));
  service = service_find(&iface, &protocol);
  source = candidate_find(service, "source");
  for (i = 1; i <= 1000; i++) {
    char member[64], address[64];
    snprintf(member, sizeof(member), "configured%zu", i);
    snprintf(address, sizeof(address), "192.0.%zu.%zu", i / 250, i % 250 + 1);
    assert(nhrp_address_parse(address, &nbma, NULL));
    nhrp_ha_mark_configured();
    assert(nhrp_ha_config_map(&iface, &protocol, 24, "source", &source->nbma, 100));
    assert(nhrp_ha_config_map(&iface, &protocol, 24, member, &nbma, 100));
    assert(nhrp_ha_config_advertise(&iface, &protocol, 24, i, "hub", &nbma, 100));
    nhrp_ha_sweep_unconfigured();
    advertisement = advertisement_find(&iface, &protocol);
    assert(candidate_count(service) == 3);
    assert(advertisement_count(advertisement) == 1);
  }
  target = candidate_find(service, "configured1000");
  for (i = 0; i < 100; i++) {
    struct nhrp_address rejected = nbma;
    rejected.addr[3] = 254;
    nhrp_ha_mark_configured();
    assert(nhrp_ha_config_map(&iface, &protocol, 24, "rejected", &rejected, 1));
    assert(nhrp_ha_config_advertise(&iface, &protocol, 24, 1001, "hub", &rejected, 1));
    nhrp_ha_config_reload_abort();
    assert(candidate_count(service) == 3 && candidate_find(service, "rejected") == NULL);
    assert(source->configured && source->static_configured);
    assert(target->configured && target->static_configured);
    assert(advertisement->generation == 1000);
    assert(advertisement_count(advertisement) == 1);
  }
  /* An outstanding Netlink selection keeps its target alive until the ACK. */
  service->switching = TRUE;
  service->switch_callback = selection_done;
  assert(candidate_begin_activation(service, target));
  nhrp_ha_mark_configured();
  assert(nhrp_ha_config_map(&iface, &protocol, 24, "source", &source->nbma, 100));
  nhrp_ha_sweep_unconfigured();
  assert(candidate_find(service, "configured1000") == target && !target->configured);
  neighbor_callback(neighbor_ctx, 0);
  neighbor_callback = NULL;
  assert(completed == 1 && candidate_count(service) == 2);
  assert(candidate_find(service, "configured1000") == NULL);

  /* Keep the old active object while a reconciliation and switch overlap. */
  target = candidate_find(service, "latest");
  service->active = target;
  reconcile_timer_cb(&service->reconcile_timer, 0);
  assert(service->reconciling && neighbor_callback != NULL);
  target->dynamically_discovered = FALSE;
  nhrp_ha_mark_configured();
  assert(nhrp_ha_config_map(&iface, &protocol, 24, "source", &source->nbma, 100));
  nhrp_ha_sweep_unconfigured();
  assert(!target->configured && candidate_count(service) == 2);
  service->active = source;
  candidates_sweep(service);
  assert(candidate_count(service) == 2);
  neighbor_callback(neighbor_ctx, 0);
  neighbor_callback = NULL;
  assert(service->reconcile_candidate == NULL && candidate_count(service) == 1);
  service->active = NULL;
}

static void test_managed_reload(void) {
  char directory[] = "/tmp/opennhrp-ha-lifecycle.XXXXXX";
  char state_path[PATH_MAX], keys_path[PATH_MAX], identity_path[PATH_MAX];
  char seen_path[PATH_MAX];
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_auth_keys keys;
  struct in_addr protocol, advertised;
  struct nhrp_ha_advertisement *advertisement;
  struct nhrp_ha_advertised_entry *old;
  struct nhrp_address old_nbma;
  size_t i;
  int fd;

  assert(mkdtemp(directory) != NULL);
  assert(inet_pton(AF_INET, "10.0.0.1", &protocol) == 1);
  assert(inet_pton(AF_INET, "192.0.2.10", &advertised) == 1);
  iface.protocol_address_prefix = 24;
  hub_enable.interface = &iface;
  hub_enable.configured = TRUE;
  strcpy(hub_enable.member_id, "hub");
  assert(nhrp_ha_managed_cluster_init(directory, iface.name, "hub", &protocol,
                                     24, &advertised, 1, &state) ==
         NHRP_HA_MANAGED_INIT_OK);
  assert(nhrp_ha_managed_paths(directory, state_path, sizeof(state_path),
                                keys_path, sizeof(keys_path), identity_path,
                                sizeof(identity_path)));
  assert(nhrp_ha_managed_keyring_load(keys_path, &keys));
  assert(nhrp_ha_prepare_managed(directory));
  advertisement = advertisement_find(&iface, &iface.protocol_address);
  for (i = 0; i < 50; i++) {
    advertised.s_addr = htonl(0xc000020b + i);
    state.members[0].addresses[0] = advertised;
    state.manifest_revision++;
    assert(nhrp_ha_managed_state_save(state_path, &keys, &state));
    assert(nhrp_ha_reload_managed(directory));
    assert(advertisement_count(advertisement) == 1);
  }
  old = list_entry(advertisement->entries.next,
                   struct nhrp_ha_advertised_entry, list_entry);
  old_nbma = old->nbma;
  snprintf(seen_path, sizeof(seen_path), "%s/seen.state", directory);
  fd = open(seen_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(fd >= 0 && close(fd) == 0);
  /* Invalid seen state fails validation after the new advertisements exist. */
  for (i = 0; i < 50; i++) {
    uint32_t saved_generation = advertisement->generation;
    advertised.s_addr = htonl(0xc0000280 + i);
    state.members[0].addresses[0] = advertised;
    state.manifest_revision++;
    assert(nhrp_ha_managed_state_save(state_path, &keys, &state));
    assert(!nhrp_ha_reload_managed(directory));
    assert(advertisement_count(advertisement) == 1 && old->configured);
    assert(advertisement->entries.next == &old->list_entry);
    assert(nhrp_address_cmp(&old_nbma, &old->nbma) == 0);
    assert(advertisement->generation == saved_generation);
  }
  assert(unlink(seen_path) == 0);
  assert(nhrp_ha_reload_managed(directory));
  assert(advertisement_count(advertisement) == 1);
  nhrp_ha_auth_keys_clear(&keys);
  assert(nhrp_ha_managed_state_destroy(directory));
  snprintf(seen_path, sizeof(seen_path), "%s/.lock", directory);
  assert(unlink(seen_path) == 0);
  assert(rmdir(directory) == 0);
}

static size_t object_count(struct list_head *list) {
  struct list_head *entry;
  size_t count = 0;
  list_for_each(entry, list)
    count++;
  return count;
}

static void test_protocol_rotation(void) {
  struct nhrp_address protocol, rejected, nbma;
  size_t i;

  memset(&hub_enable, 0, sizeof(hub_enable));
  assert(nhrp_address_parse("192.0.2.1", &nbma, NULL));
  assert(nhrp_address_parse("10.255.0.1", &rejected, NULL));
  for (i = 1; i <= 100; i++) {
    char address[64];
    snprintf(address, sizeof(address), "10.1.%zu.1", i);
    assert(nhrp_address_parse(address, &protocol, NULL));
    nhrp_ha_mark_configured();
    assert(nhrp_ha_config_map(&iface, &protocol, 24, "hub", &nbma, 100));
    assert(nhrp_ha_config_advertise(&iface, &protocol, 24, i, "hub", &nbma, 100));
    nhrp_ha_sweep_unconfigured();
    assert(object_count(&services) == 1 && object_count(&advertisements) == 1);
    nhrp_ha_mark_configured();
    assert(nhrp_ha_config_map(&iface, &rejected, 24, "hub", &nbma, 100));
    assert(nhrp_ha_config_advertise(&iface, &rejected, 24, i, "hub", &nbma, 100));
    nhrp_ha_config_reload_abort();
    assert(object_count(&services) == 1 && object_count(&advertisements) == 1);
    assert(service_find(&iface, &protocol)->configured);
    assert(advertisement_find(&iface, &protocol)->configured);
  }
  /* A removed service is freed by its final packet callback, after reload. */
  struct nhrp_ha_service *service = service_find(&iface, &protocol);
  struct nhrp_ha_candidate *candidate = candidate_find(service, "hub");
  registration_timer_cb(&candidate->registration_timer, 0);
  assert(candidate->pending_requests == 1);
  nhrp_ha_mark_configured();
  nhrp_ha_sweep_unconfigured();
  assert(object_count(&services) == 1 && object_count(&advertisements) == 0);
  struct nhrp_packet *packet =
      list_entry(pending_requests.next, struct nhrp_packet, request_list_entry);
  ev_invoke((ev_watcher *)&packet->timeout, EV_TIMER);
  assert(list_empty(&pending_requests));
  assert(object_count(&services) == 0);
}

static void test_spoke_keyring_reload(void) {
  char directory[] = "/tmp/opennhrp-spoke-keyring.XXXXXX";
  char path[PATH_MAX], saved_directory[PATH_MAX];
  struct nhrp_interface spoke = {.name = "gre-keys"};
  struct nhrp_interface second_spoke = {.name = "gre-other"};
  struct nhrp_ha_service service = {.interface = &spoke, .configured = TRUE};
  struct nhrp_ha_service second_service = {
      .interface = &second_spoke, .configured = TRUE};
  struct nhrp_ha_candidate candidate = {.service = &service};
  struct nhrp_peer anchor = {
      .interface = &spoke, .type = NHRP_PEER_TYPE_STATIC,
      .flags = NHRP_PEER_FLAG_REGISTER | NHRP_PEER_FLAG_CONFIGURED,
      .accepted_forwarding_members = " hub"};
  struct nhrp_packet *reply;
  struct nhrp_ha_bootstrap *bootstrap;
  struct nhrp_ha_bootstrap *second_bootstrap;
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_ha_auth_profile *second_profile;
  struct nhrp_ha_auth_keys keys = {0}, wrong_keys = {0};
  struct nhrp_ha_auth_metadata expected = {
      .cluster_id = {1}, .term = 1, .commit_index = 2, .leader = "hub"};
  struct nhrp_ha_auth_metadata observed;
  const uint8_t probe[] = {2, NHRP_HA_PROBE_REPLY};
  struct nhrp_ha_auth_input input = {
      .packet_type = NHRP_PACKET_RESOLUTION_REPLY,
      .ha_payload = probe, .ha_payload_length = sizeof(probe)};
  struct nhrp_buffer *auth;
  struct nhrp_address nbma, advertised, selected;
  uint8_t key_id[NHRP_HA_AUTH_KEY_ID_SIZE];
  uint8_t psk[NHRP_HA_AUTH_KEY_SIZE] = {1};

  assert(mkdtemp(directory) != NULL);
  strcpy(saved_directory, managed_state_directory);
  strcpy(managed_state_directory, directory);
  assert(setenv("OPENNHRP_HA_KEY_DIR", directory, 1) == 0);
  assert(nhrp_address_parse("10.90.0.1", &service.protocol, NULL));
  assert(nhrp_address_parse("192.0.2.1", &nbma, NULL));
  assert(bootstrap_configure(&spoke, &service.protocol, &nbma, NULL));
  bootstrap = bootstrap_find(&spoke, FALSE);
  bootstrap->automatic = TRUE;
  profile = auth_profile_find(&spoke, FALSE);
  assert(auth_profile_validate(profile));
  list_add(&service.list_entry, &services);

  list_init(&spoke.peer_list);
  anchor.protocol_address = service.protocol;
  anchor.next_hop_address = nbma;
  list_add(&anchor.peer_list_entry, &spoke.peer_list);
  strcpy(candidate.member_id, "hub");
  assert(nhrp_address_parse("192.0.2.2", &advertised, NULL));
  reply = nhrp_packet_alloc();
  assert(reply != NULL);
  nhrp_packet_request_forwarding(reply, NHRP_EXTENSION_HA_FORWARDING);
  nhrp_packet_reply_forwarding(reply, NHRP_EXTENSION_HA_FORWARDING, &advertised);
  candidate_observe_forwarding(&candidate, reply);
  selected = candidate_forwarding_nbma(&candidate);
  assert(!nhrp_address_cmp(&selected, &advertised));
  strcpy(candidate.member_id, "other-hub");
  assert(candidate_forwarding_nbma(&candidate).type == AF_UNSPEC);
  strcpy(candidate.member_id, "hub");

  assert(!nhrp_ha_reload_spoke_keyring(&spoke));
  assert(spoke_keyring_path(&spoke, path, sizeof(path)));
  assert(nhrp_ha_managed_keyring_generate(path, &keys));
  assert(chmod(path, 0644) == 0 && !nhrp_ha_reload_spoke_keyring(&spoke));
  assert(chmod(path, 0600) == 0 && nhrp_ha_reload_spoke_keyring(NULL));
  assert(bootstrap->pending_auth && !profile->auth_required);
  spoke_keyring_pending_clear(bootstrap);

  second_service.protocol = service.protocol;
  assert(bootstrap_configure(&second_spoke, &second_service.protocol, &nbma, NULL));
  second_bootstrap = bootstrap_find(&second_spoke, FALSE);
  second_bootstrap->automatic = TRUE;
  list_del(&second_bootstrap->list_entry);
  list_add(&second_bootstrap->list_entry, &bootstraps);
  second_profile = auth_profile_find(&second_spoke, FALSE);
  assert(auth_profile_validate(second_profile));
  list_add(&second_service.list_entry, &services);
  /* A missing key on the first interface must not skip the second. */
  assert(!nhrp_ha_reload_spoke_keyring(NULL));
  assert(!second_bootstrap->pending_auth);
  assert(bootstrap->pending_auth && !profile->auth_required);
  assert(nhrp_ha_reload_spoke_keyring(&spoke));
  list_del(&second_service.list_entry);
  list_del(&second_profile->list_entry);
  free(second_profile);
  list_del(&second_bootstrap->list_entry);
  free(second_bootstrap);

  assert(nhrp_ha_auth_key_from_bytes(&wrong_keys.key[0], psk));
  auth = nhrp_buffer_alloc(nhrp_ha_auth_encoded_size(&keys, &expected));
  assert(auth);
  assert(nhrp_ha_auth_encode(&wrong_keys, &input, &expected, auth->data,
                            auth->length) == NHRP_HA_AUTH_OK);
  assert(!spoke_keyring_accept(&candidate, profile, &input, auth, &observed, key_id));
  assert(bootstrap->pending_auth && !profile->auth_required);
  assert(nhrp_ha_auth_encode(&keys, &input, &expected, auth->data,
                            auth->length) == NHRP_HA_AUTH_OK);
  assert(spoke_keyring_accept(&candidate, profile, &input, auth, &observed, key_id));
  assert(!bootstrap->pending_auth && profile->auth_required);
  candidate.auth_valid = TRUE;
  assert(candidate_forwarding_nbma(&candidate).type == AF_UNSPEC);
  candidate_observe_forwarding(&candidate, reply);
  selected = candidate_forwarding_nbma(&candidate);
  assert(!nhrp_address_cmp(&selected, &advertised));
  assert(profile->seen.commit_index == expected.commit_index);
  assert(unlink(path) == 0 && !nhrp_ha_reload_spoke_keyring(&spoke));
  assert(profile->auth_required);

  nhrp_packet_put(reply);
  nhrp_buffer_free(auth);
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_auth_keys_clear(&wrong_keys);
  nhrp_ha_auth_keys_clear(&profile->keys);
  assert(unlink(profile->state_path) == 0);
  list_del(&profile->list_entry);
  free(profile);
  list_del(&bootstrap->list_entry);
  free(bootstrap);
  list_del(&service.list_entry);
  snprintf(path, sizeof(path), "%s/.lock", directory);
  assert(unlink(path) == 0 && rmdir(directory) == 0);
  strcpy(managed_state_directory, saved_directory);
  unsetenv("OPENNHRP_HA_KEY_DIR");
}

int main(void) {
  ev_default_loop(0);
  strcpy(iface.name, "gre-test");
  test_hub_rotation();
  test_configuration_retirement();
  test_managed_reload();
  test_protocol_rotation();
  test_candidate_connect_address();
  test_spoke_keyring_reload();
  puts("HA candidate retirement, pending request and reload lifecycle tests passed");
  ev_loop_destroy();
  return 0;
}
