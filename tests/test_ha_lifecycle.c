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
  assert(!"unexpected route lookup");
  return FALSE;
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
int nhrp_peer_ha_anchor_configured(struct nhrp_interface *interface,
                                   struct nhrp_address *protocol) {
  return TRUE;
}
int kernel_send(uint8_t *data, size_t length, struct nhrp_interface *interface,
                struct nhrp_address *destination) {
  return TRUE;
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

int main(void) {
  ev_default_loop(0);
  strcpy(iface.name, "gre-test");
  test_hub_rotation();
  test_configuration_retirement();
  test_managed_reload();
  test_protocol_rotation();
  puts("HA candidate retirement, pending request and reload lifecycle tests passed");
  ev_loop_destroy();
  return 0;
}
