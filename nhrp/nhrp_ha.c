/* nhrp_ha.c - Shared protocol address HA for pure mGRE */

#include <arpa/inet.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <openssl/crypto.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "nhrp_common.h"
#include "nhrp_ha.h"
#include "nhrp_ha_auth.h"
#include "nhrp_ha_hub.h"
#include "nhrp_ha_managed.h"
#include "nhrp_ha_seen.h"
#include "nhrp_ha_wire.h"
#include "nhrp_interface.h"
#include "nhrp_packet.h"
#include "nhrp_peer.h"

#define HA_REGISTRATION_RETRY 1.0
#define HA_ACTIVE_PROBE_INTERVAL 0.15
#define HA_STANDBY_PROBE_INTERVAL 0.50
#define HA_ACTIVE_MIN_RTO 0.25
#define HA_STANDBY_MIN_RTO 0.75

enum nhrp_ha_candidate_state {
  NHRP_HA_CANDIDATE_INIT,
  NHRP_HA_CANDIDATE_REGISTERING,
  NHRP_HA_CANDIDATE_REGISTERED,
  NHRP_HA_CANDIDATE_READY,
  NHRP_HA_CANDIDATE_SUSPECT,
  NHRP_HA_CANDIDATE_OFFLINE,
  NHRP_HA_CANDIDATE_DISABLED,
};

struct nhrp_ha_service;

struct nhrp_ha_candidate {
  struct list_head list_entry;
  struct nhrp_ha_service *service;
  char member_id[NHRP_HA_MEMBER_ID_MAX + 1];
  struct nhrp_address nbma;
  struct nhrp_address endpoints[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t endpoint_count;
  size_t endpoint_index;
  struct nhrp_address preferred_endpoint;
  int preferred_endpoint_valid;
  uint8_t endpoint_ready[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  uint8_t endpoint_misses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t endpoint_probe_cursor;
  uint32_t probe_round;
  struct nhrp_address bootstrap_local_nbma;
  int priority;
  int configured;
  int static_configured;
  int dynamically_discovered;
  int bootstrap_unbound;
  int bootstrap_anchor;
  int registered;
  int registration_pending;
  uint32_t registration_generation;
  uint32_t endpoint_generation;
  enum nhrp_ha_candidate_state state;
  struct nhrp_cie nat_cie;
  ev_tstamp last_registration_reply;
  ev_tstamp last_probe_reply;
  struct ev_timer registration_timer;
  struct ev_timer probe_timer;
  int probe_pending;
  uint32_t probe_sequence;
  uint32_t probe_generation;
  uint64_t probe_nonce;
  ev_tstamp probe_sent;
  double srtt;
  double rttvar;
  double rto;
  unsigned int consecutive_misses;
  int auth_valid;
  uint8_t auth_key_id[NHRP_HA_AUTH_KEY_ID_SIZE];
  uint64_t auth_term;
  uint64_t auth_commit_index;
  char auth_leader[NHRP_HA_AUTH_LEADER_MAX + 1];
};

struct nhrp_ha_registration_request {
  struct nhrp_ha_candidate *candidate;
  uint32_t endpoint_generation;
  uint32_t registration_generation;
  struct nhrp_address bootstrap_local_nbma;
  int has_bootstrap_local_nbma;
};

struct nhrp_ha_probe_request {
  struct nhrp_ha_candidate *candidate;
  uint32_t endpoint_generation;
  uint32_t sequence;
  uint32_t generation;
  uint64_t nonce;
  ev_tstamp sent;
  size_t endpoint_index;
  int selected_endpoint;
};

struct nhrp_ha_service {
  struct list_head list_entry;
  struct nhrp_interface *interface;
  struct nhrp_address protocol;
  uint8_t prefix_length;
  struct list_head candidates;
  struct nhrp_ha_candidate *active;
  struct nhrp_peer *active_peer;
  struct nhrp_ha_candidate *switch_target;
  uint32_t generation;
  uint32_t hub_list_generation;
  char hub_list_source[NHRP_HA_MEMBER_ID_MAX + 1];
  char bootstrap_member[NHRP_HA_MEMBER_ID_MAX + 1];
  uint64_t event_sequence;
  int switching;
  int configured;
  int automatic;
  nhrp_ha_activate_callback switch_callback;
  void *switch_callback_ctx;
  struct nhrp_address switch_nbma;
  int switch_has_local_nbma;
  struct ev_timer reconcile_timer;
  int reconciling;
  struct nhrp_ha_candidate *reconcile_candidate;
  struct nhrp_address reconcile_nbma;
  int reconcile_has_local_nbma;
};

struct nhrp_ha_local_override {
  struct list_head list_entry;
  struct nhrp_interface *interface;
  char member_id[NHRP_HA_MEMBER_ID_MAX + 1];
  struct nhrp_address local_nbma;
  int configured;
  int reload_existing;
  struct nhrp_address reload_local_nbma;
};

struct nhrp_ha_advertised_entry {
  struct list_head list_entry;
  char member_id[NHRP_HA_MEMBER_ID_MAX + 1];
  struct nhrp_address nbma;
  int priority;
  int configured;
};

struct nhrp_ha_advertisement {
  struct list_head list_entry;
  struct nhrp_interface *interface;
  struct nhrp_address protocol;
  uint8_t prefix_length;
  uint32_t generation;
  int configured;
  struct list_head entries;
};

struct nhrp_ha_auth_profile {
  struct list_head list_entry;
  struct nhrp_interface *interface;
  uint8_t cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE];
  int cluster_configured;
  int auth_configured;
  int auth_required;
  int key_configured[NHRP_HA_AUTH_MAX_KEYS];
  struct nhrp_ha_auth_keys keys;
  int state_configured;
  char state_path[PATH_MAX];
  struct nhrp_ha_seen_state seen;
  int valid;
  int managed;
  int bootstrap;
};

struct nhrp_ha_bootstrap {
  struct list_head list_entry;
  struct nhrp_interface *interface;
  struct nhrp_address protocol;
  struct nhrp_address nbma;
  char keyring_path[PATH_MAX];
  int configured;
  int automatic;
  int warned_unauthenticated;
};

static struct list_head services = LIST_INITIALIZER(services);
static struct list_head advertisements = LIST_INITIALIZER(advertisements);
static struct list_head auth_profiles = LIST_INITIALIZER(auth_profiles);
static struct list_head bootstraps = LIST_INITIALIZER(bootstraps);
static struct list_head local_overrides = LIST_INITIALIZER(local_overrides);

struct nhrp_ha_enable_config {
  struct nhrp_interface *interface;
  char member_id[NHRP_HA_MEMBER_ID_MAX + 1];
  struct nhrp_address advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t advertised_count;
  struct nhrp_address health_targets[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t health_target_count;
  int member_explicit;
  int advertise_explicit;
  int configured;
  int runtime_locked;
};

static struct nhrp_ha_enable_config hub_enable;
static struct nhrp_ha_enable_config reload_hub_enable;
static int reload_hub_enable_valid;
static nhrp_ha_coordinator_callback coordinator_callback;
static int configuration_reload;
static char managed_state_directory[PATH_MAX] = NHRP_HA_MANAGED_DEFAULT_DIR;

struct nhrp_ha_coordinator_status {
  struct nhrp_interface *interface;
  char state[16];
  int last_exit;
};

static struct nhrp_ha_coordinator_status coordinator_status[33];

extern void admin_ha_notify(struct nhrp_interface *iface);

static void registration_timer_cb(struct ev_timer *timer, int revents);
static void probe_timer_cb(struct ev_timer *timer, int revents);
static void reconcile_timer_cb(struct ev_timer *timer, int revents);
static void reconcile_schedule(struct nhrp_ha_service *service,
                               ev_tstamp delay);
static int candidate_authenticate(struct nhrp_ha_candidate *candidate,
                                  struct nhrp_packet *reply,
                                  const struct nhrp_buffer *ha);
static int auth_profile_observe(struct nhrp_ha_auth_profile *profile,
                                const struct nhrp_ha_auth_metadata *metadata,
                                const uint8_t key_id[NHRP_HA_AUTH_KEY_ID_SIZE]);
static int bootstrap_configure(struct nhrp_interface *iface,
                               const struct nhrp_address *protocol,
                               const struct nhrp_address *nbma,
                               const char *keyring_path);

static struct nhrp_ha_local_override *
local_override_find_any(struct nhrp_interface *iface, const char *member_id) {
  struct nhrp_ha_local_override *override;

  list_for_each_entry(override, &local_overrides, list_entry) {
    if (override->interface == iface &&
        strcmp(override->member_id, member_id) == 0)
      return override;
  }
  return NULL;
}

static struct nhrp_ha_local_override *
local_override_find(struct nhrp_interface *iface, const char *member_id) {
  struct nhrp_ha_local_override *override =
      local_override_find_any(iface, member_id);

  return override != NULL && override->configured ? override : NULL;
}

static const struct nhrp_address *
candidate_local_nbma(struct nhrp_ha_candidate *candidate, const char **origin) {
  struct nhrp_ha_local_override *override =
      local_override_find(candidate->service->interface, candidate->member_id);

  if (override != NULL) {
    if (origin != NULL)
      *origin = "configured";
    return &override->local_nbma;
  }
  if (candidate->bootstrap_local_nbma.type != PF_UNSPEC) {
    if (origin != NULL)
      *origin = "bootstrap";
    return &candidate->bootstrap_local_nbma;
  }
  if (origin != NULL)
    *origin = NULL;
  return NULL;
}

static const char *candidate_state_name(enum nhrp_ha_candidate_state state) {
  static const char *const names[] = {
      [NHRP_HA_CANDIDATE_INIT] = "init",
      [NHRP_HA_CANDIDATE_REGISTERING] = "registering",
      [NHRP_HA_CANDIDATE_REGISTERED] = "registered",
      [NHRP_HA_CANDIDATE_READY] = "ready",
      [NHRP_HA_CANDIDATE_SUSPECT] = "suspect",
      [NHRP_HA_CANDIDATE_OFFLINE] = "offline",
      [NHRP_HA_CANDIDATE_DISABLED] = "disabled",
  };

  if ((unsigned int)state >= ARRAY_SIZE(names) || names[state] == NULL)
    return "unknown";
  return names[state];
}

static int member_id_valid(const char *member_id) {
  size_t i;
  size_t length = strlen(member_id);

  if (length == 0 || length > NHRP_HA_MEMBER_ID_MAX)
    return FALSE;
  for (i = 0; i < length; i++) {
    if (!isalnum((unsigned char)member_id[i]) && member_id[i] != '-' &&
        member_id[i] != '_' && member_id[i] != '.')
      return FALSE;
  }
  return TRUE;
}

static void
cluster_id_format(const uint8_t cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE],
                  char output[NHRP_HA_AUTH_CLUSTER_ID_SIZE * 2 + 1]) {
  static const char hex[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < NHRP_HA_AUTH_CLUSTER_ID_SIZE; i++) {
    output[i * 2] = hex[cluster_id[i] >> 4];
    output[i * 2 + 1] = hex[cluster_id[i] & 15];
  }
  output[NHRP_HA_AUTH_CLUSTER_ID_SIZE * 2] = 0;
}

static struct nhrp_ha_auth_profile *
auth_profile_find(struct nhrp_interface *iface, int create) {
  struct nhrp_ha_auth_profile *profile;

  list_for_each_entry(profile, &auth_profiles, list_entry) {
    if (profile->interface == iface)
      return profile;
  }
  if (!create)
    return NULL;
  profile = calloc(1, sizeof(*profile));
  if (profile == NULL)
    return NULL;
  profile->interface = iface;
  list_add_tail(&profile->list_entry, &auth_profiles);
  return profile;
}

static struct nhrp_ha_bootstrap *bootstrap_find(struct nhrp_interface *iface,
                                                int create) {
  struct nhrp_ha_bootstrap *bootstrap;

  list_for_each_entry(bootstrap, &bootstraps, list_entry) {
    if (bootstrap->interface == iface)
      return bootstrap;
  }
  if (!create)
    return NULL;
  bootstrap = calloc(1, sizeof(*bootstrap));
  if (bootstrap == NULL)
    return NULL;
  bootstrap->interface = iface;
  list_add_tail(&bootstrap->list_entry, &bootstraps);
  return bootstrap;
}

static int
auth_profile_has_configuration(const struct nhrp_ha_auth_profile *profile) {
  return profile->cluster_configured || profile->auth_configured ||
         profile->key_configured[0] || profile->key_configured[1] ||
         profile->state_configured || profile->bootstrap;
}

static int auth_profile_load_seen(struct nhrp_ha_auth_profile *profile) {
  struct nhrp_ha_seen_state loaded;

  if (!profile->state_configured)
    return TRUE;
  if (!nhrp_ha_seen_load(profile->state_path, &profile->keys,
                         profile->bootstrap && !profile->cluster_configured
                             ? NULL
                             : profile->cluster_id,
                         &loaded))
    return FALSE;
  if (profile->bootstrap && loaded.term != 0 && !profile->cluster_configured) {
    memcpy(profile->cluster_id, loaded.cluster_id, sizeof(profile->cluster_id));
    profile->cluster_configured = TRUE;
  }
  if (loaded.term > profile->seen.term ||
      (loaded.term == profile->seen.term &&
       loaded.commit_index > profile->seen.commit_index))
    profile->seen = loaded;
  return TRUE;
}

static int auth_profile_validate(struct nhrp_ha_auth_profile *profile) {
  if (!auth_profile_has_configuration(profile))
    return TRUE;
  if (profile->key_configured[1] && !profile->key_configured[0])
    return FALSE;
  if (profile->auth_configured && !profile->key_configured[0])
    return FALSE;
  if (profile->auth_required && !profile->bootstrap &&
      (!profile->cluster_configured || !profile->key_configured[0] ||
       !profile->state_configured))
    return FALSE;
  if (profile->bootstrap && profile->auth_required &&
      (!profile->key_configured[0] || !profile->state_configured))
    return FALSE;
  if (profile->bootstrap && !profile->auth_required &&
      !profile->state_configured)
    return FALSE;
  if ((profile->key_configured[0] || profile->key_configured[1] ||
       profile->state_configured) &&
      !profile->cluster_configured && !profile->bootstrap)
    return FALSE;
  if (profile->key_configured[1] &&
      CRYPTO_memcmp(profile->keys.key[0].id, profile->keys.key[1].id,
                    NHRP_HA_AUTH_KEY_ID_SIZE) == 0)
    return FALSE;
  if (profile->auth_configured && !auth_profile_load_seen(profile))
    return FALSE;
  profile->valid = TRUE;
  return TRUE;
}

static uint64_t random_u64(void) {
  uint64_t value = (uint64_t)(unsigned long)random();

  value = (value << 33) ^ (uint64_t)(unsigned long)random();
  value ^= (uint64_t)(unsigned long)random() << 2;
  return value;
}

static uint64_t monotonic_nanoseconds(void) {
  struct timespec now;

  clock_gettime(CLOCK_MONOTONIC, &now);
  return (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static struct nhrp_buffer *ha_member_payload(const char *member_id,
                                             uint32_t generation) {
  struct nhrp_buffer *buffer;
  uint16_t member_length = strlen(member_id);
  uint16_t wire_member_length = htons(member_length);
  uint32_t wire_generation = htonl(generation);

  buffer = nhrp_buffer_alloc(8 + member_length);
  if (buffer == NULL)
    return NULL;
  buffer->data[0] = NHRP_HA_WIRE_VERSION;
  buffer->data[1] = NHRP_HA_MEMBER;
  memcpy(&buffer->data[2], &wire_member_length, sizeof(wire_member_length));
  memcpy(&buffer->data[4], &wire_generation, sizeof(wire_generation));
  memcpy(&buffer->data[8], member_id, member_length);
  return buffer;
}

static int ha_member_parse(const struct nhrp_buffer *buffer, char *member_id,
                           size_t member_id_size, uint32_t *generation) {
  uint16_t member_length;
  uint32_t wire_generation;

  if (buffer == NULL || buffer->length < 8 ||
      buffer->data[0] != NHRP_HA_WIRE_VERSION ||
      buffer->data[1] != NHRP_HA_MEMBER)
    return FALSE;
  memcpy(&member_length, &buffer->data[2], sizeof(member_length));
  member_length = ntohs(member_length);
  if (member_length == 0 || member_length >= member_id_size ||
      buffer->length != 8 + member_length)
    return FALSE;
  memcpy(&wire_generation, &buffer->data[4], sizeof(wire_generation));
  *generation = ntohl(wire_generation);
  memcpy(member_id, &buffer->data[8], member_length);
  member_id[member_length] = 0;
  return member_id_valid(member_id);
}

static struct nhrp_buffer *ha_probe_payload(uint8_t message_type,
                                            const char *member_id,
                                            uint32_t sequence,
                                            uint32_t generation, uint64_t nonce,
                                            uint64_t sent_nanoseconds) {
  struct nhrp_buffer *buffer;
  uint16_t member_length = strlen(member_id);
  uint16_t wire_member_length = htons(member_length);
  uint32_t wire_sequence = htonl(sequence);
  uint32_t wire_generation = htonl(generation);
  uint64_t wire_nonce = htobe64(nonce);
  uint64_t wire_sent = htobe64(sent_nanoseconds);

  buffer = nhrp_buffer_alloc(28 + member_length);
  if (buffer == NULL)
    return NULL;
  buffer->data[0] = NHRP_HA_WIRE_VERSION;
  buffer->data[1] = message_type;
  memcpy(&buffer->data[2], &wire_member_length, sizeof(wire_member_length));
  memcpy(&buffer->data[4], &wire_sequence, sizeof(wire_sequence));
  memcpy(&buffer->data[8], &wire_generation, sizeof(wire_generation));
  memcpy(&buffer->data[12], &wire_nonce, sizeof(wire_nonce));
  memcpy(&buffer->data[20], &wire_sent, sizeof(wire_sent));
  memcpy(&buffer->data[28], member_id, member_length);
  return buffer;
}

static int ha_probe_parse(const struct nhrp_buffer *buffer,
                          uint8_t expected_type, char *member_id,
                          size_t member_id_size, uint32_t *sequence,
                          uint32_t *generation, uint64_t *nonce,
                          uint64_t *sent_nanoseconds) {
  uint16_t member_length;
  uint32_t wire32;
  uint64_t wire64;

  if (buffer == NULL || buffer->length < 28 ||
      buffer->data[0] != NHRP_HA_WIRE_VERSION ||
      buffer->data[1] != expected_type)
    return FALSE;
  memcpy(&member_length, &buffer->data[2], sizeof(member_length));
  member_length = ntohs(member_length);
  if (member_length == 0 || member_length >= member_id_size ||
      buffer->length != 28 + member_length)
    return FALSE;
  memcpy(&wire32, &buffer->data[4], sizeof(wire32));
  *sequence = ntohl(wire32);
  memcpy(&wire32, &buffer->data[8], sizeof(wire32));
  *generation = ntohl(wire32);
  memcpy(&wire64, &buffer->data[12], sizeof(wire64));
  *nonce = be64toh(wire64);
  memcpy(&wire64, &buffer->data[20], sizeof(wire64));
  *sent_nanoseconds = be64toh(wire64);
  memcpy(member_id, &buffer->data[28], member_length);
  member_id[member_length] = 0;
  return member_id_valid(member_id);
}

static struct nhrp_ha_service *
service_find(struct nhrp_interface *iface,
             const struct nhrp_address *protocol) {
  struct nhrp_ha_service *service;

  list_for_each_entry(service, &services, list_entry) {
    if (service->interface == iface &&
        nhrp_address_cmp(&service->protocol, protocol) == 0)
      return service;
  }
  return NULL;
}

static struct nhrp_ha_candidate *candidate_find(struct nhrp_ha_service *service,
                                                const char *member_id) {
  struct nhrp_ha_candidate *candidate;

  list_for_each_entry(candidate, &service->candidates, list_entry) {
    if (strcmp(candidate->member_id, member_id) == 0)
      return candidate;
  }
  return NULL;
}

static struct nhrp_ha_candidate *
candidate_alloc(struct nhrp_ha_service *service, const char *member_id) {
  struct nhrp_ha_candidate *candidate;

  candidate = calloc(1, sizeof(*candidate));
  if (candidate == NULL)
    return NULL;
  candidate->service = service;
  snprintf(candidate->member_id, sizeof(candidate->member_id), "%s", member_id);
  candidate->endpoint_generation = 1;
  candidate->rto = HA_STANDBY_MIN_RTO;
  ev_timer_init(&candidate->registration_timer, registration_timer_cb, 0.0,
                0.0);
  ev_timer_init(&candidate->probe_timer, probe_timer_cb, 0.0, 0.0);
  return candidate;
}

static void candidate_set_single_endpoint(struct nhrp_ha_candidate *candidate,
                                          const struct nhrp_address *address) {
  candidate->nbma = *address;
  candidate->endpoints[0] = *address;
  candidate->endpoint_count = 1;
  candidate->endpoint_index = 0;
  memset(candidate->endpoint_ready, 0, sizeof(candidate->endpoint_ready));
  memset(candidate->endpoint_misses, 0, sizeof(candidate->endpoint_misses));
}

static void candidate_rotate_endpoint(struct nhrp_ha_candidate *candidate) {
  if (candidate->endpoint_count <= 1)
    return;
  candidate->endpoint_index =
      (candidate->endpoint_index + 1) % candidate->endpoint_count;
  candidate->nbma = candidate->endpoints[candidate->endpoint_index];
  candidate->endpoint_ready[candidate->endpoint_index] = FALSE;
  candidate->endpoint_misses[candidate->endpoint_index] = 0;
  candidate->endpoint_generation++;
}

static void
candidate_select_available_endpoint(struct nhrp_ha_candidate *candidate) {
  size_t i;

  for (i = 0; i < candidate->endpoint_count; i++) {
    if (i == candidate->endpoint_index || !candidate->endpoint_ready[i])
      continue;
    candidate->endpoint_index = i;
    candidate->nbma = candidate->endpoints[i];
    candidate->endpoint_generation++;
    return;
  }
  candidate_rotate_endpoint(candidate);
}

static struct nhrp_ha_advertisement *
advertisement_find(struct nhrp_interface *iface,
                   const struct nhrp_address *protocol) {
  struct nhrp_ha_advertisement *advertisement;

  list_for_each_entry(advertisement, &advertisements, list_entry) {
    if (advertisement->interface == iface &&
        nhrp_address_cmp(&advertisement->protocol, protocol) == 0)
      return advertisement;
  }
  return NULL;
}

static struct nhrp_ha_advertised_entry *
advertised_entry_find(struct nhrp_ha_advertisement *advertisement,
                      const char *member_id, const struct nhrp_address *nbma) {
  struct nhrp_ha_advertised_entry *entry;

  list_for_each_entry(entry, &advertisement->entries, list_entry) {
    if (strcmp(entry->member_id, member_id) == 0 &&
        (nbma == NULL || nhrp_address_cmp(&entry->nbma, nbma) == 0))
      return entry;
  }
  return NULL;
}

static void service_changed(struct nhrp_ha_service *service) {
  service->event_sequence++;
  admin_ha_notify(service->interface);
}

static void candidate_set_state(struct nhrp_ha_candidate *candidate,
                                enum nhrp_ha_candidate_state state) {
  enum nhrp_ha_candidate_state previous;
  char protocol[64];

  if (candidate->state == state)
    return;
  previous = candidate->state;
  candidate->state = state;
  if ((previous == NHRP_HA_CANDIDATE_READY &&
       state == NHRP_HA_CANDIDATE_SUSPECT) ||
      (previous == NHRP_HA_CANDIDATE_SUSPECT &&
       state == NHRP_HA_CANDIDATE_READY))
    nhrp_debug("HA candidate %s for %s on %s state %s -> %s",
               candidate->member_id,
               nhrp_address_format(&candidate->service->protocol,
                                   sizeof(protocol), protocol),
               candidate->service->interface->name,
               candidate_state_name(previous), candidate_state_name(state));
  else
    nhrp_info("HA candidate %s for %s on %s state %s -> %s",
              candidate->member_id,
              nhrp_address_format(&candidate->service->protocol,
                                  sizeof(protocol), protocol),
              candidate->service->interface->name,
              candidate_state_name(previous), candidate_state_name(state));
  service_changed(candidate->service);
}

static struct nhrp_peer *
candidate_direct_peer(struct nhrp_ha_candidate *candidate,
                      const struct nhrp_address *endpoint) {
  struct nhrp_peer *peer;
  struct nhrp_interface *iface = candidate->service->interface;
  struct nhrp_address route_address = *endpoint;

  peer = nhrp_peer_alloc(iface);
  if (peer == NULL)
    return NULL;
  peer->type = NHRP_PEER_TYPE_LOCAL_ROUTE;
  peer->flags = NHRP_PEER_FLAG_UP | NHRP_PEER_FLAG_LOWER_UP;
  peer->next_hop_address = *endpoint;
  peer->protocol_address = candidate->service->protocol;
  peer->prefix_length = candidate->service->prefix_length;
  peer->afnum = nhrp_afnum_from_pf(endpoint->type);
  peer->protocol_type = nhrp_protocol_from_pf(
      candidate->service->interface->protocol_address.type);

  if (iface->nbma_address.type != PF_UNSPEC) {
    peer->my_nbma_address = iface->nbma_address;
    peer->my_nbma_mtu = iface->nbma_mtu;
  } else if (!kernel_route(NULL, &route_address, &peer->my_nbma_address, NULL,
                           &peer->my_nbma_mtu)) {
    nhrp_peer_put(peer);
    return NULL;
  }
  return peer;
}

static void packet_add_standard_extensions(struct nhrp_packet *packet) {
  nhrp_packet_extension(packet,
                        NHRP_EXTENSION_FORWARD_TRANSIT_NHS |
                            NHRP_EXTENSION_FLAG_COMPULSORY,
                        NHRP_PAYLOAD_TYPE_CIE_LIST);
  nhrp_packet_extension(packet,
                        NHRP_EXTENSION_REVERSE_TRANSIT_NHS |
                            NHRP_EXTENSION_FLAG_COMPULSORY,
                        NHRP_PAYLOAD_TYPE_CIE_LIST);
  nhrp_packet_extension(
      packet, NHRP_EXTENSION_RESPONDER_ADDRESS | NHRP_EXTENSION_FLAG_COMPULSORY,
      NHRP_PAYLOAD_TYPE_CIE_LIST);
}

static void registration_schedule(struct nhrp_ha_candidate *candidate,
                                  ev_tstamp delay);
static void probe_schedule(struct nhrp_ha_candidate *candidate,
                           ev_tstamp delay);

static struct nhrp_buffer *
hub_list_payload(struct nhrp_ha_advertisement *advertisement,
                 const char *source_member, uint32_t request_generation) {
  struct nhrp_ha_advertised_entry *entry;
  struct nhrp_ha_hub_list list;
  struct nhrp_buffer *buffer;
  size_t size;

  memset(&list, 0, sizeof(list));
  snprintf(list.source_member, sizeof(list.source_member), "%s", source_member);
  list.request_generation = request_generation;
  list.list_generation = advertisement->generation;
  list.prefix_length = advertisement->prefix_length;
  list_for_each_entry(entry, &advertisement->entries, list_entry) {
    struct nhrp_ha_hub_list_entry *wire_entry;

    if (!entry->configured)
      continue;
    if (list.entry_count >= NHRP_HA_HUB_LIST_MAX_ENTRIES ||
        entry->nbma.type != PF_INET ||
        entry->nbma.addr_len != NHRP_HA_HUB_LIST_NBMA_LEN)
      return NULL;
    wire_entry = &list.entries[list.entry_count++];
    snprintf(wire_entry->member, sizeof(wire_entry->member), "%s",
             entry->member_id);
    memcpy(wire_entry->nbma, entry->nbma.addr, NHRP_HA_HUB_LIST_NBMA_LEN);
    wire_entry->priority = entry->priority;
  }

  size = nhrp_ha_hub_list_encoded_size(&list);
  if (size == 0)
    return NULL;
  buffer = nhrp_buffer_alloc(size);
  if (buffer == NULL)
    return NULL;
  if (nhrp_ha_hub_list_encode(&list, buffer->data, buffer->length) !=
      NHRP_HA_HUB_LIST_OK) {
    nhrp_buffer_free(buffer);
    return NULL;
  }
  return buffer;
}

static int hub_list_apply(struct nhrp_ha_candidate *source,
                          const struct nhrp_ha_hub_list *list) {
  struct hub_group {
    char member[NHRP_HA_MEMBER_ID_MAX + 1];
    struct nhrp_address addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
    size_t address_count;
    int priority;
  } groups[NHRP_HA_MANAGED_MAX_MEMBERS];
  struct nhrp_ha_service *service = source->service;
  struct nhrp_ha_candidate *candidate;
  size_t group_count = 0;
  size_t i;

  if (!source->static_configured || service->switching ||
      list->list_generation <= service->hub_list_generation)
    return TRUE;

  memset(groups, 0, sizeof(groups));
  for (i = 0; i < list->entry_count; i++) {
    size_t group;

    for (group = 0; group < group_count; group++)
      if (strcmp(groups[group].member, list->entries[i].member) == 0)
        break;
    if (group == group_count) {
      if (group_count >= ARRAY_SIZE(groups))
        return FALSE;
      snprintf(groups[group].member, sizeof(groups[group].member), "%s",
               list->entries[i].member);
      groups[group].priority = (int)list->entries[i].priority;
      group_count++;
    } else if (groups[group].priority != (int)list->entries[i].priority) {
      return FALSE;
    }
    if (groups[group].address_count >= NHRP_HA_MANAGED_MAX_ENDPOINTS ||
        !nhrp_address_set(&groups[group].addresses[groups[group].address_count],
                          PF_INET, NHRP_HA_HUB_LIST_NBMA_LEN,
                          (uint8_t *)list->entries[i].nbma))
      return FALSE;
    groups[group].address_count++;
  }

  list_for_each_entry(candidate, &service->candidates, list_entry)
      candidate->dynamically_discovered = FALSE;

  for (i = 0; i < group_count; i++) {
    struct nhrp_address old_endpoints[NHRP_HA_MANAGED_MAX_ENDPOINTS];
    uint8_t old_ready[NHRP_HA_MANAGED_MAX_ENDPOINTS];
    size_t old_count;
    size_t endpoint;
    size_t selected = 0;
    int selected_found = FALSE;
    int endpoints_changed;

    candidate = candidate_find(service, groups[i].member);
    if (candidate == NULL) {
      candidate = candidate_alloc(service, groups[i].member);
      if (candidate == NULL)
        return FALSE;
      list_add_tail(&candidate->list_entry, &service->candidates);
    }
    old_count = candidate->endpoint_count;
    memcpy(old_endpoints, candidate->endpoints, sizeof(old_endpoints));
    memcpy(old_ready, candidate->endpoint_ready, sizeof(old_ready));
    for (endpoint = 0; endpoint < groups[i].address_count; endpoint++)
      if (nhrp_address_cmp(&candidate->nbma, &groups[i].addresses[endpoint]) ==
          0) {
        selected = endpoint;
        selected_found = TRUE;
        break;
      }
    if (candidate->static_configured &&
        (!selected_found || candidate->priority != groups[i].priority))
      return FALSE;
    endpoints_changed =
        candidate->endpoint_count != groups[i].address_count ||
        memcmp(candidate->endpoints, groups[i].addresses,
               groups[i].address_count * sizeof(groups[i].addresses[0])) != 0;
    if (!selected_found)
      selected = 0;
    if (endpoints_changed && !selected_found) {
      candidate->endpoint_generation++;
      ev_timer_stop(&candidate->registration_timer);
      ev_timer_stop(&candidate->probe_timer);
      candidate->registered = FALSE;
      candidate->registration_pending = FALSE;
      candidate->probe_pending = FALSE;
      candidate->last_registration_reply = 0.0;
      candidate->last_probe_reply = 0.0;
      candidate->consecutive_misses = 0;
      candidate->state = NHRP_HA_CANDIDATE_INIT;
    }
    memcpy(candidate->endpoints, groups[i].addresses,
           groups[i].address_count * sizeof(groups[i].addresses[0]));
    memset(candidate->endpoint_ready, 0, sizeof(candidate->endpoint_ready));
    memset(candidate->endpoint_misses, 0, sizeof(candidate->endpoint_misses));
    for (endpoint = 0; endpoint < groups[i].address_count; endpoint++) {
      size_t old;

      for (old = 0; old < old_count; old++)
        if (nhrp_address_cmp(&groups[i].addresses[endpoint],
                             &old_endpoints[old]) == 0) {
          candidate->endpoint_ready[endpoint] = old_ready[old];
          break;
        }
    }
    candidate->endpoint_count = groups[i].address_count;
    candidate->endpoint_index = selected;
    candidate->nbma = candidate->endpoints[selected];
    if (candidate->registered)
      candidate->endpoint_ready[selected] = TRUE;
    candidate->priority = groups[i].priority;
    candidate->dynamically_discovered = TRUE;
    candidate->configured = TRUE;
    if (candidate->state == NHRP_HA_CANDIDATE_DISABLED)
      candidate->state = NHRP_HA_CANDIDATE_INIT;
    if (nhrp_running && candidate != source)
      registration_schedule(candidate, 0.01);
  }

  list_for_each_entry(candidate, &service->candidates, list_entry) {
    if (candidate->static_configured || candidate->dynamically_discovered)
      continue;
    candidate->configured = FALSE;
    candidate->registered = FALSE;
    candidate->endpoint_generation++;
    candidate->registration_pending = FALSE;
    candidate->probe_pending = FALSE;
    ev_timer_stop(&candidate->registration_timer);
    ev_timer_stop(&candidate->probe_timer);
    candidate->state = NHRP_HA_CANDIDATE_DISABLED;
  }
  service->hub_list_generation = list->list_generation;
  snprintf(service->hub_list_source, sizeof(service->hub_list_source), "%s",
           list->source_member);
  service_changed(service);
  return TRUE;
}

static void registration_reply(void *ctx, struct nhrp_packet *reply) {
  struct nhrp_ha_registration_request *request = ctx;
  struct nhrp_ha_candidate *candidate = request->candidate;
  struct nhrp_payload *payload;
  struct nhrp_buffer *ha;
  struct nhrp_cie *cie = NULL;
  char member_id[NHRP_HA_MEMBER_ID_MAX + 1];
  struct nhrp_ha_hub_list hub_list;
  struct nhrp_address bootstrap_local_nbma = request->bootstrap_local_nbma;
  uint32_t generation;
  int has_bootstrap_local_nbma = request->has_bootstrap_local_nbma;
  int has_hub_list = FALSE;
  int code = -1;

  if (request->endpoint_generation != candidate->endpoint_generation ||
      request->registration_generation != candidate->registration_generation) {
    free(request);
    return;
  }
  generation = request->registration_generation;
  free(request);
  candidate->registration_pending = FALSE;
  if (!candidate->configured)
    return;
  if (reply == NULL || reply->hdr.type != NHRP_PACKET_REGISTRATION_REPLY ||
      nhrp_address_cmp(&reply->src_linklayer_address, &candidate->nbma) != 0)
    goto failed;

  payload = nhrp_packet_extension(
      reply, NHRP_EXTENSION_HA | NHRP_EXTENSION_FLAG_NOCREATE,
      NHRP_PAYLOAD_TYPE_RAW);
  if (payload == NULL || payload->u.raw == NULL || payload->u.raw->length < 2)
    goto failed;
  ha = payload->u.raw;
  if (payload->u.raw->data[1] == NHRP_HA_MEMBER) {
    if (!ha_member_parse(payload->u.raw, member_id, sizeof(member_id),
                         &generation))
      goto failed;
  } else if (payload->u.raw->data[1] == NHRP_HA_HUB_LIST) {
    if (nhrp_ha_hub_list_parse(payload->u.raw->data, payload->u.raw->length,
                               &hub_list) != NHRP_HA_HUB_LIST_OK)
      goto failed;
    snprintf(member_id, sizeof(member_id), "%s", hub_list.source_member);
    generation = hub_list.request_generation;
    has_hub_list = TRUE;
  } else {
    goto failed;
  }
  if (generation != candidate->registration_generation ||
      !candidate_authenticate(candidate, reply, ha))
    goto failed;
  if (candidate->bootstrap_unbound) {
    struct nhrp_ha_candidate *existing =
        candidate_find(candidate->service, member_id);
    size_t i;

    if (existing != NULL && existing != candidate)
      goto failed;
    snprintf(candidate->member_id, sizeof(candidate->member_id), "%s",
             member_id);
    snprintf(candidate->service->bootstrap_member,
             sizeof(candidate->service->bootstrap_member), "%s", member_id);
    if (has_bootstrap_local_nbma)
      candidate->bootstrap_local_nbma = bootstrap_local_nbma;
    else
      nhrp_address_set_type(&candidate->bootstrap_local_nbma, PF_UNSPEC);
    if (has_hub_list) {
      for (i = 0; i < hub_list.entry_count; i++)
        if (strcmp(hub_list.entries[i].member, member_id) == 0) {
          candidate->priority = hub_list.entries[i].priority;
          break;
        }
      if (i == hub_list.entry_count)
        goto failed;
    }
    candidate->bootstrap_unbound = FALSE;
  } else if (strcmp(member_id, candidate->member_id) != 0) {
    goto failed;
  }

  payload = nhrp_packet_payload(reply, NHRP_PAYLOAD_TYPE_CIE_LIST);
  if (payload != NULL) {
    cie = nhrp_payload_get_cie(payload, 1);
    if (cie != NULL)
      code = cie->hdr.code;
  }
  if (code != NHRP_CODE_SUCCESS)
    goto failed;
  if (has_hub_list && !hub_list_apply(candidate, &hub_list))
    goto failed;

  memset(&candidate->nat_cie, 0, sizeof(candidate->nat_cie));
  payload = nhrp_packet_extension(
      reply, NHRP_EXTENSION_NAT_ADDRESS | NHRP_EXTENSION_FLAG_NOCREATE,
      NHRP_PAYLOAD_TYPE_CIE_LIST);
  if (payload != NULL) {
    cie = nhrp_payload_get_cie(payload, 2);
    if (cie != NULL)
      candidate->nat_cie = *cie;
  }

  candidate->registered = TRUE;
  if (!candidate->preferred_endpoint_valid) {
    candidate->preferred_endpoint = candidate->nbma;
    candidate->preferred_endpoint_valid = TRUE;
  }
  candidate->endpoint_ready[candidate->endpoint_index] = TRUE;
  candidate->endpoint_misses[candidate->endpoint_index] = 0;
  candidate->last_registration_reply = ev_now();
  if (candidate->state != NHRP_HA_CANDIDATE_READY)
    candidate_set_state(candidate, NHRP_HA_CANDIDATE_REGISTERED);
  registration_schedule(candidate,
                        candidate->service->interface->holding_time / 3 + 1);
  probe_schedule(candidate, 0.01);
  if (candidate->bootstrap_anchor && coordinator_callback != NULL)
    coordinator_callback(candidate->service->interface);
  return;

failed:
  if (candidate->last_registration_reply == 0.0 ||
      ev_now() - candidate->last_registration_reply > 60.0) {
    candidate->registered = FALSE;
    candidate_select_available_endpoint(candidate);
    if (candidate->state != NHRP_HA_CANDIDATE_OFFLINE)
      candidate_set_state(candidate, NHRP_HA_CANDIDATE_REGISTERING);
  }
  registration_schedule(candidate, HA_REGISTRATION_RETRY);
}

int nhrp_ha_prepare_registration_discovery(struct nhrp_peer *peer,
                                           struct nhrp_packet *packet) {
  struct nhrp_payload *payload;
  struct nhrp_buffer *member;
  struct nhrp_buffer *compat;
  size_t compat_size;

  if (peer == NULL || packet == NULL || peer->type != NHRP_PEER_TYPE_STATIC ||
      !(peer->flags & NHRP_PEER_FLAG_REGISTER) ||
      (peer->flags & NHRP_PEER_FLAG_HA_BOOTSTRAP))
    return TRUE;
  peer->ha_discovery_generation++;
  if (peer->ha_discovery_generation == 0)
    peer->ha_discovery_generation++;
  member = ha_member_payload("bootstrap", peer->ha_discovery_generation);
  compat_size =
      member != NULL ? nhrp_ha_compat_encoded_size(member->length) : 0;
  compat = compat_size != 0 ? nhrp_buffer_alloc(compat_size) : NULL;
  payload = nhrp_packet_extension(packet, NHRP_EXTENSION_VENDOR,
                                  NHRP_PAYLOAD_TYPE_RAW);
  if (member == NULL || compat == NULL || payload == NULL ||
      !nhrp_ha_compat_encode(member->data, member->length, compat->data,
                             compat->length)) {
    nhrp_buffer_free(member);
    nhrp_buffer_free(compat);
    return FALSE;
  }
  nhrp_buffer_free(member);
  nhrp_payload_set_raw(payload, compat);
  return TRUE;
}

int nhrp_ha_handle_registration_discovery(struct nhrp_peer *peer,
                                          struct nhrp_packet *reply) {
  struct nhrp_ha_bootstrap *bootstrap;
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;
  struct nhrp_ha_registration_request *request;
  struct nhrp_payload *payload;
  struct nhrp_ha_hub_list list;
  const char *state_directory = managed_state_directory;
  const char *key_directory = getenv("OPENNHRP_HA_KEY_DIR");
  const char *keyring = NULL;
  char keyring_path[PATH_MAX];
  char seen_path[PATH_MAX];
  int keyring_exists;

  if (peer == NULL || reply == NULL || peer->type != NHRP_PEER_TYPE_STATIC ||
      !(peer->flags & NHRP_PEER_FLAG_REGISTER) ||
      reply->hdr.type != NHRP_PACKET_REGISTRATION_REPLY ||
      nhrp_address_cmp(&reply->src_linklayer_address,
                       &peer->next_hop_address) != 0)
    return FALSE;
  payload = nhrp_packet_extension(
      reply, NHRP_EXTENSION_HA | NHRP_EXTENSION_FLAG_NOCREATE,
      NHRP_PAYLOAD_TYPE_RAW);
  if (payload == NULL || payload->u.raw == NULL ||
      nhrp_ha_hub_list_parse(payload->u.raw->data, payload->u.raw->length,
                             &list) != NHRP_HA_HUB_LIST_OK ||
      list.request_generation != peer->ha_discovery_generation)
    return FALSE;

  profile = auth_profile_find(peer->interface, FALSE);
  if (profile != NULL && profile->managed)
    return FALSE;
  bootstrap = bootstrap_find(peer->interface, FALSE);
  if (bootstrap != NULL && bootstrap->configured &&
      (nhrp_address_cmp(&bootstrap->protocol, &peer->protocol_address) != 0 ||
       nhrp_address_cmp(&bootstrap->nbma, &peer->next_hop_address) != 0)) {
    nhrp_error("Ignoring a second automatic HA cluster on %s",
               peer->interface->name);
    return FALSE;
  }

  if (key_directory == NULL)
    key_directory = "/etc/opennhrp/ha";
  if (snprintf(keyring_path, sizeof(keyring_path), "%s/%s.keys", key_directory,
               peer->interface->name) >= (int)sizeof(keyring_path))
    return FALSE;
  keyring_exists = access(keyring_path, F_OK) == 0;
  if (!keyring_exists && errno != ENOENT) {
    nhrp_error("Unable to inspect optional HA keyring %s: %s", keyring_path,
               strerror(errno));
    return FALSE;
  }
  if (snprintf(seen_path, sizeof(seen_path), "%s/spoke-%s.state",
               state_directory,
               peer->interface->name) >= (int)sizeof(seen_path))
    return FALSE;
  if (!keyring_exists && access(seen_path, F_OK) == 0) {
    nhrp_error("Refusing to downgrade authenticated HA state on %s because %s "
               "is missing",
               peer->interface->name, keyring_path);
    return FALSE;
  }
  if (keyring_exists)
    keyring = keyring_path;
  if (!bootstrap_configure(peer->interface, &peer->protocol_address,
                           &peer->next_hop_address, keyring) ||
      !nhrp_ha_config_validate()) {
    nhrp_error("Unable to configure automatic HA discovery on %s",
               peer->interface->name);
    return FALSE;
  }
  bootstrap = bootstrap_find(peer->interface, FALSE);
  if (bootstrap == NULL)
    return FALSE;
  bootstrap->automatic = TRUE;
  if (!keyring_exists && !bootstrap->warned_unauthenticated) {
    nhrp_error("Automatic HA on %s is unauthenticated; protect the underlay or "
               "install %s",
               peer->interface->name, keyring_path);
    bootstrap->warned_unauthenticated = TRUE;
  }

  if (!nhrp_ha_config_map(peer->interface, &peer->protocol_address,
                          peer->prefix_length, "bootstrap",
                          &peer->next_hop_address, 0))
    return FALSE;
  service = service_find(peer->interface, &peer->protocol_address);
  candidate = service != NULL ? candidate_find(service, "bootstrap") : NULL;
  if (candidate == NULL)
    return FALSE;
  service->automatic = TRUE;
  candidate->bootstrap_unbound = TRUE;
  candidate->bootstrap_anchor = TRUE;
  candidate->registration_generation = peer->ha_discovery_generation;
  candidate->registration_pending = TRUE;
  request = calloc(1, sizeof(*request));
  if (request == NULL)
    return FALSE;
  request->candidate = candidate;
  request->endpoint_generation = candidate->endpoint_generation;
  request->registration_generation = candidate->registration_generation;
  if (peer->local_connect_address.type != PF_UNSPEC) {
    request->bootstrap_local_nbma = peer->local_connect_address;
    request->has_bootstrap_local_nbma = TRUE;
  }
  registration_reply(request, reply);
  return service->hub_list_generation != 0;
}

static void registration_timer_cb(struct ev_timer *timer, int revents) {
  struct nhrp_ha_candidate *candidate =
      container_of(timer, struct nhrp_ha_candidate, registration_timer);
  struct nhrp_ha_service *service = candidate->service;
  struct nhrp_packet *packet;
  struct nhrp_peer *direct_peer;
  struct nhrp_payload *payload;
  struct nhrp_cie *cie;
  struct nhrp_buffer *member;
  struct nhrp_ha_registration_request *request = NULL;

  if (!candidate->configured || candidate->registration_pending ||
      service->interface->index == 0 ||
      service->interface->protocol_address.type == PF_UNSPEC) {
    registration_schedule(candidate, HA_REGISTRATION_RETRY);
    return;
  }

  direct_peer = candidate_direct_peer(candidate, &candidate->nbma);
  packet = nhrp_packet_alloc();
  if (direct_peer == NULL || packet == NULL) {
    if (direct_peer != NULL)
      nhrp_peer_put(direct_peer);
    if (packet != NULL)
      nhrp_packet_put(packet);
    registration_schedule(candidate, HA_REGISTRATION_RETRY);
    return;
  }

  packet->hdr = (struct nhrp_packet_header){
      .afnum = direct_peer->afnum,
      .protocol_type = direct_peer->protocol_type,
      .version = NHRP_VERSION_RFC2332,
      .type = NHRP_PACKET_REGISTRATION_REQUEST,
      .hop_count = NHRP_PACKET_DEFAULT_HOP_COUNT,
      .flags = NHRP_FLAG_REGISTRATION_UNIQUE | NHRP_FLAG_REGISTRATION_NAT,
  };
  packet->src_nbma_address = direct_peer->my_nbma_address;
  packet->src_protocol_address = service->interface->protocol_address;
  packet->dst_protocol_address = service->protocol;
  packet->dst_iface = service->interface;
  packet->dst_peer = direct_peer;

  cie = nhrp_cie_alloc();
  if (cie == NULL)
    goto failed;
  cie->hdr = (struct nhrp_cie_header){
      .code = NHRP_CODE_SUCCESS,
      .prefix_length = 0xff,
      .mtu = htons(direct_peer->my_nbma_mtu),
      .holding_time = htons(service->interface->holding_time),
  };
  payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
  if (payload == NULL) {
    nhrp_cie_free(cie);
    goto failed;
  }
  nhrp_payload_add_cie(payload, cie);
  packet_add_standard_extensions(packet);

  cie = nhrp_cie_alloc();
  if (cie == NULL)
    goto failed;
  cie->hdr.prefix_length = service->protocol.addr_len * 8;
  cie->nbma_address = candidate->nbma;
  cie->protocol_address = service->protocol;
  payload = nhrp_packet_extension(packet, NHRP_EXTENSION_NAT_ADDRESS,
                                  NHRP_PAYLOAD_TYPE_CIE_LIST);
  if (payload == NULL) {
    nhrp_cie_free(cie);
    goto failed;
  }
  nhrp_payload_add_cie(payload, cie);

  candidate->registration_generation++;
  member = ha_member_payload(candidate->member_id,
                             candidate->registration_generation);
  payload =
      nhrp_packet_extension(packet, NHRP_EXTENSION_HA, NHRP_PAYLOAD_TYPE_RAW);
  if (member == NULL || payload == NULL) {
    nhrp_buffer_free(member);
    goto failed;
  }
  nhrp_payload_set_raw(payload, member);

  request = calloc(1, sizeof(*request));
  if (request == NULL)
    goto failed;
  request->candidate = candidate;
  request->endpoint_generation = candidate->endpoint_generation;
  request->registration_generation = candidate->registration_generation;

  candidate->registration_pending = TRUE;
  if (!candidate->registered && candidate->state != NHRP_HA_CANDIDATE_OFFLINE)
    candidate_set_state(candidate, NHRP_HA_CANDIDATE_REGISTERING);
  nhrp_packet_send_request_timed(packet, registration_reply, request, 1.0, 1);
  nhrp_packet_put(packet);
  return;

failed:
  free(request);
  nhrp_packet_put(packet);
  registration_schedule(candidate, HA_REGISTRATION_RETRY);
}

static void registration_schedule(struct nhrp_ha_candidate *candidate,
                                  ev_tstamp delay) {
  ev_timer_stop(&candidate->registration_timer);
  ev_timer_set(&candidate->registration_timer, delay, 0.0);
  ev_timer_start(&candidate->registration_timer);
}

static double candidate_min_rto(struct nhrp_ha_candidate *candidate) {
  return candidate->service->active == candidate ? HA_ACTIVE_MIN_RTO
                                                 : HA_STANDBY_MIN_RTO;
}

static void candidate_record_rtt(struct nhrp_ha_candidate *candidate,
                                 double sample) {
  if (candidate->srtt == 0.0) {
    candidate->srtt = sample;
    candidate->rttvar = sample / 2.0;
  } else {
    candidate->rttvar =
        0.75 * candidate->rttvar + 0.25 * fabs(candidate->srtt - sample);
    candidate->srtt = 0.875 * candidate->srtt + 0.125 * sample;
  }
  candidate->rto = candidate->srtt + 4.0 * candidate->rttvar;
  if (candidate->rto < candidate_min_rto(candidate))
    candidate->rto = candidate_min_rto(candidate);
  if (candidate->rto > 2.0)
    candidate->rto = 2.0;
}

static void candidate_probe_missed(struct nhrp_ha_candidate *candidate) {
  double deadline;

  candidate->probe_pending = FALSE;
  candidate->consecutive_misses++;
  if (candidate->consecutive_misses == 1)
    candidate_set_state(candidate, NHRP_HA_CANDIDATE_SUSPECT);

  deadline = candidate->rto > 0.0 ? candidate->rto * 3.0
                                  : candidate_min_rto(candidate) * 3.0;
  if (candidate->consecutive_misses >= 3 &&
      (candidate->last_probe_reply == 0.0 ||
       ev_now() - candidate->last_probe_reply >= deadline)) {
    candidate->registered = FALSE;
    candidate->last_registration_reply = 0.0;
    candidate->endpoint_ready[candidate->endpoint_index] = FALSE;
    candidate_select_available_endpoint(candidate);
    candidate_set_state(candidate, NHRP_HA_CANDIDATE_OFFLINE);
    registration_schedule(candidate, 0.01);
  }
}

static void probe_reply(void *ctx, struct nhrp_packet *reply) {
  struct nhrp_ha_probe_request *request = ctx;
  struct nhrp_ha_candidate *candidate = request->candidate;
  struct nhrp_ha_candidate *active = candidate->service->active;
  struct nhrp_payload *payload;
  struct nhrp_buffer *ha;
  char member_id[NHRP_HA_MEMBER_ID_MAX + 1];
  uint32_t sequence;
  uint32_t generation;
  uint64_t nonce;
  uint64_t sent_nanoseconds;
  uint64_t previous_commit;

  if (request->endpoint_generation != candidate->endpoint_generation ||
      request->sequence != candidate->probe_sequence ||
      request->generation != candidate->probe_generation ||
      request->nonce != candidate->probe_nonce || !candidate->probe_pending) {
    free(request);
    return;
  }
  if (request->endpoint_index >= candidate->endpoint_count || reply == NULL ||
      reply->hdr.type != NHRP_PACKET_RESOLUTION_REPLY ||
      nhrp_address_cmp(&reply->src_linklayer_address,
                       &candidate->endpoints[request->endpoint_index]) != 0)
    goto missed;

  payload = nhrp_packet_extension(
      reply, NHRP_EXTENSION_HA | NHRP_EXTENSION_FLAG_NOCREATE,
      NHRP_PAYLOAD_TYPE_RAW);
  if (payload == NULL ||
      !ha_probe_parse(payload->u.raw, NHRP_HA_PROBE_REPLY, member_id,
                      sizeof(member_id), &sequence, &generation, &nonce,
                      &sent_nanoseconds) ||
      strcmp(member_id, candidate->member_id) != 0 ||
      sequence != request->sequence || generation != request->generation ||
      nonce != request->nonce)
    goto missed;
  ha = payload->u.raw;
  previous_commit = candidate->auth_commit_index;
  if (!candidate_authenticate(candidate, reply, ha))
    goto missed;
  if (candidate->auth_commit_index > previous_commit && candidate == active &&
      !active->registration_pending)
    registration_schedule(active, 0.01);

  candidate->probe_pending = FALSE;
  candidate->endpoint_ready[request->endpoint_index] = TRUE;
  candidate->endpoint_misses[request->endpoint_index] = 0;
  candidate->last_probe_reply = ev_now();
  candidate_record_rtt(candidate, ev_now() - request->sent);
  if (!request->selected_endpoint) {
    if (!candidate->registration_pending &&
        candidate->preferred_endpoint_valid &&
        nhrp_address_cmp(&candidate->endpoints[request->endpoint_index],
                         &candidate->preferred_endpoint) == 0) {
      candidate->endpoint_index = request->endpoint_index;
      candidate->nbma = candidate->endpoints[request->endpoint_index];
      candidate->endpoint_generation++;
      service_changed(candidate->service);
      reconcile_schedule(candidate->service, 0.01);
      registration_schedule(candidate, 0.01);
    }
    free(request);
    probe_schedule(candidate, candidate->service->active == candidate
                                  ? HA_ACTIVE_PROBE_INTERVAL
                                  : HA_STANDBY_PROBE_INTERVAL);
    return;
  }
  candidate->consecutive_misses = 0;
  free(request);
  if (candidate->registered)
    candidate_set_state(candidate, NHRP_HA_CANDIDATE_READY);
  probe_schedule(candidate, candidate->service->active == candidate
                                ? HA_ACTIVE_PROBE_INTERVAL
                                : HA_STANDBY_PROBE_INTERVAL);
  return;

missed:
  if (!request->selected_endpoint) {
    candidate->probe_pending = FALSE;
    if (request->endpoint_index < candidate->endpoint_count &&
        candidate->endpoint_misses[request->endpoint_index] < UINT8_MAX &&
        ++candidate->endpoint_misses[request->endpoint_index] >= 3)
      candidate->endpoint_ready[request->endpoint_index] = FALSE;
    free(request);
    probe_schedule(candidate, candidate->service->active == candidate
                                  ? HA_ACTIVE_PROBE_INTERVAL
                                  : HA_STANDBY_PROBE_INTERVAL);
    return;
  }
  free(request);
  candidate_probe_missed(candidate);
  probe_schedule(candidate, candidate->service->active == candidate
                                ? HA_ACTIVE_PROBE_INTERVAL
                                : HA_STANDBY_PROBE_INTERVAL);
}

static void probe_timer_cb(struct ev_timer *timer, int revents) {
  struct nhrp_ha_candidate *candidate =
      container_of(timer, struct nhrp_ha_candidate, probe_timer);
  struct nhrp_ha_service *service = candidate->service;
  struct nhrp_packet *packet;
  struct nhrp_peer *direct_peer;
  struct nhrp_payload *payload;
  struct nhrp_buffer *probe;
  struct nhrp_ha_probe_request *request = NULL;
  size_t endpoint_index;
  int selected_endpoint = TRUE;
  double timeout;

  if (!candidate->configured || !candidate->registered ||
      service->interface->index == 0) {
    probe_schedule(candidate, HA_STANDBY_PROBE_INTERVAL);
    return;
  }
  if (candidate->probe_pending) {
    return;
  }

  endpoint_index = candidate->endpoint_index;
  candidate->probe_round++;
  if (candidate->endpoint_count > 1 && candidate->probe_round % 4 == 0) {
    size_t attempts;

    for (attempts = 0; attempts < candidate->endpoint_count; attempts++) {
      candidate->endpoint_probe_cursor =
          (candidate->endpoint_probe_cursor + 1) % candidate->endpoint_count;
      if (candidate->endpoint_probe_cursor != candidate->endpoint_index) {
        endpoint_index = candidate->endpoint_probe_cursor;
        selected_endpoint = FALSE;
        break;
      }
    }
  }
  direct_peer =
      candidate_direct_peer(candidate, &candidate->endpoints[endpoint_index]);
  packet = nhrp_packet_alloc();
  if (direct_peer == NULL || packet == NULL) {
    if (direct_peer != NULL)
      nhrp_peer_put(direct_peer);
    if (packet != NULL)
      nhrp_packet_put(packet);
    probe_schedule(candidate, HA_STANDBY_PROBE_INTERVAL);
    return;
  }

  packet->hdr = (struct nhrp_packet_header){
      .afnum = direct_peer->afnum,
      .protocol_type = direct_peer->protocol_type,
      .version = NHRP_VERSION_RFC2332,
      .type = NHRP_PACKET_RESOLUTION_REQUEST,
      .hop_count = NHRP_PACKET_DEFAULT_HOP_COUNT,
  };
  packet->src_nbma_address = direct_peer->my_nbma_address;
  packet->src_protocol_address = service->interface->protocol_address;
  packet->dst_protocol_address = service->protocol;
  packet->dst_iface = service->interface;
  packet->dst_peer = direct_peer;
  nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_NONE);
  packet_add_standard_extensions(packet);

  candidate->probe_sequence++;
  candidate->probe_generation++;
  candidate->probe_nonce = random_u64();
  candidate->probe_sent = ev_now();
  probe =
      ha_probe_payload(NHRP_HA_PROBE, candidate->member_id,
                       candidate->probe_sequence, candidate->probe_generation,
                       candidate->probe_nonce, monotonic_nanoseconds());
  payload =
      nhrp_packet_extension(packet, NHRP_EXTENSION_HA, NHRP_PAYLOAD_TYPE_RAW);
  if (probe == NULL || payload == NULL) {
    nhrp_buffer_free(probe);
    nhrp_packet_put(packet);
    probe_schedule(candidate, HA_STANDBY_PROBE_INTERVAL);
    return;
  }
  nhrp_payload_set_raw(payload, probe);

  request = calloc(1, sizeof(*request));
  if (request == NULL) {
    nhrp_packet_put(packet);
    probe_schedule(candidate, HA_STANDBY_PROBE_INTERVAL);
    return;
  }
  request->candidate = candidate;
  request->endpoint_generation = candidate->endpoint_generation;
  request->sequence = candidate->probe_sequence;
  request->generation = candidate->probe_generation;
  request->nonce = candidate->probe_nonce;
  request->sent = candidate->probe_sent;
  request->endpoint_index = endpoint_index;
  request->selected_endpoint = selected_endpoint;

  candidate->probe_pending = TRUE;
  timeout =
      candidate->rto > 0.0 ? candidate->rto : candidate_min_rto(candidate);
  nhrp_packet_send_request_timed(packet, probe_reply, request, timeout, 1);
  nhrp_packet_put(packet);
}

static void probe_schedule(struct nhrp_ha_candidate *candidate,
                           ev_tstamp delay) {
  ev_timer_stop(&candidate->probe_timer);
  ev_timer_set(&candidate->probe_timer, delay, 0.0);
  ev_timer_start(&candidate->probe_timer);
}

void nhrp_ha_start(void) {
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;
  struct nhrp_ha_bootstrap *bootstrap;

  list_for_each_entry(bootstrap, &bootstraps, list_entry) {
    struct nhrp_ha_service *bootstrap_service;
    uint32_t local;
    uint32_t gateway;
    uint32_t mask;

    if (!bootstrap->configured ||
        bootstrap->interface->protocol_address.type != PF_INET ||
        bootstrap->interface->protocol_address.addr_len != 4 ||
        bootstrap->interface->protocol_address_prefix < 0 ||
        bootstrap->interface->protocol_address_prefix > 32)
      continue;
    bootstrap_service =
        service_find(bootstrap->interface, &bootstrap->protocol);
    if (bootstrap->automatic && bootstrap_service != NULL &&
        bootstrap_service->hub_list_generation != 0)
      continue;
    memcpy(&local, bootstrap->interface->protocol_address.addr, 4);
    memcpy(&gateway, bootstrap->protocol.addr, 4);
    mask = bootstrap->interface->protocol_address_prefix == 0
               ? 0
               : htonl(UINT32_MAX
                       << (32 - bootstrap->interface->protocol_address_prefix));
    if ((local & mask) != (gateway & mask) || local == gateway ||
        !nhrp_ha_config_map(bootstrap->interface, &bootstrap->protocol,
                            bootstrap->interface->protocol_address_prefix,
                            "bootstrap", &bootstrap->nbma, 0))
      continue;
    bootstrap_service =
        service_find(bootstrap->interface, &bootstrap->protocol);
    if (bootstrap_service != NULL) {
      candidate = candidate_find(bootstrap_service, "bootstrap");
      if (candidate != NULL) {
        candidate->bootstrap_unbound = TRUE;
        candidate->bootstrap_anchor = TRUE;
      }
    }
  }

  list_for_each_entry(service, &services, list_entry) {
    if (service->bootstrap_member[0] != 0) {
      struct nhrp_address local_nbma;

      nhrp_address_set_type(&local_nbma, PF_UNSPEC);
      if (nhrp_peer_ha_anchor_local_nbma(service->interface, &service->protocol,
                                         &local_nbma)) {
        candidate = candidate_find(service, service->bootstrap_member);
        if (candidate != NULL &&
            nhrp_address_cmp(&candidate->bootstrap_local_nbma, &local_nbma) !=
                0) {
          candidate->bootstrap_local_nbma = local_nbma;
          service_changed(service);
        }
      }
    }
    list_for_each_entry(candidate, &service->candidates, list_entry)
        registration_schedule(candidate, 0.01);
    reconcile_schedule(service, 0.01);
  }
}

void nhrp_ha_cleanup(void) {
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_ha_local_override *override;
  struct nhrp_ha_local_override *next_override;

  list_for_each_entry(service, &services, list_entry) {
    ev_timer_stop(&service->reconcile_timer);
    list_for_each_entry(candidate, &service->candidates, list_entry) {
      ev_timer_stop(&candidate->registration_timer);
      ev_timer_stop(&candidate->probe_timer);
    }
    if (service->active_peer != NULL) {
      nhrp_peer_put(service->active_peer);
      service->active_peer = NULL;
    }
  }
  list_for_each_entry(profile, &auth_profiles, list_entry)
      nhrp_ha_auth_keys_clear(&profile->keys);
  list_for_each_entry_safe(override, next_override, &local_overrides,
                           list_entry) {
    list_del(&override->list_entry);
    free(override);
  }
  nhrp_ha_hub_cleanup();
}

void nhrp_ha_mark_configured(void) {
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;
  struct nhrp_ha_advertisement *advertisement;
  struct nhrp_ha_advertised_entry *entry;
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_ha_bootstrap *bootstrap;
  struct nhrp_ha_local_override *override;

  configuration_reload = TRUE;
  reload_hub_enable = hub_enable;
  reload_hub_enable_valid = TRUE;

  list_for_each_entry(override, &local_overrides, list_entry) {
    override->reload_existing = override->configured;
    override->reload_local_nbma = override->local_nbma;
    override->configured = FALSE;
  }

  list_for_each_entry(service, &services, list_entry) {
    if (service->automatic)
      continue;
    service->configured = FALSE;
    list_for_each_entry(candidate, &service->candidates, list_entry)
        candidate->static_configured = FALSE;
  }
  list_for_each_entry(advertisement, &advertisements, list_entry) {
    advertisement->configured = FALSE;
    list_for_each_entry(entry, &advertisement->entries, list_entry)
        entry->configured = FALSE;
  }
  list_for_each_entry(profile, &auth_profiles, list_entry) {
    if (profile->bootstrap)
      continue;
    profile->cluster_configured = FALSE;
    profile->auth_configured = FALSE;
    profile->key_configured[0] = FALSE;
    profile->key_configured[1] = FALSE;
    profile->state_configured = FALSE;
    profile->valid = FALSE;
    profile->managed = FALSE;
    profile->bootstrap = FALSE;
  }
  list_for_each_entry(bootstrap, &bootstraps, list_entry) {
    if (!bootstrap->automatic)
      bootstrap->configured = FALSE;
  }
  hub_enable.configured = FALSE;
}

void nhrp_ha_config_reload_abort(void) {
  struct nhrp_ha_local_override *override;
  struct nhrp_ha_local_override *next;

  list_for_each_entry_safe(override, next, &local_overrides, list_entry) {
    if (!override->reload_existing) {
      list_del(&override->list_entry);
      free(override);
      continue;
    }
    override->configured = TRUE;
    override->local_nbma = override->reload_local_nbma;
    override->reload_existing = FALSE;
  }
  if (reload_hub_enable_valid)
    hub_enable = reload_hub_enable;
  reload_hub_enable_valid = FALSE;
  configuration_reload = FALSE;
}

void nhrp_ha_sweep_unconfigured(void) {
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_ha_local_override *override;
  struct nhrp_ha_local_override *next;

  list_for_each_entry_safe(override, next, &local_overrides, list_entry) {
    if (!override->configured) {
      list_del(&override->list_entry);
      free(override);
      continue;
    }
    override->reload_existing = FALSE;
  }

  list_for_each_entry(service, &services, list_entry) {
    list_for_each_entry(candidate, &service->candidates, list_entry) {
      candidate->configured =
          service->configured &&
          (candidate->static_configured || candidate->dynamically_discovered);
      if (candidate->configured)
        continue;
      candidate->registered = FALSE;
      candidate->endpoint_generation++;
      candidate->registration_pending = FALSE;
      candidate->probe_pending = FALSE;
      ev_timer_stop(&candidate->registration_timer);
      ev_timer_stop(&candidate->probe_timer);
      candidate_set_state(candidate, NHRP_HA_CANDIDATE_DISABLED);
    }
  }
  list_for_each_entry(profile, &auth_profiles, list_entry) {
    int slot;

    for (slot = 0; slot < NHRP_HA_AUTH_MAX_KEYS; slot++) {
      if (profile->key_configured[slot])
        continue;
      nhrp_ha_auth_key_clear(&profile->keys.key[slot]);
    }
    if (!profile->state_configured)
      profile->state_path[0] = 0;
    if (!auth_profile_has_configuration(profile)) {
      memset(profile->cluster_id, 0, sizeof(profile->cluster_id));
      memset(&profile->seen, 0, sizeof(profile->seen));
      profile->auth_required = FALSE;
    }
  }
  configuration_reload = FALSE;
  reload_hub_enable_valid = FALSE;
}

int nhrp_ha_config_member(struct nhrp_interface *iface, const char *member_id) {
  if (!member_id_valid(member_id))
    return FALSE;
  snprintf(iface->ha_member_id, sizeof(iface->ha_member_id), "%s", member_id);
  return TRUE;
}

static int address_ipv4_unicast(const struct nhrp_address *address) {
  uint32_t value;

  if (address == NULL || address->type != PF_INET || address->addr_len != 4)
    return FALSE;
  memcpy(&value, address->addr, sizeof(value));
  value = ntohl(value);
  return value != INADDR_ANY && (value & 0xf0000000U) != 0xe0000000U;
}

int nhrp_ha_config_enable(struct nhrp_interface *iface, const char *member_id,
                          const struct nhrp_address *advertised,
                          size_t advertised_count) {
  size_t i;
  size_t j;

  if (iface == NULL ||
      (member_id != NULL && member_id[0] != 0 && !member_id_valid(member_id)) ||
      advertised_count > NHRP_HA_MANAGED_MAX_ENDPOINTS ||
      (advertised_count != 0 && advertised == NULL))
    return FALSE;
  for (i = 0; i < advertised_count; i++) {
    if (!address_ipv4_unicast(&advertised[i]))
      return FALSE;
    for (j = 0; j < i; j++)
      if (nhrp_address_cmp(&advertised[i], &advertised[j]) == 0)
        return FALSE;
  }
  if (configuration_reload && !hub_enable.runtime_locked)
    return FALSE;
  if (hub_enable.configured)
    return FALSE;
  if (hub_enable.interface != NULL && hub_enable.interface != iface)
    return FALSE;
  if (hub_enable.runtime_locked) {
    if (member_id != NULL && member_id[0] != 0 &&
        strcmp(hub_enable.member_id, member_id) != 0)
      return FALSE;
  } else {
    hub_enable.interface = iface;
    if (member_id != NULL && member_id[0] != 0)
      snprintf(hub_enable.member_id, sizeof(hub_enable.member_id), "%s",
               member_id);
    if (member_id != NULL && member_id[0] != 0)
      hub_enable.member_explicit = TRUE;
  }
  memset(hub_enable.advertised, 0, sizeof(hub_enable.advertised));
  if (advertised_count != 0)
    memcpy(hub_enable.advertised, advertised,
           advertised_count * sizeof(hub_enable.advertised[0]));
  hub_enable.advertised_count = advertised_count;
  hub_enable.advertise_explicit = advertised_count != 0;
  hub_enable.health_target_count = 0;
  hub_enable.configured = TRUE;
  return TRUE;
}

int nhrp_ha_hub_enabled(void) { return hub_enable.configured; }

const char *nhrp_ha_hub_interface(void) {
  return hub_enable.interface != NULL ? hub_enable.interface->name : NULL;
}

size_t nhrp_ha_hub_advertised(struct nhrp_address *addresses, size_t maximum) {
  if (!hub_enable.advertise_explicit || addresses == NULL ||
      maximum < hub_enable.advertised_count)
    return 0;
  memcpy(addresses, hub_enable.advertised,
         hub_enable.advertised_count * sizeof(addresses[0]));
  return hub_enable.advertised_count;
}

int nhrp_ha_config_health_target(struct nhrp_interface *iface,
                                 const struct nhrp_address *target) {
  size_t i;

  if (!hub_enable.configured || hub_enable.interface != iface ||
      !address_ipv4_unicast(target) ||
      hub_enable.health_target_count >= NHRP_HA_MANAGED_MAX_ENDPOINTS)
    return FALSE;
  for (i = 0; i < hub_enable.health_target_count; i++)
    if (nhrp_address_cmp(&hub_enable.health_targets[i], target) == 0)
      return FALSE;
  hub_enable.health_targets[hub_enable.health_target_count++] = *target;
  return TRUE;
}

size_t nhrp_ha_hub_health_targets(struct nhrp_address *targets,
                                  size_t maximum) {
  if (targets == NULL || maximum < hub_enable.health_target_count)
    return 0;
  memcpy(targets, hub_enable.health_targets,
         hub_enable.health_target_count * sizeof(targets[0]));
  return hub_enable.health_target_count;
}

void nhrp_ha_set_coordinator_callback(nhrp_ha_coordinator_callback callback) {
  coordinator_callback = callback;
}

static struct nhrp_ha_coordinator_status *
coordinator_status_find(struct nhrp_interface *iface, int create) {
  struct nhrp_ha_coordinator_status *unused = NULL;
  size_t i;

  for (i = 0; i < ARRAY_SIZE(coordinator_status); i++) {
    if (coordinator_status[i].interface == iface)
      return &coordinator_status[i];
    if (unused == NULL && coordinator_status[i].interface == NULL)
      unused = &coordinator_status[i];
  }
  if (create && unused != NULL)
    unused->interface = iface;
  return create ? unused : NULL;
}

void nhrp_ha_set_coordinator_status(struct nhrp_interface *iface,
                                    const char *state, int last_exit) {
  struct nhrp_ha_coordinator_status *status =
      coordinator_status_find(iface, TRUE);
  struct nhrp_ha_service *service;

  if (status == NULL)
    return;
  snprintf(status->state, sizeof(status->state), "%s", state);
  status->last_exit = last_exit;
  list_for_each_entry(service, &services, list_entry) {
    if (service->interface == iface)
      service_changed(service);
  }
}

static int bootstrap_configure(struct nhrp_interface *iface,
                               const struct nhrp_address *protocol,
                               const struct nhrp_address *nbma,
                               const char *keyring_path) {
  struct nhrp_ha_bootstrap *bootstrap = bootstrap_find(iface, TRUE);
  struct nhrp_ha_auth_profile *profile = auth_profile_find(iface, TRUE);
  struct nhrp_ha_auth_keys keys;
  char state_path[PATH_MAX];
  const char *state_directory = managed_state_directory;
  int lock_fd;

  memset(&keys, 0, sizeof(keys));
  if (bootstrap == NULL || profile == NULL || protocol->type != PF_INET ||
      protocol->addr_len != 4 || nbma->type != PF_INET || nbma->addr_len != 4 ||
      snprintf(state_path, sizeof(state_path), "%s/spoke-%s.state",
               state_directory, iface->name) >= (int)sizeof(state_path)) {
    return FALSE;
  }
  if (keyring_path != NULL && keyring_path[0] != 0) {
    if (strlen(keyring_path) >= PATH_MAX ||
        !nhrp_ha_managed_keyring_load(keyring_path, &keys)) {
      nhrp_ha_auth_keys_clear(&keys);
      return FALSE;
    }
  }
  lock_fd = nhrp_ha_managed_state_lock(state_directory);
  if (lock_fd < 0) {
    nhrp_ha_auth_keys_clear(&keys);
    return FALSE;
  }
  nhrp_ha_managed_state_unlock(lock_fd);
  bootstrap->protocol = *protocol;
  bootstrap->nbma = *nbma;
  if (keyring_path != NULL && keyring_path[0] != 0) {
    snprintf(bootstrap->keyring_path, sizeof(bootstrap->keyring_path), "%s",
             keyring_path);
  } else {
    bootstrap->keyring_path[0] = 0;
  }
  bootstrap->configured = TRUE;
  nhrp_ha_auth_keys_clear(&profile->keys);
  profile->keys = keys;
  profile->key_configured[0] = profile->keys.key[0].present;
  profile->key_configured[1] = profile->keys.key[1].present;
  profile->auth_configured = (keyring_path != NULL && keyring_path[0] != 0);
  profile->auth_required = profile->auth_configured;
  profile->bootstrap = TRUE;
  profile->state_configured = TRUE;
  snprintf(profile->state_path, sizeof(profile->state_path), "%s", state_path);
  profile->valid = FALSE;
  return TRUE;
}

static int managed_path_exists(const char *path, int *exists) {
  if (access(path, F_OK) == 0) {
    *exists = TRUE;
    return TRUE;
  }
  if (errno != ENOENT)
    return FALSE;
  *exists = FALSE;
  return TRUE;
}

int nhrp_ha_prepare_managed(const char *directory) {
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_member *member;
  struct nhrp_ha_auth_keys keys;
  struct in_addr protocol;
  struct in_addr advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  char state_path[PATH_MAX];
  char keys_path[PATH_MAX];
  char identity_path[PATH_MAX];
  char member_id[NHRP_HA_MEMBER_ID_MAX + 1];
  int state_exists;
  int keys_exist;
  int identity_exists;
  enum nhrp_ha_managed_init_result init_result;
  size_t advertised_count;
  size_t i;

  if (directory == NULL || directory[0] == 0 ||
      strlen(directory) >= sizeof(managed_state_directory))
    return FALSE;
  snprintf(managed_state_directory, sizeof(managed_state_directory), "%s",
           directory);
  if (!hub_enable.configured)
    return TRUE;
  if (directory == NULL || hub_enable.interface == NULL ||
      !nhrp_ha_managed_paths(directory, state_path, sizeof(state_path),
                             keys_path, sizeof(keys_path), identity_path,
                             sizeof(identity_path)) ||
      !managed_path_exists(state_path, &state_exists) ||
      !managed_path_exists(keys_path, &keys_exist) ||
      !managed_path_exists(identity_path, &identity_exists)) {
    nhrp_error("Unable to inspect managed HA state in %s", directory);
    return FALSE;
  }
  if ((state_exists || keys_exist || identity_exists) &&
      !(state_exists && keys_exist && identity_exists)) {
    nhrp_error("Managed HA state in %s is incomplete", directory);
    return FALSE;
  }

  if (!state_exists) {
    if (hub_enable.interface->protocol_address.type != PF_INET ||
        hub_enable.interface->protocol_address.addr_len != 4 ||
        hub_enable.interface->protocol_address_prefix < 0 ||
        hub_enable.interface->protocol_address_prefix > 32) {
      nhrp_error("enable-ha requires one IPv4 protocol address on %s",
                 hub_enable.interface->name);
      return FALSE;
    }
    memcpy(&protocol, hub_enable.interface->protocol_address.addr,
           sizeof(protocol));
    if (hub_enable.member_id[0] != 0) {
      snprintf(member_id, sizeof(member_id), "%s", hub_enable.member_id);
    } else {
      if (gethostname(member_id, sizeof(member_id)) != 0)
        member_id[0] = 0;
      member_id[sizeof(member_id) - 1] = 0;
      if (!member_id_valid(member_id)) {
        nhrp_error("Hostname is not a valid HA member ID; configure member-id");
        return FALSE;
      }
    }
    advertised_count = hub_enable.advertised_count;
    if (advertised_count != 0) {
      for (i = 0; i < advertised_count; i++)
        memcpy(&advertised[i], hub_enable.advertised[i].addr,
               sizeof(advertised[i]));
    } else if (hub_enable.interface->nbma_address.type == PF_INET &&
               hub_enable.interface->nbma_address.addr_len == 4) {
      memcpy(&advertised[0], hub_enable.interface->nbma_address.addr,
             sizeof(advertised[0]));
      advertised_count = 1;
    } else {
      nhrp_error("Cannot derive the NBMA address for %s; configure advertise",
                 hub_enable.interface->name);
      return FALSE;
    }
    init_result = nhrp_ha_managed_cluster_init(
        directory, hub_enable.interface->name, member_id, &protocol,
        (uint8_t)hub_enable.interface->protocol_address_prefix, advertised,
        advertised_count, &state);
    if (init_result != NHRP_HA_MANAGED_INIT_OK) {
      nhrp_error("Unable to initialize managed HA state in %s (status %d)",
                 directory, init_result);
      return FALSE;
    }
    nhrp_info("Initialized managed HA Primary %s on %s", member_id,
              hub_enable.interface->name);
  }

  memset(&keys, 0, sizeof(keys));
  if (!nhrp_ha_managed_keyring_load(keys_path, &keys) ||
      !nhrp_ha_managed_state_load(state_path, &keys, &state)) {
    nhrp_ha_auth_keys_clear(&keys);
    nhrp_error("Unable to load managed HA state from %s", directory);
    return FALSE;
  }
  nhrp_ha_auth_keys_clear(&keys);
  member = nhrp_ha_managed_member_find(&state, state.local_member);
  if (strcmp(state.interface, hub_enable.interface->name) != 0) {
    nhrp_error("enable-ha interface %s does not match managed interface %s in "
               "%s",
               hub_enable.interface->name, state.interface, directory);
    return FALSE;
  }
  if (member == NULL) {
    nhrp_error("enable-ha local member %s is absent from managed state in %s",
               state.local_member, directory);
    return FALSE;
  }
  if (hub_enable.member_id[0] != 0 &&
      strcmp(state.local_member, hub_enable.member_id) != 0) {
    nhrp_error("enable-ha member-id %s does not match managed member %s in %s",
               hub_enable.member_id, state.local_member, directory);
    return FALSE;
  }
  if (hub_enable.interface->protocol_address.type == PF_INET &&
      (memcmp(&state.protocol_address,
              hub_enable.interface->protocol_address.addr, 4) != 0 ||
       state.prefix_length !=
           (uint8_t)hub_enable.interface->protocol_address_prefix)) {
    char configured[64];
    char managed[INET_ADDRSTRLEN];

    nhrp_address_format(&hub_enable.interface->protocol_address,
                        sizeof(configured), configured);
    inet_ntop(AF_INET, &state.protocol_address, managed, sizeof(managed));
    nhrp_error("enable-ha protocol %s/%d does not match managed protocol "
               "%s/%u in %s",
               configured, hub_enable.interface->protocol_address_prefix,
               managed, state.prefix_length, directory);
    return FALSE;
  }
  snprintf(hub_enable.member_id, sizeof(hub_enable.member_id), "%s",
           state.local_member);
  if (!hub_enable.advertise_explicit) {
    hub_enable.advertised_count = member->configured_address_count;
    for (i = 0; i < hub_enable.advertised_count; i++)
      nhrp_address_set(&hub_enable.advertised[i], PF_INET,
                       sizeof(member->addresses[i]),
                       (uint8_t *)&member->addresses[i]);
  }
  if (!nhrp_ha_load_managed(directory))
    return FALSE;
  hub_enable.runtime_locked = TRUE;
  return TRUE;
}

int nhrp_ha_reload_managed(const char *directory) {
  struct managed_reload_entry {
    struct nhrp_ha_advertised_entry *entry;
    struct nhrp_address nbma;
    int priority;
    int configured;
  } *saved_entries;
  struct nhrp_ha_enable_config saved_enable = hub_enable;
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_ha_auth_profile saved_profile;
  struct nhrp_ha_advertisement *advertisement;
  struct nhrp_ha_advertised_entry *entry;
  struct nhrp_address protocol;
  uint32_t saved_generation;
  char saved_member_id[NHRP_HA_MEMBER_ID_MAX + 1];
  size_t entry_count = 0;
  size_t i = 0;
  int saved_configured;

  if (directory == NULL || directory[0] == 0 || !hub_enable.configured ||
      !hub_enable.runtime_locked || hub_enable.interface == NULL ||
      hub_enable.interface->protocol_address.type != PF_INET)
    return FALSE;
  protocol = hub_enable.interface->protocol_address;
  advertisement = advertisement_find(hub_enable.interface, &protocol);
  profile = auth_profile_find(hub_enable.interface, FALSE);
  if (advertisement == NULL || profile == NULL)
    return FALSE;
  list_for_each_entry(entry, &advertisement->entries, list_entry) entry_count++;
  saved_entries =
      calloc(entry_count > 0 ? entry_count : 1, sizeof(*saved_entries));
  if (saved_entries == NULL)
    return FALSE;
  list_for_each_entry(entry, &advertisement->entries, list_entry) {
    saved_entries[i].entry = entry;
    saved_entries[i].nbma = entry->nbma;
    saved_entries[i].priority = entry->priority;
    saved_entries[i].configured = entry->configured;
    i++;
  }
  saved_profile = *profile;
  snprintf(saved_member_id, sizeof(saved_member_id), "%s",
           hub_enable.interface->ha_member_id);
  saved_generation = advertisement->generation;
  saved_configured = advertisement->configured;
  advertisement->configured = FALSE;
  list_for_each_entry(entry, &advertisement->entries, list_entry)
      entry->configured = FALSE;

  nhrp_info("Reloading managed HA state from %s", directory);
  if (nhrp_ha_prepare_managed(directory)) {
    nhrp_ha_auth_keys_clear(&saved_profile.keys);
    free(saved_entries);
    nhrp_info("Managed HA state reloaded successfully");
    return TRUE;
  }

  hub_enable = saved_enable;
  snprintf(hub_enable.interface->ha_member_id,
           sizeof(hub_enable.interface->ha_member_id), "%s", saved_member_id);
  nhrp_ha_auth_keys_clear(&profile->keys);
  *profile = saved_profile;
  nhrp_ha_auth_keys_clear(&saved_profile.keys);
  advertisement->generation = saved_generation;
  advertisement->configured = saved_configured;
  list_for_each_entry(entry, &advertisement->entries, list_entry)
      entry->configured = FALSE;
  for (i = 0; i < entry_count; i++) {
    list_del(&saved_entries[i].entry->list_entry);
    list_add_tail(&saved_entries[i].entry->list_entry, &advertisement->entries);
    saved_entries[i].entry->nbma = saved_entries[i].nbma;
    saved_entries[i].entry->priority = saved_entries[i].priority;
    saved_entries[i].entry->configured = saved_entries[i].configured;
  }
  free(saved_entries);
  nhrp_error("Failed to reload managed HA state from %s", directory);
  return FALSE;
}

int nhrp_ha_config_validate(void) {
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_ha_service *service;

  if (hub_enable.runtime_locked && !hub_enable.configured) {
    nhrp_error("enable-ha cannot be removed by configuration reload");
    return FALSE;
  }
  if (configuration_reload) {
    list_for_each_entry(service, &services, list_entry) {
      if (service->automatic && !nhrp_peer_ha_anchor_configured(
                                    service->interface, &service->protocol)) {
        nhrp_error("An active automatic HA map cannot be removed by reload");
        return FALSE;
      }
    }
  }

  list_for_each_entry(profile, &auth_profiles, list_entry) {
    if (!auth_profile_validate(profile)) {
      nhrp_error("Incomplete or invalid HA authentication configuration on %s",
                 profile->interface->name);
      return FALSE;
    }
  }
  return TRUE;
}

int nhrp_ha_load_managed(const char *directory) {
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_auth_keys keys;
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_interface *iface;
  struct nhrp_address protocol;
  struct nhrp_address nbma;
  char state_path[PATH_MAX];
  char keys_path[PATH_MAX];
  char identity_path[PATH_MAX];
  char seen_path[PATH_MAX];
  uint32_t revision;
  size_t i;

  memset(&keys, 0, sizeof(keys));
  if (directory == NULL ||
      !nhrp_ha_managed_paths(directory, state_path, sizeof(state_path),
                             keys_path, sizeof(keys_path), identity_path,
                             sizeof(identity_path)))
    return FALSE;
  if (access(state_path, F_OK) != 0)
    return errno == ENOENT;
  if (!nhrp_ha_managed_keyring_load(keys_path, &keys) ||
      !nhrp_ha_managed_state_load(state_path, &keys, &state) ||
      snprintf(seen_path, sizeof(seen_path), "%s/seen.state", directory) >=
          (int)sizeof(seen_path)) {
    nhrp_ha_auth_keys_clear(&keys);
    return FALSE;
  }
  iface = nhrp_interface_get_by_name(state.interface, TRUE);
  if (iface == NULL || (profile = auth_profile_find(iface, TRUE)) == NULL ||
      !nhrp_ha_config_member(iface, state.local_member)) {
    nhrp_ha_auth_keys_clear(&keys);
    return FALSE;
  }
  nhrp_ha_auth_keys_clear(&profile->keys);
  profile->keys = keys;
  memset(&keys, 0, sizeof(keys));
  memcpy(profile->cluster_id, state.cluster_id, sizeof(profile->cluster_id));
  profile->cluster_configured = TRUE;
  profile->auth_configured = TRUE;
  profile->auth_required = TRUE;
  profile->key_configured[0] = profile->keys.key[0].present;
  profile->key_configured[1] = profile->keys.key[1].present;
  snprintf(profile->state_path, sizeof(profile->state_path), "%s", seen_path);
  profile->state_configured = TRUE;
  profile->managed = TRUE;
  profile->valid = FALSE;
  memcpy(profile->seen.cluster_id, state.cluster_id,
         sizeof(profile->seen.cluster_id));
  profile->seen.term = state.term;
  profile->seen.commit_index = state.commit_index;
  snprintf(profile->seen.leader, sizeof(profile->seen.leader), "%s",
           state.leader);
  if (profile->keys.key[0].present)
    memcpy(profile->seen.key_id, profile->keys.key[0].id,
           sizeof(profile->seen.key_id));

  nhrp_address_set(&protocol, PF_INET, sizeof(state.protocol_address),
                   (uint8_t *)&state.protocol_address);
  revision = (uint32_t)state.manifest_revision;
  if (revision == 0)
    revision = UINT32_MAX;
  for (i = 0; i < state.member_count; i++) {
    size_t j;

    if (state.members[i].state != NHRP_HA_MANAGED_ACTIVE)
      continue;
    for (j = 0; j < state.members[i].address_count; j++) {
      nhrp_address_set(&nbma, PF_INET, sizeof(state.members[i].addresses[j]),
                       (uint8_t *)&state.members[i].addresses[j]);
      if (!nhrp_ha_config_advertise(iface, &protocol, state.prefix_length,
                                    revision, state.members[i].member, &nbma,
                                    (int)state.members[i].priority))
        return FALSE;
    }
  }
  return nhrp_ha_config_validate();
}

int nhrp_ha_set_cluster_state(struct nhrp_interface *iface, uint64_t term,
                              uint64_t commit_index, const char *leader) {
  struct nhrp_ha_auth_profile *profile = auth_profile_find(iface, FALSE);
  struct nhrp_ha_auth_metadata metadata;
  struct nhrp_ha_service *service;

  if (profile == NULL || !profile->valid || !profile->key_configured[0] ||
      term == 0 || !member_id_valid(leader))
    return FALSE;
  if (term == profile->seen.term && strcmp(leader, profile->seen.leader) == 0 &&
      commit_index <= profile->seen.commit_index)
    return TRUE;
  memset(&metadata, 0, sizeof(metadata));
  memcpy(metadata.cluster_id, profile->cluster_id, sizeof(metadata.cluster_id));
  metadata.term = term;
  metadata.commit_index = commit_index;
  snprintf(metadata.leader, sizeof(metadata.leader), "%s", leader);
  if (!auth_profile_observe(profile, &metadata, profile->keys.key[0].id))
    return FALSE;
  list_for_each_entry(service, &services, list_entry) {
    if (service->interface == iface)
      service_changed(service);
  }
  return TRUE;
}

int nhrp_ha_config_map(struct nhrp_interface *iface,
                       const struct nhrp_address *protocol,
                       uint8_t prefix_length, const char *member_id,
                       const struct nhrp_address *nbma, int priority) {
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;

  if (!member_id_valid(member_id) || protocol->type == PF_UNSPEC ||
      nbma->type == PF_UNSPEC || protocol->type != nbma->type || priority < 0)
    return FALSE;

  service = service_find(iface, protocol);
  if (service == NULL) {
    service = calloc(1, sizeof(*service));
    if (service == NULL)
      return FALSE;
    service->interface = iface;
    service->protocol = *protocol;
    service->prefix_length = prefix_length;
    service->configured = TRUE;
    list_init(&service->candidates);
    ev_timer_init(&service->reconcile_timer, reconcile_timer_cb, 0.0, 0.0);
    list_add_tail(&service->list_entry, &services);
  } else if (service->prefix_length != prefix_length) {
    return FALSE;
  }
  service->configured = TRUE;

  candidate = candidate_find(service, member_id);
  if (candidate == NULL) {
    candidate = candidate_alloc(service, member_id);
    if (candidate == NULL)
      return FALSE;
    list_add_tail(&candidate->list_entry, &service->candidates);
  }
  if (nhrp_address_cmp(&candidate->nbma, nbma) != 0) {
    if (service->active == candidate)
      return FALSE;
    candidate->endpoint_generation++;
    candidate->registered = FALSE;
    candidate->registration_pending = FALSE;
    candidate->probe_pending = FALSE;
    candidate->last_registration_reply = 0.0;
    candidate->last_probe_reply = 0.0;
    candidate->consecutive_misses = 0;
    candidate->state = NHRP_HA_CANDIDATE_INIT;
    ev_timer_stop(&candidate->registration_timer);
    ev_timer_stop(&candidate->probe_timer);
  }
  candidate_set_single_endpoint(candidate, nbma);
  candidate->preferred_endpoint = *nbma;
  candidate->preferred_endpoint_valid = TRUE;
  candidate->priority = priority;
  candidate->configured = TRUE;
  candidate->static_configured = TRUE;
  if (candidate->state == NHRP_HA_CANDIDATE_DISABLED)
    candidate->state = NHRP_HA_CANDIDATE_INIT;
  if (nhrp_running)
    registration_schedule(candidate, 0.01);
  return TRUE;
}

int nhrp_ha_config_local_nbma(struct nhrp_interface *iface,
                              const char *member_id,
                              const struct nhrp_address *local_nbma) {
  struct nhrp_ha_local_override *override;

  if (iface == NULL || !member_id_valid(member_id) ||
      !address_ipv4_unicast(local_nbma))
    return FALSE;
  override = local_override_find(iface, member_id);
  if (override != NULL)
    return FALSE;
  override = local_override_find_any(iface, member_id);
  if (override == NULL) {
    override = calloc(1, sizeof(*override));
    if (override == NULL)
      return FALSE;
    override->interface = iface;
    snprintf(override->member_id, sizeof(override->member_id), "%s", member_id);
    list_add_tail(&override->list_entry, &local_overrides);
  }
  override->local_nbma = *local_nbma;
  override->configured = TRUE;
  return TRUE;
}

int nhrp_ha_config_advertise(struct nhrp_interface *iface,
                             const struct nhrp_address *protocol,
                             uint8_t prefix_length, uint32_t list_generation,
                             const char *member_id,
                             const struct nhrp_address *nbma, int priority) {
  struct nhrp_ha_advertisement *advertisement;
  struct nhrp_ha_advertised_entry *entry;
  size_t configured_entries = 0;

  if (!member_id_valid(member_id) || protocol->type != PF_INET ||
      nbma->type != PF_INET || protocol->addr_len != 4 || nbma->addr_len != 4 ||
      nhrp_address_is_any_addr(nbma) || nhrp_address_is_multicast(nbma) ||
      nbma->addr[0] >= 224 || prefix_length > 32 || list_generation == 0 ||
      priority < 0)
    return FALSE;

  advertisement = advertisement_find(iface, protocol);
  if (advertisement == NULL) {
    advertisement = calloc(1, sizeof(*advertisement));
    if (advertisement == NULL)
      return FALSE;
    advertisement->interface = iface;
    advertisement->protocol = *protocol;
    advertisement->prefix_length = prefix_length;
    advertisement->generation = list_generation;
    list_init(&advertisement->entries);
    list_add_tail(&advertisement->list_entry, &advertisements);
  } else if (advertisement->prefix_length != prefix_length ||
             (advertisement->configured &&
              advertisement->generation != list_generation)) {
    return FALSE;
  }
  if (!advertisement->configured)
    advertisement->generation = list_generation;
  advertisement->configured = TRUE;

  list_for_each_entry(entry, &advertisement->entries, list_entry) {
    if (entry->configured)
      configured_entries++;
    if (entry->configured && strcmp(entry->member_id, member_id) != 0 &&
        nhrp_address_cmp(&entry->nbma, nbma) == 0)
      return FALSE;
  }
  entry = advertised_entry_find(advertisement, member_id, nbma);
  if (entry != NULL && entry->configured)
    return FALSE;
  if (configured_entries >= NHRP_HA_HUB_LIST_MAX_ENTRIES)
    return FALSE;
  if (entry == NULL) {
    entry = calloc(1, sizeof(*entry));
    if (entry == NULL)
      return FALSE;
    snprintf(entry->member_id, sizeof(entry->member_id), "%s", member_id);
    list_add_tail(&entry->list_entry, &advertisement->entries);
  } else {
    list_del(&entry->list_entry);
    list_add_tail(&entry->list_entry, &advertisement->entries);
  }
  entry->nbma = *nbma;
  entry->priority = priority;
  entry->configured = TRUE;
  return TRUE;
}

void nhrp_ha_save_config(FILE *file, struct nhrp_interface *iface) {
  struct nhrp_ha_local_override *override;

  if (hub_enable.configured && hub_enable.interface == iface) {
    char advertised[64];
    size_t i;

    fprintf(file, "  enable-ha");
    if (hub_enable.member_explicit)
      fprintf(file, " member-id %s", hub_enable.member_id);
    for (i = 0; i < hub_enable.advertised_count; i++) {
      nhrp_address_format(&hub_enable.advertised[i], sizeof(advertised),
                          advertised);
      fprintf(file, " advertise %s", advertised);
    }
    fprintf(file, "\n");
    for (i = 0; i < hub_enable.health_target_count; i++) {
      nhrp_address_format(&hub_enable.health_targets[i], sizeof(advertised),
                          advertised);
      fprintf(file, "  ha-health-target %s\n", advertised);
    }
  }
  list_for_each_entry(override, &local_overrides, list_entry) {
    char local_nbma[64];

    if (!override->configured || override->interface != iface)
      continue;
    nhrp_address_format(&override->local_nbma, sizeof(local_nbma), local_nbma);
    fprintf(file, "  ha-local-nbma %s %s\n", override->member_id, local_nbma);
  }
}

int nhrp_ha_prepare_registration_reply(struct nhrp_packet *packet) {
  struct nhrp_payload *payload;
  struct nhrp_buffer *member;
  struct nhrp_buffer *compat_member = NULL;
  struct nhrp_ha_advertisement *advertisement;
  const uint8_t *compat_data;
  size_t compat_size;
  char requested_member[NHRP_HA_MEMBER_ID_MAX + 1];
  uint32_t generation;
  int compat = FALSE;

  payload = nhrp_packet_extension(
      packet, NHRP_EXTENSION_HA | NHRP_EXTENSION_FLAG_NOCREATE,
      NHRP_PAYLOAD_TYPE_RAW);
  if (payload == NULL) {
    payload = nhrp_packet_extension(
        packet, NHRP_EXTENSION_VENDOR | NHRP_EXTENSION_FLAG_NOCREATE,
        NHRP_PAYLOAD_TYPE_RAW);
    if (payload == NULL || payload->u.raw == NULL ||
        !nhrp_ha_compat_parse(payload->u.raw->data, payload->u.raw->length,
                              &compat_data, &compat_size))
      return TRUE;
    compat_member = nhrp_buffer_alloc(compat_size);
    if (compat_member == NULL)
      return FALSE;
    memcpy(compat_member->data, compat_data, compat_size);
    compat = TRUE;
  }
  if (!ha_member_parse(compat ? compat_member : payload->u.raw,
                       requested_member, sizeof(requested_member), &generation))
    goto failed;
  if (packet->src_iface->ha_member_id[0] == 0)
    goto ordinary;
  if ((strcmp(requested_member, packet->src_iface->ha_member_id) != 0 &&
       strcmp(requested_member, "bootstrap") != 0))
    goto failed;

  advertisement =
      advertisement_find(packet->src_iface, &packet->dst_protocol_address);
  if (advertisement != NULL && advertisement->configured)
    member = hub_list_payload(advertisement, packet->src_iface->ha_member_id,
                              generation);
  else
    member = ha_member_payload(packet->src_iface->ha_member_id, generation);
  if (member == NULL)
    goto failed;
  nhrp_buffer_free(compat_member);
  if (compat)
    payload->extension_type = NHRP_EXTENSION_HA;
  nhrp_payload_set_raw(payload, member);
  return TRUE;

ordinary:
  nhrp_buffer_free(compat_member);
  return strcmp(requested_member, "bootstrap") == 0;
failed:
  nhrp_buffer_free(compat_member);
  return FALSE;
}

int nhrp_ha_prepare_probe_reply(struct nhrp_packet *packet) {
  struct nhrp_payload *payload;
  struct nhrp_buffer *probe;
  char requested_member[NHRP_HA_MEMBER_ID_MAX + 1];
  uint32_t sequence;
  uint32_t generation;
  uint64_t nonce;
  uint64_t sent_nanoseconds;

  payload = nhrp_packet_extension(
      packet, NHRP_EXTENSION_HA | NHRP_EXTENSION_FLAG_NOCREATE,
      NHRP_PAYLOAD_TYPE_RAW);
  if (payload == NULL || payload->u.raw == NULL || payload->u.raw->length < 2 ||
      payload->u.raw->data[1] != NHRP_HA_PROBE)
    return TRUE;
  if (packet->src_iface->ha_member_id[0] == 0 ||
      !ha_probe_parse(payload->u.raw, NHRP_HA_PROBE, requested_member,
                      sizeof(requested_member), &sequence, &generation, &nonce,
                      &sent_nanoseconds) ||
      strcmp(requested_member, packet->src_iface->ha_member_id) != 0)
    return FALSE;

  probe = ha_probe_payload(NHRP_HA_PROBE_REPLY, packet->src_iface->ha_member_id,
                           sequence, generation, nonce, sent_nanoseconds);
  if (probe == NULL)
    return FALSE;
  nhrp_payload_set_raw(payload, probe);
  return 2;
}

static const char *auth_initial_leader(struct nhrp_interface *iface,
                                       const struct nhrp_address *protocol) {
  struct nhrp_ha_advertisement *advertisement;
  struct nhrp_ha_advertised_entry *entry;
  struct nhrp_ha_advertised_entry *best = NULL;

  advertisement = advertisement_find(iface, protocol);
  if (advertisement != NULL && advertisement->configured) {
    list_for_each_entry(entry, &advertisement->entries, list_entry) {
      if (!entry->configured)
        continue;
      if (best == NULL || entry->priority > best->priority ||
          (entry->priority == best->priority &&
           strcmp(entry->member_id, best->member_id) < 0))
        best = entry;
    }
  }
  if (best != NULL)
    return best->member_id;
  return iface->ha_member_id;
}

static uint64_t
auth_advertisement_generation(struct nhrp_interface *iface,
                              const struct nhrp_address *protocol) {
  struct nhrp_ha_advertisement *advertisement =
      advertisement_find(iface, protocol);

  if (advertisement == NULL || !advertisement->configured)
    return 0;
  return advertisement->generation;
}

static int auth_input_from_packet(struct nhrp_packet *packet,
                                  const struct nhrp_buffer *ha,
                                  struct nhrp_ha_auth_input *input) {
  if (ha == NULL || packet->src_protocol_address.type != PF_INET ||
      packet->dst_protocol_address.type != PF_INET ||
      packet->src_protocol_address.addr_len != 4 ||
      packet->dst_protocol_address.addr_len != 4)
    return FALSE;
  memset(input, 0, sizeof(*input));
  input->packet_type = packet->hdr.type;
  input->request_id_wire = packet->hdr.u.request_id;
  memcpy(input->src_protocol, packet->src_protocol_address.addr, 4);
  memcpy(input->dst_protocol, packet->dst_protocol_address.addr, 4);
  input->ha_payload = ha->data;
  input->ha_payload_length = ha->length;
  return TRUE;
}

static int
auth_profile_observe(struct nhrp_ha_auth_profile *profile,
                     const struct nhrp_ha_auth_metadata *metadata,
                     const uint8_t key_id[NHRP_HA_AUTH_KEY_ID_SIZE]) {
  struct nhrp_ha_seen_state state;
  int changed;

  if (profile->bootstrap && !profile->cluster_configured) {
    memcpy(profile->cluster_id, metadata->cluster_id,
           sizeof(profile->cluster_id));
    profile->cluster_configured = TRUE;
  }
  if (CRYPTO_memcmp(profile->cluster_id, metadata->cluster_id,
                    NHRP_HA_AUTH_CLUSTER_ID_SIZE) != 0 ||
      !member_id_valid(metadata->leader) || metadata->term == 0 ||
      metadata->term < profile->seen.term ||
      (metadata->term == profile->seen.term && profile->seen.leader[0] != 0 &&
       strcmp(metadata->leader, profile->seen.leader) != 0) ||
      (metadata->term == profile->seen.term &&
       metadata->commit_index < profile->seen.commit_index))
    return FALSE;

  changed = metadata->term > profile->seen.term ||
            metadata->commit_index > profile->seen.commit_index ||
            profile->seen.leader[0] == 0;
  if (!changed)
    return TRUE;
  memset(&state, 0, sizeof(state));
  memcpy(state.cluster_id, metadata->cluster_id, sizeof(state.cluster_id));
  state.term = metadata->term;
  state.commit_index = metadata->commit_index;
  snprintf(state.leader, sizeof(state.leader), "%s", metadata->leader);
  memcpy(state.key_id, key_id, sizeof(state.key_id));
  if (profile->state_configured &&
      !nhrp_ha_seen_save(profile->state_path, &profile->keys, &state)) {
    nhrp_error("Unable to persist HA authentication state for %s",
               profile->interface->name);
    return FALSE;
  }
  profile->seen = state;
  return TRUE;
}

int nhrp_ha_prepare_outgoing(struct nhrp_packet *packet) {
  struct nhrp_ha_auth_profile *profile;
  struct nhrp_ha_auth_metadata metadata;
  struct nhrp_ha_auth_input input;
  struct nhrp_payload *ha_payload;
  struct nhrp_payload *auth_payload;
  struct nhrp_buffer *auth;
  struct nhrp_interface *iface = packet->dst_iface;
  const char *leader;
  uint8_t key_id[NHRP_HA_AUTH_KEY_ID_SIZE] = {0};
  size_t encoded_size;

  if (packet->hdr.type != NHRP_PACKET_REGISTRATION_REPLY &&
      packet->hdr.type != NHRP_PACKET_RESOLUTION_REPLY)
    return TRUE;
  ha_payload = nhrp_packet_extension(
      packet, NHRP_EXTENSION_HA | NHRP_EXTENSION_FLAG_NOCREATE,
      NHRP_PAYLOAD_TYPE_RAW);
  if (ha_payload == NULL || ha_payload->u.raw == NULL ||
      ha_payload->u.raw->length < 2 ||
      (ha_payload->u.raw->data[1] != NHRP_HA_MEMBER &&
       ha_payload->u.raw->data[1] != NHRP_HA_HUB_LIST &&
       ha_payload->u.raw->data[1] != NHRP_HA_PROBE_REPLY))
    return TRUE;
  if (iface == NULL)
    iface = packet->src_iface;
  profile = auth_profile_find(iface, FALSE);
  if (profile == NULL || !profile->auth_configured)
    return TRUE;
  if (!profile->valid || !profile->key_configured[0])
    return profile->auth_required ? FALSE : TRUE;

  memset(&metadata, 0, sizeof(metadata));
  memcpy(metadata.cluster_id, profile->cluster_id, sizeof(metadata.cluster_id));
  metadata.term = profile->seen.term != 0 ? profile->seen.term : 1;
  metadata.commit_index =
      auth_advertisement_generation(iface, &packet->dst_protocol_address);
  if (metadata.commit_index < profile->seen.commit_index)
    metadata.commit_index = profile->seen.commit_index;
  leader = profile->seen.leader[0] != 0
               ? profile->seen.leader
               : auth_initial_leader(iface, &packet->dst_protocol_address);
  if (!member_id_valid(leader))
    return FALSE;
  snprintf(metadata.leader, sizeof(metadata.leader), "%s", leader);
  memcpy(key_id, profile->keys.key[0].id, sizeof(key_id));
  if (!auth_profile_observe(profile, &metadata, key_id) ||
      !auth_input_from_packet(packet, ha_payload->u.raw, &input))
    return FALSE;

  encoded_size = nhrp_ha_auth_encoded_size(&profile->keys, &metadata);
  auth = nhrp_buffer_alloc(encoded_size);
  auth_payload = nhrp_packet_extension(packet, NHRP_EXTENSION_HA_AUTH,
                                       NHRP_PAYLOAD_TYPE_RAW);
  if (encoded_size == 0 || auth == NULL || auth_payload == NULL ||
      nhrp_ha_auth_encode(&profile->keys, &input, &metadata, auth->data,
                          auth->length) != NHRP_HA_AUTH_OK) {
    nhrp_buffer_free(auth);
    return FALSE;
  }
  nhrp_payload_set_raw(auth_payload, auth);
  return TRUE;
}

static void candidate_auth_clear(struct nhrp_ha_candidate *candidate) {
  int changed = candidate->auth_valid || candidate->auth_term != 0 ||
                candidate->auth_commit_index != 0 ||
                candidate->auth_leader[0] != 0;

  candidate->auth_valid = FALSE;
  memset(candidate->auth_key_id, 0, sizeof(candidate->auth_key_id));
  candidate->auth_term = 0;
  candidate->auth_commit_index = 0;
  candidate->auth_leader[0] = 0;
  if (changed)
    service_changed(candidate->service);
}

static int candidate_authenticate(struct nhrp_ha_candidate *candidate,
                                  struct nhrp_packet *reply,
                                  const struct nhrp_buffer *ha) {
  struct nhrp_ha_auth_profile *profile =
      auth_profile_find(candidate->service->interface, FALSE);
  struct nhrp_ha_auth_metadata metadata;
  struct nhrp_ha_auth_input input;
  struct nhrp_payload *payload;
  uint8_t key_id[NHRP_HA_AUTH_KEY_ID_SIZE];
  enum nhrp_ha_auth_result res;
  int changed;

  if (profile == NULL)
    return TRUE;
  if (!profile->valid && profile->auth_configured) {
    candidate_auth_clear(candidate);
    return FALSE;
  }
  payload = nhrp_packet_extension(
      reply, NHRP_EXTENSION_HA_AUTH | NHRP_EXTENSION_FLAG_NOCREATE,
      NHRP_PAYLOAD_TYPE_RAW);
  if (payload == NULL || payload->u.raw == NULL) {
    if (profile->auth_configured)
      candidate_auth_clear(candidate);
    return profile->auth_required ? FALSE : TRUE;
  }
  if (!auth_input_from_packet(reply, ha, &input)) {
    if (profile->auth_configured)
      candidate_auth_clear(candidate);
    return profile->auth_required ? FALSE : TRUE;
  }

  res = nhrp_ha_auth_verify(&profile->keys, &input, payload->u.raw->data,
                            payload->u.raw->length, &metadata, key_id);
  if (profile->auth_configured) {
    int same_leader_lower_commit;

    if (res != NHRP_HA_AUTH_OK) {
      nhrp_debug("HA authentication for %s failed with result %d",
                 candidate->member_id, res);
      candidate_auth_clear(candidate);
      return FALSE;
    }
    same_leader_lower_commit =
        metadata.term == profile->seen.term &&
        metadata.commit_index < profile->seen.commit_index &&
        strcmp(metadata.leader, profile->seen.leader) == 0;
    if (!same_leader_lower_commit &&
        !auth_profile_observe(profile, &metadata, key_id)) {
      nhrp_debug(
          "HA metadata for %s rejected: term %llu leader %s commit %llu; "
          "seen term %llu leader %s commit %llu",
          candidate->member_id, (unsigned long long)metadata.term,
          metadata.leader, (unsigned long long)metadata.commit_index,
          (unsigned long long)profile->seen.term,
          profile->seen.leader[0] != 0 ? profile->seen.leader : "none",
          (unsigned long long)profile->seen.commit_index);
      candidate_auth_clear(candidate);
      return FALSE;
    }
  }

  if (res == NHRP_HA_AUTH_OK || !profile->auth_configured) {
    changed = !candidate->auth_valid || candidate->auth_term != metadata.term ||
              candidate->auth_commit_index != metadata.commit_index ||
              strcmp(candidate->auth_leader, metadata.leader) != 0 ||
              CRYPTO_memcmp(candidate->auth_key_id, key_id,
                            sizeof(candidate->auth_key_id)) != 0;
    candidate->auth_valid = TRUE;
    memcpy(candidate->auth_key_id, key_id, sizeof(candidate->auth_key_id));
    candidate->auth_term = metadata.term;
    candidate->auth_commit_index = metadata.commit_index;
    snprintf(candidate->auth_leader, sizeof(candidate->auth_leader), "%s",
             metadata.leader);
    if (changed)
      service_changed(candidate->service);
    return TRUE;
  }

  if (profile->auth_configured) {
    candidate_auth_clear(candidate);
    return FALSE;
  }
  return TRUE;
}

static size_t append(char *buffer, size_t size, size_t offset,
                     const char *format, ...) {
  va_list args;
  int length;

  if (offset >= size)
    return offset;
  va_start(args, format);
  length = vsnprintf(buffer + offset, size - offset, format, args);
  va_end(args);
  if (length < 0)
    return offset;
  return offset + length;
}

size_t nhrp_ha_render(char *buffer, size_t size, const char *interface_name,
                      int json) {
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;
  size_t offset = 0;
  int rendered = 0;
  char protocol[64];
  char nbma[64];

  list_for_each_entry(service, &services, list_entry) {
    struct nhrp_ha_auth_profile *profile =
        auth_profile_find(service->interface, FALSE);
    struct nhrp_ha_coordinator_status *status =
        coordinator_status_find(service->interface, FALSE);
    const char *mode = service->automatic && service->active == NULL
                           ? "discovering"
                           : "managed";
    char cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE * 2 + 1] = {0};
    char current_key_id[NHRP_HA_AUTH_KEY_ID_SIZE * 2 + 1] = {0};
    char next_key_id[NHRP_HA_AUTH_KEY_ID_SIZE * 2 + 1] = {0};
    int first = TRUE;

    if (interface_name != NULL && interface_name[0] != 0 &&
        strcmp(service->interface->name, interface_name) != 0)
      continue;
    rendered++;
    nhrp_address_format(&service->protocol, sizeof(protocol), protocol);
    if (profile != NULL && profile->cluster_configured)
      cluster_id_format(profile->cluster_id, cluster_id);
    if (profile != NULL && profile->key_configured[0])
      nhrp_ha_auth_key_id_format(profile->keys.key[0].id, current_key_id);
    if (profile != NULL && profile->key_configured[1])
      nhrp_ha_auth_key_id_format(profile->keys.key[1].id, next_key_id);
    if (json) {
      offset = append(
          buffer, size, offset,
          "%s{\"event_sequence\":%llu,\"interface\":\"%s\","
          "\"mode\":\"%s\",\"coordinator_state\":\"%s\","
          "\"coordinator_last_exit\":%d,"
          "\"protocol\":\"%s\",\"prefix_length\":%u,"
          "\"generation\":%u,\"hub_list_generation\":%u,"
          "\"hub_list_source\":%s%s%s,\"switching\":%s,"
          "\"auth_mode\":\"%s\",\"auth_cluster_id\":%s%s%s,"
          "\"seen_term\":%llu,\"seen_commit_index\":%llu,"
          "\"seen_leader\":%s%s%s,\"current_key_id\":%s%s%s,"
          "\"next_key_id\":%s%s%s,"
          "\"active_member\":",
          rendered > 1 ? "\n" : "", (unsigned long long)service->event_sequence,
          service->interface->name, mode,
          status != NULL && status->state[0] != 0 ? status->state : "stopped",
          status != NULL ? status->last_exit : 0, protocol,
          service->prefix_length, service->generation,
          service->hub_list_generation,
          service->hub_list_source[0] != 0 ? "\"" : "",
          service->hub_list_source[0] != 0 ? service->hub_list_source : "null",
          service->hub_list_source[0] != 0 ? "\"" : "",
          service->switching ? "true" : "false",
          profile != NULL && profile->auth_configured
              ? (profile->auth_required ? "required" : "optional")
              : "disabled",
          cluster_id[0] != 0 ? "\"" : "",
          cluster_id[0] != 0 ? cluster_id : "null",
          cluster_id[0] != 0 ? "\"" : "",
          (unsigned long long)(profile != NULL ? profile->seen.term : 0),
          (unsigned long long)(profile != NULL ? profile->seen.commit_index
                                               : 0),
          profile != NULL && profile->seen.leader[0] != 0 ? "\"" : "",
          profile != NULL && profile->seen.leader[0] != 0 ? profile->seen.leader
                                                          : "null",
          profile != NULL && profile->seen.leader[0] != 0 ? "\"" : "",
          current_key_id[0] != 0 ? "\"" : "",
          current_key_id[0] != 0 ? current_key_id : "null",
          current_key_id[0] != 0 ? "\"" : "", next_key_id[0] != 0 ? "\"" : "",
          next_key_id[0] != 0 ? next_key_id : "null",
          next_key_id[0] != 0 ? "\"" : "");
      if (service->active != NULL)
        offset =
            append(buffer, size, offset, "\"%s\"", service->active->member_id);
      else
        offset = append(buffer, size, offset, "null");
      offset = append(buffer, size, offset, ",\"candidates\":[");
      list_for_each_entry(candidate, &service->candidates, list_entry) {
        char endpoints[320] = {0};
        char endpoint_reachable[64] = {0};
        size_t endpoint_offset = 0;
        size_t reachable_offset = 0;
        size_t endpoint;

        nhrp_address_format(&candidate->nbma, sizeof(nbma), nbma);
        char candidate_key_id[NHRP_HA_AUTH_KEY_ID_SIZE * 2 + 1] = {0};
        char local_nbma[64] = {0};
        const char *local_origin = NULL;
        const struct nhrp_address *local =
            candidate_local_nbma(candidate, &local_origin);

        if (candidate->auth_valid)
          nhrp_ha_auth_key_id_format(candidate->auth_key_id, candidate_key_id);
        if (local != NULL)
          nhrp_address_format(local, sizeof(local_nbma), local_nbma);
        for (endpoint = 0; endpoint < candidate->endpoint_count; endpoint++) {
          char address[64];

          nhrp_address_format(&candidate->endpoints[endpoint], sizeof(address),
                              address);
          endpoint_offset =
              append(endpoints, sizeof(endpoints), endpoint_offset, "%s\"%s\"",
                     endpoint == 0 ? "" : ",", address);
          reachable_offset =
              append(endpoint_reachable, sizeof(endpoint_reachable),
                     reachable_offset, "%s%s", endpoint == 0 ? "" : ",",
                     candidate->endpoint_ready[endpoint] ? "true" : "false");
        }
        offset = append(
            buffer, size, offset,
            "%s{\"member\":\"%s\",\"nbma\":\"%s\","
            "\"addresses\":[%s],\"endpoint_reachable\":[%s],"
            "\"selected_address\":\"%s\","
            "\"priority\":%d,"
            "\"local_nbma\":%s%s%s,\"local_nbma_origin\":%s%s%s,"
            "\"origin\":\"%s\","
            "\"state\":\"%s\",\"registered\":%s,\"ready\":%s,"
            "\"active\":%s,\"authenticated\":%s,"
            "\"auth_key_id\":%s%s%s,\"term\":%llu,"
            "\"commit_index\":%llu,\"leader\":%s%s%s,"
            "\"srtt_ms\":%.3f,\"rto_ms\":%.3f}",
            first ? "" : ",", candidate->member_id, nbma, endpoints,
            endpoint_reachable, nbma, candidate->priority,
            local != NULL ? "\"" : "", local != NULL ? local_nbma : "null",
            local != NULL ? "\"" : "", local_origin != NULL ? "\"" : "",
            local_origin != NULL ? local_origin : "null",
            local_origin != NULL ? "\"" : "",
            candidate->static_configured
                ? (candidate->dynamically_discovered ? "static+dynamic"
                                                     : "static")
                : "dynamic",
            candidate_state_name(candidate->state),
            candidate->registered ? "true" : "false",
            candidate->state == NHRP_HA_CANDIDATE_READY ? "true" : "false",
            service->active == candidate ? "true" : "false",
            candidate->auth_valid ? "true" : "false",
            candidate_key_id[0] != 0 ? "\"" : "",
            candidate_key_id[0] != 0 ? candidate_key_id : "null",
            candidate_key_id[0] != 0 ? "\"" : "",
            (unsigned long long)candidate->auth_term,
            (unsigned long long)candidate->auth_commit_index,
            candidate->auth_leader[0] != 0 ? "\"" : "",
            candidate->auth_leader[0] != 0 ? candidate->auth_leader : "null",
            candidate->auth_leader[0] != 0 ? "\"" : "",
            candidate->srtt * 1000.0, candidate->rto * 1000.0);
        first = FALSE;
      }
      offset = append(buffer, size, offset, "]}\n");
    } else {
      offset = append(
          buffer, size, offset,
          "Interface: %s\nMode: %s\nCoordinator-State: %s\n"
          "Coordinator-Last-Exit: %d\nProtocol-Address: %s/%u\nGeneration: %u\n"
          "Hub-List-Generation: %u\nHub-List-Source: %s\n"
          "Switching: %s\nAuth-Mode: %s\nSeen-Term: %llu\n"
          "Seen-Commit-Index: %llu\nSeen-Leader: %s\n"
          "Current-Key-ID: %s\nNext-Key-ID: %s\nActive-Member: %s\n",
          service->interface->name, mode,
          status != NULL && status->state[0] != 0 ? status->state : "stopped",
          status != NULL ? status->last_exit : 0, protocol,
          service->prefix_length, service->generation,
          service->hub_list_generation,
          service->hub_list_source[0] != 0 ? service->hub_list_source : "none",
          service->switching ? "yes" : "no",
          profile != NULL && profile->auth_configured
              ? (profile->auth_required ? "required" : "optional")
              : "disabled",
          (unsigned long long)(profile != NULL ? profile->seen.term : 0),
          (unsigned long long)(profile != NULL ? profile->seen.commit_index
                                               : 0),
          profile != NULL && profile->seen.leader[0] != 0 ? profile->seen.leader
                                                          : "none",
          current_key_id[0] != 0 ? current_key_id : "none",
          next_key_id[0] != 0 ? next_key_id : "none",
          service->active != NULL ? service->active->member_id : "none");
      list_for_each_entry(candidate, &service->candidates, list_entry) {
        char endpoints[320] = {0};
        size_t endpoint_offset = 0;
        size_t endpoint;
        char candidate_key_id[NHRP_HA_AUTH_KEY_ID_SIZE * 2 + 1] = {0};
        char local_nbma[64] = {0};
        const char *local_origin = NULL;
        const struct nhrp_address *local =
            candidate_local_nbma(candidate, &local_origin);

        nhrp_address_format(&candidate->nbma, sizeof(nbma), nbma);
        if (local != NULL)
          nhrp_address_format(local, sizeof(local_nbma), local_nbma);
        if (candidate->auth_valid)
          nhrp_ha_auth_key_id_format(candidate->auth_key_id, candidate_key_id);
        for (endpoint = 0; endpoint < candidate->endpoint_count; endpoint++) {
          char address[64];

          nhrp_address_format(&candidate->endpoints[endpoint], sizeof(address),
                              address);
          endpoint_offset =
              append(endpoints, sizeof(endpoints), endpoint_offset, "%s%s",
                     endpoint == 0 ? "" : ",", address);
        }
        offset = append(
            buffer, size, offset,
            "Candidate: %s nbma %s addresses %s local-nbma %s "
            "local-nbma-origin %s "
            "priority %d origin %s state %s%s "
            "authenticated %s key-id %s term %llu commit-index %llu "
            "leader %s\n",
            candidate->member_id, nbma, endpoints,
            local != NULL ? local_nbma : "none",
            local_origin != NULL ? local_origin : "none", candidate->priority,
            candidate->static_configured
                ? (candidate->dynamically_discovered ? "static+dynamic"
                                                     : "static")
                : "dynamic",
            candidate_state_name(candidate->state),
            service->active == candidate ? " active" : "",
            candidate->auth_valid ? "yes" : "no",
            candidate_key_id[0] != 0 ? candidate_key_id : "none",
            (unsigned long long)candidate->auth_term,
            (unsigned long long)candidate->auth_commit_index,
            candidate->auth_leader[0] != 0 ? candidate->auth_leader : "none");
      }
      offset = append(buffer, size, offset, "\n");
    }
  }

  if (rendered == 0) {
    struct nhrp_interface *iface =
        interface_name != NULL && interface_name[0] != 0
            ? nhrp_interface_get_by_name(interface_name, FALSE)
            : NULL;
    struct nhrp_ha_coordinator_status *status =
        iface != NULL ? coordinator_status_find(iface, FALSE) : NULL;
    const char *mode =
        iface != NULL && hub_enable.configured && hub_enable.interface == iface
            ? "managed"
            : "legacy";
    const char *auth_mode =
        iface != NULL && hub_enable.configured && hub_enable.interface == iface
            ? "required"
            : "disabled";

    if (iface == NULL) {
      offset = append(buffer, size, offset,
                      json ? "{\"error\":\"service-not-found\"}\n"
                           : "No HA services.\n");
    } else if (json) {
      offset = append(
          buffer, size, offset,
          "{\"event_sequence\":0,\"interface\":\"%s\",\"mode\":\"%s\","
          "\"coordinator_state\":\"%s\",\"coordinator_last_exit\":%d,"
          "\"auth_mode\":\"%s\",\"active_member\":null,"
          "\"candidates\":[]}\n",
          iface->name, mode,
          status != NULL && status->state[0] != 0 ? status->state : "stopped",
          status != NULL ? status->last_exit : 0, auth_mode);
    } else {
      offset = append(buffer, size, offset,
                      "Interface: %s\nMode: %s\nCoordinator-State: %s\n"
                      "Coordinator-Last-Exit: %d\nAuth-Mode: %s\n",
                      iface->name, mode,
                      status != NULL && status->state[0] != 0 ? status->state
                                                              : "stopped",
                      status != NULL ? status->last_exit : 0, auth_mode);
    }
  }
  if (size > 0)
    buffer[offset < size ? offset : size - 1] = 0;
  return offset < size ? offset : (size > 0 ? size - 1 : 0);
}

static int service_active_mapping_current(struct nhrp_ha_service *service) {
  const struct nhrp_address *local;

  if (service->active == NULL || service->active_peer == NULL ||
      nhrp_address_cmp(&service->active_peer->next_hop_address,
                       &service->active->nbma) != 0)
    return FALSE;
  local = candidate_local_nbma(service->active, NULL);
  if (local == NULL)
    return service->active_peer->local_connect_address.type == PF_UNSPEC;
  return nhrp_address_cmp(&service->active_peer->local_connect_address,
                          local) == 0;
}

static void reconcile_schedule(struct nhrp_ha_service *service,
                               ev_tstamp delay) {
  if (!nhrp_running || service->active == NULL ||
      service_active_mapping_current(service))
    return;
  ev_timer_stop(&service->reconcile_timer);
  ev_timer_set(&service->reconcile_timer, delay, 0.0);
  ev_timer_start(&service->reconcile_timer);
}

static void reconcile_neighbor_done(void *ctx, int status) {
  struct nhrp_ha_service *service = ctx;
  struct nhrp_peer *peer;
  struct nhrp_address *local;
  char protocol[64];

  service->reconciling = FALSE;
  if (status != 0) {
    nhrp_error(
        "Failed to update HA local NBMA for %s on %s: Netlink status %d",
        nhrp_address_format(&service->protocol, sizeof(protocol), protocol),
        service->interface->name, status);
    reconcile_schedule(service, 1.0);
    return;
  }
  if (service->active != service->reconcile_candidate) {
    reconcile_schedule(service, 0.01);
    return;
  }
  local = service->reconcile_has_local_nbma ? &service->reconcile_nbma : NULL;
  peer = nhrp_peer_ha_commit(service->interface, &service->protocol,
                             service->prefix_length, &service->active->nbma,
                             local);
  if (peer == NULL) {
    nhrp_error(
        "Failed to commit HA local NBMA for %s on %s",
        nhrp_address_format(&service->protocol, sizeof(protocol), protocol),
        service->interface->name);
    reconcile_schedule(service, 1.0);
    return;
  }
  if (service->active_peer != NULL)
    nhrp_peer_put(service->active_peer);
  service->active_peer = peer;
  service_changed(service);
  reconcile_schedule(service, 0.01);
}

static void reconcile_timer_cb(struct ev_timer *timer, int revents) {
  struct nhrp_ha_service *service =
      container_of(timer, struct nhrp_ha_service, reconcile_timer);
  const struct nhrp_address *local;

  (void)revents;
  if (service->active == NULL)
    return;
  if (service->switching || service->reconciling) {
    reconcile_schedule(service, 0.1);
    return;
  }
  if (service_active_mapping_current(service))
    return;
  local = candidate_local_nbma(service->active, NULL);
  service->reconcile_candidate = service->active;
  service->reconcile_has_local_nbma = local != NULL;
  service->reconcile_nbma = local != NULL ? *local : service->active->nbma;
  service->reconciling = TRUE;
  if (!kernel_inject_neighbor_async(
          &service->protocol, &service->reconcile_nbma, service->interface,
          reconcile_neighbor_done, service)) {
    service->reconciling = FALSE;
    reconcile_schedule(service, 0.1);
  }
}

static void activate_neighbor_done(void *ctx, int status) {
  struct nhrp_ha_service *service = ctx;
  struct nhrp_peer *peer;
  nhrp_ha_activate_callback callback = service->switch_callback;
  void *callback_ctx = service->switch_callback_ctx;
  char protocol[64];

  service->switch_callback = NULL;
  service->switch_callback_ctx = NULL;
  if (status != 0) {
    service->switching = FALSE;
    service->switch_target = NULL;
    service_changed(service);
    if (callback != NULL)
      callback(callback_ctx, status, "netlink-ack-failed", service->generation);
    return;
  }

  peer = nhrp_peer_ha_commit(
      service->interface, &service->protocol, service->prefix_length,
      &service->switch_target->nbma,
      service->switch_has_local_nbma ? &service->switch_nbma : NULL);
  if (peer == NULL) {
    service->switching = FALSE;
    service->switch_target = NULL;
    service_changed(service);
    if (callback != NULL)
      callback(callback_ctx, -ENOMEM, "peer-commit-failed",
               service->generation);
    return;
  }

  if (service->active_peer != NULL)
    nhrp_peer_put(service->active_peer);
  service->active_peer = peer;
  if (service->automatic)
    nhrp_peer_ha_suspend_static(service->interface, &service->protocol);
  if (service->active != NULL)
    probe_schedule(service->active, 0.01);
  nhrp_info("HA active Hub for %s on %s changed %s -> %s",
            nhrp_address_format(&service->protocol, sizeof(protocol), protocol),
            service->interface->name,
            service->active != NULL ? service->active->member_id : "none",
            service->switch_target->member_id);
  service->active = service->switch_target;
  if (service->active->srtt > 0.0)
    service->active->rto =
        service->active->srtt + 4.0 * service->active->rttvar;
  if (service->active->rto < HA_ACTIVE_MIN_RTO)
    service->active->rto = HA_ACTIVE_MIN_RTO;
  probe_schedule(service->active, 0.01);
  service->interface->nat_cie = service->active->nat_cie;
  service->generation++;
  service->switching = FALSE;
  service->switch_target = NULL;
  service_changed(service);
  reconcile_schedule(service, 0.01);
  if (callback != NULL)
    callback(callback_ctx, 0, "ok", service->generation);
}

int nhrp_ha_activate(const char *interface_name,
                     const struct nhrp_address *protocol, const char *member_id,
                     uint32_t expect_generation,
                     nhrp_ha_activate_callback callback, void *ctx,
                     const char **reason) {
  struct nhrp_interface *iface;
  struct nhrp_ha_service *service;
  struct nhrp_ha_candidate *candidate;

  iface = nhrp_interface_get_by_name(interface_name, FALSE);
  if (iface == NULL) {
    *reason = "interface-not-found";
    return FALSE;
  }
  service = service_find(iface, protocol);
  if (service == NULL) {
    *reason = "service-not-found";
    return FALSE;
  }
  candidate = candidate_find(service, member_id);
  if (candidate == NULL) {
    *reason = "candidate-not-found";
    return FALSE;
  }
  if (service->switching) {
    *reason = "switch-in-progress";
    return FALSE;
  }
  if (service->generation != expect_generation) {
    *reason = "generation-mismatch";
    return FALSE;
  }
  if (!candidate->registered || candidate->state != NHRP_HA_CANDIDATE_READY) {
    *reason = "candidate-not-ready";
    return FALSE;
  }
  if (service->active == candidate) {
    reconcile_schedule(service, 0.01);
    if (callback != NULL)
      callback(ctx, 0, "already-active", service->generation);
    return TRUE;
  }

  service->switching = TRUE;
  service->switch_target = candidate;
  service->switch_callback = callback;
  service->switch_callback_ctx = ctx;
  {
    const struct nhrp_address *local = candidate_local_nbma(candidate, NULL);

    service->switch_has_local_nbma = local != NULL;
    service->switch_nbma = local != NULL ? *local : candidate->nbma;
  }
  service_changed(service);
  if (!kernel_inject_neighbor_async(&service->protocol, &service->switch_nbma,
                                    service->interface, activate_neighbor_done,
                                    service)) {
    service->switching = FALSE;
    service->switch_target = NULL;
    service->switch_callback = NULL;
    service->switch_callback_ctx = NULL;
    service_changed(service);
    *reason = "netlink-transaction-unavailable";
    return FALSE;
  }
  return TRUE;
}
