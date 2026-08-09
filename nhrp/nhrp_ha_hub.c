/* nhrp_ha_hub.c - Hub registration shadow and projection state */

#include <openssl/sha.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nhrp_common.h"
#include "nhrp_ha_hub.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

struct nhrp_ha_hub_value {
  struct nhrp_ha_hub_binding binding;
  ev_tstamp expires;
  int present;
};

struct nhrp_ha_hub_entry {
  struct list_head list_entry;
  struct nhrp_address protocol;
  uint8_t prefix_length;
  struct nhrp_ha_hub_value direct;
  struct nhrp_ha_hub_value replica;
  int replica_seen;
};

struct nhrp_ha_hub_state {
  struct list_head list_entry;
  struct nhrp_interface *interface;
  enum nhrp_ha_hub_role role;
  uint64_t term;
  uint64_t index;
  uint64_t pending_term;
  uint64_t pending_index;
  size_t count;
  int sync_active;
  struct list_head entries;
};

static struct list_head hub_states = LIST_INITIALIZER(hub_states);

static struct nhrp_ha_hub_state *hub_state_find(struct nhrp_interface *iface,
                                                int create) {
  struct nhrp_ha_hub_state *state;

  list_for_each_entry(state, &hub_states, list_entry) {
    if (state->interface == iface)
      return state;
  }
  if (!create)
    return NULL;
  state = calloc(1, sizeof(*state));
  if (state == NULL)
    return NULL;
  state->interface = iface;
  list_init(&state->entries);
  list_add_tail(&state->list_entry, &hub_states);
  return state;
}

static struct nhrp_ha_hub_entry *
hub_entry_find(struct nhrp_ha_hub_state *state,
               const struct nhrp_address *protocol, uint8_t prefix_length) {
  struct nhrp_ha_hub_entry *entry;

  list_for_each_entry(entry, &state->entries, list_entry) {
    if (entry->prefix_length == prefix_length &&
        nhrp_address_cmp(&entry->protocol, protocol) == 0)
      return entry;
  }
  return NULL;
}

static struct nhrp_ha_hub_entry *
hub_entry_get(struct nhrp_ha_hub_state *state,
              const struct nhrp_address *protocol, uint8_t prefix_length) {
  struct nhrp_ha_hub_entry *entry =
      hub_entry_find(state, protocol, prefix_length);

  if (entry != NULL)
    return entry;
  if (state->count >= NHRP_HA_HUB_MAX_REGISTRATIONS)
    return NULL;
  entry = calloc(1, sizeof(*entry));
  if (entry == NULL)
    return NULL;
  entry->protocol = *protocol;
  entry->prefix_length = prefix_length;
  list_add_tail(&entry->list_entry, &state->entries);
  state->count++;
  return entry;
}

static void hub_entry_remove(struct nhrp_ha_hub_state *state,
                             struct nhrp_ha_hub_entry *entry) {
  list_del(&entry->list_entry);
  free(entry);
  state->count--;
}

static void hub_value_expire(struct nhrp_ha_hub_value *value) {
  if (value->present && value->expires <= ev_now())
    value->present = FALSE;
}

static const struct nhrp_ha_hub_value *
hub_entry_value(struct nhrp_ha_hub_entry *entry) {
  hub_value_expire(&entry->direct);
  hub_value_expire(&entry->replica);
  if (entry->direct.present)
    return &entry->direct;
  if (entry->replica.present)
    return &entry->replica;
  return NULL;
}

static void binding_from_peer(struct nhrp_ha_hub_binding *binding,
                              const struct nhrp_peer *peer) {
  int holding = peer->expire_time > ev_now() ? peer->expire_time - ev_now() : 1;

  if (holding > UINT16_MAX)
    holding = UINT16_MAX;
  memset(binding, 0, sizeof(*binding));
  binding->nbma = peer->next_hop_address;
  binding->nat_oa = peer->next_hop_nat_oa;
  binding->mtu = peer->mtu;
  binding->holding_time = holding;
  binding->flags = peer->flags & (NHRP_PEER_FLAG_UNIQUE | NHRP_PEER_FLAG_UP |
                                  NHRP_PEER_FLAG_LOWER_UP);
}

static int project_entry(struct nhrp_ha_hub_state *state,
                         struct nhrp_ha_hub_entry *entry) {
  const struct nhrp_ha_hub_value *value = hub_entry_value(entry);
  struct nhrp_peer *peer;

  if (value == NULL)
    return TRUE;
  peer = nhrp_peer_alloc(state->interface);
  if (peer == NULL)
    return FALSE;
  peer->type = NHRP_PEER_TYPE_DYNAMIC;
  peer->afnum = nhrp_afnum_from_pf(value->binding.nbma.type);
  peer->protocol_type = nhrp_protocol_from_pf(entry->protocol.type);
  peer->protocol_address = entry->protocol;
  peer->prefix_length = entry->prefix_length;
  peer->next_hop_address = value->binding.nbma;
  peer->next_hop_nat_oa = value->binding.nat_oa;
  peer->mtu = value->binding.mtu;
  peer->holding_time = value->binding.holding_time;
  peer->expire_time = ev_now() + value->binding.holding_time;
  peer->flags = value->binding.flags | NHRP_PEER_FLAG_HA_PROJECTED;
  nhrp_peer_insert(peer);
  nhrp_peer_put(peer);
  return TRUE;
}

static int remove_projected(void *ctx, struct nhrp_peer *peer) {
  if (peer->flags & NHRP_PEER_FLAG_HA_PROJECTED)
    nhrp_peer_remove(peer);
  return 0;
}

void nhrp_ha_hub_cleanup(void) {
  struct nhrp_ha_hub_state *state;
  struct nhrp_ha_hub_state *next_state;

  list_for_each_entry_safe(state, next_state, &hub_states, list_entry) {
    struct nhrp_ha_hub_entry *entry;
    struct nhrp_ha_hub_entry *next_entry;

    list_for_each_entry_safe(entry, next_entry, &state->entries, list_entry)
        hub_entry_remove(state, entry);
    list_del(&state->list_entry);
    free(state);
  }
}

int nhrp_ha_hub_capture_direct(struct nhrp_peer *peer) {
  struct nhrp_ha_hub_state *state = hub_state_find(peer->interface, FALSE);
  struct nhrp_ha_hub_entry *entry;

  if (state == NULL || state->role == NHRP_HA_HUB_UNMANAGED)
    return 1;
  entry = hub_entry_get(state, &peer->protocol_address, peer->prefix_length);
  if (entry == NULL)
    return -1;
  binding_from_peer(&entry->direct.binding, peer);
  entry->direct.binding.term = state->term;
  entry->direct.binding.index = state->index;
  entry->direct.expires = ev_now() + entry->direct.binding.holding_time;
  entry->direct.present = TRUE;
  if (state->role == NHRP_HA_HUB_LEADER) {
    peer->flags |= NHRP_PEER_FLAG_HA_PROJECTED;
    return 1;
  }
  return 0;
}

int nhrp_ha_hub_set_role(struct nhrp_interface *iface,
                         enum nhrp_ha_hub_role role, uint64_t term,
                         uint64_t index) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, TRUE);
  struct nhrp_peer_selector selector;
  struct nhrp_ha_hub_entry *entry;

  if (state == NULL || role == NHRP_HA_HUB_UNMANAGED || term == 0 ||
      term < state->term || (term == state->term && index < state->index))
    return FALSE;
  state->term = term;
  state->index = index;
  if (state->role == role)
    return TRUE;
  if (role == NHRP_HA_HUB_STANDBY) {
    memset(&selector, 0, sizeof(selector));
    selector.interface = iface;
    selector.type_mask = BIT(NHRP_PEER_TYPE_DYNAMIC);
    nhrp_peer_foreach(remove_projected, NULL, &selector);
  } else {
    list_for_each_entry(entry, &state->entries, list_entry) {
      if (!project_entry(state, entry))
        return FALSE;
    }
  }
  state->role = role;
  return TRUE;
}

int nhrp_ha_hub_sync_begin(struct nhrp_interface *iface, uint64_t term,
                           uint64_t index) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, TRUE);
  struct nhrp_ha_hub_entry *entry;

  if (state == NULL || term == 0 || term < state->term || state->sync_active)
    return FALSE;
  state->pending_term = term;
  state->pending_index = index;
  state->sync_active = TRUE;
  list_for_each_entry(entry, &state->entries, list_entry) entry->replica_seen =
      FALSE;
  return TRUE;
}

int nhrp_ha_hub_sync_apply(struct nhrp_interface *iface,
                           const struct nhrp_address *protocol,
                           uint8_t prefix_length,
                           const struct nhrp_ha_hub_binding *binding) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, FALSE);
  struct nhrp_ha_hub_entry *entry;

  if (state == NULL || !state->sync_active || protocol->type != PF_INET ||
      binding->nbma.type != PF_INET || prefix_length > 32 ||
      binding->holding_time == 0 || binding->term != state->pending_term ||
      binding->index > state->pending_index)
    return FALSE;
  entry = hub_entry_get(state, protocol, prefix_length);
  if (entry == NULL)
    return FALSE;
  entry->replica.binding = *binding;
  entry->replica.expires = ev_now() + binding->holding_time;
  entry->replica.present = TRUE;
  entry->replica_seen = TRUE;
  if (state->role == NHRP_HA_HUB_LEADER && !entry->direct.present)
    return project_entry(state, entry);
  return TRUE;
}

int nhrp_ha_hub_sync_end(struct nhrp_interface *iface) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, FALSE);
  struct nhrp_ha_hub_entry *entry;
  struct nhrp_ha_hub_entry *next;

  if (state == NULL || !state->sync_active)
    return FALSE;
  list_for_each_entry_safe(entry, next, &state->entries, list_entry) {
    if (!entry->replica_seen)
      entry->replica.present = FALSE;
    if (hub_entry_value(entry) == NULL)
      hub_entry_remove(state, entry);
  }
  state->term = state->pending_term;
  state->index = state->pending_index;
  state->sync_active = FALSE;
  return TRUE;
}

static int entry_compare(const void *left, const void *right) {
  const struct nhrp_ha_hub_entry *a =
      *(const struct nhrp_ha_hub_entry *const *)left;
  const struct nhrp_ha_hub_entry *b =
      *(const struct nhrp_ha_hub_entry *const *)right;
  int result = nhrp_address_cmp(&a->protocol, &b->protocol);

  if (result != 0)
    return result;
  return (int)a->prefix_length - (int)b->prefix_length;
}

static size_t append(char *buffer, size_t size, size_t offset,
                     const char *format, ...) {
  va_list arguments;
  int length;

  if (offset >= size)
    return offset;
  va_start(arguments, format);
  length = vsnprintf(buffer + offset, size - offset, format, arguments);
  va_end(arguments);
  return length < 0 ? offset : offset + length;
}

static size_t snapshot_line(struct nhrp_ha_hub_entry *entry, char *buffer,
                            size_t size) {
  const struct nhrp_ha_hub_value *value = hub_entry_value(entry);
  char protocol[64];
  char nbma[64];
  char nat_oa[64];

  if (value == NULL)
    return 0;
  nhrp_address_format(&entry->protocol, sizeof(protocol), protocol);
  nhrp_address_format(&value->binding.nbma, sizeof(nbma), nbma);
  if (value->binding.nat_oa.type != PF_UNSPEC)
    nhrp_address_format(&value->binding.nat_oa, sizeof(nat_oa), nat_oa);
  else
    snprintf(nat_oa, sizeof(nat_oa), "-");
  return snprintf(buffer, size, "entry %s %u %s %s %u %u %u %llu %llu %s\n",
                  protocol, entry->prefix_length, nbma, nat_oa,
                  value->binding.mtu, value->binding.holding_time,
                  value->binding.flags, (unsigned long long)value->binding.term,
                  (unsigned long long)value->binding.index,
                  entry->direct.present ? "direct" : "replica");
}

size_t nhrp_ha_hub_snapshot_render(struct nhrp_interface *iface, char *buffer,
                                   size_t size, size_t page_offset,
                                   size_t limit, size_t *total,
                                   char digest[65]) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, FALSE);
  struct nhrp_ha_hub_entry **entries;
  struct nhrp_ha_hub_entry *entry;
  uint8_t hash[32];
  char *canonical;
  size_t canonical_size;
  size_t canonical_offset = 0;
  size_t output_offset = 0;
  size_t count = 0;
  size_t i;

  *total = 0;
  digest[0] = 0;
  if (state == NULL)
    return 0;
  entries = calloc(state->count, sizeof(*entries));
  canonical_size = state->count * 256 + 1;
  canonical = malloc(canonical_size);
  if ((state->count != 0 && entries == NULL) || canonical == NULL) {
    free(entries);
    free(canonical);
    return 0;
  }
  list_for_each_entry(entry, &state->entries, list_entry) {
    if (hub_entry_value(entry) != NULL)
      entries[count++] = entry;
  }
  qsort(entries, count, sizeof(*entries), entry_compare);
  for (i = 0; i < count; i++)
    canonical_offset += snapshot_line(entries[i], canonical + canonical_offset,
                                      canonical_size - canonical_offset);
  if (SHA256((uint8_t *)canonical, canonical_offset, hash) == NULL)
    goto done;
  for (i = 0; i < sizeof(hash); i++)
    snprintf(&digest[i * 2], 3, "%02x", hash[i]);
  if (limit == 0 || limit > count)
    limit = count;
  for (i = page_offset; i < count && i - page_offset < limit; i++) {
    char line[256];

    snapshot_line(entries[i], line, sizeof(line));
    output_offset = append(buffer, size, output_offset, "%s", line);
  }
  *total = count;

done:
  free(canonical);
  free(entries);
  if (size != 0)
    buffer[output_offset < size ? output_offset : size - 1] = 0;
  return output_offset < size ? output_offset : (size != 0 ? size - 1 : 0);
}

size_t nhrp_ha_hub_status_render(struct nhrp_interface *iface, char *buffer,
                                 size_t size, int json) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, FALSE);
  const char *role;
  size_t offset = 0;

  if (state == NULL)
    return append(buffer, size, 0,
                  json ? "{\"role\":\"unmanaged\"}\n" : "Role: unmanaged\n");
  role = state->role == NHRP_HA_HUB_LEADER    ? "leader"
         : state->role == NHRP_HA_HUB_STANDBY ? "standby"
                                              : "unmanaged";
  if (json)
    offset = append(buffer, size, offset,
                    "{\"interface\":\"%s\",\"role\":\"%s\","
                    "\"term\":%llu,\"index\":%llu,"
                    "\"registrations\":%zu,\"syncing\":%s}\n",
                    iface->name, role, (unsigned long long)state->term,
                    (unsigned long long)state->index, state->count,
                    state->sync_active ? "true" : "false");
  else
    offset = append(buffer, size, offset,
                    "Interface: %s\nRole: %s\nTerm: %llu\nIndex: %llu\n"
                    "Registrations: %zu\nSyncing: %s\n",
                    iface->name, role, (unsigned long long)state->term,
                    (unsigned long long)state->index, state->count,
                    state->sync_active ? "yes" : "no");
  return offset;
}
