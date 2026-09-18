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

extern void admin_ha_notify(struct nhrp_interface *iface);

struct nhrp_ha_hub_value {
  struct nhrp_ha_hub_binding binding;
  ev_tstamp expires;
  int present;
  int retired;
  int prepared;
};

struct nhrp_ha_hub_entry {
  struct list_head list_entry;
  struct nhrp_address protocol;
  uint8_t prefix_length;
  uint64_t owner_term;
  uint64_t owner_index;
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

static void hub_state_gc(struct nhrp_ha_hub_state *state) {
  struct nhrp_ha_hub_entry *entry;
  struct nhrp_ha_hub_entry *next;

  list_for_each_entry_safe(entry, next, &state->entries, list_entry) {
    hub_value_expire(&entry->direct);
    hub_value_expire(&entry->replica);
    if (!entry->direct.present && !entry->replica.present)
      hub_entry_remove(state, entry);
  }
}

static int binding_version_cmp(const struct nhrp_ha_hub_binding *left,
                               const struct nhrp_ha_hub_binding *right) {
  if (left->term != right->term)
    return left->term > right->term ? 1 : -1;
  if (left->index != right->index)
    return left->index > right->index ? 1 : -1;
  return 0;
}

static void binding_version_next(uint64_t *term, uint64_t *index) {
  if (*index == UINT64_MAX) {
    if (*term != UINT64_MAX)
      (*term)++;
    *index = 0;
  } else {
    (*index)++;
  }
}

static void hub_owner_observe(struct nhrp_ha_hub_entry *entry,
                              const struct nhrp_ha_hub_binding *binding) {
  struct nhrp_ha_hub_binding owner;

  memset(&owner, 0, sizeof(owner));
  owner.term = entry->owner_term;
  owner.index = entry->owner_index;
  if (entry->owner_term == 0 || binding_version_cmp(binding, &owner) > 0) {
    entry->owner_term = binding->term;
    entry->owner_index = binding->index;
  }
}

static void hub_owner_next(struct nhrp_ha_hub_state *state,
                           struct nhrp_ha_hub_entry *entry, uint64_t *term,
                           uint64_t *index) {
  struct nhrp_ha_hub_binding next;
  struct nhrp_ha_hub_binding owner;

  memset(&next, 0, sizeof(next));
  next.term = state->term;
  owner.term = entry->owner_term;
  owner.index = entry->owner_index;
  if (entry->owner_term != 0 && binding_version_cmp(&owner, &next) > 0)
    next = owner;
  binding_version_next(&next.term, &next.index);
  entry->owner_term = next.term;
  entry->owner_index = next.index;
  *term = next.term;
  *index = next.index;
}

static const struct nhrp_ha_hub_value *
hub_entry_value(struct nhrp_ha_hub_entry *entry) {
  hub_value_expire(&entry->direct);
  hub_value_expire(&entry->replica);
  if (entry->direct.present && !entry->direct.retired)
    return &entry->direct;
  if (entry->direct.present && entry->direct.retired &&
      entry->replica.present &&
      binding_version_cmp(&entry->replica.binding,
                          &entry->direct.binding) > 0)
    return &entry->replica;
  if (entry->direct.present && entry->direct.retired)
    return NULL;
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

static int is_local_registration(void *ctx, struct nhrp_peer *peer) {
  (void)ctx;
  return nhrp_peer_is_persistable(peer);
}

static int has_local_registration(struct nhrp_interface *iface,
                                  const struct nhrp_address *protocol,
                                  uint8_t prefix_length) {
  struct nhrp_peer_selector selector = {
      .flags = NHRP_PEER_FIND_EXACT,
      .type_mask = BIT(NHRP_PEER_TYPE_DYNAMIC),
      .interface = iface,
      .protocol_address = *protocol,
      .prefix_length = prefix_length,
  };
  return nhrp_peer_foreach(is_local_registration, NULL, &selector);
}

struct hub_peer_match {
  const struct nhrp_address *protocol;
  uint8_t prefix_length;
  int direct_only;
};

static int hub_peer_matches(void *ctx, struct nhrp_peer *peer) {
  struct hub_peer_match *match = ctx;

  return (peer->flags & NHRP_PEER_FLAG_HA_PROJECTED) &&
         (!match->direct_only || (peer->flags & NHRP_PEER_FLAG_HA_DIRECT)) &&
         peer->prefix_length == match->prefix_length &&
         nhrp_address_cmp(&peer->protocol_address, match->protocol) == 0;
}

static int remove_hub_peer(void *ctx, struct nhrp_peer *peer) {
  if (hub_peer_matches(ctx, peer))
    nhrp_peer_remove(peer);
  return 0;
}

static int remove_replica_effective(void *ctx, struct nhrp_peer *peer) {
  (void)ctx;
  if ((peer->flags & NHRP_PEER_FLAG_HA_PROJECTED) &&
      !(peer->flags & NHRP_PEER_FLAG_HA_DIRECT))
    nhrp_peer_remove(peer);
  return 0;
}

static int has_effective_registration(struct nhrp_interface *iface,
                                      const struct nhrp_address *protocol,
                                      uint8_t prefix_length) {
  struct hub_peer_match match = {
      .protocol = protocol,
      .prefix_length = prefix_length,
  };
  struct nhrp_peer_selector selector = {
      .flags = NHRP_PEER_FIND_EXACT,
      .type_mask = BIT(NHRP_PEER_TYPE_DYNAMIC),
      .interface = iface,
      .protocol_address = *protocol,
      .prefix_length = prefix_length,
  };

  return nhrp_peer_foreach(hub_peer_matches, &match, &selector);
}

static void remove_effective(struct nhrp_interface *iface,
                             const struct nhrp_address *protocol,
                             uint8_t prefix_length, int direct_only) {
  struct hub_peer_match match = {
      .protocol = protocol,
      .prefix_length = prefix_length,
      .direct_only = direct_only,
  };
  struct nhrp_peer_selector selector = {
      .flags = NHRP_PEER_FIND_EXACT,
      .type_mask = BIT(NHRP_PEER_TYPE_DYNAMIC),
      .interface = iface,
      .protocol_address = *protocol,
      .prefix_length = prefix_length,
  };

  nhrp_peer_foreach(remove_hub_peer, &match, &selector);
}

static int project_entry(struct nhrp_ha_hub_state *state,
                         struct nhrp_ha_hub_entry *entry) {
  const struct nhrp_ha_hub_value *value = hub_entry_value(entry);
  struct nhrp_peer *peer;
  if (value == NULL || has_local_registration(state->interface,
                                              &entry->protocol,
                                              entry->prefix_length))
    return TRUE;
  if (has_effective_registration(state->interface, &entry->protocol,
                                 entry->prefix_length)) {
    if (value == &entry->direct)
      return TRUE;
    remove_effective(state->interface, &entry->protocol, entry->prefix_length,
                     FALSE);
  }
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
  peer->ha_registration_id = value->binding.registration_id;
  if (value == &entry->direct)
    peer->flags |= NHRP_PEER_FLAG_HA_DIRECT;
  nhrp_peer_insert(peer);
  nhrp_peer_put(peer);
  return TRUE;
}

static int retire_direct_entry(struct nhrp_ha_hub_state *state,
                               struct nhrp_ha_hub_entry *entry,
                               int clear_replica) {
  if (!entry->direct.present)
    return FALSE;
  entry->direct.retired = TRUE;
  if (clear_replica)
    entry->replica.present = FALSE;
  remove_effective(state->interface, &entry->protocol, entry->prefix_length,
                   TRUE);
  return TRUE;
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

void nhrp_ha_hub_fence(struct nhrp_interface *iface) {
  struct nhrp_ha_hub_state *state;
  struct nhrp_ha_hub_entry *entry;

  if (iface == NULL)
    return;
  state = hub_state_find(iface, TRUE);
  if (state == NULL)
    return;
  hub_state_gc(state);
  list_for_each_entry(entry, &state->entries, list_entry) {
    if (entry->direct.present && !entry->direct.retired) {
      entry->direct.prepared = TRUE;
      retire_direct_entry(state, entry, FALSE);
    }
    remove_effective(state->interface, &entry->protocol, entry->prefix_length,
                     FALSE);
  }
  state->sync_active = FALSE;
  state->role = NHRP_HA_HUB_STANDBY;
  admin_ha_notify(iface);
}

int nhrp_ha_hub_capture_direct(struct nhrp_peer *peer) {
  struct nhrp_ha_hub_state *state = hub_state_find(peer->interface, FALSE);
  struct nhrp_ha_hub_entry *entry;
  uint64_t owner_term;
  uint64_t owner_index;

  if (state == NULL || state->role == NHRP_HA_HUB_UNMANAGED)
    return 1;
  hub_state_gc(state);
  if (!(peer->flags & NHRP_PEER_FLAG_HA_CAPABLE)) {
    entry = hub_entry_find(state, &peer->protocol_address, peer->prefix_length);
    if (entry != NULL)
      hub_entry_remove(state, entry);
    return 1;
  }
  entry = hub_entry_get(state, &peer->protocol_address, peer->prefix_length);
  if (entry == NULL)
    return -1;
  if (entry->direct.present)
    hub_owner_observe(entry, &entry->direct.binding);
  if (entry->replica.present)
    hub_owner_observe(entry, &entry->replica.binding);
  owner_term = entry->direct.present &&
                       strcmp(entry->direct.binding.owner_member,
                              peer->interface->ha_member_id) == 0 &&
                       (!entry->direct.retired || !entry->replica.present ||
                        binding_version_cmp(&entry->replica.binding,
                                            &entry->direct.binding) <= 0)
                   ? entry->direct.binding.term
                   : 0;
  owner_index = owner_term != 0 ? entry->direct.binding.index : 0;
  if (owner_term == 0)
    hub_owner_next(state, entry, &owner_term, &owner_index);
  binding_from_peer(&entry->direct.binding, peer);
  entry->direct.binding.registration_id = peer->ha_registration_id;
  entry->direct.binding.term = owner_term;
  entry->direct.binding.index = owner_index;
  snprintf(entry->direct.binding.owner_member,
           sizeof(entry->direct.binding.owner_member), "%s",
           peer->interface->ha_member_id);
  entry->direct.expires = ev_now() + entry->direct.binding.holding_time;
  entry->direct.present = TRUE;
  entry->direct.retired = FALSE;
  entry->direct.prepared = state->role == NHRP_HA_HUB_STANDBY;
  if (state->role != NHRP_HA_HUB_STANDBY) {
    peer->flags |= NHRP_PEER_FLAG_HA_PROJECTED | NHRP_PEER_FLAG_HA_DIRECT;
    return 1;
  }
  return 0;
}

int nhrp_ha_hub_retire_direct(struct nhrp_interface *iface,
                              const struct nhrp_address *protocol,
                              uint8_t prefix_length,
                              const struct nhrp_address *nbma,
                              uint32_t registration_id, uint64_t term,
                              uint64_t index) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, FALSE);
  struct nhrp_ha_hub_entry *entry;

  if (state == NULL || protocol == NULL || registration_id == 0)
    return FALSE;
  hub_state_gc(state);
  entry = hub_entry_find(state, protocol, prefix_length);
  if (entry == NULL || !entry->direct.present ||
      entry->direct.binding.registration_id != registration_id ||
      (entry->direct.binding.owner_member[0] != 0 &&
       strcmp(entry->direct.binding.owner_member,
              iface->ha_member_id) != 0) ||
      (nbma != NULL &&
       nhrp_address_cmp(&entry->direct.binding.nbma, nbma) != 0 &&
       (entry->direct.binding.nat_oa.type == PF_UNSPEC ||
        nhrp_address_cmp(&entry->direct.binding.nat_oa, nbma) != 0)))
    return FALSE;
  if (term != 0 || index != 0) {
    struct nhrp_ha_hub_binding version = entry->direct.binding;

    version.term = term;
    version.index = index;
    if (binding_version_cmp(&version, &entry->direct.binding) < 0)
      return FALSE;
    hub_owner_observe(entry, &version);
  }
  /* Keep a newer replicated owner; a delayed release for the old token must
   * not erase the next owner's shadow. */
  if (!retire_direct_entry(state, entry, FALSE))
    return FALSE;
  admin_ha_notify(iface);
  return TRUE;
}

int nhrp_ha_hub_serviceable(struct nhrp_interface *iface) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, FALSE);

  return state == NULL || state->role != NHRP_HA_HUB_STANDBY;
}

int nhrp_ha_hub_takeover_version(struct nhrp_interface *iface,
                                  const struct nhrp_address *protocol,
                                  uint8_t prefix_length,
                                  uint64_t *term, uint64_t *index) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, FALSE);
  struct nhrp_ha_hub_entry *entry;
  const struct nhrp_ha_hub_value *value;

  if (state == NULL || protocol == NULL)
    return FALSE;
  hub_state_gc(state);
  entry = hub_entry_find(state, protocol, prefix_length);
  if (entry == NULL)
    return FALSE;
  value = hub_entry_value(entry);
  if (value == NULL)
    return FALSE;
  if (term != NULL)
    *term = value->binding.term;
  if (index != NULL)
    *index = value->binding.index;
  return strcmp(value->binding.owner_member, iface->ha_member_id) == 0;
}

int nhrp_ha_hub_set_role(struct nhrp_interface *iface,
                         enum nhrp_ha_hub_role role, uint64_t term,
                         uint64_t index) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, TRUE);
  struct nhrp_peer_selector selector;
  struct nhrp_ha_hub_entry *entry;
  enum nhrp_ha_hub_role previous_role;
  uint64_t previous_term;

  if (state == NULL || role == NHRP_HA_HUB_UNMANAGED || term == 0 ||
      term < state->term || (term == state->term && index < state->index))
    return FALSE;
  hub_state_gc(state);
  previous_role = state->role;
  previous_term = state->term;
  state->term = term;
  state->index = index;
  if (state->role == role &&
      (role != NHRP_HA_HUB_LEADER || term == previous_term))
    return TRUE;
  if (role == NHRP_HA_HUB_STANDBY) {
    memset(&selector, 0, sizeof(selector));
    selector.interface = iface;
    selector.type_mask = BIT(NHRP_PEER_TYPE_DYNAMIC);
    nhrp_peer_foreach(remove_replica_effective, NULL, &selector);
  } else if (role == NHRP_HA_HUB_FOLLOWER) {
    /* Keep the old Leader's owners until each Spoke commits its takeover and
     * releases them, or their holding time expires. */
    if (previous_role != NHRP_HA_HUB_LEADER) {
      memset(&selector, 0, sizeof(selector));
      selector.interface = iface;
      selector.type_mask = BIT(NHRP_PEER_TYPE_DYNAMIC);
      nhrp_peer_foreach(remove_replica_effective, NULL, &selector);
      list_for_each_entry(entry, &state->entries, list_entry)
        if (entry->direct.prepared)
          retire_direct_entry(state, entry, FALSE);
    }
  } else {
    list_for_each_entry(entry, &state->entries, list_entry) {
      uint64_t owner_term;
      uint64_t owner_index;

      if (entry->direct.present)
        hub_owner_observe(entry, &entry->direct.binding);
      if (entry->replica.present)
        hub_owner_observe(entry, &entry->replica.binding);
      hub_owner_next(state, entry, &owner_term, &owner_index);
      if (entry->direct.present && entry->direct.retired &&
          entry->direct.prepared &&
          (!entry->replica.present ||
           binding_version_cmp(&entry->direct.binding,
                               &entry->replica.binding) >= 0))
        entry->direct.retired = FALSE;
      if (entry->direct.present && !entry->direct.retired) {
        entry->direct.binding.term = owner_term;
        entry->direct.binding.index = owner_index;
        snprintf(entry->direct.binding.owner_member,
                 sizeof(entry->direct.binding.owner_member), "%s",
                 iface->ha_member_id);
      }
      if (entry->replica.present &&
          (!entry->direct.present || entry->direct.retired)) {
        entry->replica.binding.term = owner_term;
        entry->replica.binding.index = owner_index;
        entry->replica.binding.registration_id = 0;
        snprintf(entry->replica.binding.owner_member,
                 sizeof(entry->replica.binding.owner_member), "%s",
                 iface->ha_member_id);
      }
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
  hub_state_gc(state);
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
      binding->holding_time == 0 || binding->term > state->pending_term)
    return FALSE;
  hub_state_gc(state);
  /* A replicated HA binding must never take over a local legacy spoke. */
  if (has_local_registration(iface, protocol, prefix_length))
    return TRUE;
  entry = hub_entry_get(state, protocol, prefix_length);
  if (entry == NULL)
    return FALSE;
  hub_owner_observe(entry, binding);
  if (entry->direct.present && !entry->direct.retired &&
      strcmp(binding->owner_member, iface->ha_member_id) != 0 &&
      binding_version_cmp(binding, &entry->direct.binding) > 0)
    retire_direct_entry(state, entry, FALSE);
  entry->replica.binding = *binding;
  entry->replica.expires = ev_now() + binding->holding_time;
  entry->replica.present = TRUE;
  entry->replica_seen = TRUE;
  /* A Follower normally keeps the replica for a future takeover.  A
   * standby-to-follower transition may project it as a local fallback, but
   * a retired direct owner remains fenced. */
  if (state->role == NHRP_HA_HUB_LEADER &&
      (!entry->direct.present || entry->direct.retired))
    return project_entry(state, entry);
  return TRUE;
}

int nhrp_ha_hub_sync_end(struct nhrp_interface *iface) {
  struct nhrp_ha_hub_state *state = hub_state_find(iface, FALSE);
  struct nhrp_ha_hub_entry *entry;
  struct nhrp_ha_hub_entry *next;

  if (state == NULL || !state->sync_active)
    return FALSE;
  hub_state_gc(state);
  list_for_each_entry_safe(entry, next, &state->entries, list_entry) {
    if (!entry->replica_seen)
      entry->replica.present = FALSE;
    hub_value_expire(&entry->direct);
    hub_value_expire(&entry->replica);
    if (!entry->direct.present && !entry->replica.present)
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
  return snprintf(buffer, size,
                  "entry %s %u %s %s %u %u %u %llu %llu %u %s %s\n",
                  protocol, entry->prefix_length, nbma, nat_oa,
                  value->binding.mtu, value->binding.holding_time,
                  value->binding.flags, (unsigned long long)value->binding.term,
                  (unsigned long long)value->binding.index,
                  value->binding.registration_id,
                  value->binding.owner_member[0] != 0
                      ? value->binding.owner_member
                      : "-",
                  value == &entry->direct ? "direct" : "replica");
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
  hub_state_gc(state);
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
  hub_state_gc(state);
  role = state->role == NHRP_HA_HUB_LEADER     ? "leader"
         : state->role == NHRP_HA_HUB_FOLLOWER ? "follower"
         : state->role == NHRP_HA_HUB_STANDBY  ? "standby"
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
