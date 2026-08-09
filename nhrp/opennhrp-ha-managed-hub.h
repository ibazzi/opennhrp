/* opennhrp-ha-managed-hub.h - Managed multi-Hub coordinator */

#ifndef OPENNHRP_HA_MANAGED_HUB_H
#define OPENNHRP_HA_MANAGED_HUB_H

#include <stdint.h>
#include <string.h>

#include "nhrp_ha_managed.h"

static inline int opennhrp_ha_witness_quorum(unsigned int active_hubs,
                                             uint8_t mode, int peer_vote,
                                             int manager_vote) {
  if (active_hubs <= 1)
    return active_hubs == 1;
  return mode == NHRP_HA_WITNESS_LEGACY || peer_vote || manager_vote;
}

static inline int
opennhrp_ha_witness_single_hub_fallback(unsigned int active_hubs, uint8_t mode,
                                        const char *local_member,
                                        const char *leader) {
  return active_hubs == 1 && mode != NHRP_HA_WITNESS_LEGACY &&
         strcmp(local_member, leader) == 0;
}

static inline unsigned int
opennhrp_ha_hub_majority_required(unsigned int active_hubs) {
  return active_hubs / 2 + 1;
}

static inline int opennhrp_ha_hub_majority(unsigned int active_hubs,
                                           unsigned int votes) {
  return active_hubs >= 3 &&
         votes >= opennhrp_ha_hub_majority_required(active_hubs);
}

static inline int
opennhrp_ha_autonomous_election_allowed(unsigned int active_hubs, uint8_t mode,
                                        int hub_majority) {
  if (active_hubs == 1)
    return 1;
  if (active_hubs == 2)
    return mode == NHRP_HA_WITNESS_LEGACY;
  return active_hubs >= 3 && hub_majority;
}

static inline int opennhrp_ha_witness_lease_acceptable(
    uint8_t mode, int epoch_matches, uint64_t current_term, uint64_t lease_term,
    uint64_t last_sequence, uint64_t sequence, uint64_t ttl_ms) {
  return mode == NHRP_HA_WITNESS_ACTIVE && epoch_matches &&
         lease_term >= current_term && sequence > last_sequence && ttl_ms > 0 &&
         ttl_ms <= 3000;
}

static inline int opennhrp_ha_term_evidence_covers(uint64_t current_term,
                                                   uint64_t evidence_term) {
  return evidence_term == current_term ||
         (current_term > 0 && evidence_term == current_term - 1);
}

static inline int
opennhrp_ha_witness_peer_mode_compatible(uint8_t local_mode, uint8_t peer_mode,
                                         int epoch_matches,
                                         int activation_pending) {
  if (local_mode == NHRP_HA_WITNESS_LEGACY)
    return 0;
  return local_mode == NHRP_HA_WITNESS_PREPARING || activation_pending ||
         (peer_mode == local_mode && epoch_matches);
}

static inline int opennhrp_ha_manifest_core_reload_needed(
    const struct nhrp_ha_managed_state *current,
    const struct nhrp_ha_managed_state *next) {
  size_t left_index = 0;
  size_t right_index = 0;

  if (memcmp(current->cluster_id, next->cluster_id,
             sizeof(current->cluster_id)) != 0 ||
      strcmp(current->interface, next->interface) != 0 ||
      current->protocol_address.s_addr != next->protocol_address.s_addr ||
      current->prefix_length != next->prefix_length ||
      strcmp(current->local_member, next->local_member) != 0)
    return 1;

  for (;;) {
    const struct nhrp_ha_managed_member *left;
    const struct nhrp_ha_managed_member *right;

    while (left_index < current->member_count &&
           current->members[left_index].state != NHRP_HA_MANAGED_ACTIVE)
      left_index++;
    while (right_index < next->member_count &&
           next->members[right_index].state != NHRP_HA_MANAGED_ACTIVE)
      right_index++;
    if (left_index == current->member_count ||
        right_index == next->member_count)
      return left_index != current->member_count ||
             right_index != next->member_count;

    left = &current->members[left_index++];
    right = &next->members[right_index++];

    if (strcmp(left->member, right->member) != 0 ||
        left->address_count != right->address_count ||
        memcmp(left->addresses, right->addresses,
               left->address_count * sizeof(left->addresses[0])) != 0 ||
        left->priority != right->priority)
      return 1;
  }
}

static inline int opennhrp_ha_backup_became_leader(const char *local_member,
                                                   const char *primary_member,
                                                   const char *previous_leader,
                                                   const char *next_leader) {
  return strcmp(local_member, primary_member) != 0 &&
         strcmp(previous_leader, local_member) != 0 &&
         strcmp(next_leader, local_member) == 0;
}

static inline int opennhrp_ha_witness_reprepare_needed(uint8_t mode,
                                                       int epoch_matches,
                                                       int manager_vote) {
  return mode != NHRP_HA_WITNESS_LEGACY &&
         (!epoch_matches || mode == NHRP_HA_WITNESS_DISABLING) && !manager_vote;
}

static inline int opennhrp_ha_witness_fallback_safe(
    int peer_healthy, int same_mode_epoch, uint64_t local_term,
    uint64_t peer_term, const char *local_leader, const char *peer_leader,
    uint64_t local_index, uint64_t peer_index, const char *local_digest,
    const char *peer_digest) {
  return peer_healthy && same_mode_epoch && local_term == peer_term &&
         strcmp(local_leader, peer_leader) == 0 && local_index == peer_index &&
         local_digest[0] != 0 && strcmp(local_digest, peer_digest) == 0;
}

static inline int opennhrp_ha_witness_transition_allowed(uint8_t current,
                                                         uint8_t next) {
  if (current == next)
    return 1;
  if (current == NHRP_HA_WITNESS_PREPARING)
    return next == NHRP_HA_WITNESS_ACTIVE;
  if (current == NHRP_HA_WITNESS_ACTIVE)
    return next == NHRP_HA_WITNESS_DISABLING;
  if (current == NHRP_HA_WITNESS_DISABLING)
    return next == NHRP_HA_WITNESS_ACTIVE || next == NHRP_HA_WITNESS_LEGACY;
  return 0;
}

static inline int opennhrp_ha_witness_manifest_transition_allowed(
    uint8_t current, uint8_t next, unsigned int active_hubs, int local_active) {
  return !local_active ||
         opennhrp_ha_witness_transition_allowed(current, next) ||
         (active_hubs != 2 && next == NHRP_HA_WITNESS_LEGACY);
}

static inline int opennhrp_ha_snapshot_resync_needed(uint64_t local_index,
                                                     const char *local_digest,
                                                     uint64_t peer_index,
                                                     const char *peer_digest) {
  return local_digest[0] != 0 && peer_index >= local_index &&
         strcmp(peer_digest, local_digest) != 0;
}

static inline int opennhrp_ha_snapshot_cache_matches(
    const uint8_t *cached, size_t cached_length, const char *cached_digest,
    const uint8_t *fresh, size_t fresh_length, const char *fresh_digest) {
  return cached != NULL && cached_length == fresh_length &&
         strcmp(cached_digest, fresh_digest) == 0 &&
         memcmp(cached, fresh, fresh_length) == 0;
}

static inline const char *opennhrp_ha_reconnect_target(const char *local_member,
                                                       const char *leader,
                                                       const char *primary) {
  if (strcmp(local_member, leader) != 0)
    return leader;
  if (strcmp(local_member, primary) != 0)
    return primary;
  return NULL;
}

static inline const char *
opennhrp_ha_split_recovery_leader(const char *local_member, const char *primary,
                                  const char *peer_member, int local_is_leader,
                                  int peer_is_leader) {
  if (!local_is_leader || !peer_is_leader)
    return NULL;
  if (strcmp(local_member, primary) == 0 && strcmp(peer_member, primary) != 0)
    return peer_member;
  if (strcmp(peer_member, primary) == 0 && strcmp(local_member, primary) != 0)
    return local_member;
  return NULL;
}

static inline const char *opennhrp_ha_startup_leader(const char *local_member,
                                                     const char *primary,
                                                     const char *leader) {
  if (strcmp(local_member, primary) != 0 && strcmp(local_member, leader) == 0)
    return primary;
  return leader;
}

static inline int opennhrp_ha_replace_with_incoming(const char *local_member,
                                                    const char *peer_member,
                                                    int current_outgoing) {
  return current_outgoing && strcmp(local_member, peer_member) > 0;
}

int opennhrp_ha_managed_hub_main(int argc, char **argv);

#endif
