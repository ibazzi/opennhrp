/* nhrp_ha_seen.h - Persistent highest-seen OpenNHRP HA term */

#ifndef NHRP_HA_SEEN_H
#define NHRP_HA_SEEN_H

#include <stdint.h>

#include "nhrp_ha_auth.h"

struct nhrp_ha_seen_state {
  uint8_t cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE];
  uint64_t term;
  uint64_t commit_index;
  char leader[NHRP_HA_AUTH_LEADER_MAX + 1];
  uint8_t key_id[NHRP_HA_AUTH_KEY_ID_SIZE];
};

int nhrp_ha_seen_load(const char *path, const struct nhrp_ha_auth_keys *keys,
                      const uint8_t cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE],
                      struct nhrp_ha_seen_state *state);
int nhrp_ha_seen_save(const char *path, const struct nhrp_ha_auth_keys *keys,
                      const struct nhrp_ha_seen_state *state);

#endif
