/* nhrp_ha_store.h - Authenticated atomic HA snapshot storage */

#ifndef NHRP_HA_STORE_H
#define NHRP_HA_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "nhrp_ha_auth.h"

struct nhrp_ha_store_record {
  uint8_t cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE];
  uint64_t term;
  uint64_t index;
  char leader[NHRP_HA_AUTH_LEADER_MAX + 1];
  uint8_t *payload;
  size_t payload_length;
  uint8_t key_id[NHRP_HA_AUTH_KEY_ID_SIZE];
};

int nhrp_ha_store_load(const char *path, const struct nhrp_ha_auth_keys *keys,
                       const uint8_t cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE],
                       struct nhrp_ha_store_record *record);
int nhrp_ha_store_save(const char *path, const struct nhrp_ha_auth_keys *keys,
                       const struct nhrp_ha_store_record *record);
void nhrp_ha_store_record_clear(struct nhrp_ha_store_record *record);

#endif
