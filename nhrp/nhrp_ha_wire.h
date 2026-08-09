/* nhrp_ha_wire.h - Wire helpers for OpenNHRP HA messages */

#ifndef NHRP_HA_WIRE_H
#define NHRP_HA_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "nhrp_ha_managed.h"

#define NHRP_HA_HUB_LIST_MAX_ENTRIES                                           \
  (NHRP_HA_MANAGED_MAX_MEMBERS * NHRP_HA_MANAGED_MAX_ENDPOINTS)
#define NHRP_HA_HUB_LIST_NBMA_LEN 4

size_t nhrp_ha_compat_encoded_size(size_t payload_size);
int nhrp_ha_compat_encode(const uint8_t *payload, size_t payload_size,
                          uint8_t *wire, size_t wire_size);
int nhrp_ha_compat_parse(const uint8_t *wire, size_t wire_size,
                         const uint8_t **payload, size_t *payload_size);

enum nhrp_ha_hub_list_result {
  NHRP_HA_HUB_LIST_OK = 0,
  NHRP_HA_HUB_LIST_TRUNCATED,
  NHRP_HA_HUB_LIST_BAD_HEADER,
  NHRP_HA_HUB_LIST_TOO_MANY,
  NHRP_HA_HUB_LIST_BAD_ENTRY,
  NHRP_HA_HUB_LIST_DUPLICATE,
  NHRP_HA_HUB_LIST_SOURCE_MISSING,
};

struct nhrp_ha_hub_list_entry {
  char member[64];
  uint8_t nbma[NHRP_HA_HUB_LIST_NBMA_LEN];
  uint32_t priority;
};

struct nhrp_ha_hub_list {
  char source_member[64];
  uint32_t request_generation;
  uint32_t list_generation;
  uint8_t prefix_length;
  size_t entry_count;
  struct nhrp_ha_hub_list_entry entries[NHRP_HA_HUB_LIST_MAX_ENTRIES];
};

size_t nhrp_ha_hub_list_encoded_size(const struct nhrp_ha_hub_list *list);
enum nhrp_ha_hub_list_result
nhrp_ha_hub_list_encode(const struct nhrp_ha_hub_list *list, uint8_t *wire,
                        size_t wire_size);
enum nhrp_ha_hub_list_result
nhrp_ha_hub_list_parse(const uint8_t *wire, size_t wire_size,
                       struct nhrp_ha_hub_list *list);

#endif
