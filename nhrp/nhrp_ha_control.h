/* nhrp_ha_control.h - Authenticated Hub replication control frames */

#ifndef NHRP_HA_CONTROL_H
#define NHRP_HA_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#include "nhrp_ha_auth.h"

#define NHRP_HA_CONTROL_VERSION 1
#define NHRP_HA_CONTROL_MAX_FRAME (4U * 1024U * 1024U)
#define NHRP_HA_CONTROL_SENDER_MAX 63

enum nhrp_ha_control_type {
  NHRP_HA_CONTROL_HELLO = 1,
  NHRP_HA_CONTROL_SNAPSHOT = 2,
  NHRP_HA_CONTROL_DELTA = 3,
  NHRP_HA_CONTROL_ACK = 4,
  NHRP_HA_CONTROL_DIGEST = 5,
  NHRP_HA_CONTROL_RESYNC = 6,
  NHRP_HA_CONTROL_HEARTBEAT = 7,
  NHRP_HA_CONTROL_TRANSFER = 8,
  NHRP_HA_CONTROL_TRANSFER_ACK = 9,
  NHRP_HA_CONTROL_MANIFEST = 10,
  NHRP_HA_CONTROL_MANIFEST_ACK = 11,
  NHRP_HA_CONTROL_CONFIGURE = 12,
};

enum nhrp_ha_control_result {
  NHRP_HA_CONTROL_OK = 0,
  NHRP_HA_CONTROL_TRUNCATED,
  NHRP_HA_CONTROL_TOO_LARGE,
  NHRP_HA_CONTROL_BAD_HEADER,
  NHRP_HA_CONTROL_UNKNOWN_KEY,
  NHRP_HA_CONTROL_BAD_TAG,
};

enum nhrp_ha_control_sequence_result {
  NHRP_HA_CONTROL_SEQUENCE_APPLY = 0,
  NHRP_HA_CONTROL_SEQUENCE_IGNORE,
  NHRP_HA_CONTROL_SEQUENCE_RESYNC,
};

struct nhrp_ha_control_frame {
  uint8_t type;
  uint8_t flags;
  uint8_t cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE];
  uint64_t term;
  uint64_t index;
  uint64_t ack_index;
  uint64_t nonce;
  char sender[NHRP_HA_CONTROL_SENDER_MAX + 1];
  const uint8_t *payload;
  size_t payload_length;
};

size_t nhrp_ha_control_encoded_size(const struct nhrp_ha_auth_keys *keys,
                                    const struct nhrp_ha_control_frame *frame);
enum nhrp_ha_control_result
nhrp_ha_control_encode(const struct nhrp_ha_auth_keys *keys,
                       const struct nhrp_ha_control_frame *frame, uint8_t *wire,
                       size_t wire_size);
enum nhrp_ha_control_result
nhrp_ha_control_decode(const struct nhrp_ha_auth_keys *keys,
                       const uint8_t *wire, size_t wire_size,
                       struct nhrp_ha_control_frame *frame,
                       uint8_t matched_key_id[NHRP_HA_AUTH_KEY_ID_SIZE]);
enum nhrp_ha_control_sequence_result
nhrp_ha_control_sequence(uint64_t match_index, uint8_t type, uint64_t index);

#endif
