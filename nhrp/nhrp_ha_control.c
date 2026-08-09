/* nhrp_ha_control.c - Authenticated Hub replication control frames */

#include <arpa/inet.h>
#include <endian.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nhrp_ha_control.h"

#define CONTROL_PREFIX_SIZE 68
#define CONTROL_TAG_ENTRY_SIZE                                                 \
  (NHRP_HA_AUTH_KEY_ID_SIZE + NHRP_HA_AUTH_TAG_SIZE)

static int type_valid(uint8_t type) {
  return type >= NHRP_HA_CONTROL_HELLO && type <= NHRP_HA_CONTROL_CONFIGURE;
}

size_t nhrp_ha_control_encoded_size(const struct nhrp_ha_auth_keys *keys,
                                    const struct nhrp_ha_control_frame *frame) {
  size_t count = nhrp_ha_auth_key_count(keys);
  size_t sender_length = strnlen(frame->sender, sizeof(frame->sender));
  size_t size;

  if (count == 0 || !type_valid(frame->type) || frame->term == 0 ||
      sender_length == 0 || sender_length >= sizeof(frame->sender) ||
      (frame->payload_length != 0 && frame->payload == NULL) ||
      frame->payload_length > NHRP_HA_CONTROL_MAX_FRAME)
    return 0;
  size = CONTROL_PREFIX_SIZE + sender_length + count * CONTROL_TAG_ENTRY_SIZE +
         frame->payload_length;
  return size <= NHRP_HA_CONTROL_MAX_FRAME ? size : 0;
}

static int control_hmac(const struct nhrp_ha_auth_key *key,
                        const uint8_t *prefix, size_t prefix_length,
                        const uint8_t key_id[8], const uint8_t *payload,
                        size_t payload_length, uint8_t tag[32]) {
  uint8_t *authenticated;
  size_t length = prefix_length + 8 + payload_length;
  int ok;

  authenticated = malloc(length);
  if (authenticated == NULL)
    return 0;
  memcpy(authenticated, prefix, prefix_length);
  memcpy(authenticated + prefix_length, key_id, 8);
  if (payload_length != 0)
    memcpy(authenticated + prefix_length + 8, payload, payload_length);
  ok = nhrp_ha_auth_hmac(key->control_key, authenticated, length, tag);
  OPENSSL_cleanse(authenticated, length);
  free(authenticated);
  return ok;
}

enum nhrp_ha_control_result
nhrp_ha_control_encode(const struct nhrp_ha_auth_keys *keys,
                       const struct nhrp_ha_control_frame *frame, uint8_t *wire,
                       size_t wire_size) {
  uint32_t wire32;
  uint64_t wire64;
  size_t encoded_size = nhrp_ha_control_encoded_size(keys, frame);
  size_t sender_length = strlen(frame->sender);
  size_t count = nhrp_ha_auth_key_count(keys);
  size_t offset;
  size_t i;

  if (encoded_size == 0)
    return NHRP_HA_CONTROL_BAD_HEADER;
  if (wire_size < encoded_size)
    return NHRP_HA_CONTROL_TRUNCATED;
  memset(wire, 0, encoded_size);
  wire32 = htonl(encoded_size - 4);
  memcpy(&wire[0], &wire32, 4);
  memcpy(&wire[4], "NHHC", 4);
  wire[8] = NHRP_HA_CONTROL_VERSION;
  wire[9] = frame->type;
  wire[10] = count;
  wire[11] = frame->flags;
  wire32 = htonl(frame->payload_length);
  memcpy(&wire[12], &wire32, 4);
  memcpy(&wire[16], frame->cluster_id, 16);
  wire64 = htobe64(frame->term);
  memcpy(&wire[32], &wire64, 8);
  wire64 = htobe64(frame->index);
  memcpy(&wire[40], &wire64, 8);
  wire64 = htobe64(frame->ack_index);
  memcpy(&wire[48], &wire64, 8);
  wire64 = htobe64(frame->nonce);
  memcpy(&wire[56], &wire64, 8);
  wire[64] = sender_length >> 8;
  wire[65] = sender_length;
  memcpy(&wire[CONTROL_PREFIX_SIZE], frame->sender, sender_length);
  offset = CONTROL_PREFIX_SIZE + sender_length;
  for (i = 0; i < NHRP_HA_AUTH_MAX_KEYS; i++) {
    if (!keys->key[i].present)
      continue;
    memcpy(&wire[offset], keys->key[i].id, 8);
    if (!control_hmac(&keys->key[i], &wire[4],
                      CONTROL_PREFIX_SIZE - 4 + sender_length, keys->key[i].id,
                      frame->payload, frame->payload_length, &wire[offset + 8]))
      return NHRP_HA_CONTROL_BAD_HEADER;
    offset += CONTROL_TAG_ENTRY_SIZE;
  }
  if (frame->payload_length != 0)
    memcpy(&wire[offset], frame->payload, frame->payload_length);
  return NHRP_HA_CONTROL_OK;
}

enum nhrp_ha_control_result nhrp_ha_control_decode(
    const struct nhrp_ha_auth_keys *keys, const uint8_t *wire, size_t wire_size,
    struct nhrp_ha_control_frame *frame, uint8_t matched_key_id[8]) {
  uint8_t expected[32];
  uint32_t wire32;
  uint64_t wire64;
  size_t sender_length;
  size_t payload_length;
  size_t expected_size;
  size_t tags_offset;
  size_t payload_offset;
  size_t i;
  size_t j;
  int known_key = 0;

  memset(frame, 0, sizeof(*frame));
  if (wire_size < CONTROL_PREFIX_SIZE)
    return NHRP_HA_CONTROL_TRUNCATED;
  if (wire_size > NHRP_HA_CONTROL_MAX_FRAME)
    return NHRP_HA_CONTROL_TOO_LARGE;
  memcpy(&wire32, &wire[0], 4);
  if (ntohl(wire32) != wire_size - 4 || memcmp(&wire[4], "NHHC", 4) != 0 ||
      wire[8] != NHRP_HA_CONTROL_VERSION || !type_valid(wire[9]) ||
      wire[10] == 0 || wire[10] > NHRP_HA_AUTH_MAX_KEYS || wire[66] != 0 ||
      wire[67] != 0)
    return NHRP_HA_CONTROL_BAD_HEADER;
  memcpy(&wire32, &wire[12], 4);
  payload_length = ntohl(wire32);
  sender_length = ((size_t)wire[64] << 8) | wire[65];
  expected_size = CONTROL_PREFIX_SIZE + sender_length +
                  wire[10] * CONTROL_TAG_ENTRY_SIZE + payload_length;
  if (sender_length == 0 || sender_length > NHRP_HA_CONTROL_SENDER_MAX ||
      expected_size != wire_size)
    return NHRP_HA_CONTROL_BAD_HEADER;

  frame->type = wire[9];
  frame->flags = wire[11];
  memcpy(frame->cluster_id, &wire[16], 16);
  memcpy(&wire64, &wire[32], 8);
  frame->term = be64toh(wire64);
  memcpy(&wire64, &wire[40], 8);
  frame->index = be64toh(wire64);
  memcpy(&wire64, &wire[48], 8);
  frame->ack_index = be64toh(wire64);
  memcpy(&wire64, &wire[56], 8);
  frame->nonce = be64toh(wire64);
  if (frame->term == 0)
    return NHRP_HA_CONTROL_BAD_HEADER;
  memcpy(frame->sender, &wire[CONTROL_PREFIX_SIZE], sender_length);
  frame->sender[sender_length] = 0;
  tags_offset = CONTROL_PREFIX_SIZE + sender_length;
  payload_offset = tags_offset + wire[10] * CONTROL_TAG_ENTRY_SIZE;
  frame->payload = &wire[payload_offset];
  frame->payload_length = payload_length;

  for (i = 0; i < wire[10]; i++) {
    size_t tag_offset = tags_offset + i * CONTROL_TAG_ENTRY_SIZE;

    if (i != 0 && CRYPTO_memcmp(&wire[tag_offset], &wire[tags_offset], 8) == 0)
      return NHRP_HA_CONTROL_BAD_HEADER;
    for (j = 0; j < NHRP_HA_AUTH_MAX_KEYS; j++) {
      if (!keys->key[j].present ||
          CRYPTO_memcmp(keys->key[j].id, &wire[tag_offset], 8) != 0)
        continue;
      known_key = 1;
      if (control_hmac(&keys->key[j], &wire[4],
                       CONTROL_PREFIX_SIZE - 4 + sender_length,
                       &wire[tag_offset], frame->payload, frame->payload_length,
                       expected) &&
          CRYPTO_memcmp(expected, &wire[tag_offset + 8], 32) == 0) {
        memcpy(matched_key_id, &wire[tag_offset], 8);
        OPENSSL_cleanse(expected, sizeof(expected));
        return NHRP_HA_CONTROL_OK;
      }
    }
  }
  OPENSSL_cleanse(expected, sizeof(expected));
  return known_key ? NHRP_HA_CONTROL_BAD_TAG : NHRP_HA_CONTROL_UNKNOWN_KEY;
}

enum nhrp_ha_control_sequence_result
nhrp_ha_control_sequence(uint64_t match_index, uint8_t type, uint64_t index) {
  if (type == NHRP_HA_CONTROL_SNAPSHOT)
    return index < match_index ? NHRP_HA_CONTROL_SEQUENCE_IGNORE
                               : NHRP_HA_CONTROL_SEQUENCE_APPLY;
  if (type != NHRP_HA_CONTROL_DELTA)
    return NHRP_HA_CONTROL_SEQUENCE_RESYNC;
  if (index == match_index + 1)
    return NHRP_HA_CONTROL_SEQUENCE_APPLY;
  return index <= match_index ? NHRP_HA_CONTROL_SEQUENCE_IGNORE
                              : NHRP_HA_CONTROL_SEQUENCE_RESYNC;
}
