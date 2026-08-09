/* nhrp_ha_auth.h - HMAC authentication for OpenNHRP HA messages */

#ifndef NHRP_HA_AUTH_H
#define NHRP_HA_AUTH_H

#include <stddef.h>
#include <stdint.h>

#define NHRP_EXTENSION_HA_AUTH 0x3802
#define NHRP_HA_AUTH_VERSION 1
#define NHRP_HA_AUTH_ALGORITHM_HMAC_SHA256 1
#define NHRP_HA_AUTH_KEY_SIZE 32
#define NHRP_HA_AUTH_KEY_ID_SIZE 8
#define NHRP_HA_AUTH_TAG_SIZE 32
#define NHRP_HA_AUTH_CLUSTER_ID_SIZE 16
#define NHRP_HA_AUTH_MAX_KEYS 2
#define NHRP_HA_AUTH_LEADER_MAX 63

enum nhrp_ha_auth_result {
  NHRP_HA_AUTH_OK = 0,
  NHRP_HA_AUTH_TRUNCATED,
  NHRP_HA_AUTH_BAD_HEADER,
  NHRP_HA_AUTH_BAD_METADATA,
  NHRP_HA_AUTH_UNKNOWN_KEY,
  NHRP_HA_AUTH_BAD_TAG,
};

struct nhrp_ha_auth_key {
  int present;
  uint8_t id[NHRP_HA_AUTH_KEY_ID_SIZE];
  uint8_t nhrp_key[NHRP_HA_AUTH_KEY_SIZE];
  uint8_t control_key[NHRP_HA_AUTH_KEY_SIZE];
  uint8_t state_key[NHRP_HA_AUTH_KEY_SIZE];
};

struct nhrp_ha_auth_keys {
  struct nhrp_ha_auth_key key[NHRP_HA_AUTH_MAX_KEYS];
};

struct nhrp_ha_auth_input {
  uint8_t packet_type;
  uint32_t request_id_wire;
  uint8_t src_protocol[4];
  uint8_t dst_protocol[4];
  const uint8_t *ha_payload;
  size_t ha_payload_length;
};

struct nhrp_ha_auth_metadata {
  uint8_t cluster_id[NHRP_HA_AUTH_CLUSTER_ID_SIZE];
  uint64_t term;
  uint64_t commit_index;
  char leader[NHRP_HA_AUTH_LEADER_MAX + 1];
};

int nhrp_ha_auth_key_from_bytes(struct nhrp_ha_auth_key *key,
                                const uint8_t psk[NHRP_HA_AUTH_KEY_SIZE]);
int nhrp_ha_auth_key_load(struct nhrp_ha_auth_key *key, const char *path);
void nhrp_ha_auth_key_clear(struct nhrp_ha_auth_key *key);
void nhrp_ha_auth_keys_clear(struct nhrp_ha_auth_keys *keys);
size_t nhrp_ha_auth_key_count(const struct nhrp_ha_auth_keys *keys);
void nhrp_ha_auth_key_id_format(const uint8_t id[NHRP_HA_AUTH_KEY_ID_SIZE],
                                char output[NHRP_HA_AUTH_KEY_ID_SIZE * 2 + 1]);
int nhrp_ha_auth_hmac(const uint8_t key[NHRP_HA_AUTH_KEY_SIZE],
                      const void *data, size_t length,
                      uint8_t output[NHRP_HA_AUTH_TAG_SIZE]);
int nhrp_ha_secure_file_write(const char *path, const void *data,
                              size_t length);

size_t nhrp_ha_auth_encoded_size(const struct nhrp_ha_auth_keys *keys,
                                 const struct nhrp_ha_auth_metadata *metadata);
enum nhrp_ha_auth_result
nhrp_ha_auth_encode(const struct nhrp_ha_auth_keys *keys,
                    const struct nhrp_ha_auth_input *input,
                    const struct nhrp_ha_auth_metadata *metadata, uint8_t *wire,
                    size_t wire_size);
enum nhrp_ha_auth_result
nhrp_ha_auth_verify(const struct nhrp_ha_auth_keys *keys,
                    const struct nhrp_ha_auth_input *input, const uint8_t *wire,
                    size_t wire_size, struct nhrp_ha_auth_metadata *metadata,
                    uint8_t matched_key_id[NHRP_HA_AUTH_KEY_ID_SIZE]);

#endif
