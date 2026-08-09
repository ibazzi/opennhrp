#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nhrp_ha_auth.h"

static void initialize(struct nhrp_ha_auth_keys *keys,
                       struct nhrp_ha_auth_input *input,
                       struct nhrp_ha_auth_metadata *metadata) {
  uint8_t current[32];
  uint8_t next[32];

  memset(keys, 0, sizeof(*keys));
  memset(input, 0, sizeof(*input));
  memset(metadata, 0, sizeof(*metadata));
  memset(current, 0x11, sizeof(current));
  memset(next, 0x22, sizeof(next));
  assert(nhrp_ha_auth_key_from_bytes(&keys->key[0], current));
  assert(nhrp_ha_auth_key_from_bytes(&keys->key[1], next));
  input->packet_type = 4;
  input->request_id_wire = 0x78563412;
  memcpy(input->src_protocol, "\x0a\x14\x00\x01", 4);
  memcpy(input->dst_protocol, "\x0a\x14\x00\x02", 4);
  input->ha_payload = (const uint8_t *)"hub-list-payload";
  input->ha_payload_length = strlen((const char *)input->ha_payload);
  memcpy(metadata->cluster_id, "0123456789abcdef", 16);
  metadata->term = 7;
  metadata->commit_index = 42;
  strcpy(metadata->leader, "hub-primary");
}

int main(void) {
  struct nhrp_ha_auth_keys keys;
  struct nhrp_ha_auth_keys wrong_keys;
  struct nhrp_ha_auth_input input;
  struct nhrp_ha_auth_metadata metadata;
  struct nhrp_ha_auth_metadata decoded;
  uint8_t matched[8];
  uint8_t wire[512];
  struct nhrp_ha_auth_key loaded_key;
  char key_path[] = "/tmp/opennhrp-ha-auth-test.XXXXXX";
  static const char encoded_key[] = "00112233445566778899aabbccddeeff"
                                    "00112233445566778899aabbccddeeff";
  size_t length;
  int fd;

  initialize(&keys, &input, &metadata);
  length = nhrp_ha_auth_encoded_size(&keys, &metadata);
  assert(length > 0 && length < sizeof(wire));
  assert(nhrp_ha_auth_encode(&keys, &input, &metadata, wire, length) ==
         NHRP_HA_AUTH_OK);
  assert(nhrp_ha_auth_verify(&keys, &input, wire, length, &decoded, matched) ==
         NHRP_HA_AUTH_OK);
  assert(decoded.term == 7 && decoded.commit_index == 42);
  assert(strcmp(decoded.leader, "hub-primary") == 0);
  assert(memcmp(matched, keys.key[0].id, 8) == 0 ||
         memcmp(matched, keys.key[1].id, 8) == 0);

  wire[length - 1] ^= 1;
  assert(nhrp_ha_auth_verify(&keys, &input, wire, length, &decoded, matched) ==
         NHRP_HA_AUTH_OK);
  wire[length - 1 - 40] ^= 1;
  assert(nhrp_ha_auth_verify(&keys, &input, wire, length, &decoded, matched) ==
         NHRP_HA_AUTH_BAD_TAG);
  wire[length - 1] ^= 1;
  wire[length - 1 - 40] ^= 1;

  input.request_id_wire++;
  assert(nhrp_ha_auth_verify(&keys, &input, wire, length, &decoded, matched) ==
         NHRP_HA_AUTH_BAD_TAG);
  input.request_id_wire--;
  assert(nhrp_ha_auth_verify(&keys, &input, wire, length - 1, &decoded,
                             matched) == NHRP_HA_AUTH_BAD_METADATA);

  wrong_keys = keys;
  memset(wrong_keys.key[0].id, 0xa5, 8);
  memset(wrong_keys.key[1].id, 0x5a, 8);
  assert(nhrp_ha_auth_verify(&wrong_keys, &input, wire, length, &decoded,
                             matched) == NHRP_HA_AUTH_UNKNOWN_KEY);

  keys.key[1].present = 0;
  length = nhrp_ha_auth_encoded_size(&keys, &metadata);
  assert(nhrp_ha_auth_encode(&keys, &input, &metadata, wire, length) ==
         NHRP_HA_AUTH_OK);
  assert(nhrp_ha_auth_verify(&keys, &input, wire, length, &decoded, matched) ==
         NHRP_HA_AUTH_OK);

  fd = mkstemp(key_path);
  assert(fd >= 0);
  assert(write(fd, encoded_key, sizeof(encoded_key) - 1) ==
         (ssize_t)(sizeof(encoded_key) - 1));
  assert(close(fd) == 0);
  memset(&loaded_key, 0, sizeof(loaded_key));
  assert(nhrp_ha_auth_key_load(&loaded_key, key_path));
  assert(chmod(key_path, 0644) == 0);
  assert(!nhrp_ha_auth_key_load(&loaded_key, key_path));
  assert(chmod(key_path, 0600) == 0);
  fd = open(key_path, O_WRONLY);
  assert(fd >= 0);
  assert(write(fd, "A", 1) == 1);
  assert(close(fd) == 0);
  assert(!nhrp_ha_auth_key_load(&loaded_key, key_path));
  assert(unlink(key_path) == 0);
  nhrp_ha_auth_key_clear(&loaded_key);

  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_auth_keys_clear(&wrong_keys);
  puts("HA authentication tests passed");
  return 0;
}
