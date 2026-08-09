#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nhrp_ha_control.h"

int main(void) {
  struct nhrp_ha_auth_keys keys;
  struct nhrp_ha_auth_keys rotated;
  struct nhrp_ha_control_frame input;
  struct nhrp_ha_control_frame output;
  uint8_t current[32];
  uint8_t next[32];
  uint8_t matched[8];
  uint8_t *wire;
  size_t size;

  memset(&keys, 0, sizeof(keys));
  memset(current, 0x51, sizeof(current));
  memset(next, 0x52, sizeof(next));
  assert(nhrp_ha_auth_key_from_bytes(&keys.key[0], current));
  assert(nhrp_ha_auth_key_from_bytes(&keys.key[1], next));
  memset(&input, 0, sizeof(input));
  input.type = NHRP_HA_CONTROL_SNAPSHOT;
  memcpy(input.cluster_id, "0123456789abcdef", 16);
  input.term = 7;
  input.index = 42;
  input.ack_index = 40;
  input.nonce = 0x123456789abcdef0ULL;
  strcpy(input.sender, "hub-primary");
  input.payload = (const uint8_t *)"registration-snapshot";
  input.payload_length = strlen((const char *)input.payload);
  size = nhrp_ha_control_encoded_size(&keys, &input);
  assert(size > 0 && size < NHRP_HA_CONTROL_MAX_FRAME);
  wire = malloc(size);
  assert(wire != NULL);
  assert(nhrp_ha_control_encode(&keys, &input, wire, size) ==
         NHRP_HA_CONTROL_OK);
  assert(nhrp_ha_control_decode(&keys, wire, size, &output, matched) ==
         NHRP_HA_CONTROL_OK);
  assert(output.type == input.type && output.term == 7 && output.index == 42);
  assert(output.ack_index == 40 && output.nonce == input.nonce);
  assert(strcmp(output.sender, "hub-primary") == 0);
  assert(output.payload_length == input.payload_length);
  assert(memcmp(output.payload, input.payload, input.payload_length) == 0);
  memset(&rotated, 0, sizeof(rotated));
  rotated.key[0] = keys.key[1];
  assert(nhrp_ha_control_decode(&rotated, wire, size, &output, matched) ==
         NHRP_HA_CONTROL_OK);
  assert(memcmp(matched, rotated.key[0].id, 8) == 0);

  wire[size - 1] ^= 1;
  assert(nhrp_ha_control_decode(&keys, wire, size, &output, matched) ==
         NHRP_HA_CONTROL_BAD_TAG);
  wire[size - 1] ^= 1;
  wire[3] ^= 1;
  assert(nhrp_ha_control_decode(&keys, wire, size, &output, matched) ==
         NHRP_HA_CONTROL_BAD_HEADER);
  assert(nhrp_ha_control_decode(&keys, wire, 12, &output, matched) ==
         NHRP_HA_CONTROL_TRUNCATED);
  assert(nhrp_ha_control_sequence(7, NHRP_HA_CONTROL_DELTA, 8) ==
         NHRP_HA_CONTROL_SEQUENCE_APPLY);
  assert(nhrp_ha_control_sequence(7, NHRP_HA_CONTROL_DELTA, 9) ==
         NHRP_HA_CONTROL_SEQUENCE_RESYNC);
  assert(nhrp_ha_control_sequence(7, NHRP_HA_CONTROL_DELTA, 6) ==
         NHRP_HA_CONTROL_SEQUENCE_IGNORE);
  assert(nhrp_ha_control_sequence(7, NHRP_HA_CONTROL_SNAPSHOT, 6) ==
         NHRP_HA_CONTROL_SEQUENCE_IGNORE);
  assert(nhrp_ha_control_sequence(7, NHRP_HA_CONTROL_SNAPSHOT, 9) ==
         NHRP_HA_CONTROL_SEQUENCE_APPLY);
  input.type = NHRP_HA_CONTROL_DESTROY;
  input.payload = NULL;
  input.payload_length = 0;
  assert(nhrp_ha_control_encoded_size(&keys, &input) > 0);

  free(wire);
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_auth_keys_clear(&rotated);
  puts("HA control frame tests passed");
  return 0;
}
