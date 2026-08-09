#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nhrp_ha_store.h"

int main(void) {
  struct nhrp_ha_auth_keys keys;
  struct nhrp_ha_auth_keys rotated;
  struct nhrp_ha_store_record input;
  struct nhrp_ha_store_record output;
  uint8_t current[32];
  uint8_t next[32];
  char path[] = "/tmp/opennhrp-ha-store-test.XXXXXX";
  int fd;

  memset(&keys, 0, sizeof(keys));
  memset(current, 0x61, sizeof(current));
  memset(next, 0x62, sizeof(next));
  assert(nhrp_ha_auth_key_from_bytes(&keys.key[0], current));
  assert(nhrp_ha_auth_key_from_bytes(&keys.key[1], next));
  memset(&input, 0, sizeof(input));
  memcpy(input.cluster_id, "0123456789abcdef", 16);
  input.term = 11;
  input.index = 87;
  strcpy(input.leader, "hub-primary");
  input.payload = (uint8_t *)"snapshot-data";
  input.payload_length = strlen((char *)input.payload);
  fd = mkstemp(path);
  assert(fd >= 0);
  close(fd);
  assert(unlink(path) == 0);
  assert(nhrp_ha_store_save(path, &keys, &input));
  assert(nhrp_ha_store_load(path, &keys, input.cluster_id, &output));
  assert(output.term == 11 && output.index == 87);
  assert(strcmp(output.leader, "hub-primary") == 0);
  assert(output.payload_length == input.payload_length);
  assert(memcmp(output.payload, input.payload, input.payload_length) == 0);
  nhrp_ha_store_record_clear(&output);

  memset(&rotated, 0, sizeof(rotated));
  rotated.key[0] = keys.key[1];
  assert(nhrp_ha_store_load(path, &rotated, input.cluster_id, &output));
  assert(memcmp(output.key_id, rotated.key[0].id, 8) == 0);
  nhrp_ha_store_record_clear(&output);

  fd = open(path, O_WRONLY);
  assert(fd >= 0);
  assert(lseek(fd, 4, SEEK_SET) == 4);
  assert(write(fd, "x", 1) == 1);
  close(fd);
  assert(!nhrp_ha_store_load(path, &keys, input.cluster_id, &output));
  assert(unlink(path) == 0);
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_auth_keys_clear(&rotated);
  puts("HA snapshot store tests passed");
  return 0;
}
