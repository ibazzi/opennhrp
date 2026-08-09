#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nhrp_ha_seen.h"

int main(void) {
  struct nhrp_ha_auth_keys keys;
  struct nhrp_ha_auth_keys rotated_keys;
  struct nhrp_ha_seen_state input;
  struct nhrp_ha_seen_state output;
  uint8_t psk[32];
  uint8_t next_psk[32];
  uint8_t wrong_cluster[16];
  char path[] = "/tmp/opennhrp-ha-seen-test.XXXXXX";
  int fd;

  memset(&keys, 0, sizeof(keys));
  memset(psk, 0x33, sizeof(psk));
  memset(next_psk, 0x44, sizeof(next_psk));
  assert(nhrp_ha_auth_key_from_bytes(&keys.key[0], psk));
  assert(nhrp_ha_auth_key_from_bytes(&keys.key[1], next_psk));
  memset(&input, 0, sizeof(input));
  memcpy(input.cluster_id, "0123456789abcdef", 16);
  input.term = 9;
  input.commit_index = 27;
  strcpy(input.leader, "hub-backup1");
  memcpy(input.key_id, keys.key[0].id, 8);

  fd = mkstemp(path);
  assert(fd >= 0);
  close(fd);
  assert(unlink(path) == 0);
  assert(nhrp_ha_seen_load(path, &keys, input.cluster_id, &output) == 1);
  assert(output.term == 0);
  assert(nhrp_ha_seen_save(path, &keys, &input));
  assert(nhrp_ha_seen_load(path, &keys, input.cluster_id, &output) == 1);
  assert(output.term == 9 && output.commit_index == 27);
  assert(strcmp(output.leader, "hub-backup1") == 0);

  memset(&rotated_keys, 0, sizeof(rotated_keys));
  rotated_keys.key[0] = keys.key[1];
  assert(nhrp_ha_seen_load(path, &rotated_keys, input.cluster_id, &output) ==
         1);
  assert(memcmp(output.key_id, rotated_keys.key[0].id, 8) == 0);
  memcpy(wrong_cluster, input.cluster_id, sizeof(wrong_cluster));
  wrong_cluster[0] ^= 1;
  assert(nhrp_ha_seen_load(path, &rotated_keys, wrong_cluster, &output) == 0);

  assert(chmod(path, 0644) == 0);
  assert(nhrp_ha_seen_load(path, &rotated_keys, input.cluster_id, &output) ==
         0);
  assert(chmod(path, 0600) == 0);

  fd = open(path, O_WRONLY);
  assert(fd >= 0);
  assert(lseek(fd, 0, SEEK_SET) == 0);
  assert(write(fd, "x", 1) == 1);
  close(fd);
  assert(nhrp_ha_seen_load(path, &keys, input.cluster_id, &output) == 0);
  assert(unlink(path) == 0);
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_auth_keys_clear(&rotated_keys);
  puts("HA seen-state tests passed");
  return 0;
}
