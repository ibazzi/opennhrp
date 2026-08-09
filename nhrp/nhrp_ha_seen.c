/* nhrp_ha_seen.c - Persistent highest-seen OpenNHRP HA term */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nhrp_ha_seen.h"

#define SEEN_MAGIC "NHST"
#define SEEN_VERSION 1

struct nhrp_ha_seen_disk {
  uint8_t magic[4];
  uint8_t version;
  uint8_t tag_count;
  uint8_t reserved[2];
  uint8_t cluster_id[16];
  uint64_t term;
  uint64_t commit_index;
  uint8_t leader_length;
  uint8_t reserved2[7];
  char leader[64];
  struct {
    uint8_t key_id[8];
    uint8_t tag[32];
  } tags[NHRP_HA_AUTH_MAX_KEYS];
} __attribute__((packed));

static const struct nhrp_ha_auth_key *
find_key(const struct nhrp_ha_auth_keys *keys, const uint8_t id[8]) {
  size_t i;

  for (i = 0; i < NHRP_HA_AUTH_MAX_KEYS; i++)
    if (keys->key[i].present && CRYPTO_memcmp(keys->key[i].id, id, 8) == 0)
      return &keys->key[i];
  return NULL;
}

static int state_tag(const struct nhrp_ha_seen_disk *disk,
                     const struct nhrp_ha_auth_key *key,
                     const uint8_t key_id[8], uint8_t tag[32]) {
  uint8_t authenticated[offsetof(struct nhrp_ha_seen_disk, tags) + 8];
  int ok;

  memcpy(authenticated, disk, offsetof(struct nhrp_ha_seen_disk, tags));
  memcpy(authenticated + offsetof(struct nhrp_ha_seen_disk, tags), key_id, 8);
  ok = nhrp_ha_auth_hmac(key->state_key, authenticated, sizeof(authenticated),
                         tag);
  OPENSSL_cleanse(authenticated, sizeof(authenticated));
  return ok;
}

int nhrp_ha_seen_load(const char *path, const struct nhrp_ha_auth_keys *keys,
                      const uint8_t cluster_id[16],
                      struct nhrp_ha_seen_state *state) {
  struct nhrp_ha_seen_disk disk;
  uint8_t expected[32];
  struct stat status;
  ssize_t length;
  uint8_t trailing;
  static const uint8_t zero_reserved2[7];
  int fd;
  int ok = 0;
  size_t i;

  memset(state, 0, sizeof(*state));
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return errno == ENOENT ? 1 : 0;
  if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      (status.st_mode & 077) != 0 || status.st_uid != geteuid())
    goto done;
  length = read(fd, &disk, sizeof(disk));
  if (length != sizeof(disk) || memcmp(disk.magic, SEEN_MAGIC, 4) != 0 ||
      disk.version != SEEN_VERSION || disk.tag_count == 0 ||
      disk.tag_count > NHRP_HA_AUTH_MAX_KEYS || disk.reserved[0] != 0 ||
      disk.reserved[1] != 0 || disk.leader_length == 0 ||
      disk.leader_length > NHRP_HA_AUTH_LEADER_MAX ||
      memcmp(disk.reserved2, zero_reserved2, sizeof(zero_reserved2)) != 0 ||
      read(fd, &trailing, 1) != 0 ||
      (cluster_id != NULL && memcmp(disk.cluster_id, cluster_id, 16) != 0))
    goto done;
  if (disk.tag_count == 2 &&
      CRYPTO_memcmp(disk.tags[0].key_id, disk.tags[1].key_id, 8) == 0)
    goto done;
  for (i = 0; i < disk.tag_count; i++) {
    const struct nhrp_ha_auth_key *key = find_key(keys, disk.tags[i].key_id);

    if (key != NULL && state_tag(&disk, key, disk.tags[i].key_id, expected) &&
        CRYPTO_memcmp(expected, disk.tags[i].tag, sizeof(expected)) == 0)
      break;
  }
  if (i == disk.tag_count)
    goto done;
  memcpy(state->cluster_id, disk.cluster_id, 16);
  state->term = be64toh(disk.term);
  state->commit_index = be64toh(disk.commit_index);
  memcpy(state->leader, disk.leader, disk.leader_length);
  state->leader[disk.leader_length] = 0;
  memcpy(state->key_id, disk.tags[i].key_id, 8);
  ok = state->term != 0;

done:
  OPENSSL_cleanse(expected, sizeof(expected));
  OPENSSL_cleanse(&disk, sizeof(disk));
  close(fd);
  return ok;
}

int nhrp_ha_seen_save(const char *path, const struct nhrp_ha_auth_keys *keys,
                      const struct nhrp_ha_seen_state *state) {
  struct nhrp_ha_seen_disk disk;
  size_t leader_length = strlen(state->leader);
  size_t i;
  size_t tag_index = 0;
  int ok = 0;

  if (state->term == 0 || leader_length == 0 ||
      leader_length > NHRP_HA_AUTH_LEADER_MAX)
    return 0;
  memset(&disk, 0, sizeof(disk));
  memcpy(disk.magic, SEEN_MAGIC, 4);
  disk.version = SEEN_VERSION;
  memcpy(disk.cluster_id, state->cluster_id, 16);
  disk.term = htobe64(state->term);
  disk.commit_index = htobe64(state->commit_index);
  disk.leader_length = leader_length;
  memcpy(disk.leader, state->leader, leader_length);
  for (i = 0; i < NHRP_HA_AUTH_MAX_KEYS; i++)
    if (keys->key[i].present)
      disk.tag_count++;
  if (disk.tag_count == 0)
    goto done;
  for (i = 0; i < NHRP_HA_AUTH_MAX_KEYS; i++) {
    if (!keys->key[i].present)
      continue;
    memcpy(disk.tags[tag_index].key_id, keys->key[i].id, 8);
    if (!state_tag(&disk, &keys->key[i], disk.tags[tag_index].key_id,
                   disk.tags[tag_index].tag))
      goto done;
    tag_index++;
  }
  ok = nhrp_ha_secure_file_write(path, &disk, sizeof(disk));

done:
  OPENSSL_cleanse(&disk, sizeof(disk));
  return ok;
}
