/* nhrp_ha_auth.c - HMAC authentication for OpenNHRP HA messages */

#include <arpa/inet.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nhrp_ha_auth.h"

#define AUTH_HEADER_SIZE 40
#define AUTH_TAG_ENTRY_SIZE (NHRP_HA_AUTH_KEY_ID_SIZE + NHRP_HA_AUTH_TAG_SIZE)
#define AUTH_CANONICAL_MAX 4096

static const uint8_t hkdf_salt[] = "OpenNHRP-HA-HKDF-v1";
static const uint8_t auth_domain[] = "OpenNHRP-HA-AUTH-v1";

static int hmac_sha256(const uint8_t *key, size_t key_length,
                       const uint8_t *data, size_t data_length,
                       uint8_t output[32]) {
  unsigned int length = 0;

  return HMAC(EVP_sha256(), key, (int)key_length, data, data_length, output,
              &length) != NULL &&
         length == 32;
}

int nhrp_ha_auth_hmac(const uint8_t key[32], const void *data, size_t length,
                      uint8_t output[32]) {
  return hmac_sha256(key, 32, data, length, output);
}

static int write_all(int fd, const void *data, size_t length) {
  const uint8_t *position = data;

  while (length != 0) {
    ssize_t written = write(fd, position, length);

    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return 0;
    position += written;
    length -= written;
  }
  return 1;
}

static int fsync_parent(const char *path) {
  char parent[4096];
  char *slash;
  int fd;
  int ok;

  if (strlen(path) >= sizeof(parent))
    return 0;
  snprintf(parent, sizeof(parent), "%s", path);
  slash = strrchr(parent, '/');
  if (slash == NULL)
    snprintf(parent, sizeof(parent), ".");
  else if (slash == parent)
    slash[1] = 0;
  else
    *slash = 0;
  fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0)
    return 0;
  ok = fsync(fd) == 0;
  close(fd);
  return ok;
}

int nhrp_ha_secure_file_write(const char *path, const void *data,
                              size_t length) {
  char temporary[4096];
  int fd = -1;
  int ok = 0;

  if (strlen(path) >= sizeof(temporary) - 32 ||
      snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
               (long)getpid()) >= (int)sizeof(temporary))
    return 0;
  fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
  if (fd < 0 || !write_all(fd, data, length) || fsync(fd) != 0 ||
      close(fd) != 0) {
    fd = -1;
    goto done;
  }
  fd = -1;
  if (rename(temporary, path) != 0 || !fsync_parent(path))
    goto done;
  ok = 1;

done:
  if (fd >= 0)
    close(fd);
  if (!ok)
    unlink(temporary);
  return ok;
}

static int derive_key(const uint8_t psk[32], const char *label,
                      uint8_t output[32]) {
  uint8_t prk[32];
  uint8_t expand[128];
  size_t label_length = strlen(label);

  if (label_length + 1 > sizeof(expand) ||
      !hmac_sha256(hkdf_salt, sizeof(hkdf_salt) - 1, psk, 32, prk))
    return 0;
  memcpy(expand, label, label_length);
  expand[label_length] = 1;
  if (!hmac_sha256(prk, sizeof(prk), expand, label_length + 1, output)) {
    OPENSSL_cleanse(prk, sizeof(prk));
    return 0;
  }
  OPENSSL_cleanse(prk, sizeof(prk));
  OPENSSL_cleanse(expand, sizeof(expand));
  return 1;
}

int nhrp_ha_auth_key_from_bytes(struct nhrp_ha_auth_key *key,
                                const uint8_t psk[32]) {
  uint8_t digest[SHA256_DIGEST_LENGTH];

  memset(key, 0, sizeof(*key));
  if (SHA256(psk, 32, digest) == NULL ||
      !derive_key(psk, "opennhrp-ha/nhrp-auth/v1", key->nhrp_key) ||
      !derive_key(psk, "opennhrp-ha/control/v1", key->control_key) ||
      !derive_key(psk, "opennhrp-ha/state/v1", key->state_key)) {
    nhrp_ha_auth_key_clear(key);
    return 0;
  }
  memcpy(key->id, digest, sizeof(key->id));
  OPENSSL_cleanse(digest, sizeof(digest));
  key->present = 1;
  return 1;
}

static int hex_value(unsigned char character) {
  if (character >= '0' && character <= '9')
    return character - '0';
  if (character >= 'a' && character <= 'f')
    return character - 'a' + 10;
  return -1;
}

int nhrp_ha_auth_key_load(struct nhrp_ha_auth_key *key, const char *path) {
  uint8_t psk[32];
  char encoded[66];
  struct stat status;
  ssize_t length;
  size_t i;
  int fd;
  int ok = 0;

  nhrp_ha_auth_key_clear(key);
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      (status.st_mode & 077) != 0 || status.st_uid != geteuid())
    goto done;
  length = read(fd, encoded, sizeof(encoded));
  if (length != 64 && length != 65)
    goto done;
  if (length == 65 && encoded[64] != '\n')
    goto done;
  for (i = 0; i < sizeof(psk); i++) {
    int high = hex_value((unsigned char)encoded[i * 2]);
    int low = hex_value((unsigned char)encoded[i * 2 + 1]);

    if (high < 0 || low < 0)
      goto done;
    psk[i] = (uint8_t)((high << 4) | low);
  }
  ok = nhrp_ha_auth_key_from_bytes(key, psk);

done:
  OPENSSL_cleanse(psk, sizeof(psk));
  OPENSSL_cleanse(encoded, sizeof(encoded));
  close(fd);
  return ok;
}

void nhrp_ha_auth_key_clear(struct nhrp_ha_auth_key *key) {
  OPENSSL_cleanse(key, sizeof(*key));
}

void nhrp_ha_auth_keys_clear(struct nhrp_ha_auth_keys *keys) {
  OPENSSL_cleanse(keys, sizeof(*keys));
}

size_t nhrp_ha_auth_key_count(const struct nhrp_ha_auth_keys *keys) {
  size_t count = 0;
  size_t i;

  for (i = 0; i < NHRP_HA_AUTH_MAX_KEYS; i++)
    if (keys->key[i].present)
      count++;
  return count;
}

void nhrp_ha_auth_key_id_format(const uint8_t id[8], char output[17]) {
  static const char hex[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < 8; i++) {
    output[i * 2] = hex[id[i] >> 4];
    output[i * 2 + 1] = hex[id[i] & 15];
  }
  output[16] = 0;
}

size_t nhrp_ha_auth_encoded_size(const struct nhrp_ha_auth_keys *keys,
                                 const struct nhrp_ha_auth_metadata *metadata) {
  size_t count = nhrp_ha_auth_key_count(keys);
  size_t leader_length = strnlen(metadata->leader, sizeof(metadata->leader));

  if (count == 0 || leader_length == 0 ||
      leader_length >= sizeof(metadata->leader) || metadata->term == 0)
    return 0;
  return AUTH_HEADER_SIZE + leader_length + count * AUTH_TAG_ENTRY_SIZE;
}

static int append_bytes(uint8_t *buffer, size_t size, size_t *offset,
                        const void *data, size_t length) {
  if (length > size - *offset)
    return 0;
  memcpy(buffer + *offset, data, length);
  *offset += length;
  return 1;
}

static int canonical(const struct nhrp_ha_auth_input *input,
                     const uint8_t *auth_prefix, size_t auth_prefix_length,
                     const uint8_t key_id[8], uint8_t *buffer, size_t size,
                     size_t *length) {
  uint32_t wire_length;
  size_t offset = 0;

  wire_length = htonl(input->ha_payload_length);
  if (input->ha_payload == NULL || input->ha_payload_length == 0 ||
      input->ha_payload_length > UINT32_MAX ||
      !append_bytes(buffer, size, &offset, auth_domain,
                    sizeof(auth_domain) - 1) ||
      !append_bytes(buffer, size, &offset, &input->packet_type, 1) ||
      !append_bytes(buffer, size, &offset, &input->request_id_wire, 4) ||
      !append_bytes(buffer, size, &offset, input->src_protocol, 4) ||
      !append_bytes(buffer, size, &offset, input->dst_protocol, 4) ||
      !append_bytes(buffer, size, &offset, &wire_length, sizeof(wire_length)) ||
      !append_bytes(buffer, size, &offset, input->ha_payload,
                    input->ha_payload_length) ||
      !append_bytes(buffer, size, &offset, auth_prefix, auth_prefix_length) ||
      !append_bytes(buffer, size, &offset, key_id, 8))
    return 0;
  *length = offset;
  return 1;
}

enum nhrp_ha_auth_result
nhrp_ha_auth_encode(const struct nhrp_ha_auth_keys *keys,
                    const struct nhrp_ha_auth_input *input,
                    const struct nhrp_ha_auth_metadata *metadata, uint8_t *wire,
                    size_t wire_size) {
  uint8_t canonical_data[AUTH_CANONICAL_MAX];
  uint16_t wire16;
  uint64_t wire64;
  size_t canonical_length;
  size_t leader_length = strlen(metadata->leader);
  size_t encoded_size = nhrp_ha_auth_encoded_size(keys, metadata);
  size_t offset;
  size_t i;

  if (encoded_size == 0)
    return NHRP_HA_AUTH_BAD_METADATA;
  if (wire_size < encoded_size)
    return NHRP_HA_AUTH_TRUNCATED;
  memset(wire, 0, encoded_size);
  wire[0] = NHRP_HA_AUTH_VERSION;
  wire[1] = NHRP_HA_AUTH_ALGORITHM_HMAC_SHA256;
  wire[2] = nhrp_ha_auth_key_count(keys);
  wire[3] = 0;
  memcpy(&wire[4], metadata->cluster_id, 16);
  wire64 = htobe64(metadata->term);
  memcpy(&wire[20], &wire64, sizeof(wire64));
  wire64 = htobe64(metadata->commit_index);
  memcpy(&wire[28], &wire64, sizeof(wire64));
  wire16 = htons(leader_length);
  memcpy(&wire[36], &wire16, sizeof(wire16));
  memcpy(&wire[AUTH_HEADER_SIZE], metadata->leader, leader_length);
  offset = AUTH_HEADER_SIZE + leader_length;

  for (i = 0; i < NHRP_HA_AUTH_MAX_KEYS; i++) {
    if (!keys->key[i].present)
      continue;
    memcpy(&wire[offset], keys->key[i].id, 8);
    if (!canonical(input, wire, AUTH_HEADER_SIZE + leader_length,
                   keys->key[i].id, canonical_data, sizeof(canonical_data),
                   &canonical_length) ||
        !hmac_sha256(keys->key[i].nhrp_key, 32, canonical_data,
                     canonical_length, &wire[offset + 8])) {
      OPENSSL_cleanse(canonical_data, sizeof(canonical_data));
      return NHRP_HA_AUTH_BAD_METADATA;
    }
    offset += AUTH_TAG_ENTRY_SIZE;
  }
  OPENSSL_cleanse(canonical_data, sizeof(canonical_data));
  return NHRP_HA_AUTH_OK;
}

enum nhrp_ha_auth_result
nhrp_ha_auth_verify(const struct nhrp_ha_auth_keys *keys,
                    const struct nhrp_ha_auth_input *input, const uint8_t *wire,
                    size_t wire_size, struct nhrp_ha_auth_metadata *metadata,
                    uint8_t matched_key_id[8]) {
  uint8_t canonical_data[AUTH_CANONICAL_MAX];
  uint8_t expected[32];
  uint16_t wire16;
  uint64_t wire64;
  size_t canonical_length;
  size_t leader_length;
  size_t expected_size;
  size_t offset;
  size_t i;
  size_t j;
  int known_key = 0;

  memset(metadata, 0, sizeof(*metadata));
  if (wire_size < AUTH_HEADER_SIZE)
    return NHRP_HA_AUTH_TRUNCATED;
  if (wire[0] != NHRP_HA_AUTH_VERSION ||
      wire[1] != NHRP_HA_AUTH_ALGORITHM_HMAC_SHA256 || wire[2] == 0 ||
      wire[2] > NHRP_HA_AUTH_MAX_KEYS || wire[3] != 0 || wire[38] != 0 ||
      wire[39] != 0)
    return NHRP_HA_AUTH_BAD_HEADER;
  memcpy(&wire16, &wire[36], sizeof(wire16));
  leader_length = ntohs(wire16);
  expected_size =
      AUTH_HEADER_SIZE + leader_length + wire[2] * AUTH_TAG_ENTRY_SIZE;
  if (leader_length == 0 || leader_length > NHRP_HA_AUTH_LEADER_MAX ||
      expected_size != wire_size)
    return NHRP_HA_AUTH_BAD_METADATA;
  memcpy(metadata->cluster_id, &wire[4], 16);
  memcpy(&wire64, &wire[20], sizeof(wire64));
  metadata->term = be64toh(wire64);
  memcpy(&wire64, &wire[28], sizeof(wire64));
  metadata->commit_index = be64toh(wire64);
  memcpy(metadata->leader, &wire[AUTH_HEADER_SIZE], leader_length);
  metadata->leader[leader_length] = 0;
  if (metadata->term == 0)
    return NHRP_HA_AUTH_BAD_METADATA;
  offset = AUTH_HEADER_SIZE + leader_length;

  for (i = 0; i < wire[2]; i++, offset += AUTH_TAG_ENTRY_SIZE) {
    for (j = 0; j < NHRP_HA_AUTH_MAX_KEYS; j++) {
      if (!keys->key[j].present ||
          CRYPTO_memcmp(keys->key[j].id, &wire[offset], 8) != 0)
        continue;
      known_key = 1;
      if (!canonical(input, wire, AUTH_HEADER_SIZE + leader_length,
                     &wire[offset], canonical_data, sizeof(canonical_data),
                     &canonical_length) ||
          !hmac_sha256(keys->key[j].nhrp_key, 32, canonical_data,
                       canonical_length, expected))
        continue;
      if (CRYPTO_memcmp(expected, &wire[offset + 8], 32) == 0) {
        memcpy(matched_key_id, &wire[offset], 8);
        OPENSSL_cleanse(expected, sizeof(expected));
        OPENSSL_cleanse(canonical_data, sizeof(canonical_data));
        return NHRP_HA_AUTH_OK;
      }
    }
  }
  OPENSSL_cleanse(expected, sizeof(expected));
  OPENSSL_cleanse(canonical_data, sizeof(canonical_data));
  return known_key ? NHRP_HA_AUTH_BAD_TAG : NHRP_HA_AUTH_UNKNOWN_KEY;
}
