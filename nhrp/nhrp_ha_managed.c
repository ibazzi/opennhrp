/* nhrp_ha_managed.c - Managed OpenNHRP HA cluster state */

#include <arpa/inet.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "nhrp_ha_managed.h"

#define MANAGED_STATE_MAGIC "ONHM"
#define MANAGED_STATE_VERSION 1
#define MANAGED_INVITE_MAGIC "ONHI"
#define MANAGED_INVITE_VERSION 1
#define MANAGED_INVITE_PREFIX "opennhrp-ha1:"
#define MANAGED_INVITE_PREFIX_SIZE 13
#define MANAGED_TAG_SIZE (NHRP_HA_AUTH_KEY_ID_SIZE + NHRP_HA_AUTH_TAG_SIZE)

struct managed_member_wire {
  char member[64];
  uint32_t addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  uint8_t address_count;
  uint8_t configured_address_count;
  uint8_t reserved_address[2];
  uint32_t priority;
  uint8_t state;
  uint8_t reserved[3];
  uint8_t public_key[32];
  uint64_t match_index;
  uint8_t digest[32];
} __attribute__((packed));

struct managed_invite_wire {
  uint8_t id[16];
  uint8_t secret_hash[32];
  char member[64];
  uint32_t priority;
  uint64_t expires_at;
  uint8_t state;
  uint8_t reserved[7];
  uint8_t claimed_key[32];
} __attribute__((packed));

struct managed_state_wire {
  uint8_t magic[4];
  uint8_t version;
  uint8_t key_count;
  uint8_t prefix_length;
  uint8_t reserved;
  uint8_t cluster_id[16];
  char interface[16];
  uint32_t protocol_address;
  char local_member[64];
  char primary_member[64];
  char leader[64];
  uint64_t term;
  uint64_t commit_index;
  uint64_t manifest_revision;
  uint16_t port;
  uint16_t member_count;
  uint16_t invite_count;
  uint16_t reserved2;
  struct managed_member_wire members[NHRP_HA_MANAGED_MAX_MEMBERS];
  struct managed_invite_wire invites[NHRP_HA_MANAGED_MAX_INVITES];
} __attribute__((packed));

struct managed_invite_token_wire {
  uint8_t magic[4];
  uint8_t version;
  uint8_t prefix_length;
  uint8_t reserved[2];
  uint8_t cluster_id[16];
  uint8_t invite_id[16];
  uint32_t protocol_address;
  uint32_t leader_addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  uint8_t leader_address_count;
  uint8_t reserved_address[3];
  uint16_t leader_port;
  uint16_t reserved2;
  uint32_t priority;
  uint64_t expires_at;
  char member[64];
  uint8_t leader_public_key[32];
  uint8_t secret[32];
  uint8_t signature[64];
} __attribute__((packed));

static int read_all(int fd, void *data, size_t length) {
  uint8_t *position = data;

  while (length != 0) {
    ssize_t got = read(fd, position, length);

    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return 0;
    position += got;
    length -= got;
  }
  return 1;
}

static int secure_regular(int fd, struct stat *status) {
  return fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
         (status->st_mode & 077) == 0 && status->st_uid == geteuid();
}

static int ensure_directory(const char *path) {
  char current[4096];
  char *position;
  struct stat status;

  if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(current))
    return 0;
  snprintf(current, sizeof(current), "%s", path);
  for (position = current + 1; *position != 0; position++) {
    if (*position != '/')
      continue;
    *position = 0;
    if (mkdir(current, 0700) != 0 && errno != EEXIST)
      return 0;
    *position = '/';
  }
  if (mkdir(path, 0700) != 0 && errno != EEXIST)
    return 0;
  return lstat(path, &status) == 0 && S_ISDIR(status.st_mode) &&
         status.st_uid == geteuid() && (status.st_mode & 022) == 0;
}

int nhrp_ha_managed_member_valid(const char *member) {
  size_t length;
  size_t i;

  if (member == NULL)
    return 0;
  length = strlen(member);
  if (length == 0 || length > NHRP_HA_MANAGED_MEMBER_MAX)
    return 0;
  for (i = 0; i < length; i++)
    if (!isalnum((unsigned char)member[i]) && member[i] != '-' &&
        member[i] != '_' && member[i] != '.')
      return 0;
  return 1;
}

int nhrp_ha_managed_endpoints_valid(const struct in_addr *addresses,
                                    size_t count) {
  size_t i;

  if (count > NHRP_HA_MANAGED_MAX_ENDPOINTS ||
      (count != 0 && addresses == NULL))
    return 0;
  for (i = 0; i < count; i++) {
    uint32_t host = ntohl(addresses[i].s_addr);
    size_t j;

    if (host == INADDR_ANY || (host & 0xf0000000U) == 0xe0000000U)
      return 0;
    for (j = 0; j < i; j++)
      if (addresses[j].s_addr == addresses[i].s_addr)
        return 0;
  }
  return 1;
}

int nhrp_ha_managed_paths(const char *directory, char *state_path,
                          size_t state_size, char *keys_path, size_t keys_size,
                          char *identity_path, size_t identity_size) {
  return directory != NULL && directory[0] != 0 &&
         snprintf(state_path, state_size, "%s/cluster.state", directory) <
             (int)state_size &&
         snprintf(keys_path, keys_size, "%s/keys", directory) <
             (int)keys_size &&
         snprintf(identity_path, identity_size, "%s/identity.key", directory) <
             (int)identity_size;
}

static int hex_value(unsigned char character) {
  if (character >= '0' && character <= '9')
    return character - '0';
  if (character >= 'a' && character <= 'f')
    return character - 'a' + 10;
  return -1;
}

static void hex_encode(const uint8_t *input, size_t length, char *output) {
  static const char digits[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < length; i++) {
    output[i * 2] = digits[input[i] >> 4];
    output[i * 2 + 1] = digits[input[i] & 15];
  }
  output[length * 2] = 0;
}

static int hex_decode(const char *input, size_t length, uint8_t *output) {
  size_t i;

  for (i = 0; i < length; i++) {
    int high = hex_value((unsigned char)input[i * 2]);
    int low = hex_value((unsigned char)input[i * 2 + 1]);

    if (high < 0 || low < 0)
      return 0;
    output[i] = (uint8_t)((high << 4) | low);
  }
  return 1;
}

int nhrp_ha_managed_keyring_load(const char *path,
                                 struct nhrp_ha_auth_keys *keys) {
  char content[160];
  struct stat status;
  uint8_t psk[32];
  ssize_t length;
  int fd;
  int key_count;
  int ok = 0;

  memset(keys, 0, sizeof(*keys));
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  if (!secure_regular(fd, &status) ||
      (length = read(fd, content, sizeof(content) - 1)) <= 0 ||
      length >= (ssize_t)sizeof(content) - 1)
    goto done;
  if (length == 73 && memcmp(content, "current ", 8) == 0 &&
      content[72] == '\n')
    key_count = 1;
  else if (length == 143 && memcmp(content, "current ", 8) == 0 &&
           content[72] == '\n' && memcmp(content + 73, "next ", 5) == 0 &&
           content[142] == '\n')
    key_count = 2;
  else
    goto done;
  if (!hex_decode(content + 8, 32, psk) ||
      !nhrp_ha_auth_key_from_bytes(&keys->key[0], psk))
    goto done;
  OPENSSL_cleanse(psk, sizeof(psk));
  if (key_count == 2 && (!hex_decode(content + 78, 32, psk) ||
                         !nhrp_ha_auth_key_from_bytes(&keys->key[1], psk) ||
                         CRYPTO_memcmp(keys->key[0].id, keys->key[1].id,
                                       NHRP_HA_AUTH_KEY_ID_SIZE) == 0))
    goto done;
  ok = 1;

done:
  if (!ok)
    nhrp_ha_auth_keys_clear(keys);
  OPENSSL_cleanse(psk, sizeof(psk));
  OPENSSL_cleanse(content, sizeof(content));
  close(fd);
  return ok;
}

int nhrp_ha_managed_keyring_generate(const char *path,
                                     struct nhrp_ha_auth_keys *keys) {
  uint8_t psk[32];
  char encoded[74];
  int ok = 0;

  if (access(path, F_OK) == 0 || RAND_bytes(psk, sizeof(psk)) != 1)
    goto done;
  memcpy(encoded, "current ", 8);
  hex_encode(psk, sizeof(psk), encoded + 8);
  encoded[72] = '\n';
  encoded[73] = 0;
  if (!nhrp_ha_secure_file_write(path, encoded, 73) ||
      !nhrp_ha_auth_key_from_bytes(&keys->key[0], psk))
    goto done;
  ok = 1;

done:
  OPENSSL_cleanse(psk, sizeof(psk));
  OPENSSL_cleanse(encoded, sizeof(encoded));
  return ok;
}

int nhrp_ha_managed_keyring_export(const char *source,
                                   const char *destination) {
  uint8_t buffer[256];
  struct stat status;
  ssize_t length;
  int fd;
  int ok = 0;

  if (access(destination, F_OK) == 0)
    return 0;
  fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  if (!secure_regular(fd, &status) ||
      (length = read(fd, buffer, sizeof(buffer))) <= 0 ||
      length == (ssize_t)sizeof(buffer))
    goto done;
  ok = nhrp_ha_secure_file_write(destination, buffer, (size_t)length);

done:
  OPENSSL_cleanse(buffer, sizeof(buffer));
  close(fd);
  return ok;
}

int nhrp_ha_managed_keyring_read(const char *path, uint8_t *buffer, size_t size,
                                 size_t *length) {
  struct stat status;
  ssize_t got;
  int fd;

  if (buffer == NULL || size == 0 || length == NULL)
    return 0;
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  if (!secure_regular(fd, &status) || (got = read(fd, buffer, size)) <= 0 ||
      got == (ssize_t)size || read(fd, buffer + got, 1) != 0) {
    close(fd);
    return 0;
  }
  close(fd);
  *length = (size_t)got;
  return 1;
}

int nhrp_ha_managed_keyring_import(const char *path, const uint8_t *buffer,
                                   size_t length) {
  struct nhrp_ha_auth_keys keys;

  if (buffer == NULL || length == 0 || length >= 256 ||
      access(path, F_OK) == 0 ||
      !nhrp_ha_secure_file_write(path, buffer, length))
    return 0;
  if (!nhrp_ha_managed_keyring_load(path, &keys)) {
    unlink(path);
    return 0;
  }
  nhrp_ha_auth_keys_clear(&keys);
  return 1;
}

int nhrp_ha_managed_keyring_prepare_rotation(const char *path,
                                             struct nhrp_ha_auth_keys *keys) {
  struct nhrp_ha_auth_keys current_keys;
  uint8_t existing[256];
  uint8_t next[32];
  char next_hex[65];
  char output[160];
  size_t length;
  int output_length;
  int ok = 0;

  memset(&current_keys, 0, sizeof(current_keys));
  if (!nhrp_ha_managed_keyring_load(path, &current_keys) ||
      current_keys.key[1].present ||
      !nhrp_ha_managed_keyring_read(path, existing, sizeof(existing),
                                    &length) ||
      length != 73 || memcmp(existing, "current ", 8) != 0 ||
      existing[72] != '\n' || RAND_bytes(next, sizeof(next)) != 1)
    goto done;
  existing[length] = 0;
  hex_encode(next, sizeof(next), next_hex);
  output_length = snprintf(output, sizeof(output), "%.*snext %s\n", (int)length,
                           existing, next_hex);
  if (output_length <= 0 || output_length >= (int)sizeof(output) ||
      !nhrp_ha_secure_file_write(path, output, (size_t)output_length) ||
      !nhrp_ha_managed_keyring_load(path, keys))
    goto done;
  ok = 1;

done:
  nhrp_ha_auth_keys_clear(&current_keys);
  OPENSSL_cleanse(existing, sizeof(existing));
  OPENSSL_cleanse(next, sizeof(next));
  OPENSSL_cleanse(next_hex, sizeof(next_hex));
  OPENSSL_cleanse(output, sizeof(output));
  return ok;
}

int nhrp_ha_managed_keyring_commit_rotation(const char *path) {
  uint8_t existing[256];
  char next[65];
  char output[80];
  size_t length;
  int output_length;
  int ok = 0;

  memset(next, 0, sizeof(next));
  if (!nhrp_ha_managed_keyring_read(path, existing, sizeof(existing), &length))
    goto done;
  if (length != 143 || memcmp(existing, "current ", 8) != 0 ||
      existing[72] != '\n' || memcmp(existing + 73, "next ", 5) != 0 ||
      existing[142] != '\n')
    goto done;
  memcpy(next, existing + 78, 64);
  next[64] = 0;
  {
    uint8_t decoded[32];

    if (!hex_decode(next, 32, decoded)) {
      OPENSSL_cleanse(decoded, sizeof(decoded));
      goto done;
    }
    OPENSSL_cleanse(decoded, sizeof(decoded));
  }
  output_length = snprintf(output, sizeof(output), "current %s\n", next);
  if (output_length != 73 ||
      !nhrp_ha_secure_file_write(path, output, (size_t)output_length))
    goto done;
  ok = 1;

done:
  OPENSSL_cleanse(existing, sizeof(existing));
  OPENSSL_cleanse(next, sizeof(next));
  OPENSSL_cleanse(output, sizeof(output));
  return ok;
}

static int identity_load(const char *path, uint8_t private_key[32]) {
  char encoded[66];
  struct stat status;
  ssize_t length;
  int fd;
  int ok = 0;

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  if (!secure_regular(fd, &status) ||
      (length = read(fd, encoded, sizeof(encoded))) < 64 || length > 65 ||
      (length == 65 && encoded[64] != '\n') ||
      !hex_decode(encoded, 32, private_key))
    goto done;
  ok = 1;

done:
  OPENSSL_cleanse(encoded, sizeof(encoded));
  close(fd);
  return ok;
}

static EVP_PKEY *identity_key(const char *path, uint8_t private_key[32]) {
  if (!identity_load(path, private_key))
    return NULL;
  return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key, 32);
}

int nhrp_ha_managed_identity_public(const char *path, uint8_t public_key[32]) {
  uint8_t private_key[32];
  EVP_PKEY *key = identity_key(path, private_key);
  size_t length = 32;
  int ok = key != NULL &&
           EVP_PKEY_get_raw_public_key(key, public_key, &length) == 1 &&
           length == 32;

  EVP_PKEY_free(key);
  OPENSSL_cleanse(private_key, sizeof(private_key));
  return ok;
}

int nhrp_ha_managed_identity_generate(const char *path,
                                      uint8_t public_key[32]) {
  uint8_t private_key[32];
  char encoded[66];
  EVP_PKEY *key = NULL;
  size_t length = 32;
  int ok = 0;

  if (access(path, F_OK) == 0 || RAND_bytes(private_key, 32) != 1)
    goto done;
  key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key, 32);
  if (key == NULL ||
      EVP_PKEY_get_raw_public_key(key, public_key, &length) != 1 ||
      length != 32)
    goto done;
  hex_encode(private_key, 32, encoded);
  encoded[64] = '\n';
  encoded[65] = 0;
  ok = nhrp_ha_secure_file_write(path, encoded, 65);

done:
  EVP_PKEY_free(key);
  OPENSSL_cleanse(private_key, sizeof(private_key));
  OPENSSL_cleanse(encoded, sizeof(encoded));
  return ok;
}

int nhrp_ha_managed_identity_sign(const char *path, const void *data,
                                  size_t length, uint8_t signature[64]) {
  uint8_t private_key[32];
  EVP_PKEY *key = identity_key(path, private_key);
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  size_t signature_length = 64;
  int ok = key != NULL && context != NULL && data != NULL && length != 0 &&
           EVP_DigestSignInit(context, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestSign(context, signature, &signature_length, data,
                          length) == 1 &&
           signature_length == 64;

  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  OPENSSL_cleanse(private_key, sizeof(private_key));
  return ok;
}

int nhrp_ha_managed_identity_verify(const uint8_t public_key[32],
                                    const void *data, size_t length,
                                    const uint8_t signature[64]) {
  EVP_PKEY *key =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  int ok = key != NULL && context != NULL && data != NULL && length != 0 &&
           EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestVerify(context, signature, 64, data, length) == 1;

  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return ok;
}

static int state_validate(const struct nhrp_ha_managed_state *state) {
  static const uint8_t zero32[32];
  static const uint8_t zero16[16];
  size_t i;
  size_t j;
  int have_local = 0;
  int have_primary = 0;
  int have_leader = 0;

  if (CRYPTO_memcmp(state->cluster_id, zero16, sizeof(zero16)) == 0 ||
      state->interface[0] == 0 || strlen(state->interface) >= 16 ||
      state->protocol_address.s_addr == 0 || state->prefix_length > 32 ||
      !nhrp_ha_managed_member_valid(state->local_member) ||
      !nhrp_ha_managed_member_valid(state->primary_member) ||
      !nhrp_ha_managed_member_valid(state->leader) || state->term == 0 ||
      state->manifest_revision == 0 || state->port == 0 ||
      state->witness_mode > NHRP_HA_WITNESS_DISABLING ||
      state->member_count == 0 ||
      state->member_count > NHRP_HA_MANAGED_MAX_MEMBERS ||
      state->invite_count > NHRP_HA_MANAGED_MAX_INVITES)
    return 0;
  for (i = 0; i < state->member_count; i++) {
    const struct nhrp_ha_managed_member *member = &state->members[i];
    size_t address_index;

    if (!nhrp_ha_managed_member_valid(member->member) ||
        member->address_count == 0 ||
        !nhrp_ha_managed_endpoints_valid(member->addresses,
                                         member->address_count) ||
        member->configured_address_count > member->address_count ||
        member->address_count - member->configured_address_count > 1 ||
        member->priority == 0 || member->state < NHRP_HA_MANAGED_LEARNER ||
        member->state > NHRP_HA_MANAGED_DISABLED ||
        CRYPTO_memcmp(member->public_key, zero32, sizeof(zero32)) == 0)
      return 0;
    if (strcmp(member->member, state->local_member) == 0)
      have_local = 1;
    if (strcmp(member->member, state->primary_member) == 0)
      have_primary = 1;
    if (strcmp(member->member, state->leader) == 0 &&
        member->state == NHRP_HA_MANAGED_ACTIVE)
      have_leader = 1;
    for (address_index = 0; address_index < member->address_count;
         address_index++) {
      for (j = i + 1; j < state->member_count; j++) {
        size_t other;

        if (state->members[j].address_count > NHRP_HA_MANAGED_MAX_ENDPOINTS ||
            strcmp(member->member, state->members[j].member) == 0)
          return 0;
        for (other = 0; other < state->members[j].address_count; other++)
          if (member->addresses[address_index].s_addr ==
              state->members[j].addresses[other].s_addr)
            return 0;
      }
    }
  }
  if (!have_local || !have_primary || !have_leader)
    return 0;
  for (i = 0; i < state->invite_count; i++) {
    const struct nhrp_ha_managed_invite *invite = &state->invites[i];

    if (!nhrp_ha_managed_member_valid(invite->member) ||
        invite->priority == 0 || invite->expires_at <= 0 ||
        invite->state > NHRP_HA_MANAGED_INVITE_REVOKED ||
        CRYPTO_memcmp(invite->id, zero16, sizeof(zero16)) == 0 ||
        CRYPTO_memcmp(invite->secret_hash, zero32, sizeof(zero32)) == 0)
      return 0;
    for (j = i + 1; j < state->invite_count; j++)
      if (CRYPTO_memcmp(invite->id, state->invites[j].id, 16) == 0 ||
          (invite->state != NHRP_HA_MANAGED_INVITE_REVOKED &&
           state->invites[j].state != NHRP_HA_MANAGED_INVITE_REVOKED &&
           strcmp(invite->member, state->invites[j].member) == 0))
        return 0;
  }
  return 1;
}

static void state_encode(const struct nhrp_ha_managed_state *state,
                         struct managed_state_wire *wire, uint8_t key_count) {
  size_t i;
  size_t j;

  memset(wire, 0, sizeof(*wire));
  memcpy(wire->magic, MANAGED_STATE_MAGIC, 4);
  wire->version = MANAGED_STATE_VERSION;
  wire->key_count = key_count;
  wire->prefix_length = state->prefix_length;
  wire->reserved = state->witness_mode;
  memcpy(wire->cluster_id, state->cluster_id, 16);
  snprintf(wire->interface, sizeof(wire->interface), "%s", state->interface);
  wire->protocol_address = state->protocol_address.s_addr;
  snprintf(wire->local_member, sizeof(wire->local_member), "%s",
           state->local_member);
  snprintf(wire->primary_member, sizeof(wire->primary_member), "%s",
           state->primary_member);
  snprintf(wire->leader, sizeof(wire->leader), "%s", state->leader);
  wire->term = htobe64(state->term);
  wire->commit_index = htobe64(state->commit_index);
  wire->manifest_revision = htobe64(state->manifest_revision);
  wire->port = htons(state->port);
  wire->member_count = htons((uint16_t)state->member_count);
  wire->invite_count = htons((uint16_t)state->invite_count);
  for (i = 0; i < state->member_count; i++) {
    const struct nhrp_ha_managed_member *input = &state->members[i];
    struct managed_member_wire *output = &wire->members[i];

    snprintf(output->member, sizeof(output->member), "%s", input->member);
    for (j = 0; j < input->address_count; j++)
      output->addresses[j] = input->addresses[j].s_addr;
    output->address_count = input->address_count;
    output->configured_address_count = input->configured_address_count;
    output->priority = htonl(input->priority);
    output->state = input->state;
    memcpy(output->public_key, input->public_key, 32);
    output->match_index = htobe64(input->match_index);
    memcpy(output->digest, input->digest, 32);
  }
  for (i = 0; i < state->invite_count; i++) {
    const struct nhrp_ha_managed_invite *input = &state->invites[i];
    struct managed_invite_wire *output = &wire->invites[i];

    memcpy(output->id, input->id, 16);
    memcpy(output->secret_hash, input->secret_hash, 32);
    snprintf(output->member, sizeof(output->member), "%s", input->member);
    output->priority = htonl(input->priority);
    output->expires_at = htobe64((uint64_t)input->expires_at);
    output->state = input->state;
    memcpy(output->claimed_key, input->claimed_key, 32);
  }
}

static int terminated(const char *value, size_t size) {
  return memchr(value, 0, size) != NULL;
}

static int state_decode(const struct managed_state_wire *wire,
                        struct nhrp_ha_managed_state *state) {
  size_t i;
  size_t j;

  memset(state, 0, sizeof(*state));
  if (memcmp(wire->magic, MANAGED_STATE_MAGIC, 4) != 0 ||
      wire->version != MANAGED_STATE_VERSION ||
      wire->reserved > NHRP_HA_WITNESS_DISABLING || wire->reserved2 != 0 ||
      !terminated(wire->interface, 16) || !terminated(wire->local_member, 64) ||
      !terminated(wire->primary_member, 64) || !terminated(wire->leader, 64))
    return 0;
  memcpy(state->cluster_id, wire->cluster_id, 16);
  snprintf(state->interface, sizeof(state->interface), "%s", wire->interface);
  state->protocol_address.s_addr = wire->protocol_address;
  state->prefix_length = wire->prefix_length;
  state->witness_mode = wire->reserved;
  snprintf(state->local_member, sizeof(state->local_member), "%s",
           wire->local_member);
  snprintf(state->primary_member, sizeof(state->primary_member), "%s",
           wire->primary_member);
  snprintf(state->leader, sizeof(state->leader), "%s", wire->leader);
  state->term = be64toh(wire->term);
  state->commit_index = be64toh(wire->commit_index);
  state->manifest_revision = be64toh(wire->manifest_revision);
  state->port = ntohs(wire->port);
  state->member_count = ntohs(wire->member_count);
  state->invite_count = ntohs(wire->invite_count);
  if (state->member_count > NHRP_HA_MANAGED_MAX_MEMBERS ||
      state->invite_count > NHRP_HA_MANAGED_MAX_INVITES)
    return 0;
  for (i = 0; i < state->member_count; i++) {
    const struct managed_member_wire *input = &wire->members[i];
    struct nhrp_ha_managed_member *output = &state->members[i];

    if (!terminated(input->member, 64))
      return 0;
    if (input->reserved_address[0] != 0 || input->reserved_address[1] != 0)
      return 0;
    if (input->address_count == 0 ||
        input->address_count > NHRP_HA_MANAGED_MAX_ENDPOINTS ||
        input->configured_address_count > input->address_count ||
        input->address_count - input->configured_address_count > 1)
      return 0;
    snprintf(output->member, sizeof(output->member), "%s", input->member);
    output->address_count = input->address_count;
    output->configured_address_count = input->configured_address_count;
    for (j = 0; j < output->address_count; j++)
      output->addresses[j].s_addr = input->addresses[j];
    output->priority = ntohl(input->priority);
    output->state = input->state;
    memcpy(output->public_key, input->public_key, 32);
    output->match_index = be64toh(input->match_index);
    memcpy(output->digest, input->digest, 32);
  }
  for (i = 0; i < state->invite_count; i++) {
    const struct managed_invite_wire *input = &wire->invites[i];
    struct nhrp_ha_managed_invite *output = &state->invites[i];

    if (!terminated(input->member, 64))
      return 0;
    memcpy(output->id, input->id, 16);
    memcpy(output->secret_hash, input->secret_hash, 32);
    snprintf(output->member, sizeof(output->member), "%s", input->member);
    output->priority = ntohl(input->priority);
    output->expires_at = (int64_t)be64toh(input->expires_at);
    output->state = input->state;
    memcpy(output->claimed_key, input->claimed_key, 32);
  }
  return state_validate(state);
}

size_t nhrp_ha_managed_state_encoded_size(void) {
  return sizeof(struct managed_state_wire);
}

int nhrp_ha_managed_state_encode(const struct nhrp_ha_managed_state *state,
                                 uint8_t *buffer, size_t size) {
  struct managed_state_wire wire;

  if (buffer == NULL || size != sizeof(wire) || !state_validate(state))
    return 0;
  state_encode(state, &wire, 0);
  memcpy(buffer, &wire, sizeof(wire));
  return 1;
}

int nhrp_ha_managed_state_decode(const uint8_t *buffer, size_t size,
                                 struct nhrp_ha_managed_state *state) {
  struct managed_state_wire wire;

  if (buffer == NULL || size != sizeof(wire))
    return 0;
  memcpy(&wire, buffer, sizeof(wire));
  return state_decode(&wire, state);
}

int nhrp_ha_managed_state_save(const char *path,
                               const struct nhrp_ha_auth_keys *keys,
                               const struct nhrp_ha_managed_state *state) {
  struct managed_state_wire wire;
  uint8_t output[sizeof(wire) + NHRP_HA_AUTH_MAX_KEYS * MANAGED_TAG_SIZE];
  size_t key_count = nhrp_ha_auth_key_count(keys);
  size_t offset = sizeof(wire);
  size_t i;
  int ok;

  if (!state_validate(state) || key_count == 0)
    return 0;
  state_encode(state, &wire, (uint8_t)key_count);
  memcpy(output, &wire, sizeof(wire));
  for (i = 0; i < NHRP_HA_AUTH_MAX_KEYS; i++) {
    if (!keys->key[i].present)
      continue;
    memcpy(output + offset, keys->key[i].id, NHRP_HA_AUTH_KEY_ID_SIZE);
    if (!nhrp_ha_auth_hmac(keys->key[i].state_key, &wire, sizeof(wire),
                           output + offset + NHRP_HA_AUTH_KEY_ID_SIZE)) {
      OPENSSL_cleanse(output, sizeof(output));
      return 0;
    }
    offset += MANAGED_TAG_SIZE;
  }
  ok = nhrp_ha_secure_file_write(path, output, offset);
  OPENSSL_cleanse(output, sizeof(output));
  return ok;
}

int nhrp_ha_managed_state_load(const char *path,
                               const struct nhrp_ha_auth_keys *keys,
                               struct nhrp_ha_managed_state *state) {
  struct managed_state_wire wire;
  uint8_t tags[NHRP_HA_AUTH_MAX_KEYS * MANAGED_TAG_SIZE];
  uint8_t expected[NHRP_HA_AUTH_TAG_SIZE];
  struct stat status;
  size_t tag_length;
  size_t i;
  size_t j;
  int fd;
  int authenticated = 0;

  memset(state, 0, sizeof(*state));
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  if (!secure_regular(fd, &status) || !read_all(fd, &wire, sizeof(wire)) ||
      wire.key_count == 0 || wire.key_count > NHRP_HA_AUTH_MAX_KEYS) {
    close(fd);
    return 0;
  }
  tag_length = (size_t)wire.key_count * MANAGED_TAG_SIZE;
  if (!read_all(fd, tags, tag_length) || read(fd, expected, 1) != 0) {
    close(fd);
    return 0;
  }
  close(fd);
  for (i = 0; i < wire.key_count && !authenticated; i++) {
    const uint8_t *tag = tags + i * MANAGED_TAG_SIZE;

    for (j = 0; j < NHRP_HA_AUTH_MAX_KEYS; j++) {
      if (!keys->key[j].present ||
          CRYPTO_memcmp(tag, keys->key[j].id, NHRP_HA_AUTH_KEY_ID_SIZE) != 0 ||
          !nhrp_ha_auth_hmac(keys->key[j].state_key, &wire, sizeof(wire),
                             expected))
        continue;
      if (CRYPTO_memcmp(expected, tag + NHRP_HA_AUTH_KEY_ID_SIZE,
                        NHRP_HA_AUTH_TAG_SIZE) == 0)
        authenticated = 1;
    }
  }
  OPENSSL_cleanse(tags, sizeof(tags));
  OPENSSL_cleanse(expected, sizeof(expected));
  if (!authenticated)
    return 0;
  return state_decode(&wire, state);
}

int nhrp_ha_managed_state_lock(const char *directory) {
  char path[4096];
  int fd;

  if (!ensure_directory(directory) ||
      snprintf(path, sizeof(path), "%s/.lock", directory) >= (int)sizeof(path))
    return -1;
  fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0 || flock(fd, LOCK_EX) != 0) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  return fd;
}

void nhrp_ha_managed_state_unlock(int fd) {
  if (fd >= 0) {
    flock(fd, LOCK_UN);
    close(fd);
  }
}

int nhrp_ha_managed_state_destroy(const char *directory) {
  const char *names[] = {"registrations.state", "seen.state", "cluster.state",
                         "keys", "identity.key"};
  char path[4096];
  size_t i;
  int lock_fd = nhrp_ha_managed_state_lock(directory);
  int directory_fd = -1;
  int ok = lock_fd >= 0;

  for (i = 0; ok && i < sizeof(names) / sizeof(names[0]); i++) {
    if (snprintf(path, sizeof(path), "%s/%s", directory, names[i]) >=
            (int)sizeof(path) ||
        (unlink(path) != 0 && errno != ENOENT))
      ok = 0;
  }
  if (ok) {
    directory_fd =
        open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    ok = directory_fd >= 0 && fsync(directory_fd) == 0;
  }
  if (directory_fd >= 0)
    close(directory_fd);
  nhrp_ha_managed_state_unlock(lock_fd);
  return ok;
}

int nhrp_ha_managed_member_remove(struct nhrp_ha_managed_state *state,
                                  const char *member_id) {
  struct nhrp_ha_managed_member *member =
      nhrp_ha_managed_member_find(state, member_id);
  size_t index;

  if (member == NULL)
    return 0;
  index = (size_t)(member - state->members);
  memmove(&state->members[index], &state->members[index + 1],
          (state->member_count - index - 1) * sizeof(state->members[0]));
  state->member_count--;
  memset(&state->members[state->member_count], 0, sizeof(state->members[0]));
  return 1;
}

enum nhrp_ha_managed_init_result nhrp_ha_managed_cluster_init(
    const char *directory, const char *interface, const char *member_id,
    const struct in_addr *protocol, uint8_t prefix_length,
    const struct in_addr *advertised, size_t advertised_count,
    struct nhrp_ha_managed_state *created) {
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_member *member;
  struct nhrp_ha_auth_keys keys;
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  uint8_t public_key[32];
  int state_exists;
  int keys_exist;
  int identity_exists;
  int lock_fd = -1;
  enum nhrp_ha_managed_init_result result = NHRP_HA_MANAGED_INIT_FAILED;
  uint32_t protocol_host = protocol != NULL ? ntohl(protocol->s_addr) : 0;

  if (directory == NULL || interface == NULL || interface[0] == 0 ||
      strlen(interface) >= sizeof(state.interface) ||
      !nhrp_ha_managed_member_valid(member_id) || protocol == NULL ||
      advertised_count == 0 ||
      !nhrp_ha_managed_endpoints_valid(advertised, advertised_count) ||
      protocol_host == INADDR_ANY ||
      (protocol_host & 0xf0000000U) == 0xe0000000U || prefix_length > 32 ||
      !nhrp_ha_managed_paths(directory, state_path, sizeof(state_path),
                             keys_path, sizeof(keys_path), identity_path,
                             sizeof(identity_path)))
    return NHRP_HA_MANAGED_INIT_INVALID;
  lock_fd = nhrp_ha_managed_state_lock(directory);
  if (lock_fd < 0)
    return NHRP_HA_MANAGED_INIT_LOCK_FAILED;

  state_exists = access(state_path, F_OK) == 0;
  keys_exist = access(keys_path, F_OK) == 0;
  identity_exists = access(identity_path, F_OK) == 0;
  if (state_exists || keys_exist || identity_exists) {
    result = state_exists && keys_exist && identity_exists
                 ? NHRP_HA_MANAGED_INIT_EXISTS
                 : NHRP_HA_MANAGED_INIT_INCOMPLETE;
    goto done;
  }

  memset(&keys, 0, sizeof(keys));
  memset(&state, 0, sizeof(state));
  if (!nhrp_ha_managed_keyring_generate(keys_path, &keys) ||
      !nhrp_ha_managed_identity_generate(identity_path, public_key) ||
      RAND_bytes(state.cluster_id, sizeof(state.cluster_id)) != 1)
    goto rollback;

  snprintf(state.interface, sizeof(state.interface), "%s", interface);
  state.protocol_address = *protocol;
  state.prefix_length = prefix_length;
  snprintf(state.local_member, sizeof(state.local_member), "%s", member_id);
  snprintf(state.primary_member, sizeof(state.primary_member), "%s", member_id);
  snprintf(state.leader, sizeof(state.leader), "%s", member_id);
  state.term = 1;
  state.commit_index = 1;
  state.manifest_revision = 1;
  state.port = NHRP_HA_MANAGED_DEFAULT_PORT;
  state.member_count = 1;
  member = &state.members[0];
  snprintf(member->member, sizeof(member->member), "%s", member_id);
  memcpy(member->addresses, advertised,
         advertised_count * sizeof(member->addresses[0]));
  member->address_count = (uint8_t)advertised_count;
  member->configured_address_count = (uint8_t)advertised_count;
  member->priority = 100;
  member->state = NHRP_HA_MANAGED_ACTIVE;
  memcpy(member->public_key, public_key, sizeof(member->public_key));
  member->match_index = 1;
  if (!nhrp_ha_managed_state_save(state_path, &keys, &state))
    goto rollback;
  if (created != NULL)
    *created = state;
  result = NHRP_HA_MANAGED_INIT_OK;
  goto clear;

rollback:
  unlink(state_path);
  unlink(keys_path);
  unlink(identity_path);
clear:
  nhrp_ha_auth_keys_clear(&keys);
done:
  nhrp_ha_managed_state_unlock(lock_fd);
  return result;
}

int nhrp_ha_managed_member_has_address(
    const struct nhrp_ha_managed_member *member,
    const struct in_addr *address) {
  size_t i;

  if (member == NULL || address == NULL)
    return 0;
  for (i = 0; i < member->address_count; i++)
    if (member->addresses[i].s_addr == address->s_addr)
      return 1;
  return 0;
}

int nhrp_ha_managed_member_set_configured(struct nhrp_ha_managed_state *state,
                                          struct nhrp_ha_managed_member *member,
                                          const struct in_addr *addresses,
                                          size_t address_count) {
  struct in_addr observed;
  int have_observed;
  size_t i;
  size_t j;

  if (state == NULL || member == NULL || address_count == 0 ||
      !nhrp_ha_managed_endpoints_valid(addresses, address_count))
    return -1;
  for (i = 0; i < address_count; i++) {
    for (j = 0; j < state->member_count; j++)
      if (&state->members[j] != member &&
          nhrp_ha_managed_member_has_address(&state->members[j], &addresses[i]))
        return -2;
  }
  if (member->configured_address_count == address_count &&
      memcmp(member->addresses, addresses,
             address_count * sizeof(addresses[0])) == 0)
    return 0;
  have_observed = member->address_count > member->configured_address_count;
  memset(&observed, 0, sizeof(observed));
  if (have_observed)
    observed = member->addresses[member->configured_address_count];
  memset(member->addresses, 0, sizeof(member->addresses));
  memcpy(member->addresses, addresses, address_count * sizeof(addresses[0]));
  member->address_count = (uint8_t)address_count;
  member->configured_address_count = (uint8_t)address_count;
  if (have_observed)
    nhrp_ha_managed_member_set_observed(state, member, &observed);
  member->match_index = 0;
  memset(member->digest, 0, sizeof(member->digest));
  return 1;
}

int nhrp_ha_managed_member_set_observed(struct nhrp_ha_managed_state *state,
                                        struct nhrp_ha_managed_member *member,
                                        const struct in_addr *address) {
  size_t i;

  if (state == NULL || member == NULL || address == NULL ||
      address->s_addr == 0)
    return -1;
  {
    uint32_t host = ntohl(address->s_addr);

    if ((host & 0xf0000000U) == 0xe0000000U)
      return -1;
  }
  for (i = 0; i < state->member_count; i++) {
    struct nhrp_ha_managed_member *other = &state->members[i];

    if (other != member && nhrp_ha_managed_member_has_address(other, address))
      return -2;
  }
  for (i = 0; i < member->configured_address_count; i++) {
    if (member->addresses[i].s_addr != address->s_addr)
      continue;
    if (member->address_count == member->configured_address_count)
      return 0;
    member->address_count = member->configured_address_count;
    memset(&member->addresses[member->address_count], 0,
           (NHRP_HA_MANAGED_MAX_ENDPOINTS - member->address_count) *
               sizeof(member->addresses[0]));
    return 1;
  }
  if (member->address_count > member->configured_address_count) {
    if (member->addresses[member->configured_address_count].s_addr ==
        address->s_addr)
      return 0;
    member->addresses[member->configured_address_count] = *address;
    return 1;
  }
  if (member->address_count >= NHRP_HA_MANAGED_MAX_ENDPOINTS)
    return -1;
  member->addresses[member->address_count++] = *address;
  return 1;
}

struct nhrp_ha_managed_member *
nhrp_ha_managed_member_find(struct nhrp_ha_managed_state *state,
                            const char *member) {
  size_t i;

  for (i = 0; i < state->member_count; i++)
    if (strcmp(state->members[i].member, member) == 0)
      return &state->members[i];
  return NULL;
}

struct nhrp_ha_managed_invite *
nhrp_ha_managed_invite_find(struct nhrp_ha_managed_state *state,
                            const uint8_t id[16]) {
  size_t i;

  for (i = 0; i < state->invite_count; i++)
    if (CRYPTO_memcmp(state->invites[i].id, id, 16) == 0)
      return &state->invites[i];
  return NULL;
}

int nhrp_ha_managed_invite_remove(struct nhrp_ha_managed_state *state,
                                  const uint8_t id[16]) {
  size_t i;

  if (state == NULL || id == NULL)
    return 0;
  for (i = 0; i < state->invite_count; i++) {
    if (CRYPTO_memcmp(state->invites[i].id, id, 16) != 0)
      continue;
    state->invite_count--;
    if (i < state->invite_count)
      memmove(&state->invites[i], &state->invites[i + 1],
              (state->invite_count - i) * sizeof(state->invites[0]));
    memset(&state->invites[state->invite_count], 0, sizeof(state->invites[0]));
    return 1;
  }
  return 0;
}

static void base64url(char *text) {
  for (; *text != 0; text++) {
    if (*text == '+')
      *text = '-';
    else if (*text == '/')
      *text = '_';
  }
}

static int invite_sign(const char *path,
                       struct managed_invite_token_wire *wire) {
  uint8_t private_key[32];
  EVP_PKEY *key = identity_key(path, private_key);
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  size_t length = sizeof(wire->signature);
  int ok = key != NULL && context != NULL &&
           EVP_DigestSignInit(context, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestSign(
               context, wire->signature, &length, (const uint8_t *)wire,
               offsetof(struct managed_invite_token_wire, signature)) == 1 &&
           length == sizeof(wire->signature);

  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  OPENSSL_cleanse(private_key, sizeof(private_key));
  return ok;
}

static int invite_verify(const struct managed_invite_token_wire *wire) {
  EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                              wire->leader_public_key, 32);
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  int ok = key != NULL && context != NULL &&
           EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestVerify(
               context, wire->signature, sizeof(wire->signature),
               (const uint8_t *)wire,
               offsetof(struct managed_invite_token_wire, signature)) == 1;

  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return ok;
}

int nhrp_ha_managed_invite_encode(const struct nhrp_ha_managed_state *state,
                                  const struct nhrp_ha_managed_invite *invite,
                                  const uint8_t secret[32],
                                  const char *identity_path, char **encoded) {
  struct managed_invite_token_wire wire;
  struct nhrp_ha_managed_member *leader;
  struct nhrp_ha_managed_state *mutable_state =
      (struct nhrp_ha_managed_state *)state;
  size_t maximum;
  char *text;

  leader = nhrp_ha_managed_member_find(mutable_state, state->leader);
  if (leader == NULL || invite == NULL || secret == NULL)
    return 0;
  memset(&wire, 0, sizeof(wire));
  memcpy(wire.magic, MANAGED_INVITE_MAGIC, 4);
  wire.version = MANAGED_INVITE_VERSION;
  wire.prefix_length = state->prefix_length;
  memcpy(wire.cluster_id, state->cluster_id, 16);
  memcpy(wire.invite_id, invite->id, 16);
  wire.protocol_address = state->protocol_address.s_addr;
  for (maximum = 0; maximum < leader->address_count; maximum++)
    wire.leader_addresses[maximum] = leader->addresses[maximum].s_addr;
  wire.leader_address_count = leader->address_count;
  wire.leader_port = htons(state->port);
  wire.priority = htonl(invite->priority);
  wire.expires_at = htobe64((uint64_t)invite->expires_at);
  snprintf(wire.member, sizeof(wire.member), "%s", invite->member);
  if (!nhrp_ha_managed_identity_public(identity_path, wire.leader_public_key))
    return 0;
  memcpy(wire.secret, secret, 32);
  if (!invite_sign(identity_path, &wire))
    return 0;
  maximum = MANAGED_INVITE_PREFIX_SIZE + 4 * ((sizeof(wire) + 2) / 3) + 1;
  text = calloc(1, maximum);
  if (text == NULL)
    return 0;
  memcpy(text, MANAGED_INVITE_PREFIX, MANAGED_INVITE_PREFIX_SIZE);
  EVP_EncodeBlock((unsigned char *)text + MANAGED_INVITE_PREFIX_SIZE,
                  (const unsigned char *)&wire, sizeof(wire));
  base64url(text + MANAGED_INVITE_PREFIX_SIZE);
  while (text[strlen(text) - 1] == '=')
    text[strlen(text) - 1] = 0;
  *encoded = text;
  OPENSSL_cleanse(&wire, sizeof(wire));
  return 1;
}

int nhrp_ha_managed_invite_decode(const char *encoded,
                                  struct nhrp_ha_managed_invite_token *token) {
  struct managed_invite_token_wire wire;
  unsigned char decoded[sizeof(wire) + 2];
  char *copy;
  size_t length;
  size_t padding;
  size_t decoded_length;
  size_t i;
  int ok = 0;

  memset(token, 0, sizeof(*token));
  if (encoded == NULL ||
      strncmp(encoded, MANAGED_INVITE_PREFIX, MANAGED_INVITE_PREFIX_SIZE) != 0)
    return 0;
  length = strlen(encoded + MANAGED_INVITE_PREFIX_SIZE);
  padding = (4 - length % 4) % 4;
  copy = calloc(1, length + padding + 1);
  if (copy == NULL)
    return 0;
  memcpy(copy, encoded + MANAGED_INVITE_PREFIX_SIZE, length);
  for (i = 0; i < length; i++) {
    if (copy[i] == '-')
      copy[i] = '+';
    else if (copy[i] == '_')
      copy[i] = '/';
  }
  for (i = 0; i < padding; i++)
    copy[length + i] = '=';
  decoded_length = (size_t)EVP_DecodeBlock(decoded, (unsigned char *)copy,
                                           (int)(length + padding));
  if (decoded_length < padding || decoded_length - padding != sizeof(wire))
    goto done;
  memcpy(&wire, decoded, sizeof(wire));
  if (memcmp(wire.magic, MANAGED_INVITE_MAGIC, 4) != 0 ||
      wire.version != MANAGED_INVITE_VERSION || wire.reserved[0] != 0 ||
      wire.reserved[1] != 0 || wire.reserved2 != 0 ||
      wire.reserved_address[0] != 0 || wire.reserved_address[1] != 0 ||
      wire.reserved_address[2] != 0 || wire.prefix_length > 32 ||
      wire.leader_address_count == 0 ||
      wire.leader_address_count > NHRP_HA_MANAGED_MAX_ENDPOINTS ||
      !terminated(wire.member, 64) ||
      !nhrp_ha_managed_member_valid(wire.member) || !invite_verify(&wire))
    goto done;
  memcpy(token->cluster_id, wire.cluster_id, 16);
  memcpy(token->invite_id, wire.invite_id, 16);
  token->protocol_address.s_addr = wire.protocol_address;
  token->prefix_length = wire.prefix_length;
  token->leader_address_count = wire.leader_address_count;
  for (i = 0; i < token->leader_address_count; i++)
    token->leader_addresses[i].s_addr = wire.leader_addresses[i];
  token->leader_port = ntohs(wire.leader_port);
  token->priority = ntohl(wire.priority);
  token->expires_at = (int64_t)be64toh(wire.expires_at);
  snprintf(token->member, sizeof(token->member), "%s", wire.member);
  memcpy(token->leader_public_key, wire.leader_public_key, 32);
  memcpy(token->secret, wire.secret, 32);
  ok = token->protocol_address.s_addr != 0 && token->leader_port != 0 &&
       token->priority != 0 && token->expires_at > 0;
  for (i = 0; ok && i < token->leader_address_count; i++)
    ok = token->leader_addresses[i].s_addr != 0;

done:
  OPENSSL_cleanse(&wire, sizeof(wire));
  OPENSSL_cleanse(decoded, sizeof(decoded));
  OPENSSL_cleanse(copy, length + padding + 1);
  free(copy);
  if (!ok)
    OPENSSL_cleanse(token, sizeof(*token));
  return ok;
}
