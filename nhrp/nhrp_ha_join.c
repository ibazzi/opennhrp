/* nhrp_ha_join.c - Secure online OpenNHRP HA enrollment */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "nhrp_ha_join.h"

#define JOIN_VERSION 1
#define JOIN_MAX_PAYLOAD (256U * 1024U)
#define JOIN_DOMAIN "OpenNHRP-HA-JOIN-v1"

struct join_hello {
  uint8_t magic[4];
  uint8_t version;
  uint8_t reserved[3];
  uint8_t invite_id[16];
  uint8_t client_nonce[16];
  uint8_t client_public_key[32];
  uint8_t client_x25519[32];
  uint32_t advertised_addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  uint8_t advertised_address_count;
  uint8_t reserved_address[3];
  uint8_t proof[32];
} __attribute__((packed));

struct join_reply {
  uint8_t magic[4];
  uint8_t version;
  uint8_t status;
  uint8_t reserved[2];
  uint8_t server_nonce[16];
  uint8_t server_x25519[32];
  uint8_t iv[12];
  uint8_t tag[16];
  uint32_t ciphertext_length;
  uint8_t signature[64];
} __attribute__((packed));

struct join_plain_header {
  uint32_t state_length;
  uint16_t keyring_length;
  uint16_t reserved;
} __attribute__((packed));

static int io_all(int fd, void *data, size_t length, int sending) {
  uint8_t *position = data;

  while (length != 0) {
    ssize_t result = sending ? send(fd, position, length, MSG_NOSIGNAL)
                             : recv(fd, position, length, 0);

    if (result < 0 && errno == EINTR)
      continue;
    if (result <= 0)
      return 0;
    position += result;
    length -= (size_t)result;
  }
  return 1;
}

static void hello_proof(struct join_hello *hello,
                        const uint8_t secret_hash[32]) {
  uint8_t
      canonical[sizeof(JOIN_DOMAIN) - 1 + offsetof(struct join_hello, proof)];

  memcpy(canonical, JOIN_DOMAIN, sizeof(JOIN_DOMAIN) - 1);
  memcpy(canonical + sizeof(JOIN_DOMAIN) - 1, hello,
         offsetof(struct join_hello, proof));
  nhrp_ha_auth_hmac(secret_hash, canonical, sizeof(canonical), hello->proof);
  OPENSSL_cleanse(canonical, sizeof(canonical));
}

static EVP_PKEY *x25519_generate(uint8_t public_key[32]) {
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  EVP_PKEY *key = NULL;
  size_t length = 32;

  if (context == NULL || EVP_PKEY_keygen_init(context) != 1 ||
      EVP_PKEY_keygen(context, &key) != 1 ||
      EVP_PKEY_get_raw_public_key(key, public_key, &length) != 1 ||
      length != 32) {
    EVP_PKEY_free(key);
    key = NULL;
  }
  EVP_PKEY_CTX_free(context);
  return key;
}

static int session_derive(EVP_PKEY *local_key, const uint8_t peer_public[32],
                          const uint8_t secret_hash[32],
                          const uint8_t client_nonce[16],
                          const uint8_t server_nonce[16], uint8_t session[32]) {
  EVP_PKEY *peer =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, 32);
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(local_key, NULL);
  uint8_t shared[32];
  uint8_t input[sizeof(JOIN_DOMAIN) - 1 + 32 + 16 + 16];
  size_t shared_length = sizeof(shared);
  int ok = peer != NULL && context != NULL &&
           EVP_PKEY_derive_init(context) == 1 &&
           EVP_PKEY_derive_set_peer(context, peer) == 1 &&
           EVP_PKEY_derive(context, shared, &shared_length) == 1 &&
           shared_length == sizeof(shared);

  if (ok) {
    memcpy(input, JOIN_DOMAIN, sizeof(JOIN_DOMAIN) - 1);
    memcpy(input + sizeof(JOIN_DOMAIN) - 1, shared, sizeof(shared));
    memcpy(input + sizeof(JOIN_DOMAIN) - 1 + sizeof(shared), client_nonce, 16);
    memcpy(input + sizeof(JOIN_DOMAIN) - 1 + sizeof(shared) + 16, server_nonce,
           16);
    ok = nhrp_ha_auth_hmac(secret_hash, input, sizeof(input), session);
  }
  EVP_PKEY_CTX_free(context);
  EVP_PKEY_free(peer);
  OPENSSL_cleanse(shared, sizeof(shared));
  OPENSSL_cleanse(input, sizeof(input));
  return ok;
}

static int crypt_payload(int encrypt, const uint8_t session[32],
                         const uint8_t iv[12], const uint8_t *input,
                         size_t length, uint8_t *output, uint8_t tag[16]) {
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  int output_length = 0;
  int final_length = 0;
  int ok =
      context != NULL &&
      EVP_CipherInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL,
                        encrypt) == 1 &&
      EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
      EVP_CipherInit_ex(context, NULL, NULL, session, iv, encrypt) == 1;

  if (!encrypt && ok)
    ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
  if (ok)
    ok = EVP_CipherUpdate(context, output, &output_length, input,
                          (int)length) == 1;
  if (ok)
    ok =
        EVP_CipherFinal_ex(context, output + output_length, &final_length) == 1;
  if (encrypt && ok)
    ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
  EVP_CIPHER_CTX_free(context);
  return ok && (size_t)(output_length + final_length) == length;
}

static EVP_PKEY *identity_private(const char *path) {
  char encoded[66];
  uint8_t raw[32];
  struct stat status;
  ssize_t length;
  int fd;
  size_t i;
  EVP_PKEY *key = NULL;

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return NULL;
  if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      (status.st_mode & 077) != 0 || status.st_uid != geteuid() ||
      (length = read(fd, encoded, sizeof(encoded))) < 64 || length > 65 ||
      (length == 65 && encoded[64] != '\n'))
    goto done;
  for (i = 0; i < sizeof(raw); i++) {
    unsigned char high = (unsigned char)encoded[i * 2];
    unsigned char low = (unsigned char)encoded[i * 2 + 1];
    int high_value = high >= '0' && high <= '9'   ? high - '0'
                     : high >= 'a' && high <= 'f' ? high - 'a' + 10
                                                  : -1;
    int low_value = low >= '0' && low <= '9'   ? low - '0'
                    : low >= 'a' && low <= 'f' ? low - 'a' + 10
                                               : -1;

    if (high_value < 0 || low_value < 0)
      goto done;
    raw[i] = (uint8_t)((high_value << 4) | low_value);
  }
  key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw, sizeof(raw));

done:
  close(fd);
  OPENSSL_cleanse(encoded, sizeof(encoded));
  OPENSSL_cleanse(raw, sizeof(raw));
  return key;
}

static int reply_signature(const char *identity_path,
                           const struct join_hello *hello,
                           struct join_reply *reply, int verify,
                           const uint8_t expected_public[32]) {
  uint8_t canonical[sizeof(*hello) + offsetof(struct join_reply, signature)];
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  size_t signature_length = sizeof(reply->signature);
  int ok;

  memcpy(canonical, hello, sizeof(*hello));
  memcpy(canonical + sizeof(*hello), reply,
         offsetof(struct join_reply, signature));
  if (verify)
    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, expected_public,
                                      32);
  else
    key = identity_private(identity_path);
  if (verify)
    ok = key != NULL && context != NULL &&
         EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
         EVP_DigestVerify(context, reply->signature, sizeof(reply->signature),
                          canonical, sizeof(canonical)) == 1;
  else
    ok = key != NULL && context != NULL &&
         EVP_DigestSignInit(context, NULL, NULL, NULL, key) == 1 &&
         EVP_DigestSign(context, reply->signature, &signature_length, canonical,
                        sizeof(canonical)) == 1 &&
         signature_length == sizeof(reply->signature);
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  OPENSSL_cleanse(canonical, sizeof(canonical));
  return ok;
}

int nhrp_ha_join_is_request(const void *prefix, size_t length) {
  return prefix != NULL && length >= 4 &&
         memcmp(prefix, NHRP_HA_JOIN_MAGIC, 4) == 0;
}

static int socket_connect(struct in_addr address, uint16_t port) {
  struct sockaddr_in destination;
  struct timeval timeout = {.tv_sec = 3, .tv_usec = 0};
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

  if (fd < 0)
    return -1;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  memset(&destination, 0, sizeof(destination));
  destination.sin_family = AF_INET;
  destination.sin_addr = address;
  destination.sin_port = htons(port);
  if (connect(fd, (struct sockaddr *)&destination, sizeof(destination)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int nhrp_ha_join_client_fd(int fd,
                           const struct nhrp_ha_managed_invite_token *token,
                           const char *interface,
                           const struct in_addr *advertised_addresses,
                           size_t advertised_address_count,
                           const char *directory) {
  struct join_hello hello;
  struct join_reply reply;
  struct join_plain_header plain_header;
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_member *local;
  struct nhrp_ha_auth_keys keys;
  EVP_PKEY *x25519 = NULL;
  uint8_t secret_hash[32];
  uint8_t session[32];
  uint8_t keyring[256];
  uint8_t *ciphertext = NULL;
  uint8_t *plain = NULL;
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  size_t state_length;
  size_t keyring_length;
  size_t ciphertext_length;
  int lock_fd = -1;
  int generated_identity = 0;
  int imported_keys = 0;
  int result = 0;
  int stage = 0;
  size_t i;

  memset(&hello, 0, sizeof(hello));
  memset(&reply, 0, sizeof(reply));
  memset(&keys, 0, sizeof(keys));
  if (token == NULL || interface == NULL || strlen(interface) >= 16 ||
      token->expires_at < (int64_t)time(NULL) ||
      !nhrp_ha_managed_endpoints_valid(advertised_addresses,
                                       advertised_address_count) ||
      !nhrp_ha_managed_paths(directory, state_path, sizeof(state_path),
                             keys_path, sizeof(keys_path), identity_path,
                             sizeof(identity_path)))
    return 0;
  lock_fd = nhrp_ha_managed_state_lock(directory);
  stage = 1;
  if (lock_fd < 0 || access(state_path, F_OK) == 0 ||
      access(keys_path, F_OK) == 0 || access(identity_path, F_OK) == 0)
    goto done;
  if (!nhrp_ha_managed_identity_generate(identity_path,
                                         hello.client_public_key))
    goto done;
  generated_identity = 1;
  stage = 2;
  memcpy(hello.magic, NHRP_HA_JOIN_MAGIC, 4);
  hello.version = JOIN_VERSION;
  memcpy(hello.invite_id, token->invite_id, 16);
  if (RAND_bytes(hello.client_nonce, sizeof(hello.client_nonce)) != 1 ||
      (x25519 = x25519_generate(hello.client_x25519)) == NULL ||
      SHA256(token->secret, sizeof(token->secret), secret_hash) == NULL)
    goto done;
  hello.advertised_address_count = (uint8_t)advertised_address_count;
  for (i = 0; i < advertised_address_count; i++)
    hello.advertised_addresses[i] = advertised_addresses[i].s_addr;
  hello_proof(&hello, secret_hash);
  stage = 30;
  if (fd < 0 || !io_all(fd, &hello, sizeof(hello), 1))
    goto done;
  stage = 31;
  if (!io_all(fd, &reply, sizeof(reply), 0))
    goto done;
  stage = 32;
  if (memcmp(reply.magic, NHRP_HA_JOIN_MAGIC, 4) != 0 ||
      reply.version != JOIN_VERSION || reply.status != 0 ||
      reply.reserved[0] != 0 || reply.reserved[1] != 0)
    goto done;
  stage = 33;
  if (!reply_signature(NULL, &hello, &reply, 1, token->leader_public_key))
    goto done;
  stage = 34;
  if (!session_derive(x25519, reply.server_x25519, secret_hash,
                      hello.client_nonce, reply.server_nonce, session))
    goto done;
  stage = 4;
  ciphertext_length = ntohl(reply.ciphertext_length);
  if (ciphertext_length < sizeof(plain_header) ||
      ciphertext_length > JOIN_MAX_PAYLOAD)
    goto done;
  stage = 5;
  ciphertext = malloc(ciphertext_length);
  plain = malloc(ciphertext_length);
  if (ciphertext == NULL || plain == NULL ||
      !io_all(fd, ciphertext, ciphertext_length, 0) ||
      !crypt_payload(0, session, reply.iv, ciphertext, ciphertext_length, plain,
                     reply.tag))
    goto done;
  stage = 6;
  memcpy(&plain_header, plain, sizeof(plain_header));
  state_length = ntohl(plain_header.state_length);
  keyring_length = ntohs(plain_header.keyring_length);
  if (plain_header.reserved != 0 ||
      state_length != nhrp_ha_managed_state_encoded_size() ||
      keyring_length == 0 || keyring_length >= sizeof(keyring) ||
      sizeof(plain_header) + state_length + keyring_length != ciphertext_length)
    goto done;
  stage = 7;
  memcpy(keyring, plain + sizeof(plain_header) + state_length, keyring_length);
  if (!nhrp_ha_managed_state_decode(plain + sizeof(plain_header), state_length,
                                    &state) ||
      memcmp(state.cluster_id, token->cluster_id, 16) != 0 ||
      state.protocol_address.s_addr != token->protocol_address.s_addr ||
      state.prefix_length != token->prefix_length ||
      strcmp(state.local_member, token->member) != 0 ||
      (local = nhrp_ha_managed_member_find(&state, token->member)) == NULL ||
      CRYPTO_memcmp(local->public_key, hello.client_public_key, 32) != 0)
    goto done;
  snprintf(state.interface, sizeof(state.interface), "%s", interface);
  if (!nhrp_ha_managed_keyring_import(keys_path, keyring, keyring_length))
    goto done;
  imported_keys = 1;
  if (!nhrp_ha_managed_keyring_load(keys_path, &keys) ||
      !nhrp_ha_managed_state_save(state_path, &keys, &state))
    goto done;
  result = 1;

done:
  if (!result)
    fprintf(stderr,
            "opennhrp-ha: join client failed at stage %d status %u: %s\n",
            stage, reply.status, strerror(errno));
  EVP_PKEY_free(x25519);
  if (!result) {
    unlink(state_path);
    if (imported_keys)
      unlink(keys_path);
    if (generated_identity)
      unlink(identity_path);
  }
  free(ciphertext);
  free(plain);
  nhrp_ha_auth_keys_clear(&keys);
  OPENSSL_cleanse(secret_hash, sizeof(secret_hash));
  OPENSSL_cleanse(session, sizeof(session));
  OPENSSL_cleanse(keyring, sizeof(keyring));
  nhrp_ha_managed_state_unlock(lock_fd);
  return result;
}

int nhrp_ha_join_client(const struct nhrp_ha_managed_invite_token *token,
                        const char *interface,
                        const struct in_addr *advertised_addresses,
                        size_t advertised_address_count,
                        const char *directory) {
  int fd;
  int result;
  size_t i;

  if (token == NULL)
    return 0;
  fd = -1;
  for (i = 0; i < token->leader_address_count; i++) {
    fd = socket_connect(token->leader_addresses[i], token->leader_port);
    if (fd >= 0)
      break;
  }
  if (fd < 0)
    return 0;
  result = nhrp_ha_join_client_fd(fd, token, interface, advertised_addresses,
                                  advertised_address_count, directory);
  close(fd);
  return result;
}

static int reply_error(int fd, uint8_t status) {
  struct join_reply reply;

  memset(&reply, 0, sizeof(reply));
  memcpy(reply.magic, NHRP_HA_JOIN_MAGIC, 4);
  reply.version = JOIN_VERSION;
  reply.status = status;
  return io_all(fd, &reply, sizeof(reply), 1);
}

int nhrp_ha_join_server(int fd, const char *directory) {
  struct join_hello hello;
  struct join_reply reply;
  struct join_plain_header plain_header;
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_state join_state;
  struct nhrp_ha_managed_invite *invite;
  struct nhrp_ha_managed_member *member;
  struct nhrp_ha_auth_keys keys;
  struct sockaddr_in source;
  socklen_t source_length = sizeof(source);
  EVP_PKEY *x25519 = NULL;
  uint8_t expected[32];
  uint8_t session[32];
  uint8_t keyring[256];
  uint8_t *plain = NULL;
  uint8_t *ciphertext = NULL;
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  size_t state_length = nhrp_ha_managed_state_encoded_size();
  size_t keyring_length = 0;
  size_t plain_length;
  int lock_fd = -1;
  int result = 0;
  int newly_claimed = 0;
  size_t i;

  memset(&hello, 0, sizeof(hello));
  memset(&reply, 0, sizeof(reply));
  memset(&keys, 0, sizeof(keys));
  memset(&source, 0, sizeof(source));
  if (!io_all(fd, &hello, sizeof(hello), 0) ||
      memcmp(hello.magic, NHRP_HA_JOIN_MAGIC, 4) != 0 ||
      hello.version != JOIN_VERSION || hello.reserved[0] != 0 ||
      hello.reserved[1] != 0 || hello.reserved[2] != 0 ||
      hello.reserved_address[0] != 0 || hello.reserved_address[1] != 0 ||
      hello.reserved_address[2] != 0 ||
      hello.advertised_address_count > NHRP_HA_MANAGED_MAX_ENDPOINTS)
    return 0;
  {
    struct in_addr advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];

    for (i = 0; i < hello.advertised_address_count; i++)
      advertised[i].s_addr = hello.advertised_addresses[i];
    if (!nhrp_ha_managed_endpoints_valid(advertised,
                                         hello.advertised_address_count))
      return 0;
  }
  lock_fd = nhrp_ha_managed_state_lock(directory);
  if (lock_fd < 0 ||
      !nhrp_ha_managed_paths(directory, state_path, sizeof(state_path),
                             keys_path, sizeof(keys_path), identity_path,
                             sizeof(identity_path)) ||
      !nhrp_ha_managed_keyring_load(keys_path, &keys) ||
      !nhrp_ha_managed_state_load(state_path, &keys, &state) ||
      strcmp(state.local_member, state.leader) != 0) {
    reply_error(fd, 1);
    goto done;
  }
  invite = nhrp_ha_managed_invite_find(&state, hello.invite_id);
  if (invite == NULL || invite->state == NHRP_HA_MANAGED_INVITE_REVOKED ||
      (invite->state == NHRP_HA_MANAGED_INVITE_UNUSED &&
       invite->expires_at < (int64_t)time(NULL))) {
    reply_error(fd, 2);
    goto done;
  }
  memcpy(expected, hello.proof, sizeof(expected));
  hello_proof(&hello, invite->secret_hash);
  if (CRYPTO_memcmp(expected, hello.proof, sizeof(expected)) != 0 ||
      (invite->state == NHRP_HA_MANAGED_INVITE_CLAIMED &&
       CRYPTO_memcmp(invite->claimed_key, hello.client_public_key, 32) != 0)) {
    reply_error(fd, 3);
    goto done;
  }
  member = nhrp_ha_managed_member_find(&state, invite->member);
  if (invite->state == NHRP_HA_MANAGED_INVITE_UNUSED) {
    if (member != NULL || state.member_count >= NHRP_HA_MANAGED_MAX_MEMBERS ||
        getpeername(fd, (struct sockaddr *)&source, &source_length) != 0) {
      reply_error(fd, 4);
      goto done;
    }
    member = &state.members[state.member_count++];
    memset(member, 0, sizeof(*member));
    snprintf(member->member, sizeof(member->member), "%s", invite->member);
    member->address_count = hello.advertised_address_count;
    member->configured_address_count = hello.advertised_address_count;
    for (i = 0; i < member->address_count; i++)
      member->addresses[i].s_addr = hello.advertised_addresses[i];
    {
      int observed =
          nhrp_ha_managed_member_set_observed(&state, member, &source.sin_addr);

      if (observed == -2) {
        state.member_count--;
        reply_error(fd, 4);
        goto done;
      }
      if (observed == -1)
        fprintf(stderr,
                "opennhrp-ha: observed address ignored for %s; endpoint list "
                "is full\n",
                member->member);
    }
    member->priority = invite->priority;
    member->state = NHRP_HA_MANAGED_LEARNER;
    memcpy(member->public_key, hello.client_public_key, 32);
    invite->state = NHRP_HA_MANAGED_INVITE_CLAIMED;
    memcpy(invite->claimed_key, hello.client_public_key, 32);
    state.commit_index++;
    state.manifest_revision++;
    newly_claimed = 1;
  } else if (member == NULL ||
             CRYPTO_memcmp(member->public_key, hello.client_public_key, 32) !=
                 0) {
    reply_error(fd, 5);
    goto done;
  }
  join_state = state;
  snprintf(join_state.local_member, sizeof(join_state.local_member), "%s",
           invite->member);
  if (!nhrp_ha_managed_keyring_read(keys_path, keyring, sizeof(keyring),
                                    &keyring_length) ||
      keyring_length > UINT16_MAX ||
      (plain_length = sizeof(plain_header) + state_length + keyring_length) >
          JOIN_MAX_PAYLOAD)
    goto done;
  plain = malloc(plain_length);
  ciphertext = malloc(plain_length);
  if (plain == NULL || ciphertext == NULL)
    goto done;
  memset(&plain_header, 0, sizeof(plain_header));
  plain_header.state_length = htonl((uint32_t)state_length);
  plain_header.keyring_length = htons((uint16_t)keyring_length);
  memcpy(plain, &plain_header, sizeof(plain_header));
  if (!nhrp_ha_managed_state_encode(&join_state, plain + sizeof(plain_header),
                                    state_length))
    goto done;
  memcpy(plain + sizeof(plain_header) + state_length, keyring, keyring_length);
  memcpy(reply.magic, NHRP_HA_JOIN_MAGIC, 4);
  reply.version = JOIN_VERSION;
  if (RAND_bytes(reply.server_nonce, sizeof(reply.server_nonce)) != 1 ||
      RAND_bytes(reply.iv, sizeof(reply.iv)) != 1 ||
      (x25519 = x25519_generate(reply.server_x25519)) == NULL ||
      !session_derive(x25519, hello.client_x25519, invite->secret_hash,
                      hello.client_nonce, reply.server_nonce, session) ||
      !crypt_payload(1, session, reply.iv, plain, plain_length, ciphertext,
                     reply.tag))
    goto done;
  reply.ciphertext_length = htonl((uint32_t)plain_length);
  if (!reply_signature(identity_path, &hello, &reply, 0, NULL))
    goto done;
  if (newly_claimed && !nhrp_ha_managed_state_save(state_path, &keys, &state))
    goto done;
  if (!io_all(fd, &reply, sizeof(reply), 1) ||
      !io_all(fd, ciphertext, plain_length, 1))
    goto done;
  result = 1;

done:
  EVP_PKEY_free(x25519);
  free(plain);
  free(ciphertext);
  nhrp_ha_auth_keys_clear(&keys);
  OPENSSL_cleanse(expected, sizeof(expected));
  OPENSSL_cleanse(session, sizeof(session));
  OPENSSL_cleanse(keyring, sizeof(keyring));
  nhrp_ha_managed_state_unlock(lock_fd);
  return result;
}
