/* nhrp_ha_managed.h - Managed OpenNHRP HA cluster state */

#ifndef NHRP_HA_MANAGED_H
#define NHRP_HA_MANAGED_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include "nhrp_ha_auth.h"

#define NHRP_HA_MANAGED_MAX_MEMBERS 32
#define NHRP_HA_MANAGED_MAX_ENDPOINTS 4
#define NHRP_HA_MANAGED_MAX_INVITES 64
#define NHRP_HA_MANAGED_MEMBER_MAX 63
#define NHRP_HA_MANAGED_DEFAULT_DIR "/etc/opennhrp/ha"
#define NHRP_HA_MANAGED_DEFAULT_PORT 49002

enum nhrp_ha_managed_member_state {
  NHRP_HA_MANAGED_LEARNER = 1,
  NHRP_HA_MANAGED_ACTIVE = 2,
  NHRP_HA_MANAGED_DISABLED = 3,
};

enum nhrp_ha_managed_invite_state {
  NHRP_HA_MANAGED_INVITE_UNUSED = 0,
  NHRP_HA_MANAGED_INVITE_CLAIMED = 1,
  NHRP_HA_MANAGED_INVITE_REVOKED = 2,
};

enum nhrp_ha_managed_init_result {
  NHRP_HA_MANAGED_INIT_OK = 0,
  NHRP_HA_MANAGED_INIT_INVALID,
  NHRP_HA_MANAGED_INIT_LOCK_FAILED,
  NHRP_HA_MANAGED_INIT_EXISTS,
  NHRP_HA_MANAGED_INIT_INCOMPLETE,
  NHRP_HA_MANAGED_INIT_FAILED,
};

enum nhrp_ha_witness_mode {
  NHRP_HA_WITNESS_LEGACY = 0,
  NHRP_HA_WITNESS_PREPARING = 1,
  NHRP_HA_WITNESS_ACTIVE = 2,
  NHRP_HA_WITNESS_DISABLING = 3,
};

struct nhrp_ha_managed_member {
  char member[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  struct in_addr addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  uint8_t address_count;
  uint8_t configured_address_count;
  uint32_t priority;
  uint8_t state;
  uint8_t public_key[32];
  uint64_t match_index;
  uint8_t digest[32];
};

struct nhrp_ha_managed_invite {
  uint8_t id[16];
  uint8_t secret_hash[32];
  char member[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  uint32_t priority;
  int64_t expires_at;
  uint8_t state;
  uint8_t claimed_key[32];
};

struct nhrp_ha_managed_state {
  uint8_t cluster_id[16];
  char interface[16];
  struct in_addr protocol_address;
  uint8_t prefix_length;
  char local_member[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  char primary_member[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  char leader[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  uint64_t term;
  uint64_t commit_index;
  uint64_t manifest_revision;
  uint16_t port;
  uint8_t witness_mode;
  size_t member_count;
  size_t invite_count;
  struct nhrp_ha_managed_member members[NHRP_HA_MANAGED_MAX_MEMBERS];
  struct nhrp_ha_managed_invite invites[NHRP_HA_MANAGED_MAX_INVITES];
};

struct nhrp_ha_managed_invite_token {
  uint8_t cluster_id[16];
  uint8_t invite_id[16];
  struct in_addr protocol_address;
  uint8_t prefix_length;
  struct in_addr leader_addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  uint8_t leader_address_count;
  uint16_t leader_port;
  uint32_t priority;
  int64_t expires_at;
  char member[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  uint8_t leader_public_key[32];
  uint8_t secret[32];
};

int nhrp_ha_managed_member_valid(const char *member);
int nhrp_ha_managed_endpoints_valid(const struct in_addr *addresses,
                                    size_t count);
int nhrp_ha_managed_paths(const char *directory, char *state_path,
                          size_t state_size, char *keys_path, size_t keys_size,
                          char *identity_path, size_t identity_size);
int nhrp_ha_managed_keyring_load(const char *path,
                                 struct nhrp_ha_auth_keys *keys);
int nhrp_ha_managed_keyring_generate(const char *path,
                                     struct nhrp_ha_auth_keys *keys);
int nhrp_ha_managed_keyring_export(const char *source, const char *destination);
int nhrp_ha_managed_keyring_read(const char *path, uint8_t *buffer, size_t size,
                                 size_t *length);
int nhrp_ha_managed_keyring_import(const char *path, const uint8_t *buffer,
                                   size_t length);
int nhrp_ha_managed_keyring_prepare_rotation(const char *path,
                                             struct nhrp_ha_auth_keys *keys);
int nhrp_ha_managed_keyring_commit_rotation(const char *path);
int nhrp_ha_managed_identity_generate(const char *path, uint8_t public_key[32]);
int nhrp_ha_managed_identity_public(const char *path, uint8_t public_key[32]);
int nhrp_ha_managed_identity_sign(const char *path, const void *data,
                                  size_t length, uint8_t signature[64]);
int nhrp_ha_managed_identity_verify(const uint8_t public_key[32],
                                    const void *data, size_t length,
                                    const uint8_t signature[64]);
int nhrp_ha_managed_state_load(const char *path,
                               const struct nhrp_ha_auth_keys *keys,
                               struct nhrp_ha_managed_state *state);
int nhrp_ha_managed_state_save(const char *path,
                               const struct nhrp_ha_auth_keys *keys,
                               const struct nhrp_ha_managed_state *state);
size_t nhrp_ha_managed_state_encoded_size(void);
int nhrp_ha_managed_state_encode(const struct nhrp_ha_managed_state *state,
                                 uint8_t *buffer, size_t size);
int nhrp_ha_managed_state_decode(const uint8_t *buffer, size_t size,
                                 struct nhrp_ha_managed_state *state);
int nhrp_ha_managed_state_lock(const char *directory);
void nhrp_ha_managed_state_unlock(int fd);
int nhrp_ha_managed_state_destroy(const char *directory);
int nhrp_ha_managed_member_remove(struct nhrp_ha_managed_state *state,
                                  const char *member);
enum nhrp_ha_managed_init_result nhrp_ha_managed_cluster_init(
    const char *directory, const char *interface, const char *member_id,
    const struct in_addr *protocol, uint8_t prefix_length,
    const struct in_addr *advertised, size_t advertised_count,
    struct nhrp_ha_managed_state *created);
int nhrp_ha_managed_member_has_address(
    const struct nhrp_ha_managed_member *member, const struct in_addr *address);
int nhrp_ha_managed_member_set_configured(struct nhrp_ha_managed_state *state,
                                          struct nhrp_ha_managed_member *member,
                                          const struct in_addr *addresses,
                                          size_t address_count);
int nhrp_ha_managed_member_set_observed(struct nhrp_ha_managed_state *state,
                                        struct nhrp_ha_managed_member *member,
                                        const struct in_addr *address);
struct nhrp_ha_managed_member *
nhrp_ha_managed_member_find(struct nhrp_ha_managed_state *state,
                            const char *member);
struct nhrp_ha_managed_invite *
nhrp_ha_managed_invite_find(struct nhrp_ha_managed_state *state,
                            const uint8_t id[16]);
int nhrp_ha_managed_invite_remove(struct nhrp_ha_managed_state *state,
                                  const uint8_t id[16]);
int nhrp_ha_managed_invite_encode(const struct nhrp_ha_managed_state *state,
                                  const struct nhrp_ha_managed_invite *invite,
                                  const uint8_t secret[32],
                                  const char *identity_path, char **encoded);
int nhrp_ha_managed_invite_decode(const char *encoded,
                                  struct nhrp_ha_managed_invite_token *token);

#endif
