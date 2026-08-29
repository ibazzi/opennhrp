#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../nhrp/nhrp_ha_managed.h"

int main(void) {
  char directory[] = "/tmp/opennhrp-ha-managed-test.XXXXXX";
  char init_directory[] = "/tmp/opennhrp-ha-init-test.XXXXXX";
  char state_path[512];
  char keys_path[512];
  char identity_path[512];
  char export_path[512];
  char malformed_path[512];
  struct nhrp_ha_auth_keys keys;
  struct nhrp_ha_auth_keys exported_keys;
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_state loaded;
  struct nhrp_ha_managed_invite_token token;
  struct nhrp_ha_managed_member *member;
  struct nhrp_ha_managed_invite *invite;
  uint8_t public_key[32];
  uint8_t secret[32];
  char *encoded = NULL;
  int fd;

  {
    struct in_addr endpoints[2];

    assert(nhrp_ha_managed_endpoints_valid(NULL, 0));
    assert(inet_pton(AF_INET, "192.0.2.10", &endpoints[0]) == 1);
    assert(inet_pton(AF_INET, "198.51.100.10", &endpoints[1]) == 1);
    assert(nhrp_ha_managed_endpoints_valid(endpoints, 2));
    endpoints[1] = endpoints[0];
    assert(!nhrp_ha_managed_endpoints_valid(endpoints, 2));
    assert(inet_pton(AF_INET, "0.0.0.0", &endpoints[0]) == 1);
    assert(!nhrp_ha_managed_endpoints_valid(endpoints, 1));
    assert(inet_pton(AF_INET, "224.0.0.1", &endpoints[0]) == 1);
    assert(!nhrp_ha_managed_endpoints_valid(endpoints, 1));
  }

  {
    struct in_addr protocol;
    struct in_addr advertised;
    struct nhrp_ha_managed_state initialized;
    int lock_fd;

    assert(mkdtemp(init_directory) != NULL);
    assert(chmod(init_directory, 0755) == 0);
    lock_fd = nhrp_ha_managed_state_lock(init_directory);
    assert(lock_fd >= 0);
    nhrp_ha_managed_state_unlock(lock_fd);
    assert(chmod(init_directory, 0777) == 0);
    assert(nhrp_ha_managed_state_lock(init_directory) < 0);
    assert(chmod(init_directory, 0700) == 0);
    assert(inet_pton(AF_INET, "10.20.0.1", &protocol) == 1);
    assert(inet_pton(AF_INET, "192.0.2.10", &advertised) == 1);
    assert(nhrp_ha_managed_cluster_init(
               init_directory, "gre-ha", "hub-primary", &protocol, 24,
               &advertised, 1, &initialized) == NHRP_HA_MANAGED_INIT_OK);
    assert(strcmp(initialized.local_member, "hub-primary") == 0);
    assert(initialized.protocol_address.s_addr == protocol.s_addr);
    assert(initialized.members[0].address_count == 1);
    assert(initialized.members[0].addresses[0].s_addr == advertised.s_addr);
    assert(nhrp_ha_managed_cluster_init(init_directory, "gre-ha", "hub-primary",
                                        &protocol, 24, &advertised, 1,
                                        NULL) == NHRP_HA_MANAGED_INIT_EXISTS);
    assert(nhrp_ha_managed_paths(init_directory, state_path, sizeof(state_path),
                                 keys_path, sizeof(keys_path), identity_path,
                                 sizeof(identity_path)));
    assert(nhrp_ha_managed_state_destroy(init_directory));
    assert(access(state_path, F_OK) != 0 && access(keys_path, F_OK) != 0 &&
           access(identity_path, F_OK) != 0);
    assert(nhrp_ha_managed_cluster_init(init_directory, "gre-ha", "hub-primary",
                                        &protocol, 24, &advertised, 1,
                                        NULL) == NHRP_HA_MANAGED_INIT_OK);
    assert(unlink(keys_path) == 0);
    assert(nhrp_ha_managed_cluster_init(init_directory, "gre-ha", "hub-primary",
                                        &protocol, 24, &advertised, 1, NULL) ==
           NHRP_HA_MANAGED_INIT_INCOMPLETE);
    assert(unlink(state_path) == 0);
    assert(unlink(identity_path) == 0);
    snprintf(state_path, sizeof(state_path), "%s/.lock", init_directory);
    unlink(state_path);
    assert(rmdir(init_directory) == 0);
  }

  assert(mkdtemp(directory) != NULL);
  assert(chmod(directory, 0700) == 0);
  assert(nhrp_ha_managed_paths(directory, state_path, sizeof(state_path),
                               keys_path, sizeof(keys_path), identity_path,
                               sizeof(identity_path)));
  snprintf(export_path, sizeof(export_path), "%s/exported.keys", directory);
  snprintf(malformed_path, sizeof(malformed_path), "%s/malformed.keys",
           directory);
  memset(&keys, 0, sizeof(keys));
  assert(nhrp_ha_managed_keyring_generate(keys_path, &keys));
  assert(keys.key[0].present && !keys.key[1].present);
  assert(nhrp_ha_managed_identity_generate(identity_path, public_key));
  assert(nhrp_ha_managed_keyring_export(keys_path, export_path));
  assert(nhrp_ha_managed_keyring_load(export_path, &exported_keys));
  assert(memcmp(keys.key[0].id, exported_keys.key[0].id, 8) == 0);
  fd = open(malformed_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  assert(fd >= 0);
  assert(
      write(fd,
            "current "
            "0000000000000000000000000000000000000000000000000000000000000000\n"
            "trailing\n",
            82) == 82);
  close(fd);
  assert(!nhrp_ha_managed_keyring_load(malformed_path, &exported_keys));

  memset(&state, 0, sizeof(state));
  assert(RAND_bytes(state.cluster_id, sizeof(state.cluster_id)) == 1);
  snprintf(state.interface, sizeof(state.interface), "gre-ha");
  assert(inet_pton(AF_INET, "10.20.0.1", &state.protocol_address) == 1);
  state.prefix_length = 24;
  snprintf(state.local_member, sizeof(state.local_member), "hub-primary");
  snprintf(state.primary_member, sizeof(state.primary_member), "hub-primary");
  snprintf(state.leader, sizeof(state.leader), "hub-primary");
  state.term = 1;
  state.commit_index = 1;
  state.manifest_revision = 1;
  state.port = NHRP_HA_MANAGED_DEFAULT_PORT;
  state.member_count = 1;
  member = &state.members[0];
  snprintf(member->member, sizeof(member->member), "hub-primary");
  assert(inet_pton(AF_INET, "192.0.2.10", &member->addresses[0]) == 1);
  assert(inet_pton(AF_INET, "10.0.4.17", &member->addresses[1]) == 1);
  member->address_count = 2;
  member->configured_address_count = 2;
  member->priority = 100;
  member->state = NHRP_HA_MANAGED_ACTIVE;
  memcpy(member->public_key, public_key, 32);
  member->match_index = 1;

  {
    struct in_addr configured[2];
    struct in_addr observed;

    assert(inet_pton(AF_INET, "192.0.2.11", &configured[0]) == 1);
    assert(inet_pton(AF_INET, "10.0.4.18", &configured[1]) == 1);
    assert(nhrp_ha_managed_member_set_configured(&state, member, configured,
                                                 2) == 1);
    assert(member->configured_address_count == 2);
    assert(member->addresses[0].s_addr == configured[0].s_addr);
    assert(member->addresses[1].s_addr == configured[1].s_addr);

    assert(inet_pton(AF_INET, "198.51.100.10", &observed) == 1);
    assert(nhrp_ha_managed_member_set_observed(&state, member, &observed) == 1);
    assert(member->address_count == 3);
    assert(member->configured_address_count == 2);
    assert(member->addresses[2].s_addr == observed.s_addr);
    assert(nhrp_ha_managed_member_set_observed(&state, member, &observed) == 0);
    observed = member->addresses[0];
    assert(nhrp_ha_managed_member_set_observed(&state, member, &observed) == 1);
    assert(member->address_count == 2);

    assert(inet_pton(AF_INET, "203.0.113.10", &member->addresses[2]) == 1);
    assert(inet_pton(AF_INET, "203.0.113.11", &member->addresses[3]) == 1);
    member->address_count = 4;
    member->configured_address_count = 4;
    assert(inet_pton(AF_INET, "203.0.113.12", &observed) == 1);
    assert(nhrp_ha_managed_member_set_observed(&state, member, &observed) ==
           -1);
    memset(&member->addresses[2], 0, 2 * sizeof(member->addresses[0]));
    member->address_count = 2;
    member->configured_address_count = 2;

    state.member_count = 2;
    snprintf(state.members[1].member, sizeof(state.members[1].member),
             "hub-backup1");
    assert(inet_pton(AF_INET, "203.0.113.20", &state.members[1].addresses[0]) ==
           1);
    state.members[1].address_count = 1;
    state.members[1].configured_address_count = 1;
    observed = state.members[1].addresses[0];
    assert(nhrp_ha_managed_member_set_observed(&state, member, &observed) ==
           -2);
    assert(nhrp_ha_managed_member_remove(&state, "hub-backup1"));
    assert(state.member_count == 1 && state.members[1].member[0] == 0);
    assert(!nhrp_ha_managed_member_remove(&state, "hub-backup1"));
  }

  state.invite_count = 1;
  invite = &state.invites[0];
  assert(RAND_bytes(invite->id, sizeof(invite->id)) == 1);
  assert(RAND_bytes(secret, sizeof(secret)) == 1);
  assert(SHA256(secret, sizeof(secret), invite->secret_hash) != NULL);
  snprintf(invite->member, sizeof(invite->member), "hub-backup1");
  invite->priority = 90;
  invite->expires_at = (int64_t)time(NULL) + 600;
  invite->state = NHRP_HA_MANAGED_INVITE_UNUSED;

  state.invites[1] = *invite;
  state.invites[1].id[0] ^= 1;
  snprintf(state.invites[1].member, sizeof(state.invites[1].member),
           "expired-invite");
  state.invites[1].expires_at = (int64_t)time(NULL) - 1;
  state.invites[2] = *invite;
  state.invites[2].id[0] ^= 2;
  snprintf(state.invites[2].member, sizeof(state.invites[2].member),
           "claimed-invite");
  state.invites[2].state = NHRP_HA_MANAGED_INVITE_CLAIMED;
  state.invite_count = 3;
  {
    uint8_t expired_id[16];
    uint8_t claimed_id[16];
    struct nhrp_ha_managed_invite empty;

    memcpy(expired_id, state.invites[1].id, sizeof(expired_id));
    memcpy(claimed_id, state.invites[2].id, sizeof(claimed_id));
    memset(&empty, 0, sizeof(empty));
    assert(nhrp_ha_managed_invite_remove(&state, expired_id));
    assert(state.invite_count == 2);
    assert(strcmp(state.invites[1].member, "claimed-invite") == 0);
    assert(memcmp(&state.invites[2], &empty, sizeof(empty)) == 0);
    assert(nhrp_ha_managed_invite_remove(&state, claimed_id));
    assert(state.invite_count == 1);
    assert(memcmp(&state.invites[1], &empty, sizeof(empty)) == 0);
    assert(!nhrp_ha_managed_invite_remove(&state, expired_id));
  }

  assert(nhrp_ha_managed_state_save(state_path, &keys, &state));
  assert(nhrp_ha_managed_state_load(state_path, &keys, &loaded));
  assert(loaded.member_count == 1 && loaded.invite_count == 1);
  assert(strcmp(loaded.interface, "gre-ha") == 0);
  assert(strcmp(loaded.members[0].member, "hub-primary") == 0);
  assert(loaded.manifest_revision == 1);
  assert(loaded.witness_mode == NHRP_HA_WITNESS_LEGACY);
  state.witness_mode = NHRP_HA_WITNESS_PREPARING;
  assert(nhrp_ha_managed_state_save(state_path, &keys, &state));
  assert(nhrp_ha_managed_state_load(state_path, &keys, &loaded));
  assert(loaded.witness_mode == NHRP_HA_WITNESS_PREPARING);
  state.witness_mode = NHRP_HA_WITNESS_ACTIVE;
  assert(nhrp_ha_managed_state_save(state_path, &keys, &state));
  assert(nhrp_ha_managed_state_load(state_path, &keys, &loaded));
  assert(loaded.witness_mode == NHRP_HA_WITNESS_ACTIVE);
  state.witness_mode = NHRP_HA_WITNESS_DISABLING;
  assert(nhrp_ha_managed_state_save(state_path, &keys, &state));
  assert(nhrp_ha_managed_state_load(state_path, &keys, &loaded));
  assert(loaded.witness_mode == NHRP_HA_WITNESS_DISABLING);
  state.witness_mode = NHRP_HA_WITNESS_LEGACY;

  assert(nhrp_ha_managed_invite_encode(&state, invite, secret, identity_path,
                                       &encoded));
  assert(strncmp(encoded, "opennhrp-ha1:", 13) == 0);
  assert(nhrp_ha_managed_invite_decode(encoded, &token));
  assert(strcmp(token.member, "hub-backup1") == 0);
  assert(token.protocol_address.s_addr == state.protocol_address.s_addr);
  assert(token.leader_address_count == 2);
  assert(token.leader_addresses[0].s_addr == member->addresses[0].s_addr);
  assert(token.leader_addresses[1].s_addr == member->addresses[1].s_addr);
  assert(memcmp(token.secret, secret, sizeof(secret)) == 0);
  encoded[13 + 20] = encoded[13 + 20] == 'A' ? 'B' : 'A';
  assert(!nhrp_ha_managed_invite_decode(encoded, &token));

  nhrp_ha_auth_keys_clear(&keys);
  assert(nhrp_ha_managed_keyring_load(keys_path, &keys));
  assert(nhrp_ha_managed_keyring_prepare_rotation(keys_path, &exported_keys));
  assert(exported_keys.key[0].present && exported_keys.key[1].present);
  assert(nhrp_ha_managed_state_save(state_path, &exported_keys, &state));
  nhrp_ha_auth_keys_clear(&keys);
  keys.key[0] = exported_keys.key[1];
  assert(nhrp_ha_managed_state_save(state_path, &keys, &state));
  assert(nhrp_ha_managed_keyring_commit_rotation(keys_path));
  nhrp_ha_auth_keys_clear(&exported_keys);
  assert(nhrp_ha_managed_keyring_load(keys_path, &exported_keys));
  assert(exported_keys.key[0].present && !exported_keys.key[1].present);
  assert(nhrp_ha_managed_state_load(state_path, &exported_keys, &loaded));

  fd = open(state_path, O_WRONLY | O_APPEND);
  assert(fd >= 0 && write(fd, "x", 1) == 1);
  close(fd);
  assert(!nhrp_ha_managed_state_load(state_path, &keys, &loaded));

  free(encoded);
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_auth_keys_clear(&exported_keys);
  unlink(state_path);
  unlink(keys_path);
  unlink(identity_path);
  unlink(export_path);
  unlink(malformed_path);
  {
    char lock_path[512];
    snprintf(lock_path, sizeof(lock_path), "%s/.lock", directory);
    unlink(lock_path);
  }
  assert(rmdir(directory) == 0);
  puts("HA managed-state and invite tests passed");
  return 0;
}
