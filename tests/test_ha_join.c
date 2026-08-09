#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../nhrp/nhrp_ha_join.h"

static void paths(const char *directory, char state[512], char keys[512],
                  char identity[512]) {
  assert(
      nhrp_ha_managed_paths(directory, state, 512, keys, 512, identity, 512));
}

static void cleanup(const char *directory) {
  char state[512];
  char keys[512];
  char identity[512];
  char lock[512];

  paths(directory, state, keys, identity);
  snprintf(lock, sizeof(lock), "%s/.lock", directory);
  unlink(state);
  unlink(keys);
  unlink(identity);
  unlink(lock);
  assert(rmdir(directory) == 0);
}

int main(void) {
  char primary_directory[] = "/tmp/opennhrp-ha-join-primary.XXXXXX";
  char backup_directory[] = "/tmp/opennhrp-ha-join-backup.XXXXXX";
  char primary_state_path[512];
  char primary_keys_path[512];
  char primary_identity_path[512];
  char backup_state_path[512];
  char backup_keys_path[512];
  char backup_identity_path[512];
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_state loaded;
  struct nhrp_ha_managed_member *primary;
  struct nhrp_ha_managed_invite *invite;
  struct nhrp_ha_managed_invite_token token;
  struct nhrp_ha_auth_keys keys;
  uint8_t primary_public[32];
  uint8_t secret[32];
  struct in_addr advertised;
  char *encoded = NULL;
  struct sockaddr_in listen_address;
  struct sockaddr_in client_address;
  socklen_t listen_length = sizeof(listen_address);
  int listener;
  int client;
  pid_t child;
  int status;

  assert(mkdtemp(primary_directory) != NULL);
  assert(mkdtemp(backup_directory) != NULL);
  assert(chmod(primary_directory, 0700) == 0);
  assert(chmod(backup_directory, 0700) == 0);
  listener = socket(AF_INET, SOCK_STREAM, 0);
  if (listener < 0 && errno == EPERM) {
    cleanup(primary_directory);
    cleanup(backup_directory);
    puts("HA encrypted online-join socket test skipped by sandbox");
    return 0;
  }
  assert(listener >= 0);
  memset(&listen_address, 0, sizeof(listen_address));
  listen_address.sin_family = AF_INET;
  listen_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  assert(bind(listener, (struct sockaddr *)&listen_address,
              sizeof(listen_address)) == 0);
  assert(listen(listener, 1) == 0);
  assert(getsockname(listener, (struct sockaddr *)&listen_address,
                     &listen_length) == 0);
  paths(primary_directory, primary_state_path, primary_keys_path,
        primary_identity_path);
  paths(backup_directory, backup_state_path, backup_keys_path,
        backup_identity_path);
  memset(&keys, 0, sizeof(keys));
  assert(nhrp_ha_managed_keyring_generate(primary_keys_path, &keys));
  assert(
      nhrp_ha_managed_identity_generate(primary_identity_path, primary_public));

  memset(&state, 0, sizeof(state));
  assert(RAND_bytes(state.cluster_id, sizeof(state.cluster_id)) == 1);
  snprintf(state.interface, sizeof(state.interface), "gre-primary");
  assert(inet_pton(AF_INET, "10.20.0.1", &state.protocol_address) == 1);
  state.prefix_length = 24;
  snprintf(state.local_member, sizeof(state.local_member), "hub-primary");
  snprintf(state.primary_member, sizeof(state.primary_member), "hub-primary");
  snprintf(state.leader, sizeof(state.leader), "hub-primary");
  state.term = 1;
  state.commit_index = 1;
  state.manifest_revision = 1;
  state.witness_mode = NHRP_HA_WITNESS_ACTIVE;
  state.port = NHRP_HA_MANAGED_DEFAULT_PORT;
  state.member_count = 1;
  primary = &state.members[0];
  snprintf(primary->member, sizeof(primary->member), "hub-primary");
  assert(inet_pton(AF_INET, "127.0.0.1", &primary->addresses[0]) == 1);
  primary->address_count = 1;
  primary->configured_address_count = 1;
  primary->priority = 100;
  primary->state = NHRP_HA_MANAGED_ACTIVE;
  memcpy(primary->public_key, primary_public, 32);
  primary->match_index = 1;
  state.invite_count = 1;
  invite = &state.invites[0];
  assert(RAND_bytes(invite->id, sizeof(invite->id)) == 1);
  assert(RAND_bytes(secret, sizeof(secret)) == 1);
  assert(SHA256(secret, sizeof(secret), invite->secret_hash) != NULL);
  snprintf(invite->member, sizeof(invite->member), "hub-backup1");
  invite->priority = 90;
  invite->expires_at = (int64_t)time(NULL) + 600;
  assert(nhrp_ha_managed_state_save(primary_state_path, &keys, &state));
  assert(nhrp_ha_managed_invite_encode(&state, invite, secret,
                                       primary_identity_path, &encoded));
  assert(nhrp_ha_managed_invite_decode(encoded, &token));

  child = fork();
  assert(child >= 0);
  if (child == 0) {
    int accepted;
    int ok;

    accepted = accept(listener, NULL, NULL);
    ok = accepted >= 0 && nhrp_ha_join_server(accepted, primary_directory);
    if (accepted >= 0)
      close(accepted);
    close(listener);
    _exit(ok ? 0 : 1);
  }
  client = socket(AF_INET, SOCK_STREAM, 0);
  assert(client >= 0);
  memset(&client_address, 0, sizeof(client_address));
  client_address.sin_family = AF_INET;
  assert(inet_pton(AF_INET, "127.0.0.3", &client_address.sin_addr) == 1);
  assert(bind(client, (struct sockaddr *)&client_address,
              sizeof(client_address)) == 0);
  assert(connect(client, (struct sockaddr *)&listen_address,
                 sizeof(listen_address)) == 0);
  close(listener);
  assert(inet_pton(AF_INET, "127.0.0.2", &advertised) == 1);
  assert(nhrp_ha_join_client_fd(client, &token, "gre-backup", &advertised, 1,
                                backup_directory));
  close(client);
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);

  nhrp_ha_auth_keys_clear(&keys);
  assert(nhrp_ha_managed_keyring_load(backup_keys_path, &keys));
  assert(nhrp_ha_managed_state_load(backup_state_path, &keys, &loaded));
  assert(strcmp(loaded.interface, "gre-backup") == 0);
  assert(strcmp(loaded.local_member, "hub-backup1") == 0);
  assert(loaded.member_count == 2);
  assert(loaded.members[1].state == NHRP_HA_MANAGED_LEARNER);
  assert(loaded.members[1].address_count == 2);
  assert(loaded.members[1].configured_address_count == 1);
  assert(loaded.members[1].addresses[0].s_addr == advertised.s_addr);
  assert(inet_pton(AF_INET, "127.0.0.3", &advertised) == 1);
  assert(loaded.members[1].addresses[1].s_addr == advertised.s_addr);
  assert(access(backup_identity_path, F_OK) == 0);

  nhrp_ha_auth_keys_clear(&keys);
  assert(nhrp_ha_managed_keyring_load(primary_keys_path, &keys));
  assert(nhrp_ha_managed_state_load(primary_state_path, &keys, &loaded));
  assert(loaded.invites[0].state == NHRP_HA_MANAGED_INVITE_CLAIMED);
  assert(loaded.member_count == 2 && loaded.manifest_revision == 2);

  free(encoded);
  nhrp_ha_auth_keys_clear(&keys);
  cleanup(primary_directory);
  cleanup(backup_directory);
  puts("HA encrypted online-join tests passed");
  return 0;
}
