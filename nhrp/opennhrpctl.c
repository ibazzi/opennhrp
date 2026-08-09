/* opennhrpctl.c - OpenNHRP command line control utility */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "nhrp_ha_join.h"
#include "nhrp_ha_managed.h"
#include "nhrp_ha_seen.h"
#include "nhrp_ha_store.h"

static int admin_init(const char *opennhrp_socket) {
  struct sockaddr_un address;
  int fd;

  if (strlen(opennhrp_socket) >= sizeof(address.sun_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "%s", opennhrp_socket);
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int admin_send(int fd, const char *string) {
  size_t length = strlen(string);
  size_t offset = 0;

  while (offset < length) {
    ssize_t written = write(fd, string + offset, length - offset);

    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return -1;
    offset += (size_t)written;
  }
  shutdown(fd, SHUT_WR);
  return 0;
}

static int admin_receive(int fd) {
  char message[512];
  ssize_t length;

  while ((length = recv(fd, message, sizeof(message), 0)) > 0) {
    size_t offset = 0;

    while (offset < (size_t)length) {
      ssize_t written =
          write(STDOUT_FILENO, message + offset, (size_t)length - offset);

      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0)
        return -1;
      offset += (size_t)written;
    }
  }
  return length < 0 ? -1 : 0;
}

static const char *option_value(int argc, char **argv, const char *name) {
  int i;

  for (i = 1; i + 1 < argc; i++)
    if (strcmp(argv[i], name) == 0)
      return argv[i + 1];
  return NULL;
}

static const char *managed_directory(int argc, char **argv) {
  const char *directory = option_value(argc, argv, "--state-dir");

  if (directory == NULL)
    directory = getenv("OPENNHRP_HA_STATE_DIR");
  return directory != NULL ? directory : NHRP_HA_MANAGED_DEFAULT_DIR;
}

static int managed_paths(int argc, char **argv, char state_path[4096],
                         char keys_path[4096], char identity_path[4096]) {
  return nhrp_ha_managed_paths(managed_directory(argc, argv), state_path, 4096,
                               keys_path, 4096, identity_path, 4096);
}

static int duration_seconds(const char *text, int64_t *seconds) {
  char *end;
  long long value;
  int64_t multiplier = 1;

  if (text == NULL || text[0] == 0)
    return 0;
  errno = 0;
  value = strtoll(text, &end, 10);
  if (errno != 0 || end == text || value <= 0)
    return 0;
  if (*end != 0) {
    if (end[1] != 0)
      return 0;
    if (*end == 'm')
      multiplier = 60;
    else if (*end == 'h')
      multiplier = 3600;
    else if (*end == 'd')
      multiplier = 86400;
    else if (*end != 's')
      return 0;
  }
  if (value > INT64_MAX / multiplier)
    return 0;
  *seconds = value * multiplier;
  return 1;
}

static int integer_value(const char *text, long minimum, long maximum,
                         long *value) {
  char *end;
  long parsed;

  if (text == NULL || text[0] == 0)
    return 0;
  errno = 0;
  parsed = strtol(text, &end, 10);
  if (errno != 0 || end == text || *end != 0 || parsed < minimum ||
      parsed > maximum)
    return 0;
  *value = parsed;
  return 1;
}

static int prefix_from_mask(struct sockaddr *netmask, uint8_t *prefix) {
  uint32_t mask;
  uint32_t host;
  int seen_zero = 0;
  unsigned int bits = 0;
  int i;

  if (netmask == NULL || netmask->sa_family != AF_INET)
    return 0;
  mask = ((struct sockaddr_in *)netmask)->sin_addr.s_addr;
  host = ntohl(mask);
  for (i = 31; i >= 0; i--) {
    if ((host & (1U << i)) != 0) {
      if (seen_zero)
        return 0;
      bits++;
    } else {
      seen_zero = 1;
    }
  }
  *prefix = (uint8_t)bits;
  return 1;
}

static int interface_ipv4(const char *interface, struct in_addr *address,
                          uint8_t *prefix) {
  struct ifaddrs *addresses = NULL;
  struct ifaddrs *entry;
  size_t count = 0;
  int ok = 0;

  if (interface == NULL || interface[0] == 0 || strlen(interface) >= IFNAMSIZ ||
      getifaddrs(&addresses) != 0)
    return 0;
  for (entry = addresses; entry != NULL; entry = entry->ifa_next) {
    struct sockaddr_in *socket_address;
    uint32_t host;
    uint8_t candidate_prefix;

    if (entry->ifa_addr == NULL || entry->ifa_addr->sa_family != AF_INET ||
        strcmp(entry->ifa_name, interface) != 0 ||
        (entry->ifa_flags & IFF_UP) == 0 ||
        !prefix_from_mask(entry->ifa_netmask, &candidate_prefix))
      continue;
    socket_address = (struct sockaddr_in *)entry->ifa_addr;
    host = ntohl(socket_address->sin_addr.s_addr);
    if (host == INADDR_ANY || (host & 0xffff0000U) == 0xa9fe0000U ||
        (host & 0xf0000000U) == 0xe0000000U)
      continue;
    count++;
    *address = socket_address->sin_addr;
    *prefix = candidate_prefix;
  }
  ok = count == 1;
  freeifaddrs(addresses);
  return ok;
}

static int ipv4_unicast(const char *text, struct in_addr *address) {
  uint32_t host;

  if (text == NULL || inet_pton(AF_INET, text, address) != 1)
    return 0;
  host = ntohl(address->s_addr);
  return host != INADDR_ANY && (host & 0xf0000000U) != 0xe0000000U;
}

static int option_ipv4_values(int argc, char **argv, const char *name,
                              struct in_addr *addresses, size_t *count) {
  int i;

  *count = 0;
  for (i = 1; i < argc; i++) {
    size_t j;

    if (strcmp(argv[i], name) != 0)
      continue;
    if (i + 1 >= argc || *count >= NHRP_HA_MANAGED_MAX_ENDPOINTS ||
        !ipv4_unicast(argv[i + 1], &addresses[*count]))
      return 0;
    for (j = 0; j < *count; j++)
      if (addresses[j].s_addr == addresses[*count].s_addr)
        return 0;
    (*count)++;
    i++;
  }
  return 1;
}

static int state_load(int argc, char **argv,
                      struct nhrp_ha_managed_state *state,
                      struct nhrp_ha_auth_keys *keys, char state_path[4096],
                      char keys_path[4096], char identity_path[4096]) {
  if (!managed_paths(argc, argv, state_path, keys_path, identity_path) ||
      !nhrp_ha_managed_keyring_load(keys_path, keys) ||
      !nhrp_ha_managed_state_load(state_path, keys, state)) {
    fprintf(stderr, "failed to load managed HA state from %s\n",
            managed_directory(argc, argv));
    return 0;
  }
  return 1;
}

static int command_cluster_init(int argc, char **argv) {
  const char *interface = option_value(argc, argv, "--interface");
  const char *member_id = option_value(argc, argv, "--member-id");
  const char *format = option_value(argc, argv, "--format");
  struct nhrp_ha_managed_state state;
  struct in_addr protocol;
  struct in_addr advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t advertised_count;
  uint8_t prefix = 0;
  enum nhrp_ha_managed_init_result result;

  if (format == NULL)
    format = "human";
  if (!nhrp_ha_managed_member_valid(member_id) ||
      !option_ipv4_values(argc, argv, "--advertise-address", advertised,
                          &advertised_count) ||
      advertised_count == 0 || !interface_ipv4(interface, &protocol, &prefix)) {
    fprintf(stderr, "ha cluster init requires one IPv4 on --interface, a valid "
                    "--member-id, and --advertise-address\n");
    return 2;
  }
  if (strcmp(format, "human") != 0 && strcmp(format, "json") != 0) {
    fprintf(stderr, "invalid --format; expected human or json\n");
    return 2;
  }
  result = nhrp_ha_managed_cluster_init(managed_directory(argc, argv),
                                        interface, member_id, &protocol, prefix,
                                        advertised, advertised_count, &state);
  if (result != NHRP_HA_MANAGED_INIT_OK) {
    if (result == NHRP_HA_MANAGED_INIT_EXISTS)
      fprintf(stderr, "HA is already initialized; refusing to overwrite %s\n",
              managed_directory(argc, argv));
    else if (result == NHRP_HA_MANAGED_INIT_INCOMPLETE)
      fprintf(stderr, "managed HA state is incomplete in %s\n",
              managed_directory(argc, argv));
    else if (result == NHRP_HA_MANAGED_INIT_LOCK_FAILED)
      fprintf(stderr, "failed to lock managed HA directory\n");
    else
      fprintf(stderr, "failed to initialize managed HA state\n");
    return 1;
  }
  if (strcmp(format, "json") == 0) {
    char protocol_text[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &protocol, protocol_text, sizeof(protocol_text));
    printf("{\"action\":\"ha.cluster.init\",\"success\":true,"
           "\"member\":\"%s\",\"interface\":\"%s\","
           "\"protocol\":\"%s/%u\",\"state_dir\":\"%s\"}\n",
           member_id, interface, protocol_text, prefix,
           managed_directory(argc, argv));
  } else {
    char protocol_text[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &protocol, protocol_text, sizeof(protocol_text));
    printf("HA cluster initialized.\nMember:   %s\nProtocol: %s/%u\nState:    "
           "%s\n",
           member_id, protocol_text, prefix, managed_directory(argc, argv));
  }
  return 0;
}

static void id_format(const uint8_t id[16], char output[33]) {
  static const char digits[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < 16; i++) {
    output[i * 2] = digits[id[i] >> 4];
    output[i * 2 + 1] = digits[id[i] & 15];
  }
  output[32] = 0;
}

static int command_invite_create(int argc, char **argv) {
  const char *member_id = option_value(argc, argv, "--member-id");
  const char *priority_text = option_value(argc, argv, "--priority");
  const char *expires_text = option_value(argc, argv, "--expires");
  const char *format = option_value(argc, argv, "--format");
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_invite *invite;
  struct nhrp_ha_auth_keys keys;
  uint8_t secret[32];
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  char *encoded = NULL;
  int64_t expires;
  long priority = 90;
  int lock_fd = -1;
  int result = 1;
  int64_t now;
  size_t i;
  size_t invite_index;

  if (format == NULL)
    format = "plain";
  if (!nhrp_ha_managed_member_valid(member_id) ||
      (priority_text != NULL &&
       !integer_value(priority_text, 1, INT32_MAX, &priority)) ||
      !duration_seconds(expires_text != NULL ? expires_text : "10m",
                        &expires) ||
      strcmp(format, "plain") != 0) {
    fprintf(stderr, "ha invite create requires --member-id and valid optional "
                    "--priority/--expires/--format\n");
    return 2;
  }
  lock_fd = nhrp_ha_managed_state_lock(managed_directory(argc, argv));
  if (lock_fd < 0 || !state_load(argc, argv, &state, &keys, state_path,
                                 keys_path, identity_path))
    goto done;
  if (strcmp(state.local_member, state.leader) != 0) {
    fprintf(stderr, "only the current Leader can create an Invite\n");
    goto done;
  }
  if (nhrp_ha_managed_member_find(&state, member_id) != NULL) {
    fprintf(stderr, "member %s already exists\n", member_id);
    goto done;
  }
  now = (int64_t)time(NULL);
  invite_index = state.invite_count;
  for (i = 0; i < state.invite_count; i++)
    if (strcmp(state.invites[i].member, member_id) == 0 &&
        state.invites[i].state != NHRP_HA_MANAGED_INVITE_REVOKED) {
      if (state.invites[i].state == NHRP_HA_MANAGED_INVITE_UNUSED &&
          state.invites[i].expires_at <= now) {
        invite_index = i;
        break;
      }
      fprintf(stderr, "an active Invite already exists for %s\n", member_id);
      goto done;
    }
  if (invite_index == state.invite_count &&
      state.invite_count >= NHRP_HA_MANAGED_MAX_INVITES) {
    fprintf(stderr, "Invite table is full\n");
    goto done;
  }
  invite = &state.invites[invite_index];
  memset(invite, 0, sizeof(*invite));
  if (RAND_bytes(invite->id, sizeof(invite->id)) != 1 ||
      RAND_bytes(secret, sizeof(secret)) != 1 ||
      SHA256(secret, sizeof(secret), invite->secret_hash) == NULL)
    goto done;
  snprintf(invite->member, sizeof(invite->member), "%s", member_id);
  invite->priority = (uint32_t)priority;
  invite->expires_at = now + expires;
  if (!nhrp_ha_managed_invite_encode(&state, invite, secret, identity_path,
                                     &encoded))
    goto done;
  if (invite_index == state.invite_count)
    state.invite_count++;
  state.commit_index++;
  state.manifest_revision++;
  if (!nhrp_ha_managed_state_save(state_path, &keys, &state))
    goto done;
  printf("%s\n", encoded);
  result = 0;

done:
  free(encoded);
  OPENSSL_cleanse(secret, sizeof(secret));
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return result;
}

static const char *
invite_state_name(const struct nhrp_ha_managed_invite *invite, int64_t now) {
  if (invite->state == NHRP_HA_MANAGED_INVITE_REVOKED)
    return "revoked";
  if (invite->state == NHRP_HA_MANAGED_INVITE_CLAIMED)
    return "claimed";
  return invite->expires_at <= now ? "expired" : "unused";
}

static int command_invite_list(int argc, char **argv) {
  const char *format = option_value(argc, argv, "--format");
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_auth_keys keys;
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  int64_t now = (int64_t)time(NULL);
  size_t i;

  if (!state_load(argc, argv, &state, &keys, state_path, keys_path,
                  identity_path))
    return 1;
  if (format != NULL && strcmp(format, "json") == 0)
    printf("{\"invites\":[");
  for (i = 0; i < state.invite_count; i++) {
    char id[33];

    id_format(state.invites[i].id, id);
    if (format != NULL && strcmp(format, "json") == 0)
      printf("%s{\"id_prefix\":\"%.12s\",\"member\":\"%s\","
             "\"priority\":%u,\"expires_at\":%lld,\"state\":\"%s\"}",
             i == 0 ? "" : ",", id, state.invites[i].member,
             state.invites[i].priority, (long long)state.invites[i].expires_at,
             invite_state_name(&state.invites[i], now));
    else
      printf("%.12s %-24s priority=%u state=%s expires=%lld\n", id,
             state.invites[i].member, state.invites[i].priority,
             invite_state_name(&state.invites[i], now),
             (long long)state.invites[i].expires_at);
  }
  if (format != NULL && strcmp(format, "json") == 0)
    puts("]}");
  nhrp_ha_auth_keys_clear(&keys);
  return 0;
}

static int command_invite_remove(int argc, char **argv, int do_delete) {
  const char *prefix = option_value(argc, argv, "--id-prefix");
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_invite *found = NULL;
  struct nhrp_ha_auth_keys keys;
  char member[64];
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  int lock_fd = -1;
  size_t i;
  size_t prefix_length;

  prefix_length = prefix != NULL ? strlen(prefix) : 0;
  if (prefix_length < 6 || prefix_length > 32) {
    fprintf(stderr, "ha invite %s requires --id-prefix of 6-32 hex chars\n",
            do_delete ? "delete" : "revoke");
    return 2;
  }
  for (i = 0; i < prefix_length; i++)
    if ((prefix[i] < '0' || prefix[i] > '9') &&
        (prefix[i] < 'a' || prefix[i] > 'f')) {
      fprintf(stderr, "Invite prefix must use lowercase hexadecimal\n");
      return 2;
    }
  lock_fd = nhrp_ha_managed_state_lock(managed_directory(argc, argv));
  if (lock_fd < 0 || !state_load(argc, argv, &state, &keys, state_path,
                                 keys_path, identity_path))
    goto failed;
  for (i = 0; i < state.invite_count; i++) {
    char id[33];

    id_format(state.invites[i].id, id);
    if (strncmp(id, prefix, prefix_length) != 0)
      continue;
    if (found != NULL) {
      fprintf(stderr, "Invite prefix is ambiguous\n");
      goto failed;
    }
    found = &state.invites[i];
  }
  if (found == NULL) {
    fprintf(stderr, "Invite not found\n");
    goto failed;
  }
  if (!do_delete && found->state == NHRP_HA_MANAGED_INVITE_CLAIMED) {
    fprintf(stderr, "claimed Invite cannot be revoked\n");
    goto failed;
  }
  snprintf(member, sizeof(member), "%s", found->member);
  if (do_delete) {
    if (strcmp(state.local_member, state.leader) != 0) {
      fprintf(stderr, "only the current Leader can delete an Invite\n");
      goto failed;
    }
    if (!nhrp_ha_managed_invite_remove(&state, found->id))
      goto failed;
  } else {
    found->state = NHRP_HA_MANAGED_INVITE_REVOKED;
  }
  state.commit_index++;
  state.manifest_revision++;
  if (!nhrp_ha_managed_state_save(state_path, &keys, &state))
    goto failed;
  printf("Invite for %s %s.\n", member, do_delete ? "deleted" : "revoked");
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return 0;

failed:
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return 1;
}

static int command_members_show(int argc, char **argv) {
  const char *format = option_value(argc, argv, "--format");
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_auth_keys keys;
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  size_t i;

  if (!state_load(argc, argv, &state, &keys, state_path, keys_path,
                  identity_path))
    return 1;
  if (format != NULL && strcmp(format, "json") == 0)
    printf("{\"primary\":\"%s\",\"leader\":\"%s\",\"term\":%llu,"
           "\"manifest_revision\":%llu,\"members\":[",
           state.primary_member, state.leader, (unsigned long long)state.term,
           (unsigned long long)state.manifest_revision);
  for (i = 0; i < state.member_count; i++) {
    size_t j;
    const char *state_name =
        state.members[i].state == NHRP_HA_MANAGED_ACTIVE    ? "active"
        : state.members[i].state == NHRP_HA_MANAGED_LEARNER ? "learner"
                                                            : "disabled";

    if (format != NULL && strcmp(format, "json") == 0) {
      printf("%s{\"member\":\"%s\",\"addresses\":[", i == 0 ? "" : ",",
             state.members[i].member);
      for (j = 0; j < state.members[i].address_count; j++) {
        char address[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &state.members[i].addresses[j], address,
                  sizeof(address));
        printf("%s{\"address\":\"%s\",\"origin\":\"%s\"}", j == 0 ? "" : ",",
               address,
               j < state.members[i].configured_address_count ? "configured"
                                                             : "observed");
      }
      printf("],\"priority\":%u,\"state\":\"%s\",\"match_index\":%llu}",
             state.members[i].priority, state_name,
             (unsigned long long)state.members[i].match_index);
    } else {
      printf("%-24s ", state.members[i].member);
      for (j = 0; j < state.members[i].address_count; j++) {
        char address[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &state.members[i].addresses[j], address,
                  sizeof(address));
        printf("%s%s(%s)", j == 0 ? "" : ",", address,
               j < state.members[i].configured_address_count ? "configured"
                                                             : "observed");
      }
      printf(
          " priority=%u state=%s match=%llu%s%s\n", state.members[i].priority,
          state_name, (unsigned long long)state.members[i].match_index,
          strcmp(state.members[i].member, state.primary_member) == 0
              ? " primary"
              : "",
          strcmp(state.members[i].member, state.leader) == 0 ? " leader" : "");
    }
  }
  if (format != NULL && strcmp(format, "json") == 0)
    puts("]}");
  nhrp_ha_auth_keys_clear(&keys);
  return 0;
}

static int command_member_change(int argc, char **argv, const char *action) {
  const char *member_id = argc > 4 ? argv[4] : NULL;
  const char *priority_text = option_value(argc, argv, "--priority");
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_managed_member *member;
  struct nhrp_ha_auth_keys keys;
  struct in_addr addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t address_count;
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  char changed_member[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  long priority = 0;
  int lock_fd = -1;
  size_t index;

  if (!nhrp_ha_managed_member_valid(member_id) ||
      (priority_text != NULL &&
       !integer_value(priority_text, 1, INT32_MAX, &priority)) ||
      !option_ipv4_values(argc, argv, "--advertise-address", addresses,
                          &address_count)) {
    fprintf(stderr, "invalid member ID, priority, or advertised address\n");
    return 2;
  }
  lock_fd = nhrp_ha_managed_state_lock(managed_directory(argc, argv));
  if (lock_fd < 0 || !state_load(argc, argv, &state, &keys, state_path,
                                 keys_path, identity_path))
    goto failed;
  if (strcmp(state.local_member, state.leader) != 0) {
    fprintf(stderr, "only the current Leader can update membership\n");
    goto failed;
  }
  member = nhrp_ha_managed_member_find(&state, member_id);
  if (member == NULL) {
    fprintf(stderr, "member %s not found\n", member_id);
    goto failed;
  }
  snprintf(changed_member, sizeof(changed_member), "%s", member->member);
  if (strcmp(action, "set") == 0) {
    if (priority_text == NULL && address_count == 0) {
      fprintf(stderr,
              "ha member set requires --priority or --advertise-address\n");
      goto failed;
    }
    if (priority_text != NULL)
      member->priority = (uint32_t)priority;
    if (address_count != 0) {
      int changed = nhrp_ha_managed_member_set_configured(
          &state, member, addresses, address_count);

      if (changed < 0) {
        fprintf(stderr, "invalid or duplicate advertised address\n");
        goto failed;
      }
    }
  } else if (strcmp(action, "disable") == 0) {
    if (strcmp(member->member, state.leader) == 0) {
      fprintf(stderr, "the current Leader must transfer leadership first\n");
      goto failed;
    }
    member->state = NHRP_HA_MANAGED_DISABLED;
  } else if (strcmp(action, "enable") == 0) {
    if (member->state != NHRP_HA_MANAGED_DISABLED) {
      fprintf(stderr, "member must be disabled before it can be enabled\n");
      goto failed;
    }
    member->state = NHRP_HA_MANAGED_LEARNER;
  } else if (strcmp(action, "remove") == 0) {
    if (member->state != NHRP_HA_MANAGED_DISABLED ||
        strcmp(member->member, state.local_member) == 0 ||
        strcmp(member->member, state.primary_member) == 0 ||
        strcmp(member->member, state.leader) == 0) {
      fprintf(stderr,
              "member must be disabled and cannot be local, Primary, or "
              "Leader\n");
      goto failed;
    }
    index = (size_t)(member - state.members);
    memmove(&state.members[index], &state.members[index + 1],
            (state.member_count - index - 1) * sizeof(state.members[0]));
    state.member_count--;
    memset(&state.members[state.member_count], 0, sizeof(state.members[0]));
  } else {
    goto failed;
  }
  state.manifest_revision++;
  state.commit_index++;
  if (!nhrp_ha_managed_state_save(state_path, &keys, &state))
    goto failed;
  printf("Member %s %s completed.\n", changed_member, action);
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return 0;

failed:
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return 1;
}

static int command_key_export(int argc, char **argv) {
  const char *output = option_value(argc, argv, "--output");
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];

  if (output == NULL || output[0] != '/' ||
      !managed_paths(argc, argv, state_path, keys_path, identity_path)) {
    fprintf(stderr, "ha key export-spoke requires absolute --output FILE\n");
    return 2;
  }
  if (!nhrp_ha_managed_keyring_export(keys_path, output)) {
    fprintf(stderr, "failed to export keyring; destination must not exist\n");
    return 1;
  }
  printf("Spoke keyring exported to %s\n", output);
  return 0;
}

static int resign_auxiliary_state(const char *directory,
                                  const struct nhrp_ha_auth_keys *old_keys,
                                  const struct nhrp_ha_auth_keys *new_keys,
                                  const struct nhrp_ha_managed_state *managed) {
  struct nhrp_ha_store_record registrations;
  struct nhrp_ha_seen_state seen;
  char path[4096];

  snprintf(path, sizeof(path), "%s/registrations.state", directory);
  memset(&registrations, 0, sizeof(registrations));
  if (access(path, F_OK) == 0) {
    if (!nhrp_ha_store_load(path, old_keys, managed->cluster_id,
                            &registrations) ||
        !nhrp_ha_store_save(path, new_keys, &registrations)) {
      nhrp_ha_store_record_clear(&registrations);
      return 0;
    }
    nhrp_ha_store_record_clear(&registrations);
  }
  snprintf(path, sizeof(path), "%s/seen.state", directory);
  if (access(path, F_OK) == 0) {
    if (!nhrp_ha_seen_load(path, old_keys, managed->cluster_id, &seen) ||
        (seen.term != 0 && !nhrp_ha_seen_save(path, new_keys, &seen)))
      return 0;
  }
  return 1;
}

static int command_key_rotate(int argc, char **argv) {
  const char *action = argc > 4 ? argv[4] : NULL;
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_auth_keys keys;
  struct nhrp_ha_auth_keys rotated;
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  int lock_fd = -1;
  int result = 1;

  memset(&keys, 0, sizeof(keys));
  memset(&rotated, 0, sizeof(rotated));
  if (action == NULL ||
      (strcmp(action, "prepare") != 0 && strcmp(action, "commit") != 0)) {
    fprintf(stderr, "ha key rotate requires prepare or commit\n");
    return 2;
  }
  lock_fd = nhrp_ha_managed_state_lock(managed_directory(argc, argv));
  if (lock_fd < 0 || !state_load(argc, argv, &state, &keys, state_path,
                                 keys_path, identity_path))
    goto done;
  if (strcmp(action, "prepare") == 0) {
    if (keys.key[1].present ||
        !nhrp_ha_managed_keyring_prepare_rotation(keys_path, &rotated) ||
        !nhrp_ha_managed_state_save(state_path, &rotated, &state) ||
        !resign_auxiliary_state(managed_directory(argc, argv), &keys, &rotated,
                                &state)) {
      fprintf(stderr, "failed to prepare key rotation\n");
      goto done;
    }
    printf(
        "Next HA key generated. Export and deploy the updated keyring before "
        "commit.\n");
  } else {
    if (!keys.key[1].present) {
      fprintf(stderr, "no next key is prepared\n");
      goto done;
    }
    rotated.key[0] = keys.key[1];
    memset(&rotated.key[1], 0, sizeof(rotated.key[1]));
    if (!nhrp_ha_managed_state_save(state_path, &rotated, &state) ||
        !resign_auxiliary_state(managed_directory(argc, argv), &keys, &rotated,
                                &state) ||
        !nhrp_ha_managed_keyring_commit_rotation(keys_path)) {
      fprintf(stderr, "failed to commit key rotation\n");
      goto done;
    }
    printf("Next HA key promoted to current.\n");
  }
  result = 0;

done:
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_auth_keys_clear(&rotated);
  nhrp_ha_managed_state_unlock(lock_fd);
  return result;
}

static int invite_read(char **value) {
  char input[2048];
  struct termios original;
  struct termios hidden;
  int tty = isatty(STDIN_FILENO);
  int changed = 0;

  if (tty) {
    fprintf(stderr, "Invite ID: ");
    fflush(stderr);
    if (tcgetattr(STDIN_FILENO, &original) == 0) {
      hidden = original;
      hidden.c_lflag &= (tcflag_t)~ECHO;
      if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0)
        changed = 1;
    }
  }
  if (fgets(input, sizeof(input), stdin) == NULL) {
    if (changed)
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
    return 0;
  }
  if (changed)
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
  if (tty)
    fputc('\n', stderr);
  input[strcspn(input, "\r\n")] = 0;
  if (input[0] == 0)
    return 0;
  *value = strdup(input);
  OPENSSL_cleanse(input, sizeof(input));
  return *value != NULL;
}

static int command_join(int argc, char **argv) {
  const char *interface = option_value(argc, argv, "--interface");
  struct nhrp_ha_managed_invite_token token;
  struct in_addr protocol;
  struct in_addr advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t advertised_count;
  uint8_t prefix = 0;
  char *encoded = NULL;
  char protocol_text[INET_ADDRSTRLEN];
  int result = 1;

  memset(&token, 0, sizeof(token));
  if (interface == NULL || !interface_ipv4(interface, &protocol, &prefix) ||
      !option_ipv4_values(argc, argv, "--advertise-address", advertised,
                          &advertised_count)) {
    fprintf(stderr, "ha join requires --interface with exactly one IPv4 and an "
                    "optional valid --advertise-address\n");
    return 2;
  }
  if (!invite_read(&encoded) ||
      !nhrp_ha_managed_invite_decode(encoded, &token)) {
    fprintf(stderr, "invalid Invite ID\n");
    goto done;
  }
  if (token.expires_at < (int64_t)time(NULL)) {
    fprintf(stderr, "Invite ID has expired\n");
    goto done;
  }
  if (protocol.s_addr != token.protocol_address.s_addr ||
      prefix != token.prefix_length) {
    inet_ntop(AF_INET, &token.protocol_address, protocol_text,
              sizeof(protocol_text));
    fprintf(stderr,
            "interface %s address does not match invited protocol %s/%u\n",
            interface, protocol_text, token.prefix_length);
    goto done;
  }
  if (!nhrp_ha_join_client(&token, interface,
                           advertised_count != 0 ? advertised : NULL,
                           advertised_count, managed_directory(argc, argv))) {
    fprintf(stderr, "online HA enrollment failed\n");
    goto done;
  }
  printf("Hub %s joined the HA cluster.\nState: %s\n", token.member,
         managed_directory(argc, argv));
  result = 0;

done:
  if (encoded != NULL) {
    OPENSSL_cleanse(encoded, strlen(encoded));
    free(encoded);
  }
  OPENSSL_cleanse(&token, sizeof(token));
  return result;
}

static int local_command(int argc, char **argv) {
  if (argc >= 4 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "cluster") == 0 && strcmp(argv[3], "init") == 0)
    return command_cluster_init(argc, argv);
  if (argc >= 4 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "invite") == 0 && strcmp(argv[3], "create") == 0)
    return command_invite_create(argc, argv);
  if (argc >= 4 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "invite") == 0 && strcmp(argv[3], "list") == 0)
    return command_invite_list(argc, argv);
  if (argc >= 4 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "invite") == 0 && strcmp(argv[3], "revoke") == 0)
    return command_invite_remove(argc, argv, 0);
  if (argc >= 4 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "invite") == 0 && strcmp(argv[3], "delete") == 0)
    return command_invite_remove(argc, argv, 1);
  if (argc >= 4 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "members") == 0 && strcmp(argv[3], "show") == 0)
    return command_members_show(argc, argv);
  if (argc >= 5 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "member") == 0 && strcmp(argv[3], "set") == 0)
    return command_member_change(argc, argv, "set");
  if (argc >= 5 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "member") == 0 && strcmp(argv[3], "disable") == 0)
    return command_member_change(argc, argv, "disable");
  if (argc >= 5 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "member") == 0 && strcmp(argv[3], "enable") == 0)
    return command_member_change(argc, argv, "enable");
  if (argc >= 5 && strcmp(argv[1], "ha") == 0 &&
      strcmp(argv[2], "member") == 0 && strcmp(argv[3], "remove") == 0)
    return command_member_change(argc, argv, "remove");
  if (argc >= 4 && strcmp(argv[1], "ha") == 0 && strcmp(argv[2], "key") == 0 &&
      strcmp(argv[3], "export-spoke") == 0)
    return command_key_export(argc, argv);
  if (argc >= 5 && strcmp(argv[1], "ha") == 0 && strcmp(argv[2], "key") == 0 &&
      strcmp(argv[3], "rotate") == 0)
    return command_key_rotate(argc, argv);
  if (argc >= 3 && strcmp(argv[1], "ha") == 0 && strcmp(argv[2], "join") == 0)
    return command_join(argc, argv);
  return -1;
}

static int usage(const char *program) {
  fprintf(stderr,
          "usage: %s [-a admin-socket] <command>\n"
          "       %s ha cluster init --interface IFACE --member-id ID "
          "--advertise-address IP [--advertise-address IP ...]\n"
          "       %s ha invite <create|list|revoke|delete> ...\n"
          "       %s ha join --interface IFACE "
          "[--advertise-address IP ...]\n",
          program, program, program, program);
  return 1;
}

int main(int argc, char **argv) {
  const char *socket_path = OPENNHRP_ADMIN_SOCKET;
  char command[4096] = "";
  char *position = command;
  int local_result;
  int i;
  int fd;

  local_result = local_command(argc, argv);
  if (local_result >= 0)
    return local_result;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-a") == 0) {
      if (++i >= argc)
        return usage(argv[0]);
      socket_path = argv[i];
      continue;
    }
    if ((size_t)(position - command) + strlen(argv[i]) + 2 >= sizeof(command)) {
      fprintf(stderr, "command is too long\n");
      return 1;
    }
    position +=
        snprintf(position, sizeof(command) - (size_t)(position - command),
                 "%s%s", position == command ? "" : " ", argv[i]);
  }
  if (position == command)
    return usage(argv[0]);
  snprintf(position, sizeof(command) - (size_t)(position - command), "\n");
  fd = admin_init(socket_path);
  if (fd < 0) {
    fprintf(stderr, "Failed to connect to OpenNHRP daemon [%s]: %s.\n",
            socket_path, strerror(errno));
    return 1;
  }
  if (admin_send(fd, command) < 0 || admin_receive(fd) < 0) {
    fprintf(stderr, "Failed to send request: %s.\n", strerror(errno));
    close(fd);
    return 2;
  }
  close(fd);
  return 0;
}
