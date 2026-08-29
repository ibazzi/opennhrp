/* opennhrp-ha-managed-hub.c - Managed multi-Hub HA coordinator */

#include <arpa/inet.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "nhrp_ha_control.h"
#include "nhrp_ha_delta.h"
#include "nhrp_ha_failback.h"
#include "nhrp_ha_join.h"
#include "nhrp_ha_managed.h"
#include "nhrp_ha_store.h"
#include "opennhrp-ha-managed-hub.h"

#define MANAGED_TICK_MS 100
#define MANAGED_SEND_MS 250
#define MANAGED_RECONNECT_MS 500
#define MANAGED_ADMIN_PAGE 128
#define MANAGED_HELLO_VERSION 1
#define MANAGED_HELLO_DOMAIN "OpenNHRP-HA-HELLO-v1"
#define HEALTH_PROBE_TIMEOUT_MS 800
#define HEALTH_FAILURE_ROUNDS 3
#define HEALTH_RECOVERY_ROUNDS 10
#define WITNESS_HEARTBEAT_VERSION 1
#define WITNESS_MANAGER_TIMEOUT_MS 3500
#define WITNESS_FALLBACK_MS 30000

struct managed_hello_payload {
  uint8_t version;
  uint8_t flags;
  uint8_t reserved[2];
  uint64_t nonce;
  uint8_t public_key[32];
  uint8_t signature[64];
} __attribute__((packed));

struct managed_hello_canonical {
  uint8_t domain[sizeof(MANAGED_HELLO_DOMAIN) - 1];
  uint8_t cluster_id[16];
  char member[64];
  uint64_t term;
  uint64_t index;
  uint64_t nonce;
  uint8_t flags;
  uint8_t public_key[32];
} __attribute__((packed));

struct managed_configure_payload {
  uint8_t address_count;
  uint8_t reserved[3];
  uint32_t addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
} __attribute__((packed));

struct managed_witness_heartbeat {
  uint8_t version;
  uint8_t mode;
  uint8_t manager_reachable;
  uint8_t reserved;
  uint8_t epoch[16];
  char leader[64];
} __attribute__((packed));

struct managed_peer {
  uint64_t last_receive_ms;
  uint64_t last_send_ms;
  uint64_t stable_since_ms;
  uint64_t last_connect_ms;
  double receive_interval_ms;
  double receive_variance_ms;
  uint64_t match_index;
  uint64_t manifest_revision;
  uint64_t reported_term;
  uint8_t *remote_snapshot;
  size_t remote_snapshot_length;
  struct in_addr addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  uint8_t address_count;
  uint8_t address_index;
  uint32_t priority;
  int fd;
  int authenticated;
  int hello_received;
  int outgoing;
  unsigned int consecutive_misses;
  unsigned int connect_failures;
  int need_snapshot;
  int reported_leader;
  int manager_reachable;
  uint8_t witness_mode;
  uint8_t witness_epoch[16];
  char reported_leader_id[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  uint8_t state;
  uint8_t public_key[32];
  char member[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  char digest[65];
};

struct managed_runtime {
  char directory[4096];
  char state_path[4096];
  char keys_path[4096];
  char identity_path[4096];
  char registrations_path[4096];
  char admin_socket[108];
  char control_socket[108];
  char listen_address[INET_ADDRSTRLEN];
  struct nhrp_ha_managed_state state;
  struct nhrp_ha_auth_keys keys;
  struct managed_peer peers[NHRP_HA_MANAGED_MAX_MEMBERS];
  size_t peer_count;
  int listener;
  int control_listener;
  uint64_t nonce;
  uint64_t local_index;
  uint64_t last_state_refresh_ms;
  uint64_t last_snapshot_ms;
  uint64_t leader_since_ms;
  uint64_t rejoin_started_ms;
  struct nhrp_ha_failback_policy failback_policy;
  struct nhrp_ha_failback_state failback;
  int service_available;
  int isolated;
  uint8_t witness_epoch[16];
  uint64_t witness_lease_term;
  uint64_t witness_lease_sequence;
  uint64_t witness_lease_deadline_ms;
  uint64_t witness_manager_seen_ms;
  uint64_t witness_fallback_since_ms;
  char witness_lease_holder[NHRP_HA_MANAGED_MEMBER_MAX + 1];
  int primary_health_known;
  int primary_healthy_last;
  uint8_t *current_snapshot;
  size_t current_snapshot_length;
  uint8_t *previous_snapshot;
  size_t previous_snapshot_length;
  uint64_t previous_index;
  char local_digest[65];
  uint64_t snapshots_sent;
  uint64_t deltas_sent;
  uint64_t snapshots_received;
  uint64_t deltas_received;
  uint64_t resync_requests;
  struct in_addr configured_addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t configured_address_count;
  int reload_core;
  int reload_peers;
  int health_socket;
  struct in_addr health_targets[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t health_target_count;
  uint8_t health_last_success[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  uint8_t health_pending;
  uint8_t health_replies;
  uint16_t health_identifier;
  uint16_t health_sequence;
  uint64_t health_deadline_ms;
  uint64_t health_next_ms;
  uint64_t health_round_started_ms;
  unsigned int health_interval_seconds;
  unsigned int health_failure_rounds;
  unsigned int health_recovery_rounds;
  unsigned int health_stable_rounds;
  int network_healthy;
};

static int learn_observed_endpoint(struct managed_runtime *runtime,
                                   const char *member_id,
                                   const struct in_addr *address);

static int configured_matches(const struct managed_runtime *runtime) {
  const struct nhrp_ha_managed_member *member = nhrp_ha_managed_member_find(
      (struct nhrp_ha_managed_state *)&runtime->state,
      runtime->state.local_member);

  return runtime->configured_address_count == 0 ||
         (member != NULL &&
          member->configured_address_count ==
              runtime->configured_address_count &&
          memcmp(member->addresses, runtime->configured_addresses,
                 runtime->configured_address_count *
                     sizeof(runtime->configured_addresses[0])) == 0);
}

static volatile sig_atomic_t managed_stop;
static int managed_debug;

static void managed_log(const char *format, ...) {
  va_list arguments;
  va_list syslog_arguments;

  va_start(arguments, format);
  va_copy(syslog_arguments, arguments);
  if (getenv("JOURNAL_STREAM") == NULL)
    vfprintf(stderr, format, arguments);
  vsyslog(managed_debug ? LOG_DEBUG : LOG_INFO, format, syslog_arguments);
  va_end(syslog_arguments);
  va_end(arguments);
}

static void managed_signal(int signal_number) {
  (void)signal_number;
  managed_stop = 1;
}

static uint64_t monotonic_ms(void) {
  struct timespec now;

  clock_gettime(CLOCK_MONOTONIC, &now);
  return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int witness_epoch_parse(const char *text, uint8_t epoch[16]) {
  size_t i;

  if (text == NULL || strlen(text) != 32)
    return 0;
  for (i = 0; i < 16; i++) {
    unsigned char high = (unsigned char)text[i * 2];
    unsigned char low = (unsigned char)text[i * 2 + 1];
    int high_value = high >= '0' && high <= '9'   ? high - '0'
                     : high >= 'a' && high <= 'f' ? high - 'a' + 10
                     : high >= 'A' && high <= 'F' ? high - 'A' + 10
                                                  : -1;
    int low_value = low >= '0' && low <= '9'   ? low - '0'
                    : low >= 'a' && low <= 'f' ? low - 'a' + 10
                    : low >= 'A' && low <= 'F' ? low - 'A' + 10
                                               : -1;

    if (high_value < 0 || low_value < 0)
      return 0;
    epoch[i] = (uint8_t)((high_value << 4) | low_value);
  }
  return 1;
}

static const char *witness_mode_name(uint8_t mode) {
  switch (mode) {
  case NHRP_HA_WITNESS_PREPARING:
    return "preparing";
  case NHRP_HA_WITNESS_ACTIVE:
    return "active";
  case NHRP_HA_WITNESS_DISABLING:
    return "disabling";
  default:
    return "legacy";
  }
}

static int interface_available(const char *interface) {
  struct ifreq request;
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  int available;

  if (fd < 0)
    return 0;
  memset(&request, 0, sizeof(request));
  snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", interface);
  available = ioctl(fd, SIOCGIFFLAGS, &request) == 0 &&
              (request.ifr_flags & IFF_UP) != 0;
  close(fd);
  return available;
}

static uint16_t icmp_checksum(const void *data, size_t length) {
  const uint16_t *word = data;
  uint32_t sum = 0;

  while (length > 1) {
    sum += *word++;
    length -= 2;
  }
  if (length != 0)
    sum += *(const uint8_t *)word;
  while ((sum >> 16) != 0)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t)~sum;
}

static void health_reset(struct managed_runtime *runtime, uint64_t now) {
  memset(runtime->health_last_success, 0, sizeof(runtime->health_last_success));
  runtime->health_pending = 0;
  runtime->health_replies = 0;
  runtime->health_deadline_ms = 0;
  runtime->health_round_started_ms = 0;
  runtime->health_next_ms = now;
  runtime->health_interval_seconds = 1;
  runtime->health_failure_rounds = 0;
  runtime->health_recovery_rounds = 0;
  runtime->health_stable_rounds = 0;
  runtime->network_healthy = 1;
}

static int health_targets_set(struct managed_runtime *runtime,
                              const struct in_addr *targets,
                              size_t target_count, uint64_t now) {
  if (!nhrp_ha_managed_endpoints_valid(targets, target_count))
    return 0;
  if (target_count != 0)
    memcpy(runtime->health_targets, targets, target_count * sizeof(targets[0]));
  runtime->health_target_count = target_count;
  health_reset(runtime, now);
  return 1;
}

static int health_socket_create(uint16_t identifier) {
  struct sock_filter instructions[] = {
      BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMP, 0, 6),
      BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
      BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP_ECHOREPLY, 0, 3),
      BPF_STMT(BPF_LD | BPF_H | BPF_IND, 4),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, identifier, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, UINT32_MAX),
      BPF_STMT(BPF_RET | BPF_K, 0),
  };
  struct sock_fprog filter = {
      .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
      .filter = instructions,
  };
  int fd =
      socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_ICMP);

  if (fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter,
                            sizeof(filter)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int health_probe_send(struct managed_runtime *runtime, uint64_t now) {
  struct icmphdr request;
  size_t i;

  if (runtime->health_target_count == 0 || runtime->health_deadline_ms != 0 ||
      now < runtime->health_next_ms)
    return 1;
  memset(&request, 0, sizeof(request));
  request.type = ICMP_ECHO;
  request.un.echo.id = htons(runtime->health_identifier);
  request.un.echo.sequence = htons(++runtime->health_sequence);
  request.checksum = icmp_checksum(&request, sizeof(request));
  runtime->health_pending = 0;
  runtime->health_replies = 0;
  memset(runtime->health_last_success, 0, sizeof(runtime->health_last_success));
  for (i = 0; i < runtime->health_target_count; i++) {
    struct sockaddr_in destination = {
        .sin_family = AF_INET,
        .sin_addr = runtime->health_targets[i],
    };

    if (sendto(runtime->health_socket, &request, sizeof(request), 0,
               (struct sockaddr *)&destination,
               sizeof(destination)) == (ssize_t)sizeof(request))
      runtime->health_pending |= (uint8_t)(1U << i);
  }
  runtime->health_deadline_ms = now + HEALTH_PROBE_TIMEOUT_MS;
  runtime->health_round_started_ms = now;
  return 1;
}

static void health_reply_read(struct managed_runtime *runtime) {
  uint8_t buffer[2048];
  struct sockaddr_in source;
  socklen_t source_length = sizeof(source);
  ssize_t length;
  unsigned int packets = 0;

  while ((length = recvfrom(runtime->health_socket, buffer, sizeof(buffer), 0,
                            (struct sockaddr *)&source, &source_length)) > 0) {
    const struct ip *ip = (const struct ip *)buffer;
    size_t header_length = (size_t)ip->ip_hl * 4;
    const struct icmphdr *reply;
    size_t i;

    if (++packets > 32)
      break;

    if (header_length < sizeof(*ip) ||
        (size_t)length < header_length + sizeof(*reply))
      continue;
    reply = (const struct icmphdr *)(buffer + header_length);
    if (reply->type != ICMP_ECHOREPLY ||
        ntohs(reply->un.echo.id) != runtime->health_identifier ||
        ntohs(reply->un.echo.sequence) != runtime->health_sequence)
      continue;
    for (i = 0; i < runtime->health_target_count; i++) {
      uint8_t bit = (uint8_t)(1U << i);

      if (runtime->health_targets[i].s_addr != source.sin_addr.s_addr ||
          (runtime->health_pending & bit) == 0)
        continue;
      runtime->health_pending &= (uint8_t)~bit;
      runtime->health_replies |= bit;
      runtime->health_last_success[i] = 1;
      break;
    }
  }
}

static int health_round_finish(struct managed_runtime *runtime, uint64_t now) {
  int previously_healthy = runtime->network_healthy;

  if (runtime->health_target_count == 0 || runtime->health_deadline_ms == 0 ||
      now < runtime->health_deadline_ms)
    return 0;
  runtime->health_pending = 0;
  runtime->health_deadline_ms = 0;
  if (runtime->health_replies != 0) {
    runtime->health_failure_rounds = 0;
    if (!runtime->network_healthy) {
      if (++runtime->health_recovery_rounds >= HEALTH_RECOVERY_ROUNDS)
        runtime->network_healthy = 1;
      runtime->health_interval_seconds = 1;
    } else {
      runtime->health_recovery_rounds = 0;
      runtime->health_stable_rounds++;
      if (runtime->health_interval_seconds < 8)
        runtime->health_interval_seconds *= 2;
      else
        runtime->health_interval_seconds = 10;
    }
  } else {
    runtime->health_stable_rounds = 0;
    runtime->health_recovery_rounds = 0;
    runtime->health_interval_seconds = 1;
    if (++runtime->health_failure_rounds >= HEALTH_FAILURE_ROUNDS)
      runtime->network_healthy = 0;
  }
  runtime->health_next_ms = runtime->health_round_started_ms +
                            (uint64_t)runtime->health_interval_seconds * 1000;
  if (previously_healthy != runtime->network_healthy)
    managed_log("opennhrp-ha: network health for %s changed %s -> %s\n",
                runtime->state.local_member,
                previously_healthy ? "healthy" : "unhealthy",
                runtime->network_healthy ? "healthy" : "unhealthy");
  return previously_healthy != runtime->network_healthy;
}

static int send_all(int fd, const void *data, size_t length) {
  const uint8_t *position = data;

  while (length != 0) {
    ssize_t written = send(fd, position, length, MSG_NOSIGNAL);

    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return 0;
    position += written;
    length -= (size_t)written;
  }
  return 1;
}

static int read_all(int fd, void *data, size_t length) {
  uint8_t *position = data;

  while (length != 0) {
    ssize_t got = recv(fd, position, length, 0);

    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return 0;
    position += got;
    length -= (size_t)got;
  }
  return 1;
}

static int admin_connect(const char *path) {
  struct sockaddr_un address;
  struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
  int fd;

  if (strlen(path) >= sizeof(address.sun_path))
    return -1;
  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static char *admin_command(const char *socket_path, const char *command) {
  size_t allocated = 4096;
  size_t used = 0;
  char *response = malloc(allocated);
  int fd = admin_connect(socket_path);

  if (response == NULL || fd < 0 || !send_all(fd, command, strlen(command))) {
    free(response);
    if (fd >= 0)
      close(fd);
    return NULL;
  }
  shutdown(fd, SHUT_WR);
  for (;;) {
    ssize_t got;

    if (used + 1 == allocated) {
      char *larger;

      if (allocated >= NHRP_HA_CONTROL_MAX_FRAME)
        goto failed;
      allocated *= 2;
      larger = realloc(response, allocated);
      if (larger == NULL)
        goto failed;
      response = larger;
    }
    got = read(fd, response + used, allocated - used - 1);
    if (got < 0 && errno == EINTR)
      continue;
    if (got < 0)
      goto failed;
    if (got == 0)
      break;
    used += (size_t)got;
  }
  close(fd);
  response[used] = 0;
  return response;

failed:
  close(fd);
  free(response);
  return NULL;
}

static int admin_status(const struct managed_runtime *runtime,
                        const char *command) {
  char *response = admin_command(runtime->admin_socket, command);
  int status = response == NULL
                   ? -1
                   : (strncmp(response, "Status: ok\n", 11) == 0 ? 1 : 0);

  free(response);
  return status;
}

static int admin_ok(const struct managed_runtime *runtime,
                    const char *command) {
  return admin_status(runtime, command) == 1;
}

static int state_reload_and_update(struct managed_runtime *runtime,
                                   uint64_t term, const char *leader);
static int managed_peer_healthy(struct managed_peer *peer, uint64_t now);
static int witness_capable(const struct managed_runtime *runtime);
static size_t active_member_count(const struct managed_runtime *runtime);
static struct nhrp_ha_managed_member *
local_member(struct managed_runtime *runtime);

static int witness_manager_reachable(const struct managed_runtime *runtime,
                                     uint64_t now) {
  return runtime->witness_manager_seen_ms != 0 &&
         now - runtime->witness_manager_seen_ms <= WITNESS_MANAGER_TIMEOUT_MS;
}

static int witness_peer_vote(struct managed_runtime *runtime, uint64_t now) {
  size_t i;

  if (runtime->state.witness_mode == NHRP_HA_WITNESS_LEGACY)
    return 0;
  for (i = 0; i < runtime->peer_count; i++) {
    struct managed_peer *peer = &runtime->peers[i];
    int leader_matches =
        strcmp(peer->reported_leader_id, runtime->state.leader) == 0;
    int role_matches =
        strcmp(runtime->state.local_member, runtime->state.leader) == 0
            ? !peer->reported_leader
            : peer->reported_leader &&
                  strcmp(peer->member, runtime->state.leader) == 0;

    if (peer->state == NHRP_HA_MANAGED_ACTIVE &&
        managed_peer_healthy(peer, now) &&
        opennhrp_ha_term_evidence_covers(runtime->state.term,
                                         peer->reported_term) &&
        leader_matches && role_matches &&
        opennhrp_ha_witness_peer_mode_compatible(
            runtime->state.witness_mode, peer->witness_mode,
            CRYPTO_memcmp(peer->witness_epoch, runtime->witness_epoch, 16) == 0,
            runtime->state.witness_mode == NHRP_HA_WITNESS_ACTIVE &&
                runtime->witness_lease_sequence == 0 &&
                witness_manager_reachable(runtime, now)))
      return 1;
  }
  return 0;
}

static size_t hub_votes(struct managed_runtime *runtime, uint64_t now,
                        int require_agreement) {
  struct nhrp_ha_managed_member *local = local_member(runtime);
  size_t votes = local != NULL && local->state == NHRP_HA_MANAGED_ACTIVE;
  size_t i;

  for (i = 0; i < runtime->peer_count; i++) {
    struct managed_peer *peer = &runtime->peers[i];
    int peer_is_leader = strcmp(peer->member, runtime->state.leader) == 0;

    if (peer->state != NHRP_HA_MANAGED_ACTIVE ||
        !managed_peer_healthy(peer, now))
      continue;
    if (!require_agreement ||
        (opennhrp_ha_term_evidence_covers(runtime->state.term,
                                          peer->reported_term) &&
         strcmp(peer->reported_leader_id, runtime->state.leader) == 0 &&
         peer->reported_leader == peer_is_leader))
      votes++;
  }
  return votes;
}

static int hub_majority(struct managed_runtime *runtime, uint64_t now,
                        int require_agreement) {
  return opennhrp_ha_hub_majority(
      (unsigned int)active_member_count(runtime),
      (unsigned int)hub_votes(runtime, now, require_agreement));
}

static int witness_manager_vote(const struct managed_runtime *runtime,
                                uint64_t now) {
  return runtime->state.witness_mode == NHRP_HA_WITNESS_ACTIVE &&
         runtime->witness_lease_deadline_ms > now &&
         opennhrp_ha_term_evidence_covers(runtime->state.term,
                                          runtime->witness_lease_term) &&
         strcmp(runtime->witness_lease_holder, runtime->state.leader) == 0;
}

static int service_quorum(struct managed_runtime *runtime, uint64_t now) {
  size_t active = active_member_count(runtime);

  if (active >= 3)
    return hub_majority(runtime, now, 1);
  return opennhrp_ha_witness_quorum(
      (unsigned int)active, runtime->state.witness_mode,
      witness_peer_vote(runtime, now), witness_manager_vote(runtime, now));
}

static int set_core_state(struct managed_runtime *runtime) {
  char command[512];
  int attempt;

  for (attempt = 0; attempt < 2; attempt++) {
    int leader =
        strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
        runtime->service_available && !runtime->isolated &&
        service_quorum(runtime, monotonic_ms());
    int status;

    snprintf(command, sizeof(command),
             "ha hub role interface %s role %s term %llu index %llu\n",
             runtime->state.interface, leader ? "leader" : "standby",
             (unsigned long long)runtime->state.term,
             (unsigned long long)runtime->local_index);
    status = admin_status(runtime, command);
    if (status == 1) {
      snprintf(command, sizeof(command),
               "ha cluster set interface %s term %llu commit-index %llu leader "
               "%s\n",
               runtime->state.interface,
               (unsigned long long)runtime->state.term,
               (unsigned long long)runtime->state.commit_index,
               runtime->state.leader);
      status = admin_status(runtime, command);
    }
    if (status == 1)
      return 1;
    if (status < 0 || attempt != 0 ||
        !state_reload_and_update(runtime, runtime->state.term + 1,
                                 runtime->state.leader))
      return 0;
  }
  return 0;
}

static struct nhrp_ha_managed_member *
local_member(struct managed_runtime *runtime) {
  return nhrp_ha_managed_member_find(&runtime->state,
                                     runtime->state.local_member);
}

static struct nhrp_ha_managed_member *
state_member(struct managed_runtime *runtime, const char *member) {
  return nhrp_ha_managed_member_find(&runtime->state, member);
}

static struct managed_peer *peer_find(struct managed_runtime *runtime,
                                      const char *member) {
  size_t i;

  for (i = 0; i < runtime->peer_count; i++)
    if (strcmp(runtime->peers[i].member, member) == 0)
      return &runtime->peers[i];
  return NULL;
}

static void peer_close(struct managed_peer *peer) {
  if (peer->fd >= 0)
    close(peer->fd);
  peer->fd = -1;
  peer->authenticated = 0;
  peer->hello_received = 0;
  peer->outgoing = 0;
  peer->stable_since_ms = 0;
}

static void peers_close(struct managed_runtime *runtime) {
  size_t i;

  for (i = 0; i < runtime->peer_count; i++)
    peer_close(&runtime->peers[i]);
}

static int service_refresh(struct managed_runtime *runtime, uint64_t now) {
  int available =
      interface_available(runtime->state.interface) && runtime->network_healthy;

  if (available == runtime->service_available)
    return 1;
  runtime->service_available = available;
  runtime->isolated = 1;
  runtime->rejoin_started_ms = available ? now : 0;
  if (!available)
    runtime->leader_since_ms = 0;
  peers_close(runtime);
  managed_log("opennhrp-ha: interface %s is %s; member %s isolated\n",
              runtime->state.interface, available ? "up" : "down",
              runtime->state.local_member);
  return set_core_state(runtime);
}

static void peers_sync(struct managed_runtime *runtime) {
  struct managed_peer updated[NHRP_HA_MANAGED_MAX_MEMBERS];
  size_t count = 0;
  size_t i;

  memset(updated, 0, sizeof(updated));
  for (i = 0; i < runtime->state.member_count; i++) {
    struct nhrp_ha_managed_member *member = &runtime->state.members[i];
    struct managed_peer *old;
    struct managed_peer *peer;
    struct in_addr current_address;
    size_t address_index;
    int current_found = 0;

    if (strcmp(member->member, runtime->state.local_member) == 0)
      continue;
    peer = &updated[count++];
    old = peer_find(runtime, member->member);
    memset(&current_address, 0, sizeof(current_address));
    if (old != NULL) {
      if (old->address_count != 0 && old->address_index < old->address_count)
        current_address = old->addresses[old->address_index];
      *peer = *old;
      old->fd = -1;
      old->remote_snapshot = NULL;
    } else {
      memset(peer, 0, sizeof(*peer));
      peer->fd = -1;
    }
    for (address_index = 0; address_index < member->address_count;
         address_index++)
      if (current_address.s_addr == member->addresses[address_index].s_addr) {
        peer->address_index = (uint8_t)address_index;
        current_found = 1;
        break;
      }
    if (current_address.s_addr != 0 && !current_found)
      peer_close(peer);
    snprintf(peer->member, sizeof(peer->member), "%s", member->member);
    memcpy(peer->addresses, member->addresses, sizeof(peer->addresses));
    peer->address_count = member->address_count;
    if (!current_found)
      peer->address_index = 0;
    peer->priority = member->priority;
    peer->state = member->state;
    memcpy(peer->public_key, member->public_key, 32);
  }
  for (i = 0; i < runtime->peer_count; i++) {
    peer_close(&runtime->peers[i]);
    free(runtime->peers[i].remote_snapshot);
  }
  memcpy(runtime->peers, updated, sizeof(updated));
  runtime->peer_count = count;
}

static int runtime_load(struct managed_runtime *runtime) {
  struct nhrp_ha_managed_state loaded;
  struct nhrp_ha_auth_keys keys;
  int reload_core;

  memset(&keys, 0, sizeof(keys));
  if (!nhrp_ha_managed_keyring_load(runtime->keys_path, &keys) ||
      !nhrp_ha_managed_state_load(runtime->state_path, &keys, &loaded) ||
      strcmp(loaded.local_member, runtime->state.local_member) != 0)
    return 0;
  reload_core =
      opennhrp_ha_manifest_core_reload_needed(&runtime->state, &loaded);
  nhrp_ha_auth_keys_clear(&runtime->keys);
  runtime->keys = keys;
  runtime->state = loaded;
  peers_sync(runtime);
  if (reload_core)
    runtime->reload_core = 1;
  return 1;
}

static int state_save(struct managed_runtime *runtime) {
  int lock_fd = nhrp_ha_managed_state_lock(runtime->directory);
  int ok = lock_fd >= 0 &&
           nhrp_ha_managed_state_save(runtime->state_path, &runtime->keys,
                                      &runtime->state);

  nhrp_ha_managed_state_unlock(lock_fd);
  return ok;
}

static int witness_mode_save(struct managed_runtime *runtime, uint8_t mode) {
  struct nhrp_ha_managed_state disk;
  struct nhrp_ha_auth_keys keys;
  int lock_fd = nhrp_ha_managed_state_lock(runtime->directory);
  int ok = 0;

  memset(&keys, 0, sizeof(keys));
  if (mode > NHRP_HA_WITNESS_DISABLING || lock_fd < 0 ||
      !nhrp_ha_managed_keyring_load(runtime->keys_path, &keys) ||
      !nhrp_ha_managed_state_load(runtime->state_path, &keys, &disk))
    goto done;
  if (disk.witness_mode != mode) {
    disk.witness_mode = mode;
    disk.manifest_revision++;
    disk.commit_index++;
    if (!nhrp_ha_managed_state_save(runtime->state_path, &keys, &disk))
      goto done;
  }
  nhrp_ha_auth_keys_clear(&runtime->keys);
  runtime->keys = keys;
  memset(&keys, 0, sizeof(keys));
  runtime->state = disk;
  peers_sync(runtime);
  ok = 1;

done:
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return ok && set_core_state(runtime);
}

static int state_reload_and_update(struct managed_runtime *runtime,
                                   uint64_t term, const char *leader) {
  struct nhrp_ha_managed_state disk;
  struct nhrp_ha_auth_keys keys;
  int lock_fd = nhrp_ha_managed_state_lock(runtime->directory);
  int backup_elected;
  int ok = 0;

  memset(&keys, 0, sizeof(keys));
  if (lock_fd < 0 || !nhrp_ha_managed_keyring_load(runtime->keys_path, &keys) ||
      !nhrp_ha_managed_state_load(runtime->state_path, &keys, &disk) ||
      term < disk.term)
    goto done;
  backup_elected = opennhrp_ha_backup_became_leader(
      disk.local_member, disk.primary_member, disk.leader, leader);
  disk.term = term;
  snprintf(disk.leader, sizeof(disk.leader), "%s", leader);
  disk.commit_index++;
  ok = nhrp_ha_managed_state_save(runtime->state_path, &keys, &disk);
  if (ok) {
    nhrp_ha_auth_keys_clear(&runtime->keys);
    runtime->keys = keys;
    memset(&keys, 0, sizeof(keys));
    runtime->state = disk;
    peers_sync(runtime);
    if (backup_elected &&
        nhrp_ha_failback_backup_elected(
            &runtime->failback, &runtime->failback_policy, monotonic_ms()))
      managed_log("opennhrp-ha: Primary failed during failback probation; "
                  "automatic failback backoff level %u until %llu\n",
                  runtime->failback.backoff_level,
                  (unsigned long long)runtime->failback.not_before_ms);
  }

done:
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return ok;
}

static int member_preferred(const struct nhrp_ha_managed_member *left,
                            const struct nhrp_ha_managed_member *right) {
  if (left == NULL)
    return 0;
  if (right == NULL)
    return 1;
  if (left->priority != right->priority)
    return left->priority > right->priority;
  return strcmp(left->member, right->member) < 0;
}

static int become_leader(struct managed_runtime *runtime) {
  uint64_t term = runtime->state.term + 1;
  uint64_t now = monotonic_ms();

  if (!state_reload_and_update(runtime, term, runtime->state.local_member))
    return 0;
  runtime->leader_since_ms = now;
  managed_log("opennhrp-ha: %s elected Leader for term %llu\n",
              runtime->state.local_member,
              (unsigned long long)runtime->state.term);
  return set_core_state(runtime);
}

static int adopt_leader(struct managed_runtime *runtime, uint64_t term,
                        const char *leader) {
  if (term < runtime->state.term ||
      nhrp_ha_managed_member_find(&runtime->state, leader) == NULL)
    return 0;
  if (term == runtime->state.term && strcmp(runtime->state.leader, leader) == 0)
    return 1;
  if (term == runtime->state.term)
    term++;
  if (!state_reload_and_update(runtime, term, leader))
    return 0;
  runtime->leader_since_ms = 0;
  managed_log("opennhrp-ha: %s adopted Leader %s for term %llu\n",
              runtime->state.local_member, leader, (unsigned long long)term);
  return set_core_state(runtime);
}

static void hello_canonical(struct managed_runtime *runtime,
                            const struct nhrp_ha_control_frame *frame,
                            const struct managed_hello_payload *payload,
                            struct managed_hello_canonical *canonical) {
  memset(canonical, 0, sizeof(*canonical));
  memcpy(canonical->domain, MANAGED_HELLO_DOMAIN,
         sizeof(MANAGED_HELLO_DOMAIN) - 1);
  memcpy(canonical->cluster_id, runtime->state.cluster_id, 16);
  snprintf(canonical->member, sizeof(canonical->member), "%s", frame->sender);
  canonical->term = htobe64(frame->term);
  canonical->index = htobe64(frame->index);
  canonical->nonce = payload->nonce;
  canonical->flags = payload->flags;
  memcpy(canonical->public_key, payload->public_key, 32);
}

static int hello_payload_build(struct managed_runtime *runtime,
                               struct nhrp_ha_control_frame *frame,
                               struct managed_hello_payload *payload) {
  struct managed_hello_canonical canonical;
  struct nhrp_ha_managed_member *local = local_member(runtime);

  if (local == NULL)
    return 0;
  memset(payload, 0, sizeof(*payload));
  payload->version = MANAGED_HELLO_VERSION;
  payload->flags =
      strcmp(runtime->state.local_member, runtime->state.leader) == 0;
  payload->nonce = htobe64(runtime->nonce++);
  memcpy(payload->public_key, local->public_key, 32);
  hello_canonical(runtime, frame, payload, &canonical);
  return nhrp_ha_managed_identity_sign(runtime->identity_path, &canonical,
                                       sizeof(canonical), payload->signature);
}

static int hello_payload_verify(struct managed_runtime *runtime,
                                const struct nhrp_ha_control_frame *frame,
                                const struct managed_hello_payload *payload,
                                struct nhrp_ha_managed_member *member) {
  struct managed_hello_canonical canonical;

  if (frame->payload_length != sizeof(*payload) ||
      payload->version != MANAGED_HELLO_VERSION || payload->reserved[0] != 0 ||
      payload->reserved[1] != 0 ||
      CRYPTO_memcmp(payload->public_key, member->public_key, 32) != 0)
    return 0;
  hello_canonical(runtime, frame, payload, &canonical);
  return nhrp_ha_managed_identity_verify(member->public_key, &canonical,
                                         sizeof(canonical), payload->signature);
}

static int frame_send(struct managed_runtime *runtime,
                      struct managed_peer *peer, uint8_t type,
                      const uint8_t *payload, size_t payload_length,
                      uint64_t index, uint64_t ack_index) {
  struct nhrp_ha_control_frame frame;
  uint8_t *wire;
  size_t wire_size;
  int ok;

  if (peer->fd < 0)
    return 0;
  memset(&frame, 0, sizeof(frame));
  frame.type = type;
  frame.flags = strcmp(runtime->state.local_member, runtime->state.leader) == 0;
  memcpy(frame.cluster_id, runtime->state.cluster_id, 16);
  frame.term = runtime->state.term;
  frame.index = index;
  frame.ack_index = ack_index;
  frame.nonce = runtime->nonce++;
  snprintf(frame.sender, sizeof(frame.sender), "%s",
           runtime->state.local_member);
  frame.payload = payload;
  frame.payload_length = payload_length;
  wire_size = nhrp_ha_control_encoded_size(&runtime->keys, &frame);
  wire = malloc(wire_size);
  if (wire_size == 0 || wire == NULL)
    return 0;
  ok = nhrp_ha_control_encode(&runtime->keys, &frame, wire, wire_size) ==
           NHRP_HA_CONTROL_OK &&
       send_all(peer->fd, wire, wire_size);
  free(wire);
  if (ok)
    peer->last_send_ms = monotonic_ms();
  return ok;
}

static int hello_send(struct managed_runtime *runtime,
                      struct managed_peer *peer) {
  struct nhrp_ha_control_frame frame;
  struct managed_hello_payload payload;

  memset(&frame, 0, sizeof(frame));
  memcpy(frame.cluster_id, runtime->state.cluster_id, 16);
  frame.term = runtime->state.term;
  frame.index = runtime->local_index;
  snprintf(frame.sender, sizeof(frame.sender), "%s",
           runtime->state.local_member);
  if (!hello_payload_build(runtime, &frame, &payload))
    return 0;
  return frame_send(runtime, peer, NHRP_HA_CONTROL_HELLO,
                    (const uint8_t *)&payload, sizeof(payload),
                    runtime->local_index, peer->match_index);
}

static void witness_heartbeat_build(struct managed_runtime *runtime,
                                    struct managed_witness_heartbeat *payload,
                                    uint64_t now) {
  memset(payload, 0, sizeof(*payload));
  payload->version = WITNESS_HEARTBEAT_VERSION;
  payload->mode = runtime->state.witness_mode;
  payload->manager_reachable = witness_manager_reachable(runtime, now);
  memcpy(payload->epoch, runtime->witness_epoch, 16);
  snprintf(payload->leader, sizeof(payload->leader), "%s",
           runtime->state.leader);
}

static int witness_heartbeat_apply(struct managed_runtime *runtime,
                                   struct managed_peer *peer,
                                   const struct nhrp_ha_control_frame *frame) {
  const struct managed_witness_heartbeat *payload =
      (const struct managed_witness_heartbeat *)frame->payload;

  if (frame->payload_length == 0) {
    peer->witness_mode = NHRP_HA_WITNESS_LEGACY;
    peer->manager_reachable = 0;
    memset(peer->witness_epoch, 0, sizeof(peer->witness_epoch));
    snprintf(peer->reported_leader_id, sizeof(peer->reported_leader_id), "%s",
             (frame->flags & 1) != 0 ? frame->sender : runtime->state.leader);
    return runtime->state.witness_mode == NHRP_HA_WITNESS_LEGACY;
  }
  if (frame->payload_length != sizeof(*payload) ||
      payload->version != WITNESS_HEARTBEAT_VERSION ||
      payload->mode > NHRP_HA_WITNESS_DISABLING || payload->reserved != 0 ||
      payload->manager_reachable > 1 ||
      memchr(payload->leader, 0, sizeof(payload->leader)) == NULL ||
      !nhrp_ha_managed_member_valid(payload->leader))
    return 0;
  peer->witness_mode = payload->mode;
  peer->manager_reachable = payload->manager_reachable;
  memcpy(peer->witness_epoch, payload->epoch, 16);
  snprintf(peer->reported_leader_id, sizeof(peer->reported_leader_id), "%s",
           payload->leader);
  return 1;
}

static int frame_read(int fd, const struct nhrp_ha_auth_keys *keys,
                      struct nhrp_ha_control_frame *frame, uint8_t **wire) {
  uint8_t prefix[4];
  uint8_t matched[8];
  uint32_t body_length;
  size_t wire_size;

  *wire = NULL;
  if (!read_all(fd, prefix, sizeof(prefix)))
    return 0;
  memcpy(&body_length, prefix, sizeof(body_length));
  wire_size = (size_t)ntohl(body_length) + 4;
  if (wire_size < 4 || wire_size > NHRP_HA_CONTROL_MAX_FRAME)
    return 0;
  *wire = malloc(wire_size);
  if (*wire == NULL)
    return 0;
  memcpy(*wire, prefix, 4);
  if (!read_all(fd, *wire + 4, wire_size - 4) ||
      nhrp_ha_control_decode(keys, *wire, wire_size, frame, matched) !=
          NHRP_HA_CONTROL_OK) {
    free(*wire);
    *wire = NULL;
    return 0;
  }
  return 1;
}

static void record_message(struct managed_peer *peer) {
  uint64_t now = monotonic_ms();

  if (peer->last_receive_ms != 0 && now > peer->last_receive_ms) {
    double sample = (double)(now - peer->last_receive_ms);

    if (peer->receive_interval_ms == 0.0) {
      peer->receive_interval_ms = sample;
      peer->receive_variance_ms = sample / 2.0;
    } else {
      double difference = sample - peer->receive_interval_ms;

      if (difference < 0.0)
        difference = -difference;
      peer->receive_variance_ms =
          0.75 * peer->receive_variance_ms + 0.25 * difference;
      peer->receive_interval_ms =
          0.875 * peer->receive_interval_ms + 0.125 * sample;
    }
  }
  peer->last_receive_ms = now;
  peer->consecutive_misses = 0;
  peer->connect_failures = 0;
  if (peer->stable_since_ms == 0)
    peer->stable_since_ms = now;
}

static int header_size(const char *response, const char *name, size_t *value) {
  char pattern[64];
  const char *position;
  char *end;
  unsigned long parsed;

  snprintf(pattern, sizeof(pattern), "%s: ", name);
  position = strstr(response, pattern);
  if (position == NULL)
    return 0;
  position += strlen(pattern);
  parsed = strtoul(position, &end, 10);
  if (end == position || (*end != '\n' && *end != 0) || parsed > 4096)
    return 0;
  *value = parsed;
  return 1;
}

static int header_digest(const char *response, char digest[65]) {
  const char *position = strstr(response, "Digest: ");
  size_t i;

  if (position == NULL)
    return 0;
  position += 8;
  for (i = 0; i < 64; i++)
    if (!isxdigit((unsigned char)position[i]) ||
        (position[i] >= 'A' && position[i] <= 'F'))
      return 0;
  if (position[64] != '\n')
    return 0;
  memcpy(digest, position, 64);
  digest[64] = 0;
  return 1;
}

static int snapshot_fetch(struct managed_runtime *runtime, uint8_t **payload,
                          size_t *payload_length, char digest[65]) {
  uint8_t *result = NULL;
  size_t allocated = 0;
  size_t used = 0;
  size_t offset = 0;
  size_t total = 0;
  char expected[65] = "";

  for (;;) {
    char command[256];
    char page_digest[65];
    char *response;
    char *entries;
    size_t page_total;
    size_t count;
    size_t length;

    snprintf(command, sizeof(command),
             "ha registration snapshot interface %s offset %zu limit %u\n",
             runtime->state.interface, offset, MANAGED_ADMIN_PAGE);
    response = admin_command(runtime->admin_socket, command);
    if (response == NULL || strncmp(response, "Status: ok\n", 11) != 0 ||
        !header_size(response, "Total", &page_total) ||
        !header_size(response, "Count", &count) ||
        !header_digest(response, page_digest) ||
        (offset != 0 &&
         (page_total != total || strcmp(page_digest, expected) != 0))) {
      free(response);
      free(result);
      return 0;
    }
    if (offset == 0) {
      total = page_total;
      snprintf(expected, sizeof(expected), "%s", page_digest);
    }
    entries = strstr(response, "\n\n");
    if (entries == NULL) {
      free(response);
      free(result);
      return 0;
    }
    entries += 2;
    length = strlen(entries);
    if (used + length + 1 > allocated) {
      size_t next = allocated == 0 ? 4096 : allocated;
      uint8_t *larger;

      while (next < used + length + 1)
        next *= 2;
      if (next > NHRP_HA_CONTROL_MAX_FRAME ||
          (larger = realloc(result, next)) == NULL) {
        free(response);
        free(result);
        return 0;
      }
      result = larger;
      allocated = next;
    }
    memcpy(result + used, entries, length);
    used += length;
    free(response);
    offset += count;
    if (offset >= total)
      break;
    if (count == 0) {
      free(result);
      return 0;
    }
  }
  if (result == NULL) {
    result = calloc(1, 1);
    if (result == NULL)
      return 0;
  }
  result[used] = 0;
  *payload = result;
  *payload_length = used;
  snprintf(digest, 65, "%s", expected);
  return 1;
}

static int snapshot_apply(struct managed_runtime *runtime,
                          const struct nhrp_ha_control_frame *frame,
                          const uint8_t *snapshot, size_t snapshot_length) {
  char command[768];
  char *copy;
  char *line;
  char *save = NULL;
  size_t count = 0;

  copy = malloc(snapshot_length + 1);
  if (copy == NULL)
    return 0;
  memcpy(copy, snapshot, snapshot_length);
  copy[snapshot_length] = 0;
  for (line = strtok_r(copy, "\n", &save); line != NULL;
       line = strtok_r(NULL, "\n", &save)) {
    char protocol[64];
    char nbma[64];
    char nat_oa[64];
    char origin[16];
    char extra;
    unsigned int prefix;
    unsigned int mtu;
    unsigned int holding;
    unsigned int flags;
    unsigned long long old_term;
    unsigned long long old_index;

    if (++count > 4096 ||
        sscanf(line, "entry %63s %u %63s %63s %u %u %u %llu %llu %15s %c",
               protocol, &prefix, nbma, nat_oa, &mtu, &holding, &flags,
               &old_term, &old_index, origin, &extra) != 10 ||
        prefix > 32 || mtu > UINT16_MAX || holding == 0 || holding > UINT16_MAX)
      goto failed;
  }
  snprintf(command, sizeof(command),
           "ha registration sync begin interface %s term %llu index %llu\n",
           runtime->state.interface, (unsigned long long)frame->term,
           (unsigned long long)frame->index);
  if (!admin_ok(runtime, command))
    goto failed;
  memcpy(copy, snapshot, snapshot_length);
  copy[snapshot_length] = 0;
  save = NULL;
  for (line = strtok_r(copy, "\n", &save); line != NULL;
       line = strtok_r(NULL, "\n", &save)) {
    char protocol[64];
    char nbma[64];
    char nat_oa[64];
    char origin[16];
    unsigned int prefix;
    unsigned int mtu;
    unsigned int holding;
    unsigned int flags;
    unsigned long long old_term;
    unsigned long long old_index;

    if (sscanf(line, "entry %63s %u %63s %63s %u %u %u %llu %llu %15s",
               protocol, &prefix, nbma, nat_oa, &mtu, &holding, &flags,
               &old_term, &old_index, origin) != 10)
      goto failed;
    snprintf(command, sizeof(command),
             "ha registration sync apply interface %s protocol %s/%u nbma %s "
             "nat-oa %s mtu %u holding %u flags %u term %llu index %llu\n",
             runtime->state.interface, protocol, prefix, nbma, nat_oa, mtu,
             holding, flags, (unsigned long long)frame->term,
             (unsigned long long)frame->index);
    if (!admin_ok(runtime, command))
      goto failed;
  }
  snprintf(command, sizeof(command), "ha registration sync end interface %s\n",
           runtime->state.interface);
  free(copy);
  return admin_ok(runtime, command);

failed:
  free(copy);
  return 0;
}

static int snapshot_refresh(struct managed_runtime *runtime) {
  struct nhrp_ha_store_record record;
  uint8_t *snapshot = NULL;
  size_t length = 0;
  char digest[65];

  if (!snapshot_fetch(runtime, &snapshot, &length, digest))
    return 0;
  if (opennhrp_ha_snapshot_cache_matches(
          runtime->current_snapshot, runtime->current_snapshot_length,
          runtime->local_digest, snapshot, length, digest)) {
    free(snapshot);
    return 1;
  }
  if (runtime->current_snapshot != NULL &&
      strcmp(runtime->local_digest, digest) == 0) {
    free(runtime->current_snapshot);
    free(runtime->previous_snapshot);
    runtime->current_snapshot = snapshot;
    runtime->current_snapshot_length = length;
    runtime->previous_snapshot = NULL;
    runtime->previous_snapshot_length = 0;
    return 1;
  }
  free(runtime->previous_snapshot);
  runtime->previous_snapshot = runtime->current_snapshot;
  runtime->previous_snapshot_length = runtime->current_snapshot_length;
  runtime->previous_index = runtime->local_index;
  runtime->current_snapshot = snapshot;
  runtime->current_snapshot_length = length;
  snprintf(runtime->local_digest, sizeof(runtime->local_digest), "%s", digest);
  runtime->local_index++;
  memset(&record, 0, sizeof(record));
  memcpy(record.cluster_id, runtime->state.cluster_id, 16);
  record.term = runtime->state.term;
  record.index = runtime->local_index;
  snprintf(record.leader, sizeof(record.leader), "%s", runtime->state.leader);
  record.payload = runtime->current_snapshot;
  record.payload_length = runtime->current_snapshot_length;
  return nhrp_ha_store_save(runtime->registrations_path, &runtime->keys,
                            &record);
}

static int snapshot_digest(const uint8_t *snapshot, size_t length,
                           char output[65]) {
  uint8_t digest[32];
  size_t i;

  if (SHA256(snapshot, length, digest) == NULL)
    return 0;
  for (i = 0; i < sizeof(digest); i++)
    snprintf(output + i * 2, 3, "%02x", digest[i]);
  return 1;
}

static int snapshot_send(struct managed_runtime *runtime,
                         struct managed_peer *peer) {
  uint8_t *delta = NULL;
  size_t delta_length = 0;
  int ok;

  if (runtime->current_snapshot == NULL ||
      (!peer->need_snapshot && peer->match_index >= runtime->local_index))
    return 1;
  if (!peer->need_snapshot && runtime->previous_snapshot != NULL &&
      peer->match_index == runtime->previous_index &&
      nhrp_ha_delta_build(
          runtime->previous_snapshot, runtime->previous_snapshot_length,
          runtime->current_snapshot, runtime->current_snapshot_length, &delta,
          &delta_length) &&
      delta_length < runtime->current_snapshot_length) {
    ok = frame_send(runtime, peer, NHRP_HA_CONTROL_DELTA, delta, delta_length,
                    runtime->local_index, runtime->state.commit_index);
    free(delta);
    if (ok)
      runtime->deltas_sent++;
    return ok;
  }
  ok = frame_send(runtime, peer, NHRP_HA_CONTROL_SNAPSHOT,
                  runtime->current_snapshot, runtime->current_snapshot_length,
                  runtime->local_index, runtime->state.commit_index);
  if (ok)
    runtime->snapshots_sent++;
  return ok;
}

static int promote_learner(struct managed_runtime *runtime,
                           struct managed_peer *peer) {
  struct nhrp_ha_managed_state disk;
  struct nhrp_ha_auth_keys keys;
  struct nhrp_ha_managed_member *member = state_member(runtime, peer->member);
  int lock_fd;
  int ok = 0;

  if (member == NULL || member->state != NHRP_HA_MANAGED_LEARNER ||
      peer->match_index < runtime->local_index)
    return 1;
  memset(&keys, 0, sizeof(keys));
  lock_fd = nhrp_ha_managed_state_lock(runtime->directory);
  if (lock_fd < 0 || !nhrp_ha_managed_keyring_load(runtime->keys_path, &keys) ||
      !nhrp_ha_managed_state_load(runtime->state_path, &keys, &disk) ||
      (member = nhrp_ha_managed_member_find(&disk, peer->member)) == NULL ||
      member->state != NHRP_HA_MANAGED_LEARNER)
    goto done;
  member->state = NHRP_HA_MANAGED_ACTIVE;
  member->match_index = peer->match_index;
  disk.manifest_revision++;
  disk.commit_index++;
  if (!nhrp_ha_managed_state_save(runtime->state_path, &keys, &disk))
    goto done;
  runtime->state = disk;
  nhrp_ha_auth_keys_clear(&runtime->keys);
  runtime->keys = keys;
  memset(&keys, 0, sizeof(keys));
  peers_sync(runtime);
  ok = admin_ok(runtime, "ha managed reload\n");

done:
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return ok;
}

static int manifest_send(struct managed_runtime *runtime,
                         struct managed_peer *peer) {
  uint8_t *payload;
  size_t length = nhrp_ha_managed_state_encoded_size();
  int ok;

  if (peer->manifest_revision >= runtime->state.manifest_revision)
    return 1;
  payload = malloc(length);
  if (payload == NULL ||
      !nhrp_ha_managed_state_encode(&runtime->state, payload, length)) {
    free(payload);
    return 0;
  }
  ok = frame_send(runtime, peer, NHRP_HA_CONTROL_MANIFEST, payload, length,
                  runtime->local_index, peer->match_index);
  free(payload);
  return ok;
}

static int configured_apply(struct managed_runtime *runtime,
                            const char *member_id,
                            const struct in_addr *addresses,
                            size_t address_count) {
  struct nhrp_ha_managed_state previous = runtime->state;
  struct nhrp_ha_managed_member *member = state_member(runtime, member_id);
  int changed;

  if (strcmp(runtime->state.local_member, runtime->state.leader) != 0 ||
      member == NULL)
    return 0;
  changed = nhrp_ha_managed_member_set_configured(&runtime->state, member,
                                                  addresses, address_count);
  if (changed < 0)
    return 0;
  if (changed == 0)
    return 1;
  runtime->state.manifest_revision++;
  runtime->state.commit_index++;
  if (!state_save(runtime)) {
    runtime->state = previous;
    return 0;
  }
  peers_sync(runtime);
  managed_log("opennhrp-ha: updated configured endpoints for %s\n", member_id);
  runtime->reload_core = 1;
  return 1;
}

static int member_leave_apply(struct managed_runtime *runtime,
                              const char *member_id) {
  struct nhrp_ha_managed_state disk;
  struct nhrp_ha_auth_keys keys;
  int lock_fd = nhrp_ha_managed_state_lock(runtime->directory);
  int ok = 0;

  memset(&keys, 0, sizeof(keys));
  if (lock_fd < 0 || !nhrp_ha_managed_keyring_load(runtime->keys_path, &keys) ||
      !nhrp_ha_managed_state_load(runtime->state_path, &keys, &disk) ||
      strcmp(disk.local_member, disk.leader) != 0 ||
      strcmp(member_id, disk.local_member) == 0 ||
      strcmp(member_id, disk.primary_member) == 0 ||
      strcmp(member_id, disk.leader) == 0 ||
      !nhrp_ha_managed_member_remove(&disk, member_id))
    goto done;
  disk.manifest_revision++;
  disk.commit_index++;
  if (!nhrp_ha_managed_state_save(runtime->state_path, &keys, &disk))
    goto done;
  runtime->state = disk;
  nhrp_ha_auth_keys_clear(&runtime->keys);
  runtime->keys = keys;
  memset(&keys, 0, sizeof(keys));
  runtime->reload_core = 1;
  ok = 1;

done:
  nhrp_ha_auth_keys_clear(&keys);
  nhrp_ha_managed_state_unlock(lock_fd);
  return ok;
}

static int managed_decommission(struct managed_runtime *runtime) {
  int ok;

  runtime->isolated = 1;
  if (!set_core_state(runtime) || !admin_ok(runtime, "ha managed stop\n"))
    return 0;
  ok = nhrp_ha_managed_state_destroy(runtime->directory);
  managed_stop = 1;
  return ok;
}

static int configured_send(struct managed_runtime *runtime,
                           struct managed_peer *leader) {
  struct managed_configure_payload payload;
  size_t i;

  memset(&payload, 0, sizeof(payload));
  payload.address_count = (uint8_t)runtime->configured_address_count;
  for (i = 0; i < runtime->configured_address_count; i++)
    payload.addresses[i] = runtime->configured_addresses[i].s_addr;
  return frame_send(runtime, leader, NHRP_HA_CONTROL_CONFIGURE,
                    (const uint8_t *)&payload, sizeof(payload),
                    runtime->local_index, runtime->local_index);
}

static int manifest_apply(struct managed_runtime *runtime,
                          struct managed_peer *sender,
                          const struct nhrp_ha_control_frame *frame) {
  struct nhrp_ha_managed_state manifest;
  struct nhrp_ha_managed_state previous = runtime->state;
  struct nhrp_ha_managed_member *local =
      nhrp_ha_managed_member_find(&runtime->state, runtime->state.local_member);
  struct managed_peer *reply_peer;
  uint64_t revision_wire;
  unsigned int active_hubs = 0;
  int reload_core;
  size_t i;

  if (strcmp(frame->sender, runtime->state.leader) != 0 ||
      !nhrp_ha_managed_state_decode(frame->payload, frame->payload_length,
                                    &manifest))
    return 0;
  for (i = 0; i < manifest.member_count; i++)
    if (manifest.members[i].state == NHRP_HA_MANAGED_ACTIVE)
      active_hubs++;
  if (memcmp(manifest.cluster_id, runtime->state.cluster_id, 16) != 0 ||
      manifest.protocol_address.s_addr !=
          runtime->state.protocol_address.s_addr ||
      manifest.prefix_length != runtime->state.prefix_length ||
      nhrp_ha_managed_member_find(&manifest, runtime->state.local_member) ==
          NULL)
    return 0;
  if (manifest.term < runtime->state.term ||
      manifest.manifest_revision < runtime->state.manifest_revision) {
    revision_wire = htobe64(runtime->state.manifest_revision);
    return frame_send(runtime, sender, NHRP_HA_CONTROL_MANIFEST_ACK,
                      (const uint8_t *)&revision_wire, sizeof(revision_wire),
                      runtime->local_index, runtime->local_index);
  }
  if (!opennhrp_ha_witness_manifest_transition_allowed(
          runtime->state.witness_mode, manifest.witness_mode, active_hubs,
          local != NULL && local->state == NHRP_HA_MANAGED_ACTIVE))
    return 0;
  snprintf(manifest.local_member, sizeof(manifest.local_member), "%s",
           runtime->state.local_member);
  snprintf(manifest.interface, sizeof(manifest.interface), "%s",
           runtime->state.interface);
  reload_core = opennhrp_ha_manifest_core_reload_needed(&previous, &manifest);
  runtime->state = manifest;
  if (!state_save(runtime)) {
    runtime->state = previous;
    return 0;
  }
  peers_sync(runtime);
  if (reload_core && !admin_ok(runtime, "ha managed reload\n"))
    return 0;
  revision_wire = htobe64(runtime->state.manifest_revision);
  reply_peer = peer_find(runtime, frame->sender);
  if (reply_peer == NULL)
    return 0;
  return frame_send(runtime, reply_peer, NHRP_HA_CONTROL_MANIFEST_ACK,
                    (const uint8_t *)&revision_wire, sizeof(revision_wire),
                    runtime->local_index, runtime->local_index);
}

static int registrations_persist(struct managed_runtime *runtime,
                                 const struct nhrp_ha_control_frame *frame,
                                 const uint8_t *snapshot, size_t length) {
  struct nhrp_ha_store_record record;

  memset(&record, 0, sizeof(record));
  memcpy(record.cluster_id, runtime->state.cluster_id, 16);
  record.term = frame->term;
  record.index = frame->index;
  snprintf(record.leader, sizeof(record.leader), "%s", frame->sender);
  record.payload = (uint8_t *)snapshot;
  record.payload_length = length;
  return nhrp_ha_store_save(runtime->registrations_path, &runtime->keys,
                            &record);
}

static int frame_process(struct managed_runtime *runtime,
                         struct managed_peer *peer,
                         struct nhrp_ha_control_frame *frame) {
  struct nhrp_ha_managed_member *sender = state_member(runtime, frame->sender);
  const struct managed_hello_payload *hello =
      (const struct managed_hello_payload *)frame->payload;
  const char *split_leader;
  int transfer_grace;

  if (sender == NULL ||
      memcmp(frame->cluster_id, runtime->state.cluster_id, 16) != 0 ||
      strcmp(sender->member, peer->member) != 0 ||
      (frame->type == NHRP_HA_CONTROL_HELLO &&
       !hello_payload_verify(runtime, frame, hello, sender)))
    return 0;
  record_message(peer);
  peer->reported_term = frame->term;
  peer->reported_leader = (frame->flags & 1) != 0;
  transfer_grace =
      frame->type == NHRP_HA_CONTROL_HELLO &&
      strcmp(runtime->state.local_member, runtime->state.primary_member) == 0 &&
      strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
      runtime->failback.probation_until_ms > monotonic_ms() &&
      frame->term < runtime->state.term;
  split_leader =
      frame->type == NHRP_HA_CONTROL_HELLO && !transfer_grace
          ? opennhrp_ha_split_recovery_leader(
                runtime->state.local_member, runtime->state.primary_member,
                frame->sender,
                strcmp(runtime->state.local_member, runtime->state.leader) == 0,
                (frame->flags & 1) != 0)
          : NULL;
  if (split_leader != NULL) {
    uint64_t term =
        runtime->state.term > frame->term ? runtime->state.term : frame->term;

    if (!adopt_leader(runtime, term + 1, split_leader))
      return 0;
  } else if (frame->term < runtime->state.term) {
    if (frame->type != NHRP_HA_CONTROL_HELLO &&
        !(frame->type == NHRP_HA_CONTROL_TRANSFER_ACK &&
          runtime->failback.transfer_pending &&
          strcmp(frame->sender, runtime->state.primary_member) == 0))
      return 1;
    if (frame->type == NHRP_HA_CONTROL_HELLO) {
      peer->authenticated = 1;
      peer->hello_received = 1;
      peer->match_index = frame->ack_index;
      return hello_send(runtime, peer);
    }
  }
  if (frame->term > runtime->state.term) {
    const char *leader =
        (frame->flags & 1) != 0 ? frame->sender : runtime->state.leader;

    if (!adopt_leader(runtime, frame->term, leader))
      return 0;
  }
  switch (frame->type) {
  case NHRP_HA_CONTROL_HELLO: {
    struct nhrp_ha_managed_member *current =
        state_member(runtime, runtime->state.leader);

    int first_hello = !peer->hello_received;

    peer->authenticated = 1;
    peer->hello_received = 1;
    peer->match_index = frame->ack_index;
    if (split_leader == NULL && (frame->flags & 1) != 0 &&
        strcmp(runtime->state.leader, frame->sender) != 0) {
      if (frame->term > runtime->state.term ||
          member_preferred(sender, current)) {
        if (!adopt_leader(runtime, frame->term + 1, frame->sender))
          return 0;
      } else if (strcmp(runtime->state.local_member, runtime->state.leader) ==
                     0 &&
                 !become_leader(runtime)) {
        return 0;
      }
    }
    if (first_hello && !peer->outgoing)
      return hello_send(runtime, peer);
    return 1;
  }
  case NHRP_HA_CONTROL_SNAPSHOT:
  case NHRP_HA_CONTROL_DELTA: {
    uint8_t *snapshot = NULL;
    size_t snapshot_length = 0;
    int delta = frame->type == NHRP_HA_CONTROL_DELTA;

    if (strcmp(runtime->state.local_member, runtime->state.leader) == 0 ||
        strcmp(frame->sender, runtime->state.leader) != 0)
      return 0;
    if (delta) {
      if (peer->remote_snapshot == NULL ||
          !nhrp_ha_delta_apply(peer->remote_snapshot,
                               peer->remote_snapshot_length, frame->payload,
                               frame->payload_length, &snapshot,
                               &snapshot_length)) {
        runtime->resync_requests++;
        return frame_send(runtime, peer, NHRP_HA_CONTROL_RESYNC, NULL, 0,
                          runtime->local_index, peer->match_index);
      }
    } else {
      snapshot = malloc(frame->payload_length + 1);
      if (snapshot == NULL)
        return 0;
      memcpy(snapshot, frame->payload, frame->payload_length);
      snapshot_length = frame->payload_length;
    }
    if (!snapshot_apply(runtime, frame, snapshot, snapshot_length) ||
        !registrations_persist(runtime, frame, snapshot, snapshot_length)) {
      free(snapshot);
      return 0;
    }
    free(peer->remote_snapshot);
    peer->remote_snapshot = snapshot;
    peer->remote_snapshot_length = snapshot_length;
    runtime->local_index = frame->index;
    if (!snapshot_digest(snapshot, snapshot_length, runtime->local_digest))
      return 0;
    if (delta)
      runtime->deltas_received++;
    else
      runtime->snapshots_received++;
    return frame_send(runtime, peer, NHRP_HA_CONTROL_ACK, NULL, 0,
                      runtime->local_index, runtime->local_index);
  }
  case NHRP_HA_CONTROL_ACK:
    if (strcmp(runtime->state.local_member, runtime->state.leader) != 0)
      return 0;
    if (frame->ack_index > peer->match_index)
      peer->match_index = frame->ack_index;
    if (frame->ack_index >= runtime->local_index)
      peer->need_snapshot = 0;
    return promote_learner(runtime, peer);
  case NHRP_HA_CONTROL_DIGEST:
    if (frame->payload_length == 64) {
      memcpy(peer->digest, frame->payload, 64);
      peer->digest[64] = 0;
      if (strcmp(runtime->state.local_member, runtime->state.leader) == 0) {
        peer->need_snapshot = opennhrp_ha_snapshot_resync_needed(
            runtime->local_index, runtime->local_digest, frame->index,
            peer->digest);
        if (!peer->need_snapshot)
          return promote_learner(runtime, peer);
      }
    }
    return 1;
  case NHRP_HA_CONTROL_RESYNC:
    peer->need_snapshot = 1;
    runtime->resync_requests++;
    return 1;
  case NHRP_HA_CONTROL_HEARTBEAT:
    peer->match_index = frame->ack_index;
    if (!witness_heartbeat_apply(runtime, peer, frame))
      return 0;
    if (frame->term >= runtime->state.term &&
        strcmp(peer->member, runtime->state.leader) == 0 &&
        strcmp(peer->reported_leader_id, runtime->state.leader) != 0 &&
        state_member(runtime, peer->reported_leader_id) != NULL)
      return adopt_leader(runtime, frame->term, peer->reported_leader_id);
    return 1;
  case NHRP_HA_CONTROL_TRANSFER:
    if (strcmp(runtime->state.local_member, runtime->state.primary_member) !=
            0 ||
        strcmp(frame->sender, runtime->state.leader) != 0 ||
        frame->payload_length != 64 || runtime->local_index < frame->index ||
        strcmp((const char *)frame->payload, runtime->local_digest) != 0)
      return 0;
    if (!become_leader(runtime))
      return 0;
    nhrp_ha_failback_transfer_ack(&runtime->failback, &runtime->failback_policy,
                                  monotonic_ms());
    if (managed_debug)
      managed_log("opennhrp-ha: accepted failback transfer from %s; "
                  "ignoring lower-term split claims during probation\n",
                  frame->sender);
    return frame_send(runtime, peer, NHRP_HA_CONTROL_TRANSFER_ACK, NULL, 0,
                      runtime->local_index, runtime->local_index);
  case NHRP_HA_CONTROL_TRANSFER_ACK: {
    uint64_t term =
        frame->term > runtime->state.term ? frame->term : runtime->state.term;

    if (strcmp(frame->sender, runtime->state.primary_member) != 0)
      return 0;
    if (!adopt_leader(runtime, term, frame->sender))
      return 0;
    nhrp_ha_failback_transfer_ack(&runtime->failback, &runtime->failback_policy,
                                  monotonic_ms());
    if (managed_debug)
      managed_log("opennhrp-ha: failback transfer acknowledged by Primary %s "
                  "for term %llu\n",
                  frame->sender, (unsigned long long)term);
    return 1;
  }
  case NHRP_HA_CONTROL_MANIFEST:
    return manifest_apply(runtime, peer, frame);
  case NHRP_HA_CONTROL_MANIFEST_ACK: {
    uint64_t revision;

    if (frame->payload_length != sizeof(revision) ||
        strcmp(runtime->state.local_member, runtime->state.leader) != 0)
      return 0;
    memcpy(&revision, frame->payload, sizeof(revision));
    peer->manifest_revision = be64toh(revision);
    if (peer->manifest_revision > runtime->state.manifest_revision) {
      runtime->state.manifest_revision = peer->manifest_revision;
      runtime->state.commit_index++;
      if (!state_save(runtime))
        return 0;
    }
    return 1;
  }
  case NHRP_HA_CONTROL_CONFIGURE: {
    const struct managed_configure_payload *payload =
        (const struct managed_configure_payload *)frame->payload;
    struct in_addr addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
    size_t i;

    if (frame->payload_length != sizeof(*payload) ||
        payload->address_count == 0 ||
        payload->address_count > NHRP_HA_MANAGED_MAX_ENDPOINTS ||
        strcmp(runtime->state.local_member, runtime->state.leader) != 0)
      return 0;
    for (i = 0; i < payload->address_count; i++)
      addresses[i].s_addr = payload->addresses[i];
    return configured_apply(runtime, frame->sender, addresses,
                            payload->address_count);
  }
  case NHRP_HA_CONTROL_LEAVE: {
    int sent;

    if (frame->payload_length != 0 ||
        strcmp(runtime->state.local_member, runtime->state.leader) != 0 ||
        strcmp(frame->sender, runtime->state.primary_member) == 0 ||
        strcmp(frame->sender, runtime->state.leader) == 0 ||
        !member_leave_apply(runtime, frame->sender))
      return 0;
    sent = frame_send(runtime, peer, NHRP_HA_CONTROL_LEAVE_ACK, NULL, 0,
                      runtime->local_index, runtime->local_index);
    runtime->reload_peers = 1;
    return sent;
  }
  case NHRP_HA_CONTROL_LEAVE_ACK:
    if (frame->payload_length != 0 ||
        strcmp(frame->sender, runtime->state.leader) != 0 ||
        strcmp(runtime->state.local_member, runtime->state.primary_member) == 0)
      return 0;
    return managed_decommission(runtime);
  case NHRP_HA_CONTROL_DESTROY:
    if (frame->payload_length != 0 ||
        strcmp(frame->sender, runtime->state.leader) != 0 ||
        strcmp(frame->sender, runtime->state.primary_member) != 0)
      return 0;
    return managed_decommission(runtime);
  default:
    return 0;
  }
}

static int peer_frame_handle(struct managed_runtime *runtime,
                             struct managed_peer *peer) {
  struct nhrp_ha_control_frame frame;
  uint8_t *wire = NULL;
  int ok = frame_read(peer->fd, &runtime->keys, &frame, &wire) &&
           frame_process(runtime, peer, &frame);

  free(wire);
  return ok;
}

static int listener_create(struct managed_runtime *runtime) {
  struct sockaddr_in address;
  int enabled = 1;
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

  if (fd < 0)
    return -1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(runtime->state.port);
  if (inet_pton(AF_INET, runtime->listen_address, &address.sin_addr) != 1 ||
      bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(fd, 64) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int control_listener_create(const char *path) {
  struct sockaddr_un address;
  struct stat status;
  int fd;

  if (strlen(path) >= sizeof(address.sun_path))
    return -1;
  if (lstat(path, &status) == 0) {
    if (!S_ISSOCK(status.st_mode) || status.st_uid != geteuid() ||
        unlink(path) != 0)
      return -1;
  } else if (errno != ENOENT) {
    return -1;
  }
  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      chmod(path, 0600) != 0 || listen(fd, 16) != 0) {
    close(fd);
    unlink(path);
    return -1;
  }
  return fd;
}

static int connection_timeout(int fd) {
  struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};

  return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
             0 &&
         setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ==
             0;
}

static int accept_connection(struct managed_runtime *runtime) {
  struct sockaddr_in source;
  socklen_t source_length = sizeof(source);
  uint8_t prefix[4];
  int fd =
      accept(runtime->listener, (struct sockaddr *)&source, &source_length);
  ssize_t got;

  if (fd < 0)
    return 0;
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  connection_timeout(fd);
  if (!runtime->service_available) {
    close(fd);
    return 0;
  }
  got = recv(fd, prefix, sizeof(prefix), MSG_PEEK);
  if (got == 4 && nhrp_ha_join_is_request(prefix, sizeof(prefix))) {
    int ok = nhrp_ha_join_server(fd, runtime->directory);

    close(fd);
    if (ok)
      runtime_load(runtime);
    return ok;
  }
  if (got == 4) {
    struct nhrp_ha_control_frame frame;
    struct nhrp_ha_managed_member *member;
    struct managed_peer *peer;
    uint8_t *wire = NULL;

    if (!frame_read(fd, &runtime->keys, &frame, &wire) ||
        frame.type != NHRP_HA_CONTROL_HELLO ||
        (member = state_member(runtime, frame.sender)) == NULL ||
        (peer = peer_find(runtime, frame.sender)) == NULL) {
      free(wire);
      close(fd);
      return 0;
    }
    if (peer->fd >= 0 &&
        !opennhrp_ha_replace_with_incoming(runtime->state.local_member,
                                           peer->member, peer->outgoing)) {
      free(wire);
      close(fd);
      return 1;
    }
    peer_close(peer);
    peer->fd = fd;
    peer->outgoing = 0;
    if (!frame_process(runtime, peer, &frame)) {
      free(wire);
      peer_close(peer);
      return 0;
    }
    if (!learn_observed_endpoint(runtime, frame.sender, &source.sin_addr)) {
      free(wire);
      peer_close(peer);
      return 0;
    }
    free(wire);
    return 1;
  }
  close(fd);
  return 0;
}

static int peer_connect(struct managed_runtime *runtime,
                        struct managed_peer *peer) {
  struct sockaddr_in destination;
  struct pollfd descriptor;
  int flags;
  int error = 0;
  socklen_t error_length = sizeof(error);
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  int result;

  peer->last_connect_ms = monotonic_ms();
  if (fd < 0)
    return 0;
  flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  memset(&destination, 0, sizeof(destination));
  destination.sin_family = AF_INET;
  if (peer->address_count == 0)
    goto failed;
  destination.sin_addr = peer->addresses[peer->address_index];
  destination.sin_port = htons(runtime->state.port);
  result = connect(fd, (struct sockaddr *)&destination, sizeof(destination));
  if (result != 0 && errno != EINPROGRESS)
    goto failed;
  if (result != 0) {
    descriptor.fd = fd;
    descriptor.events = POLLOUT;
    if (poll(&descriptor, 1, 300) <= 0 ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) != 0 ||
        error != 0)
      goto failed;
  }
  fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
  connection_timeout(fd);
  peer_close(peer);
  peer->fd = fd;
  peer->outgoing = 1;
  if (!hello_send(runtime, peer)) {
    peer_close(peer);
    return 0;
  }
  return 1;

failed:
  close(fd);
  peer->connect_failures++;
  if (peer->address_count != 0)
    peer->address_index =
        (uint8_t)((peer->address_index + 1) % peer->address_count);
  return 0;
}

static int learn_observed_endpoint(struct managed_runtime *runtime,
                                   const char *member_id,
                                   const struct in_addr *address) {
  struct nhrp_ha_managed_state previous;
  struct nhrp_ha_managed_member *member;
  char text[INET_ADDRSTRLEN];
  int changed;

  if (strcmp(runtime->state.local_member, runtime->state.leader) != 0)
    return 1;
  member = state_member(runtime, member_id);
  if (member == NULL)
    return 0;
  previous = runtime->state;
  changed =
      nhrp_ha_managed_member_set_observed(&runtime->state, member, address);
  if (changed == -2) {
    inet_ntop(AF_INET, address, text, sizeof(text));
    managed_log(
        "opennhrp-ha: rejecting duplicate observed endpoint %s for %s\n", text,
        member_id);
    runtime->state = previous;
    return 0;
  }
  if (changed == -1) {
    inet_ntop(AF_INET, address, text, sizeof(text));
    managed_log(
        "opennhrp-ha: observed endpoint %s ignored for %s; list is full\n",
        text, member_id);
    runtime->state = previous;
    return 1;
  }
  if (changed == 0)
    return 1;
  runtime->state.manifest_revision++;
  runtime->state.commit_index++;
  if (!state_save(runtime)) {
    runtime->state = previous;
    return 0;
  }
  inet_ntop(AF_INET, address, text, sizeof(text));
  managed_log("opennhrp-ha: learned observed endpoint %s for %s\n", text,
              member_id);
  peers_sync(runtime);
  return admin_ok(runtime, "ha managed reload\n");
}

static int rejoin_tick(struct managed_runtime *runtime, uint64_t now) {
  int local_leader =
      strcmp(runtime->state.local_member, runtime->state.leader) == 0;
  int have_candidate = 0;
  size_t i;

  if (!runtime->service_available || !runtime->isolated)
    return 1;
  for (i = 0; i < runtime->peer_count; i++) {
    struct managed_peer *peer = &runtime->peers[i];

    if (peer->state != NHRP_HA_MANAGED_ACTIVE ||
        (!local_leader && strcmp(peer->member, runtime->state.leader) != 0))
      continue;
    have_candidate = 1;
    if (peer->authenticated) {
      runtime->isolated = 0;
      runtime->rejoin_started_ms = 0;
      if (strcmp(runtime->state.local_member, runtime->state.leader) == 0)
        runtime->leader_since_ms = now;
      managed_log("opennhrp-ha: member %s rejoined through %s\n",
                  runtime->state.local_member, peer->member);
      return set_core_state(runtime);
    }
    if (local_leader && now - runtime->rejoin_started_ms < MANAGED_RECONNECT_MS)
      continue;
    if (peer->fd < 0 && now - peer->last_connect_ms >= MANAGED_RECONNECT_MS)
      peer_connect(runtime, peer);
  }
  if (have_candidate)
    return 1;
  runtime->isolated = 0;
  runtime->rejoin_started_ms = 0;
  if (strcmp(runtime->state.local_member, runtime->state.leader) == 0)
    runtime->leader_since_ms = now;
  managed_log("opennhrp-ha: member %s left isolation without a peer\n",
              runtime->state.local_member);
  return set_core_state(runtime);
}

static struct managed_peer *leader_peer(struct managed_runtime *runtime) {
  if (strcmp(runtime->state.local_member, runtime->state.leader) == 0)
    return NULL;
  return peer_find(runtime, runtime->state.leader);
}

static int adaptive_offline(struct managed_peer *peer, uint64_t now) {
  double interval = peer->receive_interval_ms;
  double deadline;
  uint64_t elapsed;

  if (!peer->authenticated || peer->last_receive_ms == 0 ||
      now <= peer->last_receive_ms)
    return 0;
  if (interval < 100.0)
    interval = MANAGED_SEND_MS;
  deadline = peer->receive_interval_ms + 4.0 * peer->receive_variance_ms;
  if (deadline < 300.0)
    deadline = 300.0;
  if (deadline > 2000.0)
    deadline = 2000.0;
  elapsed = now - peer->last_receive_ms;
  peer->consecutive_misses = (unsigned int)(elapsed / interval);
  return peer->consecutive_misses >= 3 && elapsed >= (uint64_t)deadline;
}

static int managed_peer_healthy(struct managed_peer *peer, uint64_t now) {
  return peer != NULL && peer->fd >= 0 && peer->authenticated &&
         peer->hello_received && peer->last_receive_ms != 0 &&
         !adaptive_offline(peer, now);
}

static int witness_fallback_tick(struct managed_runtime *runtime,
                                 uint64_t now) {
  struct managed_peer *peer = NULL;
  size_t active = active_member_count(runtime);
  int peer_healthy;
  int same_mode_epoch;
  int safe;
  size_t i;

  if (opennhrp_ha_witness_single_hub_fallback(
          (unsigned int)active, runtime->state.witness_mode,
          runtime->state.local_member, runtime->state.leader)) {
    runtime->witness_fallback_since_ms = 0;
    if (!witness_mode_save(runtime, NHRP_HA_WITNESS_LEGACY))
      return 0;
    runtime->witness_lease_deadline_ms = 0;
    runtime->witness_manager_seen_ms = 0;
    managed_log("opennhrp-ha: one Active Hub; Manager Witness disabled in "
                "favor of legacy availability-first\n");
    return 1;
  }

  if (active >= 3) {
    runtime->witness_fallback_since_ms = 0;
    if (runtime->state.witness_mode == NHRP_HA_WITNESS_LEGACY ||
        strcmp(runtime->state.local_member, runtime->state.leader) != 0 ||
        !hub_majority(runtime, now, 1))
      return 1;
    if (!witness_mode_save(runtime, NHRP_HA_WITNESS_LEGACY))
      return 0;
    runtime->witness_lease_deadline_ms = 0;
    runtime->witness_manager_seen_ms = 0;
    managed_log("opennhrp-ha: three or more Active Hubs; "
                "Manager Witness disabled in favor of Hub majority\n");
    return 1;
  }

  if (runtime->state.witness_mode != NHRP_HA_WITNESS_ACTIVE &&
      runtime->state.witness_mode != NHRP_HA_WITNESS_DISABLING) {
    runtime->witness_fallback_since_ms = 0;
    return 1;
  }
  for (i = 0; i < runtime->peer_count; i++)
    if (runtime->peers[i].state == NHRP_HA_MANAGED_ACTIVE) {
      peer = &runtime->peers[i];
      break;
    }
  same_mode_epoch =
      peer != NULL && peer->witness_mode == runtime->state.witness_mode &&
      CRYPTO_memcmp(peer->witness_epoch, runtime->witness_epoch, 16) == 0;
  peer_healthy = managed_peer_healthy(peer, now);
  safe = peer != NULL &&
         opennhrp_ha_witness_fallback_safe(
             peer_healthy, same_mode_epoch, runtime->state.term,
             peer->reported_term, runtime->state.leader,
             peer->reported_leader_id, runtime->local_index, peer->match_index,
             runtime->local_digest, peer->digest);
  if (witness_manager_reachable(runtime, now) || !peer_healthy ||
      peer->manager_reachable || !same_mode_epoch) {
    runtime->witness_fallback_since_ms = 0;
    return 1;
  }
  if (runtime->witness_fallback_since_ms == 0)
    runtime->witness_fallback_since_ms = now;
  if (runtime->state.witness_mode == NHRP_HA_WITNESS_ACTIVE &&
      strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
      now - runtime->witness_fallback_since_ms >= WITNESS_FALLBACK_MS && safe) {
    managed_log("opennhrp-ha: Witness Manager absent on both Hubs; "
                "starting coordinated legacy fallback\n");
    runtime->witness_fallback_since_ms = now;
    return witness_mode_save(runtime, NHRP_HA_WITNESS_DISABLING);
  }
  if (runtime->state.witness_mode == NHRP_HA_WITNESS_DISABLING &&
      strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
      peer->witness_mode == NHRP_HA_WITNESS_DISABLING && safe) {
    if (!witness_mode_save(runtime, NHRP_HA_WITNESS_LEGACY))
      return 0;
    runtime->witness_lease_deadline_ms = 0;
    runtime->witness_fallback_since_ms = 0;
    managed_log("opennhrp-ha: coordinated Witness fallback completed\n");
  }
  return 1;
}

static struct nhrp_ha_managed_member *
best_candidate(struct managed_runtime *runtime) {
  struct nhrp_ha_managed_member *best = local_member(runtime);
  size_t i;

  if (best != NULL && best->state != NHRP_HA_MANAGED_ACTIVE)
    best = NULL;
  for (i = 0; i < runtime->peer_count; i++) {
    struct managed_peer *peer = &runtime->peers[i];
    struct nhrp_ha_managed_member *member;

    if (peer->state != NHRP_HA_MANAGED_ACTIVE || peer->connect_failures >= 3)
      continue;
    member = state_member(runtime, peer->member);
    if (member_preferred(member, best))
      best = member;
  }
  return best;
}

static int election_tick(struct managed_runtime *runtime, uint64_t now) {
  struct managed_peer *leader = leader_peer(runtime);
  struct nhrp_ha_managed_member *best;
  size_t active;

  if (leader == NULL)
    return 1;
  if (leader->fd >= 0 && !adaptive_offline(leader, now))
    return 1;
  if (strcmp(runtime->state.leader, runtime->state.primary_member) == 0 &&
      nhrp_ha_failback_transfer_waiting(&runtime->failback,
                                        &runtime->failback_policy, now))
    return 1;
  if (leader->fd >= 0)
    peer_close(leader);
  leader->connect_failures++;
  best = best_candidate(runtime);
  if (best == NULL)
    return 1;
  if (strcmp(best->member, runtime->state.local_member) == 0) {
    active = active_member_count(runtime);
    if (!opennhrp_ha_autonomous_election_allowed((unsigned int)active,
                                                 runtime->state.witness_mode,
                                                 hub_majority(runtime, now, 0)))
      return 1;
    return become_leader(runtime);
  }
  leader = peer_find(runtime, best->member);
  if (leader != NULL && leader->fd < 0 &&
      now - leader->last_connect_ms >= MANAGED_RECONNECT_MS)
    peer_connect(runtime, leader);
  return 1;
}

static int failback_tick(struct managed_runtime *runtime, uint64_t now) {
  struct managed_peer *primary;
  int local_is_backup_leader;
  int primary_is_leader;
  int primary_healthy;
  int synchronized;
  int request;

  if (strcmp(runtime->state.local_member, runtime->state.primary_member) == 0)
    return 1;
  primary = peer_find(runtime, runtime->state.primary_member);
  primary_healthy = managed_peer_healthy(primary, now);
  if (managed_debug && (!runtime->primary_health_known ||
                        runtime->primary_healthy_last != primary_healthy)) {
    managed_log("opennhrp-ha: Primary %s is %s; connected=%d "
                "authenticated=%d hello=%d transfer-pending=%d\n",
                runtime->state.primary_member,
                primary_healthy ? "healthy" : "unhealthy",
                primary != NULL && primary->fd >= 0,
                primary != NULL && primary->authenticated,
                primary != NULL && primary->hello_received,
                runtime->failback.transfer_pending);
    runtime->primary_health_known = 1;
    runtime->primary_healthy_last = primary_healthy;
  }
  primary_is_leader =
      strcmp(runtime->state.leader, runtime->state.primary_member) == 0;
  local_is_backup_leader =
      strcmp(runtime->state.local_member, runtime->state.leader) == 0;
  nhrp_ha_failback_observe_primary(&runtime->failback, primary_healthy, now);
  nhrp_ha_failback_observe_primary_leader(&runtime->failback,
                                          &runtime->failback_policy, now,
                                          primary_is_leader, primary_healthy);
  if (!local_is_backup_leader)
    return 1;
  if (nhrp_ha_failback_transfer_timed_out(&runtime->failback,
                                          &runtime->failback_policy, now)) {
    managed_log("opennhrp-ha: automatic failback transfer timed out; "
                "backoff level %u until %llu\n",
                runtime->failback.backoff_level,
                (unsigned long long)runtime->failback.not_before_ms);
    return 1;
  }
  synchronized = primary != NULL &&
                 primary->match_index >= runtime->local_index &&
                 runtime->local_digest[0] != 0 &&
                 strcmp(primary->digest, runtime->local_digest) == 0;
  if (!nhrp_ha_failback_transfer_ready(&runtime->failback,
                                       &runtime->failback_policy, now,
                                       primary_healthy, synchronized))
    return 1;
  request = runtime->failback.request;
  if (!adopt_leader(runtime, runtime->state.term + 1,
                    runtime->state.local_member))
    return 0;
  if (!frame_send(runtime, primary, NHRP_HA_CONTROL_TRANSFER,
                  (const uint8_t *)runtime->local_digest, 64,
                  runtime->local_index, runtime->local_index))
    return 0;
  nhrp_ha_failback_transfer_sent(&runtime->failback, now);
  managed_log(
      "opennhrp-ha: %s safe failback transfer to Primary %s at index "
      "%llu\n",
      request == 2 ? "forced" : (request == 1 ? "requested" : "automatic"),
      runtime->state.primary_member, (unsigned long long)runtime->local_index);
  return 1;
}

static void response_append(char *response, size_t size, size_t *used,
                            const char *format, ...) {
  va_list arguments;
  int written;

  if (*used >= size)
    return;
  va_start(arguments, format);
  /* NOLINTNEXTLINE(clang-analyzer-valist.Uninitialized) */
  written = vsnprintf(response + *used, size - *used, format, arguments);
  va_end(arguments);
  if (written < 0)
    return;
  if ((size_t)written >= size - *used)
    *used = size;
  else
    *used += (size_t)written;
}

static uint64_t remaining_ms(uint64_t now, uint64_t deadline) {
  return deadline > now ? deadline - now : 0;
}

static int witness_capable(const struct managed_runtime *runtime) {
  return active_member_count(runtime) == 2;
}

static size_t active_member_count(const struct managed_runtime *runtime) {
  size_t active = 0;
  size_t i;

  for (i = 0; i < runtime->state.member_count; i++)
    if (runtime->state.members[i].state == NHRP_HA_MANAGED_ACTIVE)
      active++;
  return active;
}

static const char *quorum_policy_name(const struct managed_runtime *runtime) {
  size_t active = active_member_count(runtime);

  if (active >= 3)
    return "hub-majority";
  if (active <= 1)
    return "legacy";
  if (runtime->state.witness_mode != NHRP_HA_WITNESS_LEGACY)
    return "manager-witness";
  return "legacy";
}

static size_t quorum_voter_count(const struct managed_runtime *runtime) {
  size_t active = active_member_count(runtime);

  return active == 2 && runtime->state.witness_mode != NHRP_HA_WITNESS_LEGACY
             ? active + 1
             : active;
}

static size_t quorum_required(const struct managed_runtime *runtime) {
  size_t active = active_member_count(runtime);

  if (active >= 3)
    return opennhrp_ha_hub_majority_required((unsigned int)active);
  if (active <= 1)
    return 1;
  return runtime->state.witness_mode == NHRP_HA_WITNESS_LEGACY ? 1 : 2;
}

static size_t quorum_votes(struct managed_runtime *runtime, uint64_t now) {
  struct nhrp_ha_managed_member *local = local_member(runtime);
  size_t active = active_member_count(runtime);
  size_t votes =
      local != NULL && local->state == NHRP_HA_MANAGED_ACTIVE ? 1 : 0;

  if (active >= 3)
    return hub_votes(runtime, now, 1);
  if (witness_peer_vote(runtime, now))
    votes++;
  if (witness_manager_vote(runtime, now))
    votes++;
  return votes;
}

static int witness_epoch_matches(const struct managed_runtime *runtime,
                                 const uint8_t epoch[16]) {
  return CRYPTO_memcmp(runtime->witness_epoch, epoch, 16) == 0;
}

static int witness_prepare(struct managed_runtime *runtime,
                           const uint8_t epoch[16]) {
  static const uint8_t zero[16];
  uint64_t now = monotonic_ms();
  int epoch_matches;

  if (!witness_capable(runtime) || CRYPTO_memcmp(epoch, zero, 16) == 0)
    return 0;
  epoch_matches = witness_epoch_matches(runtime, epoch);
  if (runtime->state.witness_mode != NHRP_HA_WITNESS_LEGACY) {
    if (!opennhrp_ha_witness_reprepare_needed(
            runtime->state.witness_mode, epoch_matches,
            witness_manager_vote(runtime, now))) {
      if (!epoch_matches ||
          runtime->state.witness_mode == NHRP_HA_WITNESS_DISABLING)
        return 0;
      runtime->witness_manager_seen_ms = now;
      return 1;
    }
  }
  memcpy(runtime->witness_epoch, epoch, 16);
  runtime->witness_lease_holder[0] = 0;
  runtime->witness_lease_term = 0;
  runtime->witness_lease_sequence = 0;
  runtime->witness_lease_deadline_ms = 0;
  if (!witness_mode_save(runtime, NHRP_HA_WITNESS_PREPARING))
    return 0;
  runtime->witness_manager_seen_ms = now;
  return 1;
}

static int witness_activate(struct managed_runtime *runtime,
                            const uint8_t epoch[16]) {
  if (!witness_epoch_matches(runtime, epoch) ||
      (runtime->state.witness_mode != NHRP_HA_WITNESS_PREPARING &&
       runtime->state.witness_mode != NHRP_HA_WITNESS_ACTIVE &&
       runtime->state.witness_mode != NHRP_HA_WITNESS_DISABLING))
    return 0;
  if (!witness_mode_save(runtime, NHRP_HA_WITNESS_ACTIVE))
    return 0;
  runtime->witness_fallback_since_ms = 0;
  runtime->witness_manager_seen_ms = monotonic_ms();
  return 1;
}

static int witness_lease(struct managed_runtime *runtime,
                         const uint8_t epoch[16], uint64_t term,
                         const char *holder, uint64_t sequence,
                         uint64_t ttl_ms) {
  struct nhrp_ha_managed_member *member = state_member(runtime, holder);

  if (!witness_capable(runtime) || member == NULL ||
      member->state != NHRP_HA_MANAGED_ACTIVE ||
      !opennhrp_ha_witness_lease_acceptable(
          runtime->state.witness_mode, witness_epoch_matches(runtime, epoch),
          runtime->state.term, term, runtime->witness_lease_sequence, sequence,
          ttl_ms) ||
      (term == runtime->state.term &&
       strcmp(holder, runtime->state.leader) != 0))
    return 0;
  if ((term > runtime->state.term ||
       strcmp(holder, runtime->state.leader) != 0) &&
      !state_reload_and_update(runtime, term, holder))
    return 0;
  runtime->witness_lease_term = term;
  runtime->witness_lease_sequence = sequence;
  snprintf(runtime->witness_lease_holder, sizeof(runtime->witness_lease_holder),
           "%s", holder);
  runtime->witness_lease_deadline_ms = monotonic_ms() + ttl_ms;
  runtime->witness_manager_seen_ms = monotonic_ms();
  runtime->witness_fallback_since_ms = 0;
  if (runtime->isolated && runtime->service_available &&
      witness_manager_vote(runtime, monotonic_ms())) {
    runtime->isolated = 0;
    runtime->rejoin_started_ms = 0;
  }
  return set_core_state(runtime);
}

static int control_handle(struct managed_runtime *runtime) {
  char command[512];
  char response[32768];
  char current_key[17];
  char next_key[17] = "";
  size_t used = 0;
  ssize_t length;
  int fd = accept(runtime->control_listener, NULL, NULL);
  size_t i;

  if (fd < 0)
    return 0;
  length = read(fd, command, sizeof(command) - 1);
  if (length <= 0) {
    close(fd);
    return 0;
  }
  command[length] = 0;
  while (length > 0 && isspace((unsigned char)command[length - 1]))
    command[--length] = 0;
  if (strcmp(command, "ha leave") == 0) {
    struct managed_peer *leader = leader_peer(runtime);

    if (strcmp(runtime->state.local_member, runtime->state.primary_member) == 0)
      snprintf(response, sizeof(response),
               "Status: error\nReason: primary-must-destroy\n");
    else if (strcmp(runtime->state.local_member, runtime->state.leader) == 0)
      snprintf(response, sizeof(response),
               "Status: error\nReason: transfer-leadership-first\n");
    else if (leader == NULL || leader->fd < 0 || !leader->authenticated ||
             !leader->hello_received)
      snprintf(response, sizeof(response),
               "Status: error\nReason: leader-unavailable\n");
    else if (!frame_send(runtime, leader, NHRP_HA_CONTROL_LEAVE, NULL, 0,
                         runtime->local_index, runtime->local_index))
      snprintf(response, sizeof(response),
               "Status: error\nReason: leave-request-failed\n");
    else
      snprintf(response, sizeof(response), "Status: ok\n\nLeave requested.\n");
  } else if (strcmp(command, "ha destroy") == 0) {
    snprintf(response, sizeof(response),
             "Status: error\nReason: force-required\n");
  } else if (strcmp(command, "ha destroy --force") == 0) {
    int ready = strcmp(runtime->state.local_member,
                       runtime->state.primary_member) == 0 &&
                strcmp(runtime->state.local_member, runtime->state.leader) == 0;

    for (i = 0; ready && i < runtime->peer_count; i++)
      ready = runtime->peers[i].fd >= 0 && runtime->peers[i].authenticated &&
              runtime->peers[i].hello_received;
    if (strcmp(runtime->state.local_member, runtime->state.primary_member) != 0)
      snprintf(response, sizeof(response),
               "Status: error\nReason: primary-only\n");
    else if (strcmp(runtime->state.local_member, runtime->state.leader) != 0)
      snprintf(response, sizeof(response),
               "Status: error\nReason: primary-must-be-leader\n");
    else if (!ready)
      snprintf(response, sizeof(response),
               "Status: error\nReason: member-unavailable\n");
    else {
      for (i = 0; ready && i < runtime->peer_count; i++)
        ready = frame_send(runtime, &runtime->peers[i], NHRP_HA_CONTROL_DESTROY,
                           NULL, 0, runtime->local_index, runtime->local_index);
      if (!ready || !managed_decommission(runtime))
        snprintf(response, sizeof(response),
                 "Status: error\nReason: destroy-failed\n");
      else
        snprintf(response, sizeof(response),
                 "Status: ok\n\nHA cluster destroyed.\n");
    }
  } else if (strncmp(command, "ha configure addresses ", 23) == 0) {
    struct in_addr addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
    struct in_addr targets[NHRP_HA_MANAGED_MAX_ENDPOINTS];
    char *position;
    char *save = NULL;
    size_t address_count = 0;
    size_t target_count = 0;
    size_t expected;
    int valid = 1;

    position = strtok_r(command + 23, " ", &save);
    valid = position != NULL && sscanf(position, "%zu", &expected) == 1 &&
            expected <= NHRP_HA_MANAGED_MAX_ENDPOINTS;
    while (valid && address_count < expected) {
      position = strtok_r(NULL, " ", &save);
      if (position == NULL ||
          inet_pton(AF_INET, position, &addresses[address_count]) != 1) {
        valid = 0;
        break;
      }
      address_count++;
    }
    position = valid ? strtok_r(NULL, " ", &save) : NULL;
    valid = valid && position != NULL && strcmp(position, "health") == 0;
    position = valid ? strtok_r(NULL, " ", &save) : NULL;
    valid = valid && position != NULL &&
            sscanf(position, "%zu", &expected) == 1 &&
            expected <= NHRP_HA_MANAGED_MAX_ENDPOINTS;
    while (valid && target_count < expected) {
      position = strtok_r(NULL, " ", &save);
      if (position == NULL ||
          inet_pton(AF_INET, position, &targets[target_count]) != 1) {
        valid = 0;
        break;
      }
      target_count++;
    }
    if (valid && strtok_r(NULL, " ", &save) != NULL)
      valid = 0;
    if (!valid ||
        !health_targets_set(runtime, targets, target_count, monotonic_ms())) {
      snprintf(response, sizeof(response),
               "Status: error\nReason: invalid-addresses\n");
    } else {
      if (target_count != 0 && runtime->health_socket < 0)
        runtime->health_socket =
            health_socket_create(runtime->health_identifier);
      if (target_count != 0 && runtime->health_socket < 0) {
        snprintf(response, sizeof(response),
                 "Status: error\nReason: health-socket-failed\n");
        send_all(fd, response, strlen(response));
        close(fd);
        return 1;
      }
      if (address_count != 0) {
        memcpy(runtime->configured_addresses, addresses,
               address_count * sizeof(addresses[0]));
        runtime->configured_address_count = address_count;
      }
      if (address_count != 0 &&
          strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
          !configured_apply(runtime, runtime->state.local_member, addresses,
                            address_count))
        snprintf(response, sizeof(response),
                 "Status: error\nReason: configure-failed\n");
      else
        snprintf(response, sizeof(response), "Status: ok\n");
    }
  } else if (strncmp(command, "ha witness prepare epoch ", 25) == 0) {
    uint8_t epoch[16];

    if (!witness_epoch_parse(command + 25, epoch) ||
        !witness_prepare(runtime, epoch))
      snprintf(response, sizeof(response),
               "Status: error\nReason: witness-prepare-rejected\n");
    else
      snprintf(response, sizeof(response), "Status: ok\n");
  } else if (strncmp(command, "ha witness activate epoch ", 26) == 0) {
    uint8_t epoch[16];

    if (!witness_epoch_parse(command + 26, epoch) ||
        !witness_activate(runtime, epoch))
      snprintf(response, sizeof(response),
               "Status: error\nReason: witness-activate-rejected\n");
    else
      snprintf(response, sizeof(response), "Status: ok\n");
  } else if (strncmp(command, "ha witness lease epoch ", 23) == 0) {
    char epoch_text[33];
    char holder[NHRP_HA_MANAGED_MEMBER_MAX + 1];
    char extra;
    unsigned long long term;
    unsigned long long sequence;
    unsigned long long ttl_ms;
    uint8_t epoch[16];

    if (sscanf(command,
               "ha witness lease epoch %32s term %llu holder %63s sequence "
               "%llu ttl-ms %llu %c",
               epoch_text, &term, holder, &sequence, &ttl_ms, &extra) != 5 ||
        !witness_epoch_parse(epoch_text, epoch))
      snprintf(response, sizeof(response),
               "Status: error\nReason: witness-lease-rejected\n");
    else if (!witness_lease(runtime, epoch, term, holder, sequence, ttl_ms))
      snprintf(response, sizeof(response),
               "Status: error\nReason: witness-lease-rejected\n"
               "Current-Term: %llu\nCurrent-Leader: %s\n",
               (unsigned long long)runtime->state.term, runtime->state.leader);
    else
      snprintf(response, sizeof(response), "Status: ok\n");
  } else if (strcmp(command, "ha witness show format json") == 0 ||
             strcmp(command, "ha witness show --format json") == 0 ||
             strcmp(command, "ha witness show") == 0) {
    uint64_t now = monotonic_ms();
    int peer_vote = witness_peer_vote(runtime, now);
    int manager_vote = witness_manager_vote(runtime, now);

    response_append(response, sizeof(response), &used,
                    "Status: ok\n\n{\"capable\":%s,\"mode\":\"%s\","
                    "\"policy\":\"%s\",\"voters\":%zu,"
                    "\"required\":%zu,\"votes\":%zu,\"epoch\":\"",
                    witness_capable(runtime) ? "true" : "false",
                    witness_mode_name(runtime->state.witness_mode),
                    quorum_policy_name(runtime), quorum_voter_count(runtime),
                    quorum_required(runtime), quorum_votes(runtime, now));
    for (i = 0; i < 16; i++)
      response_append(response, sizeof(response), &used, "%02x",
                      runtime->witness_epoch[i]);
    response_append(
        response, sizeof(response), &used,
        "\",\"peer_vote\":%s,\"manager_vote\":%s,"
        "\"quorum_available\":%s,\"lease_holder\":\"%s\","
        "\"lease_term\":%llu,\"lease_sequence\":%llu,"
        "\"lease_remaining_ms\":%llu,\"fallback_remaining_ms\":%llu,"
        "\"digest\":\"%s\"}\n",
        peer_vote ? "true" : "false", manager_vote ? "true" : "false",
        service_quorum(runtime, now) ? "true" : "false",
        runtime->witness_lease_holder,
        (unsigned long long)runtime->witness_lease_term,
        (unsigned long long)runtime->witness_lease_sequence,
        (unsigned long long)remaining_ms(now,
                                         runtime->witness_lease_deadline_ms),
        (unsigned long long)(runtime->witness_fallback_since_ms != 0
                                 ? remaining_ms(
                                       now, runtime->witness_fallback_since_ms +
                                                WITNESS_FALLBACK_MS)
                                 : 0),
        runtime->local_digest);
  } else if (strcmp(command, "ha cluster show format json") == 0 ||
             strcmp(command, "ha cluster show --format json") == 0 ||
             strcmp(command, "ha cluster show") == 0) {
    uint64_t now = monotonic_ms();
    int peer_vote = witness_peer_vote(runtime, now);
    int manager_vote = witness_manager_vote(runtime, now);
    int quorum = service_quorum(runtime, now);
    int fenced = runtime->isolated || (strcmp(runtime->state.local_member,
                                              runtime->state.leader) == 0 &&
                                       !quorum);

    response_append(response, sizeof(response), &used,
                    "Status: ok\n\n{\"cluster_id\":\"");
    for (i = 0; i < 16; i++)
      response_append(response, sizeof(response), &used, "%02x",
                      runtime->state.cluster_id[i]);
    response_append(
        response, sizeof(response), &used,
        "\",\"primary\":\"%s\",\"leader\":\"%s\",\"local_member\":"
        "\"%s\",\"term\":%llu,\"commit_index\":%llu,"
        "\"manifest_revision\":%llu,\"digest\":\"%s\","
        "\"service_available\":%s,"
        "\"isolated\":%s,\"network_health\":\"%s\","
        "\"health_interval_seconds\":%u,"
        "\"health_failure_rounds\":%u,"
        "\"health_recovery_rounds\":%u,\"health_targets\":[",
        runtime->state.primary_member, runtime->state.leader,
        runtime->state.local_member, (unsigned long long)runtime->state.term,
        (unsigned long long)runtime->state.commit_index,
        (unsigned long long)runtime->state.manifest_revision,
        runtime->local_digest, runtime->service_available ? "true" : "false",
        fenced ? "true" : "false",
        runtime->health_target_count == 0
            ? "disabled"
            : (runtime->network_healthy ? "healthy" : "unhealthy"),
        runtime->health_interval_seconds, runtime->health_failure_rounds,
        runtime->health_recovery_rounds);
    for (i = 0; i < runtime->health_target_count; i++) {
      char address[INET_ADDRSTRLEN];

      inet_ntop(AF_INET, &runtime->health_targets[i], address, sizeof(address));
      response_append(response, sizeof(response), &used,
                      "%s{\"address\":\"%s\",\"last_success\":%s}",
                      i == 0 ? "" : ",", address,
                      runtime->health_last_success[i] ? "true" : "false");
    }
    response_append(response, sizeof(response), &used,
                    "],\"witness\":{\"capable\":%s,\"mode\":\"%s\","
                    "\"policy\":\"%s\",\"voters\":%zu,\"required\":%zu,"
                    "\"votes\":%zu,\"epoch\":\"",
                    witness_capable(runtime) ? "true" : "false",
                    witness_mode_name(runtime->state.witness_mode),
                    quorum_policy_name(runtime), quorum_voter_count(runtime),
                    quorum_required(runtime), quorum_votes(runtime, now));
    for (i = 0; i < 16; i++)
      response_append(response, sizeof(response), &used, "%02x",
                      runtime->witness_epoch[i]);
    response_append(
        response, sizeof(response), &used,
        "\",\"peer_vote\":%s,\"manager_vote\":%s,"
        "\"quorum_available\":%s,\"lease_holder\":\"%s\","
        "\"lease_term\":%llu,\"lease_sequence\":%llu,"
        "\"lease_remaining_ms\":%llu,\"fallback_remaining_ms\":%llu,"
        "\"digest\":\"%s\"},\"members\":[",
        peer_vote ? "true" : "false", manager_vote ? "true" : "false",
        quorum ? "true" : "false", runtime->witness_lease_holder,
        (unsigned long long)runtime->witness_lease_term,
        (unsigned long long)runtime->witness_lease_sequence,
        (unsigned long long)remaining_ms(now,
                                         runtime->witness_lease_deadline_ms),
        (unsigned long long)(runtime->witness_fallback_since_ms != 0
                                 ? remaining_ms(
                                       now, runtime->witness_fallback_since_ms +
                                                WITNESS_FALLBACK_MS)
                                 : 0),
        runtime->local_digest);
    for (i = 0; i < runtime->state.member_count; i++) {
      size_t j;
      struct managed_peer *peer =
          peer_find(runtime, runtime->state.members[i].member);
      const char *state_name =
          runtime->state.members[i].state == NHRP_HA_MANAGED_ACTIVE ? "active"
          : runtime->state.members[i].state == NHRP_HA_MANAGED_LEARNER
              ? "learner"
              : "disabled";

      response_append(response, sizeof(response), &used,
                      "%s{\"member\":\"%s\",\"addresses\":[", i == 0 ? "" : ",",
                      runtime->state.members[i].member);
      for (j = 0; j < runtime->state.members[i].address_count; j++) {
        char address[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &runtime->state.members[i].addresses[j], address,
                  sizeof(address));
        response_append(response, sizeof(response), &used,
                        "%s{\"address\":\"%s\",\"origin\":\"%s\"}",
                        j == 0 ? "" : ",", address,
                        j < runtime->state.members[i].configured_address_count
                            ? "configured"
                            : "observed");
      }
      response_append(response, sizeof(response), &used,
                      "],\"priority\":%u,"
                      "\"state\":\"%s\",\"connected\":%s,\"authenticated\":%s,"
                      "\"match_index\":%llu}",
                      runtime->state.members[i].priority, state_name,
                      peer != NULL && peer->fd >= 0 ? "true" : "false",
                      peer != NULL && peer->authenticated ? "true" : "false",
                      (unsigned long long)(peer != NULL
                                               ? peer->match_index
                                               : runtime->local_index));
    }
    response_append(response, sizeof(response), &used, "]}\n");
  } else if (strcmp(command, "ha replication show format json") == 0 ||
             strcmp(command, "ha replication show --format json") == 0 ||
             strcmp(command, "ha replication show") == 0) {
    response_append(response, sizeof(response), &used,
                    "Status: ok\n\n{\"local_index\":%llu,\"digest\":\"%s\","
                    "\"snapshots_sent\":%llu,\"deltas_sent\":%llu,"
                    "\"snapshots_received\":%llu,\"deltas_received\":%llu,"
                    "\"resync_requests\":%llu,\"peers\":[",
                    (unsigned long long)runtime->local_index,
                    runtime->local_digest,
                    (unsigned long long)runtime->snapshots_sent,
                    (unsigned long long)runtime->deltas_sent,
                    (unsigned long long)runtime->snapshots_received,
                    (unsigned long long)runtime->deltas_received,
                    (unsigned long long)runtime->resync_requests);
    for (i = 0; i < runtime->peer_count; i++)
      response_append(
          response, sizeof(response), &used,
          "%s{\"member\":\"%s\",\"match_index\":%llu,\"lag\":%llu,"
          "\"digest\":\"%s\",\"connected\":%s}",
          i == 0 ? "" : ",", runtime->peers[i].member,
          (unsigned long long)runtime->peers[i].match_index,
          (unsigned long long)(runtime->local_index >
                                       runtime->peers[i].match_index
                                   ? runtime->local_index -
                                         runtime->peers[i].match_index
                                   : 0),
          runtime->peers[i].digest,
          runtime->peers[i].fd >= 0 ? "true" : "false");
    response_append(response, sizeof(response), &used, "]}\n");
  } else if (strcmp(command, "ha key status format json") == 0 ||
             strcmp(command, "ha key status --format json") == 0 ||
             strcmp(command, "ha key status") == 0) {
    nhrp_ha_auth_key_id_format(runtime->keys.key[0].id, current_key);
    if (runtime->keys.key[1].present)
      nhrp_ha_auth_key_id_format(runtime->keys.key[1].id, next_key);
    snprintf(
        response, sizeof(response),
        "Status: ok\n\n{\"current_key_id\":\"%s\",\"next_key_id\":%s%s%s}\n",
        current_key, next_key[0] != 0 ? "\"" : "",
        next_key[0] != 0 ? next_key : "null", next_key[0] != 0 ? "\"" : "");
  } else if (strcmp(command, "ha failback show format json") == 0 ||
             strcmp(command, "ha failback show --format json") == 0 ||
             strcmp(command, "ha failback show") == 0) {
    struct managed_peer *primary =
        peer_find(runtime, runtime->state.primary_member);
    uint64_t now = monotonic_ms();
    uint64_t primary_stable_ms =
        runtime->failback.primary_stable_since_ms != 0
            ? now - runtime->failback.primary_stable_since_ms
            : 0;
    uint64_t backup_active_ms =
        strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
                strcmp(runtime->state.local_member,
                       runtime->state.primary_member) != 0 &&
                runtime->leader_since_ms != 0
            ? now - runtime->leader_since_ms
            : 0;
    int primary_healthy = managed_peer_healthy(primary, now);
    int synchronized = primary != NULL &&
                       primary->match_index >= runtime->local_index &&
                       runtime->local_digest[0] != 0 &&
                       strcmp(primary->digest, runtime->local_digest) == 0;

    snprintf(
        response, sizeof(response),
        "Status: ok\n\n{\"mode\":\"automatic\",\"primary\":\"%s\","
        "\"local_backup_leader\":%s,\"primary_connected\":%s,"
        "\"primary_authenticated\":%s,\"primary_healthy\":%s,"
        "\"primary_synchronized\":%s,\"primary_stable_ms\":%llu,"
        "\"recovery_stable_ms\":%llu,\"backup_active_ms\":%llu,"
        "\"minimum_backup_active_ms\":%llu,\"transfer_pending\":%s,"
        "\"probation_remaining_ms\":%llu,\"backoff_level\":%u,"
        "\"next_allowed_in_ms\":%llu,\"backoff_reset_in_ms\":%llu,"
        "\"request\":%d}\n",
        runtime->state.primary_member,
        strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
                strcmp(runtime->state.local_member,
                       runtime->state.primary_member) != 0
            ? "true"
            : "false",
        primary != NULL && primary->fd >= 0 ? "true" : "false",
        primary != NULL && primary->authenticated ? "true" : "false",
        primary_healthy ? "true" : "false", synchronized ? "true" : "false",
        (unsigned long long)primary_stable_ms,
        (unsigned long long)runtime->failback_policy.recovery_stable_seconds *
            1000,
        (unsigned long long)backup_active_ms, (unsigned long long)0,
        runtime->failback.transfer_pending ? "true" : "false",
        (unsigned long long)remaining_ms(now,
                                         runtime->failback.probation_until_ms),
        runtime->failback.backoff_level,
        (unsigned long long)remaining_ms(now, runtime->failback.not_before_ms),
        (unsigned long long)remaining_ms(now,
                                         runtime->failback.backoff_reset_at_ms),
        runtime->failback.request);
  } else if (strcmp(command, "ha failback request") == 0 ||
             strcmp(command, "ha failback request force") == 0) {
    nhrp_ha_failback_request(&runtime->failback,
                             strstr(command, "force") != NULL);
    snprintf(response, sizeof(response), "Status: ok\n\nRequested: %s\n",
             runtime->failback.request == 2 ? "force" : "safe");
  } else {
    snprintf(response, sizeof(response),
             "Status: error\nReason: unrecognized-command\n");
  }
  send_all(fd, response, strlen(response));
  close(fd);
  return 1;
}

static int run_loop(struct managed_runtime *runtime) {
  while (!managed_stop) {
    struct pollfd descriptors[3 + NHRP_HA_MANAGED_MAX_MEMBERS];
    struct managed_peer *mapping[NHRP_HA_MANAGED_MAX_MEMBERS];
    nfds_t peer_start = runtime->health_socket >= 0 ? 3 : 2;
    nfds_t count = peer_start;
    uint64_t now;
    size_t i;
    int poll_result;

    descriptors[0].fd = runtime->listener;
    descriptors[0].events = POLLIN;
    descriptors[1].fd = runtime->control_listener;
    descriptors[1].events = POLLIN;
    if (runtime->health_socket >= 0) {
      descriptors[2].fd = runtime->health_socket;
      descriptors[2].events = POLLIN;
    }
    for (i = 0; i < runtime->peer_count; i++) {
      if (runtime->peers[i].fd < 0)
        continue;
      descriptors[count].fd = runtime->peers[i].fd;
      descriptors[count].events = POLLIN;
      mapping[count - peer_start] = &runtime->peers[i];
      count++;
    }
    poll_result = poll(descriptors, count, MANAGED_TICK_MS);
    if (poll_result < 0 && errno == EINTR)
      continue;
    if (poll_result < 0) {
      managed_log("opennhrp-ha: poll failed: %s\n", strerror(errno));
      return 0;
    }
    now = monotonic_ms();
    if (runtime->health_socket >= 0 && (descriptors[2].revents & POLLIN) != 0)
      health_reply_read(runtime);
    health_round_finish(runtime, now);
    if (!service_refresh(runtime, now)) {
      managed_log("opennhrp-ha: failed to update core service state\n");
      return 0;
    }
    if ((descriptors[0].revents & POLLIN) != 0)
      accept_connection(runtime);
    if ((descriptors[1].revents & POLLIN) != 0)
      control_handle(runtime);
    for (i = peer_start; i < count; i++) {
      struct managed_peer *peer = mapping[i - peer_start];

      if (!runtime->service_available)
        continue;
      if ((descriptors[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
          ((descriptors[i].revents & POLLIN) != 0 &&
           !peer_frame_handle(runtime, peer)))
        peer_close(peer);
    }
    if (runtime->reload_peers) {
      runtime->reload_peers = 0;
      peers_sync(runtime);
    }
    health_probe_send(runtime, now);
    if (runtime->reload_core) {
      runtime->reload_core = 0;
      if (!admin_ok(runtime, "ha managed reload\n")) {
        managed_log("opennhrp-ha: failed to reload configured endpoints\n");
        return 0;
      }
    }
    if (now - runtime->last_state_refresh_ms >= 500) {
      runtime->last_state_refresh_ms = now;
      runtime_load(runtime);
    }
    if (!runtime->service_available)
      continue;
    if (!rejoin_tick(runtime, now)) {
      managed_log("opennhrp-ha: failed to leave member isolation\n");
      return 0;
    }
    if (runtime->isolated)
      continue;
    if (!witness_fallback_tick(runtime, now)) {
      managed_log("opennhrp-ha: Witness fallback state update failed\n");
      return 0;
    }
    failback_tick(runtime, now);
    if (!election_tick(runtime, now)) {
      managed_log("opennhrp-ha: election state update failed\n");
      return 0;
    }
    if (strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
        !configured_matches(runtime) &&
        !configured_apply(runtime, runtime->state.local_member,
                          runtime->configured_addresses,
                          runtime->configured_address_count)) {
      managed_log("opennhrp-ha: failed to apply local configured endpoints\n");
      return 0;
    }
    {
      const char *target_member = opennhrp_ha_reconnect_target(
          runtime->state.local_member, runtime->state.leader,
          runtime->state.primary_member);
      struct managed_peer *target =
          target_member != NULL ? peer_find(runtime, target_member) : NULL;

      if (target != NULL && target->fd < 0 &&
          now - target->last_connect_ms >= MANAGED_RECONNECT_MS)
        peer_connect(runtime, target);
    }
    if (strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
        now - runtime->last_snapshot_ms >= MANAGED_SEND_MS) {
      runtime->last_snapshot_ms = now;
      snapshot_refresh(runtime);
    }
    for (i = 0; i < runtime->peer_count; i++) {
      struct managed_peer *peer = &runtime->peers[i];
      struct managed_witness_heartbeat heartbeat;

      if (peer->fd < 0 || !peer->hello_received ||
          now - peer->last_send_ms < MANAGED_SEND_MS)
        continue;
      witness_heartbeat_build(runtime, &heartbeat, now);
      if (!frame_send(runtime, peer, NHRP_HA_CONTROL_HEARTBEAT,
                      (const uint8_t *)&heartbeat, sizeof(heartbeat),
                      runtime->local_index, runtime->local_index)) {
        peer_close(peer);
        continue;
      }
      if (strcmp(runtime->state.local_member, runtime->state.leader) == 0) {
        if (!manifest_send(runtime, peer) || !snapshot_send(runtime, peer) ||
            !frame_send(runtime, peer, NHRP_HA_CONTROL_DIGEST,
                        (const uint8_t *)runtime->local_digest,
                        runtime->local_digest[0] != 0 ? 64 : 0,
                        runtime->local_index, peer->match_index))
          peer_close(peer);
      } else {
        if ((!configured_matches(runtime) &&
             strcmp(peer->member, runtime->state.leader) == 0 &&
             !configured_send(runtime, peer)) ||
            (runtime->local_digest[0] != 0 &&
             !frame_send(runtime, peer, NHRP_HA_CONTROL_DIGEST,
                         (const uint8_t *)runtime->local_digest, 64,
                         runtime->local_index, runtime->local_index)))
          peer_close(peer);
      }
    }
    set_core_state(runtime);
  }
  return 1;
}

static int runtime_init(struct managed_runtime *runtime, const char *directory,
                        const char *admin_socket, const char *control_socket,
                        const char *listen_address,
                        const struct in_addr *configured_addresses,
                        size_t configured_address_count,
                        const struct in_addr *health_targets,
                        size_t health_target_count) {
  const char *startup_leader;

  memset(runtime, 0, sizeof(*runtime));
  runtime->listener = -1;
  runtime->control_listener = -1;
  runtime->health_socket = -1;
  runtime->failback_policy.recovery_stable_seconds = 120;
  runtime->failback_policy.probation_seconds = 120;
  runtime->failback_policy.backoff_seconds[0] = 300;
  runtime->failback_policy.backoff_seconds[1] = 900;
  runtime->failback_policy.backoff_seconds[2] = 1800;
  runtime->failback_policy.backoff_reset_seconds = 1800;
  runtime->failback_policy.transfer_timeout_ms = 5000;
  nhrp_ha_failback_init(&runtime->failback);
  runtime->nonce = ((uint64_t)getpid() << 32) ^ monotonic_ms();
  snprintf(runtime->directory, sizeof(runtime->directory), "%s", directory);
  snprintf(runtime->admin_socket, sizeof(runtime->admin_socket), "%s",
           admin_socket);
  snprintf(runtime->control_socket, sizeof(runtime->control_socket), "%s",
           control_socket);
  snprintf(runtime->listen_address, sizeof(runtime->listen_address), "%s",
           listen_address);
  memcpy(runtime->configured_addresses, configured_addresses,
         configured_address_count * sizeof(configured_addresses[0]));
  runtime->configured_address_count = configured_address_count;
  runtime->health_identifier = (uint16_t)getpid();
  if (!health_targets_set(runtime, health_targets, health_target_count,
                          monotonic_ms()))
    return 0;
  if (health_target_count != 0) {
    runtime->health_socket = health_socket_create(runtime->health_identifier);
    if (runtime->health_socket < 0)
      return 0;
  }
  if (!nhrp_ha_managed_paths(directory, runtime->state_path,
                             sizeof(runtime->state_path), runtime->keys_path,
                             sizeof(runtime->keys_path), runtime->identity_path,
                             sizeof(runtime->identity_path)) ||
      snprintf(runtime->registrations_path, sizeof(runtime->registrations_path),
               "%s/registrations.state",
               directory) >= (int)sizeof(runtime->registrations_path) ||
      !nhrp_ha_managed_keyring_load(runtime->keys_path, &runtime->keys) ||
      !nhrp_ha_managed_state_load(runtime->state_path, &runtime->keys,
                                  &runtime->state))
    return 0;
  startup_leader = opennhrp_ha_startup_leader(runtime->state.local_member,
                                              runtime->state.primary_member,
                                              runtime->state.leader);
  if (strcmp(startup_leader, runtime->state.leader) != 0) {
    if (!state_reload_and_update(runtime, runtime->state.term + 1,
                                 startup_leader))
      return 0;
  }
  peers_sync(runtime);
  runtime->local_index = runtime->state.commit_index;
  runtime->service_available =
      interface_available(runtime->state.interface) && runtime->network_healthy;
  runtime->isolated = !runtime->service_available || runtime->peer_count != 0;
  if (runtime->service_available && runtime->isolated)
    runtime->rejoin_started_ms = monotonic_ms();
  if (strcmp(runtime->state.local_member, runtime->state.leader) == 0 &&
      !runtime->isolated)
    runtime->leader_since_ms = monotonic_ms();
  return 1;
}

static int registrations_restore(struct managed_runtime *runtime) {
  struct nhrp_ha_store_record record;
  struct nhrp_ha_control_frame frame;
  struct managed_peer *leader;
  int loaded;

  memset(&record, 0, sizeof(record));
  loaded = nhrp_ha_store_load(runtime->registrations_path, &runtime->keys,
                              runtime->state.cluster_id, &record);
  if (!loaded)
    return 0;
  if (record.term != 0) {
    runtime->local_index = record.index;
    if (!snapshot_digest(record.payload, record.payload_length,
                         runtime->local_digest)) {
      nhrp_ha_store_record_clear(&record);
      return 0;
    }
  }
  if (!set_core_state(runtime)) {
    managed_log(
        "opennhrp-ha: failed to initialize core HA state at index %llu\n",
        (unsigned long long)runtime->local_index);
    nhrp_ha_store_record_clear(&record);
    return 0;
  }
  if (record.term == 0) {
    nhrp_ha_store_record_clear(&record);
    return 1;
  }
  if (strcmp(runtime->state.local_member, runtime->state.leader) == 0) {
    runtime->current_snapshot = record.payload;
    runtime->current_snapshot_length = record.payload_length;
    record.payload = NULL;
    record.payload_length = 0;
  } else {
    leader = leader_peer(runtime);
    if (leader == NULL) {
      nhrp_ha_store_record_clear(&record);
      return 0;
    }
    memset(&frame, 0, sizeof(frame));
    frame.term = runtime->state.term;
    frame.index = record.index;
    snprintf(frame.sender, sizeof(frame.sender), "%s", runtime->state.leader);
    if (!snapshot_apply(runtime, &frame, record.payload,
                        record.payload_length)) {
      nhrp_ha_store_record_clear(&record);
      return 0;
    }
    leader->remote_snapshot = record.payload;
    leader->remote_snapshot_length = record.payload_length;
    leader->match_index = record.index;
    record.payload = NULL;
    record.payload_length = 0;
  }
  nhrp_ha_store_record_clear(&record);
  return 1;
}

static void runtime_cleanup(struct managed_runtime *runtime) {
  size_t i;

  if (runtime->listener >= 0)
    close(runtime->listener);
  if (runtime->control_listener >= 0)
    close(runtime->control_listener);
  if (runtime->health_socket >= 0)
    close(runtime->health_socket);
  unlink(runtime->control_socket);
  for (i = 0; i < runtime->peer_count; i++) {
    peer_close(&runtime->peers[i]);
    free(runtime->peers[i].remote_snapshot);
  }
  free(runtime->current_snapshot);
  free(runtime->previous_snapshot);
  nhrp_ha_auth_keys_clear(&runtime->keys);
}

static int usage(const char *program) {
  managed_log("usage: %s [--state-dir DIR] [-a opennhrp-socket] "
              "[--control-socket PATH] [--listen-address IPV4] "
              "[--advertise-address IPV4] ... [--health-target IPV4] ... "
              "[--debug]\n",
              program);
  return 1;
}

int opennhrp_ha_managed_hub_main(int argc, char **argv) {
  struct managed_runtime runtime;
  const char *directory = NHRP_HA_MANAGED_DEFAULT_DIR;
  const char *admin_socket = "/var/run/opennhrp.socket";
  const char *control_socket = "/var/run/opennhrp-ha.socket";
  const char *listen_address = "0.0.0.0";
  struct in_addr configured_addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  struct in_addr health_targets[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t configured_address_count = 0;
  size_t health_target_count = 0;
  int i;
  int result = 1;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc)
      directory = argv[++i];
    else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc)
      admin_socket = argv[++i];
    else if (strcmp(argv[i], "--control-socket") == 0 && i + 1 < argc)
      control_socket = argv[++i];
    else if (strcmp(argv[i], "--listen-address") == 0 && i + 1 < argc)
      listen_address = argv[++i];
    else if (strcmp(argv[i], "--debug") == 0)
      managed_debug = 1;
    else if (strcmp(argv[i], "--advertise-address") == 0 && i + 1 < argc &&
             configured_address_count < NHRP_HA_MANAGED_MAX_ENDPOINTS &&
             inet_pton(AF_INET, argv[i + 1],
                       &configured_addresses[configured_address_count]) == 1) {
      configured_address_count++;
      i++;
    } else if (strcmp(argv[i], "--health-target") == 0 && i + 1 < argc &&
               health_target_count < NHRP_HA_MANAGED_MAX_ENDPOINTS &&
               inet_pton(AF_INET, argv[i + 1],
                         &health_targets[health_target_count]) == 1) {
      health_target_count++;
      i++;
    } else
      return usage(argv[0]);
  }
  openlog("opennhrp-ha", LOG_PID, LOG_DAEMON);
  if (!runtime_init(&runtime, directory, admin_socket, control_socket,
                    listen_address, configured_addresses,
                    configured_address_count, health_targets,
                    health_target_count)) {
    managed_log("opennhrp-ha: failed to load managed state from %s\n",
                directory);
    return 1;
  }
  runtime.listener = listener_create(&runtime);
  runtime.control_listener = control_listener_create(runtime.control_socket);
  if (runtime.listener < 0 || runtime.control_listener < 0) {
    managed_log("opennhrp-ha: failed to create managed listeners: %s\n",
                strerror(errno));
    goto done;
  }
  signal(SIGINT, managed_signal);
  signal(SIGTERM, managed_signal);
  if (!registrations_restore(&runtime)) {
    managed_log("opennhrp-ha: failed to restore registrations state\n");
    goto done;
  }
  if (runtime.configured_address_count != 0 &&
      strcmp(runtime.state.local_member, runtime.state.leader) == 0 &&
      !configured_apply(&runtime, runtime.state.local_member,
                        runtime.configured_addresses,
                        runtime.configured_address_count)) {
    managed_log("opennhrp-ha: failed to apply configured endpoints\n");
    goto done;
  }
  managed_log(
      "opennhrp-ha: managed member %s listening on %s:%u with %zu peers\n",
      runtime.state.local_member, runtime.listen_address, runtime.state.port,
      runtime.peer_count);
  result = run_loop(&runtime) ? 0 : 1;

done:
  runtime_cleanup(&runtime);
  closelog();
  return result;
}
