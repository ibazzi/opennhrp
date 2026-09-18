/* opennhrp-ha.c - Pure mGRE OpenNHRP HA coordinator */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "nhrp_ha.h"
#include "opennhrp-ha-managed-hub.h"

#define BUFFER_SIZE 32768
#define SCORE_SWITCH_MARGIN 10
#define SCORE_SWITCH_HOLD 15.0
#define SCORE_FAILBACK_HOLD 120.0
#define SCORE_SWITCH_COOLDOWN 30.0

struct candidate_view {
  char member[64];
  char state[32];
  char leader[64];
  int priority;
  int ready;
  int authenticated;
  unsigned int score;
  uint64_t term;
};

struct service_view {
  char protocol[64];
  char active_member[64];
  unsigned int generation;
  int switching;
  int auth_required;
  struct candidate_view candidates[32];
  size_t candidate_count;
};

struct decision_state {
  char protocol[64];
  char active_member[64];
  char superior_member[64];
  double superior_since;
  double cooldown_until;
  int degraded;
  struct decision_state *next;
};

static struct decision_state *decision_states;

static double monotonic_seconds(void) {
  struct timespec now;

  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return 0.0;
  return now.tv_sec + now.tv_nsec / 1000000000.0;
}

static int connect_admin(const char *path) {
  struct sockaddr_un address;
  int fd;

  if (strlen(path) >= sizeof(address.sun_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int send_all(int fd, const char *buffer, size_t length) {
  while (length > 0) {
    ssize_t written = write(fd, buffer, length);

    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return -1;
    buffer += written;
    length -= written;
  }
  return 0;
}

static int json_string(const char *start, const char *key, char *value,
                       size_t value_size) {
  char pattern[96];
  const char *position;
  const char *end;
  size_t length;

  snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
  position = strstr(start, pattern);
  if (position == NULL)
    return 0;
  position += strlen(pattern);
  end = strchr(position, '"');
  if (end == NULL)
    return 0;
  length = end - position;
  if (length == 0 || length >= value_size)
    return 0;
  memcpy(value, position, length);
  value[length] = 0;
  return 1;
}

static int json_unsigned(const char *start, const char *key,
                         unsigned int *value) {
  char pattern[96];
  char *end;
  const char *position;
  unsigned long parsed;

  snprintf(pattern, sizeof(pattern), "\"%s\":", key);
  position = strstr(start, pattern);
  if (position == NULL)
    return 0;
  position += strlen(pattern);
  parsed = strtoul(position, &end, 10);
  if (end == position || parsed > UINT_MAX)
    return 0;
  *value = parsed;
  return 1;
}

static int json_u64(const char *start, const char *key, uint64_t *value) {
  char pattern[96];
  char *end;
  const char *position;
  unsigned long long parsed;

  snprintf(pattern, sizeof(pattern), "\"%s\":", key);
  position = strstr(start, pattern);
  if (position == NULL)
    return 0;
  position += strlen(pattern);
  parsed = strtoull(position, &end, 10);
  if (end == position)
    return 0;
  *value = parsed;
  return 1;
}

static int parse_service(const char *line, struct service_view *view) {
  const char *active;
  const char *position;

  memset(view, 0, sizeof(*view));
  if (!json_string(line, "protocol", view->protocol, sizeof(view->protocol)) ||
      !json_unsigned(line, "generation", &view->generation))
    return 0;
  view->switching = strstr(line, "\"switching\":true") != NULL;
  view->auth_required = strstr(line, "\"auth_mode\":\"required\"") != NULL;

  active = strstr(line, "\"active_member\":");
  if (active == NULL)
    return 0;
  if (strncmp(active + strlen("\"active_member\":"), "null", 4) != 0 &&
      !json_string(active, "active_member", view->active_member,
                   sizeof(view->active_member)))
    return 0;

  position = strstr(line, "\"candidates\":[");
  if (position == NULL)
    return 0;
  while ((position = strstr(position, "{\"member\":\"")) != NULL &&
         view->candidate_count <
             sizeof(view->candidates) / sizeof(view->candidates[0])) {
    struct candidate_view *candidate = &view->candidates[view->candidate_count];
    const char *end = strchr(position, '}');
    unsigned int priority;

    if (end == NULL ||
        !json_string(position, "member", candidate->member,
                     sizeof(candidate->member)) ||
        !json_string(position, "state", candidate->state,
                     sizeof(candidate->state)) ||
        !json_unsigned(position, "priority", &priority))
      return 0;
    candidate->priority = priority > INT_MAX ? INT_MAX : (int)priority;
    candidate->ready = strstr(position, "\"ready\":true") != NULL &&
                       strstr(position, "\"ready\":true") < end;
    candidate->authenticated =
        strstr(position, "\"authenticated\":true") != NULL &&
        strstr(position, "\"authenticated\":true") < end;
    if (!json_unsigned(position, "score", &candidate->score))
      return 0;
    if (!json_u64(position, "term", &candidate->term))
      candidate->term = 0;
    json_string(position, "leader", candidate->leader,
                sizeof(candidate->leader));
    view->candidate_count++;
    position = end + 1;
  }
  return view->candidate_count > 0;
}

static struct candidate_view *find_candidate(struct service_view *view,
                                             const char *member) {
  size_t i;

  for (i = 0; i < view->candidate_count; i++) {
    if (strcmp(view->candidates[i].member, member) == 0)
      return &view->candidates[i];
  }
  return NULL;
}

static struct candidate_view *best_ready_candidate(struct service_view *view) {
  struct candidate_view *best = NULL;
  size_t i;

  for (i = 0; i < view->candidate_count; i++) {
    if (!view->candidates[i].ready)
      continue;
    if (view->auth_required && !view->candidates[i].authenticated)
      continue;
    if (best == NULL || view->candidates[i].term > best->term ||
        (view->candidates[i].term == best->term &&
         (view->candidates[i].score > best->score ||
          (view->candidates[i].score == best->score &&
           (view->candidates[i].priority > best->priority ||
            (view->candidates[i].priority == best->priority &&
             strcmp(view->candidates[i].member, best->member) < 0))))))
      best = &view->candidates[i];
  }
  return best;
}

static int candidate_precedes(const struct candidate_view *candidate,
                              const struct candidate_view *other) {
  return candidate->term > other->term ||
         (candidate->term == other->term &&
          (candidate->priority > other->priority ||
           (candidate->priority == other->priority &&
            strcmp(candidate->member, other->member) < 0)));
}

static int initial_candidate_pending(const struct service_view *view,
                                     const struct candidate_view *best) {
  size_t i;

  for (i = 0; i < view->candidate_count; i++) {
    const struct candidate_view *candidate = &view->candidates[i];

    if (candidate == best || candidate->ready ||
        strcmp(candidate->state, "offline") == 0 ||
        strcmp(candidate->state, "disabled") == 0)
      continue;
    if (candidate_precedes(candidate, best))
      return 1;
  }
  return 0;
}

static int candidate_usable(const struct service_view *view,
                            const struct candidate_view *candidate) {
  return candidate != NULL &&
         (candidate->ready || strcmp(candidate->state, "suspect") == 0) &&
         (!view->auth_required || candidate->authenticated);
}

static struct decision_state *decision_state_find(const char *protocol) {
  struct decision_state *state;

  for (state = decision_states; state != NULL; state = state->next)
    if (strcmp(state->protocol, protocol) == 0)
      return state;
  state = calloc(1, sizeof(*state));
  if (state == NULL)
    return NULL;
  snprintf(state->protocol, sizeof(state->protocol), "%s", protocol);
  state->next = decision_states;
  decision_states = state;
  return state;
}

static void decision_reset_superior(struct decision_state *state) {
  state->superior_member[0] = 0;
  state->superior_since = 0.0;
}

static struct candidate_view *select_migration(struct service_view *view,
                                               struct decision_state *state,
                                               double now,
                                               const char **reason) {
  struct candidate_view *active =
      view->active_member[0] != 0 ? find_candidate(view, view->active_member)
                                  : NULL;
  struct candidate_view *best = best_ready_candidate(view);
  double hold = SCORE_SWITCH_HOLD;

  *reason = NULL;
  if (strcmp(state->active_member, view->active_member) != 0) {
    snprintf(state->active_member, sizeof(state->active_member), "%s",
             view->active_member);
    decision_reset_superior(state);
  }
  if (active == NULL) {
    decision_reset_superior(state);
    if (best != NULL && initial_candidate_pending(view, best))
      return NULL;
    if (best != NULL)
      *reason = "initial";
    return best;
  }
  if (!candidate_usable(view, active)) {
    decision_reset_superior(state);
    if (best != NULL)
      *reason = "unavailable";
    return best;
  }
  if (best == NULL || active->term > best->term) {
    decision_reset_superior(state);
    return NULL;
  }
  if (best->term > active->term) {
    struct candidate_view *leader =
        best->leader[0] != 0 ? find_candidate(view, best->leader) : NULL;

    decision_reset_superior(state);
    if (leader == NULL || !leader->ready || leader->term != best->term ||
        (view->auth_required && !leader->authenticated))
      return NULL;
    *reason = "stale-term";
    return leader;
  }
  if (best == active || now < state->cooldown_until ||
      best->score <= active->score) {
    decision_reset_superior(state);
    return NULL;
  }
  if (best->score < active->score + SCORE_SWITCH_MARGIN) {
    if (best->priority <= active->priority) {
      decision_reset_superior(state);
      return NULL;
    }
    hold = SCORE_FAILBACK_HOLD;
  }
  if (strcmp(state->superior_member, best->member) != 0) {
    snprintf(state->superior_member, sizeof(state->superior_member), "%s",
             best->member);
    state->superior_since = now;
    return NULL;
  }
  if (now - state->superior_since < hold)
    return NULL;
  *reason = hold == SCORE_FAILBACK_HOLD ? "failback" : "quality";
  return best;
}

static int activate(const char *socket_path, const char *interface_name,
                    const struct service_view *view,
                    const struct candidate_view *active,
                    const struct candidate_view *candidate,
                    const char *reason) {
  char command[512];
  char response[2048];
  size_t used = 0;
  int fd;

  fd = connect_admin(socket_path);
  if (fd < 0)
    return -1;
  snprintf(command, sizeof(command),
           "ha activate interface %s protocol %s member %s "
           "expect-generation %u\n",
           interface_name, view->protocol, candidate->member, view->generation);
  if (send_all(fd, command, strlen(command)) != 0) {
    close(fd);
    return -1;
  }
  while (used < sizeof(response) - 1) {
    ssize_t length = read(fd, response + used, sizeof(response) - 1 - used);

    if (length < 0 && errno == EINTR)
      continue;
    if (length <= 0)
      break;
    used += length;
  }
  close(fd);
  response[used] = 0;
  if (strstr(response, "Status: ok") == NULL) {
    fprintf(stderr, "opennhrp-ha: activation of %s failed: %s",
            candidate->member, response);
    return -1;
  }
  fprintf(stderr,
          "opennhrp-ha: %s %s -> %s reason=%s score=%u/%u term=%" PRIu64
          "/%" PRIu64 " generation=%u\n",
          active == NULL ? "activated" : "migrated",
          active != NULL ? active->member : "none", candidate->member, reason,
          active != NULL ? active->score : 0, candidate->score,
          active != NULL ? active->term : 0, candidate->term,
          view->generation + 1);
  return 0;
}

static void process_event(const char *socket_path, const char *interface_name,
                          const char *line) {
  struct service_view view;
  struct candidate_view *active;
  struct candidate_view *target;
  struct decision_state *state;
  const char *reason;
  double now;

  if (!parse_service(line, &view)) {
    fprintf(stderr, "opennhrp-ha: ignored malformed HA monitor event\n");
    return;
  }
  if (view.switching)
    return;
  state = decision_state_find(view.protocol);
  if (state == NULL) {
    fprintf(stderr, "opennhrp-ha: failed to allocate HA decision state\n");
    return;
  }
  now = monotonic_seconds();
  active = view.active_member[0] != 0
               ? find_candidate(&view, view.active_member)
               : NULL;
  target = select_migration(&view, state, now, &reason);
  if (target != NULL) {
    if (activate(socket_path, interface_name, &view, active, target, reason) !=
        0)
      return;
    if (active != NULL && active != target)
      state->cooldown_until = now + SCORE_SWITCH_COOLDOWN;
    decision_reset_superior(state);
    state->degraded = 0;
    return;
  }
  if (!candidate_usable(&view, active)) {
    size_t i;

    if (view.auth_required) {
      for (i = 0; i < view.candidate_count; i++)
        fprintf(stderr,
                "opennhrp-ha: candidate %s ready=%d authenticated=%d "
                "term=%" PRIu64 " leader=%s\n",
                view.candidates[i].member, view.candidates[i].ready,
                view.candidates[i].authenticated, view.candidates[i].term,
                view.candidates[i].leader[0] != 0 ? view.candidates[i].leader
                                                  : "none");
    }
    if (!state->degraded)
      fprintf(
          stderr,
          "opennhrp-ha: degraded; no READY candidate, neighbor unchanged\n");
    state->degraded = 1;
    return;
  }
  state->degraded = 0;
}

static int monitor_once(const char *socket_path, const char *interface_name) {
  char command[256];
  char buffer[BUFFER_SIZE];
  size_t used = 0;
  int fd;

  fd = connect_admin(socket_path);
  if (fd < 0)
    return -1;
  snprintf(command, sizeof(command), "ha monitor interface %s\n",
           interface_name);
  if (send_all(fd, command, strlen(command)) != 0) {
    close(fd);
    return -1;
  }

  for (;;) {
    char *newline;
    ssize_t length;

    newline = memchr(buffer, '\n', used);
    if (newline != NULL) {
      size_t line_length = newline - buffer;

      buffer[line_length] = 0;
      process_event(socket_path, interface_name, buffer);
      memmove(buffer, newline + 1, used - line_length - 1);
      used -= line_length + 1;
      continue;
    }
    if (used == sizeof(buffer)) {
      close(fd);
      errno = EMSGSIZE;
      return -1;
    }
    length = read(fd, buffer + used, sizeof(buffer) - used);
    if (length < 0 && errno == EINTR)
      continue;
    if (length <= 0) {
      close(fd);
      return -1;
    }
    used += length;
  }
}

static int usage(const char *program) {
  fprintf(stderr,
          "usage: %s [-a admin-socket] -i interface\n"
          "       %s hub [--state-dir DIR] [-a admin-socket]\n"
          "       %s -h\n",
          program, program, program);
  return 1;
}

int main(int argc, char **argv) {
  const char *socket_path = "/var/run/opennhrp.socket";
  const char *interface_name = NULL;
  int option;

  if (argc > 1 && strcmp(argv[1], "hub") == 0)
    return opennhrp_ha_managed_hub_main(argc - 1, argv + 1);

  while ((option = getopt(argc, argv, "a:i:h")) != -1) {
    switch (option) {
    case 'a':
      socket_path = optarg;
      break;
    case 'i':
      interface_name = optarg;
      break;
    case 'h':
    default:
      return usage(argv[0]);
    }
  }
  if (interface_name == NULL || optind != argc)
    return usage(argv[0]);

  for (;;) {
    if (monitor_once(socket_path, interface_name) != 0)
      fprintf(stderr, "opennhrp-ha: monitor disconnected: %s\n",
              strerror(errno));
    sleep(1);
  }
}
