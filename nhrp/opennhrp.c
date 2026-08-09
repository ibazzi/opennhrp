/* opennhrp.c - OpenNHRP main routines
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/rtnetlink.h>
#include <malloc.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "nhrp_common.h"
#include "nhrp_ha.h"
#include "nhrp_ha_managed.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

const char *nhrp_version_string = "OpenNHRP " OPENNHRP_VERSION
#ifdef NHRP_NO_NBMA_GRE
                                  " (no NBMA GRE support)"
#endif
    ;

const char *nhrp_admin_socket = OPENNHRP_ADMIN_SOCKET;
const char *nhrp_pid_file = "/var/run/opennhrp.pid";
const char *nhrp_config_file = "/etc/opennhrp/opennhrp.conf";
const char *nhrp_script_file = "/etc/opennhrp/opennhrp-script";
static const char *nhrp_ha_state_dir = NHRP_HA_MANAGED_DEFAULT_DIR;
int nhrp_verbose = 0;
int nhrp_running = FALSE;

static int pid_file_fd;

#define NHRP_HA_CHILD_MAX 33

enum nhrp_ha_child_role {
  NHRP_HA_CHILD_NONE,
  NHRP_HA_CHILD_HUB,
  NHRP_HA_CHILD_SPOKE,
};

struct nhrp_ha_child {
  enum nhrp_ha_child_role role;
  struct nhrp_interface *interface;
  pid_t pid;
  ev_tstamp started;
  unsigned int restart_delay;
  int stopping;
  int last_status;
  struct ev_child watcher;
  struct ev_timer restart;
};

static struct nhrp_ha_child ha_children[NHRP_HA_CHILD_MAX];
static char nhrp_ha_program[PATH_MAX] = "opennhrp-ha";
static char nhrp_ha_control_socket[PATH_MAX] = "/var/run/opennhrp-ha.socket";

static void ha_child_spawn(struct nhrp_ha_child *child);

static void ha_child_restart_cb(struct ev_timer *timer, int revents) {
  struct nhrp_ha_child *child =
      container_of(timer, struct nhrp_ha_child, restart);

  ha_child_spawn(child);
}

static void ha_child_exited_cb(struct ev_child *watcher, int revents) {
  struct nhrp_ha_child *child =
      container_of(watcher, struct nhrp_ha_child, watcher);
  unsigned int delay;
  int clean_exit;

  child->last_status = watcher->rstatus;
  child->pid = 0;
  ev_child_stop(watcher);
  if (child->stopping || !nhrp_running) {
    nhrp_ha_set_coordinator_status(child->interface, "stopped",
                                   child->last_status);
    return;
  }
  nhrp_ha_set_coordinator_status(child->interface, "restarting",
                                 child->last_status);
  clean_exit =
      WIFEXITED(child->last_status) && WEXITSTATUS(child->last_status) == 0;
  if (clean_exit) {
    delay = 1;
    child->restart_delay = 1;
  } else {
    if (ev_now() - child->started >= 60.0)
      child->restart_delay = 1;
    delay = child->restart_delay != 0 ? child->restart_delay : 1;
    child->restart_delay = delay < 30 ? delay * 2 : 30;
    if (child->restart_delay > 30)
      child->restart_delay = 30;
  }
  nhrp_error("HA coordinator for %s exited with status %d; restarting in %u "
             "seconds",
             child->interface->name, child->last_status, delay);
  ev_timer_stop(&child->restart);
  ev_timer_set(&child->restart, delay, 0.0);
  ev_timer_start(&child->restart);
}

static void ha_child_exec(const struct nhrp_ha_child *child) {
  if (child->role == NHRP_HA_CHILD_HUB) {
    struct nhrp_address advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
    struct nhrp_address health_targets[NHRP_HA_MANAGED_MAX_ENDPOINTS];
    char addresses[NHRP_HA_MANAGED_MAX_ENDPOINTS][INET_ADDRSTRLEN];
    char targets[NHRP_HA_MANAGED_MAX_ENDPOINTS][INET_ADDRSTRLEN];
    char *arguments[10 + NHRP_HA_MANAGED_MAX_ENDPOINTS * 4];
    size_t count = nhrp_ha_hub_advertised(advertised, ARRAY_SIZE(advertised));
    size_t target_count =
        nhrp_ha_hub_health_targets(health_targets, ARRAY_SIZE(health_targets));
    size_t argument = 0;
    size_t i;

    arguments[argument++] = nhrp_ha_program;
    arguments[argument++] = "hub";
    arguments[argument++] = "--state-dir";
    arguments[argument++] = (char *)nhrp_ha_state_dir;
    arguments[argument++] = "-a";
    arguments[argument++] = (char *)nhrp_admin_socket;
    arguments[argument++] = "--control-socket";
    arguments[argument++] = nhrp_ha_control_socket;
    if (nhrp_verbose)
      arguments[argument++] = "--debug";
    for (i = 0; i < count; i++) {
      nhrp_address_format(&advertised[i], sizeof(addresses[i]), addresses[i]);
      arguments[argument++] = "--advertise-address";
      arguments[argument++] = addresses[i];
    }
    for (i = 0; i < target_count; i++) {
      nhrp_address_format(&health_targets[i], sizeof(targets[i]), targets[i]);
      arguments[argument++] = "--health-target";
      arguments[argument++] = targets[i];
    }
    arguments[argument] = NULL;
    execvp(nhrp_ha_program, arguments);
  } else {
    execlp(nhrp_ha_program, nhrp_ha_program, "-a", nhrp_admin_socket, "-i",
           child->interface->name, (char *)NULL);
  }
  _exit(127);
}

static int ha_process_configure_hub(void) {
  struct nhrp_address advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  struct nhrp_address health_targets[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  struct sockaddr_un address;
  char command[512] = "ha configure";
  char response[64];
  size_t count = nhrp_ha_hub_advertised(advertised, ARRAY_SIZE(advertised));
  size_t target_count =
      nhrp_ha_hub_health_targets(health_targets, ARRAY_SIZE(health_targets));
  size_t used = strlen(command);
  size_t i;
  int fd;

  used += (size_t)snprintf(command + used, sizeof(command) - used,
                           " addresses %zu", count);
  for (i = 0; i < count; i++) {
    char text[INET_ADDRSTRLEN];
    int written;

    nhrp_address_format(&advertised[i], sizeof(text), text);
    written = snprintf(command + used, sizeof(command) - used, " %s", text);
    if (written <= 0 || (size_t)written >= sizeof(command) - used)
      return FALSE;
    used += (size_t)written;
  }
  used += (size_t)snprintf(command + used, sizeof(command) - used,
                           " health %zu", target_count);
  for (i = 0; i < target_count; i++) {
    char text[INET_ADDRSTRLEN];
    int written;

    nhrp_address_format(&health_targets[i], sizeof(text), text);
    written = snprintf(command + used, sizeof(command) - used, " %s", text);
    if (written <= 0 || (size_t)written >= sizeof(command) - used)
      return FALSE;
    used += (size_t)written;
  }
  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return FALSE;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  if (strlen(nhrp_ha_control_socket) >= sizeof(address.sun_path)) {
    close(fd);
    return FALSE;
  }
  snprintf(address.sun_path, sizeof(address.sun_path), "%s",
           nhrp_ha_control_socket);
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      write(fd, command, used) != (ssize_t)used || shutdown(fd, SHUT_WR) != 0 ||
      read(fd, response, sizeof(response) - 1) <= 0) {
    close(fd);
    return FALSE;
  }
  close(fd);
  return strncmp(response, "Status: ok\n", 11) == 0;
}

static void ha_child_spawn(struct nhrp_ha_child *child) {
  pid_t pid;

  if (child->role == NHRP_HA_CHILD_NONE || child->pid != 0 || child->stopping)
    return;
  ev_timer_stop(&child->restart);
  pid = fork();
  if (pid < 0) {
    nhrp_error("Unable to start HA coordinator for %s: %s",
               child->interface->name, strerror(errno));
    ev_timer_set(&child->restart, 1.0, 0.0);
    ev_timer_start(&child->restart);
    nhrp_ha_set_coordinator_status(child->interface, "restarting", -errno);
    return;
  }
  if (pid == 0)
    ha_child_exec(child);
  child->pid = pid;
  child->started = ev_now();
  if (child->restart_delay == 0)
    child->restart_delay = 1;
  ev_child_stop(&child->watcher);
  ev_child_init(&child->watcher, ha_child_exited_cb, pid, 0);
  ev_child_start(&child->watcher);
  nhrp_ha_set_coordinator_status(child->interface, "running",
                                 child->last_status);
  nhrp_info("Started %s HA coordinator for %s as pid %ld",
            child->role == NHRP_HA_CHILD_HUB ? "Hub" : "Spoke",
            child->interface->name, (long)pid);
}

static struct nhrp_ha_child *ha_child_find(enum nhrp_ha_child_role role,
                                           struct nhrp_interface *iface) {
  size_t i;
  struct nhrp_ha_child *unused = NULL;

  for (i = 0; i < ARRAY_SIZE(ha_children); i++) {
    if (ha_children[i].role == role && ha_children[i].interface == iface)
      return &ha_children[i];
    if (unused == NULL && ha_children[i].role == NHRP_HA_CHILD_NONE)
      unused = &ha_children[i];
  }
  return unused;
}

static void ha_process_require_spoke(struct nhrp_interface *iface) {
  struct nhrp_ha_child *child = ha_child_find(NHRP_HA_CHILD_SPOKE, iface);

  if (child == NULL) {
    nhrp_error("Too many HA coordinator processes");
    return;
  }
  if (child->role == NHRP_HA_CHILD_NONE) {
    memset(child, 0, sizeof(*child));
    child->role = NHRP_HA_CHILD_SPOKE;
    child->interface = iface;
    ev_timer_init(&child->restart, ha_child_restart_cb, 0.0, 0.0);
  }
  if (nhrp_running)
    ha_child_spawn(child);
}

static void ha_process_paths_init(const char *program) {
  char resolved[PATH_MAX];
  size_t socket_length;
  char *slash;

  if (realpath(program, resolved) != NULL &&
      (slash = strrchr(resolved, '/')) != NULL) {
    *slash = 0;
    if (snprintf(nhrp_ha_program, sizeof(nhrp_ha_program), "%s/opennhrp-ha",
                 resolved) >= (int)sizeof(nhrp_ha_program))
      snprintf(nhrp_ha_program, sizeof(nhrp_ha_program), "opennhrp-ha");
  }
  snprintf(nhrp_ha_control_socket, sizeof(nhrp_ha_control_socket), "%s",
           nhrp_admin_socket);
  socket_length = strlen(nhrp_ha_control_socket);
  if (socket_length > strlen(".socket") &&
      strcmp(nhrp_ha_control_socket + socket_length - strlen(".socket"),
             ".socket") == 0) {
    snprintf(nhrp_ha_control_socket + socket_length - strlen(".socket"),
             sizeof(nhrp_ha_control_socket) - socket_length + strlen(".socket"),
             "-ha.socket");
  } else if (socket_length + strlen("-ha.socket") <
             sizeof(nhrp_ha_control_socket)) {
    snprintf(nhrp_ha_control_socket + socket_length,
             sizeof(nhrp_ha_control_socket) - socket_length, "-ha.socket");
  }
}

static void ha_process_start(void) {
  struct nhrp_interface *iface;
  struct nhrp_ha_child *child;
  const char *interface_name = nhrp_ha_hub_interface();

  nhrp_ha_set_coordinator_callback(ha_process_require_spoke);
  if (!nhrp_ha_hub_enabled() || interface_name == NULL)
    return;
  iface = nhrp_interface_get_by_name(interface_name, FALSE);
  child = ha_child_find(NHRP_HA_CHILD_HUB, iface);
  if (child == NULL)
    return;
  memset(child, 0, sizeof(*child));
  child->role = NHRP_HA_CHILD_HUB;
  child->interface = iface;
  ev_timer_init(&child->restart, ha_child_restart_cb, 0.0, 0.0);
  ha_child_spawn(child);
}

int nhrp_stop_managed_hub(void) {
  struct nhrp_interface *iface;
  struct nhrp_ha_child *child;
  const char *interface_name = nhrp_ha_hub_interface();

  if (interface_name == NULL ||
      (iface = nhrp_interface_get_by_name(interface_name, FALSE)) == NULL ||
      (child = ha_child_find(NHRP_HA_CHILD_HUB, iface)) == NULL ||
      child->role != NHRP_HA_CHILD_HUB)
    return FALSE;
  child->stopping = TRUE;
  ev_timer_stop(&child->restart);
  nhrp_ha_set_coordinator_status(child->interface, "stopping",
                                 child->last_status);
  return TRUE;
}

static void ha_process_cleanup(void) {
  size_t i;
  int attempt;

  nhrp_ha_set_coordinator_callback(NULL);
  for (i = 0; i < ARRAY_SIZE(ha_children); i++) {
    struct nhrp_ha_child *child = &ha_children[i];

    if (child->role == NHRP_HA_CHILD_NONE)
      continue;
    child->stopping = TRUE;
    nhrp_ha_set_coordinator_status(child->interface, "stopped",
                                   child->last_status);
    ev_timer_stop(&child->restart);
    ev_child_stop(&child->watcher);
    if (child->pid > 0)
      kill(child->pid, SIGTERM);
  }
  for (attempt = 0; attempt < 40; attempt++) {
    int remaining = 0;

    for (i = 0; i < ARRAY_SIZE(ha_children); i++) {
      struct nhrp_ha_child *child = &ha_children[i];
      pid_t result;

      if (child->pid <= 0)
        continue;
      result = waitpid(child->pid, NULL, WNOHANG);
      if (result == child->pid)
        child->pid = 0;
      else
        remaining++;
    }
    if (remaining == 0)
      break;
    usleep(50000);
  }
  for (i = 0; i < ARRAY_SIZE(ha_children); i++) {
    struct nhrp_ha_child *child = &ha_children[i];

    if (child->pid > 0) {
      kill(child->pid, SIGKILL);
      waitpid(child->pid, NULL, 0);
    }
    memset(child, 0, sizeof(*child));
  }
}

void nhrp_hex_dump(const char *name, const uint8_t *buf, int bytes) {
  int i, j;
  int left;

  fprintf(stderr, "%s:\n", name);
  for (i = 0; i < bytes; i++) {
    fprintf(stderr, "%02X ", buf[i]);
    if (i % 0x10 == 0x0f) {
      fprintf(stderr, "    ");
      for (j = 0; j < 0x10; j++)
        fprintf(stderr, "%c",
                isgraph(buf[i + j - 0xf]) ? buf[i + j - 0xf] : '.');
      fprintf(stderr, "\n");
    }
  }

  left = i % 0x10;
  if (left != 0) {
    fprintf(stderr, "%*s    ", 3 * (0x10 - left), "");

    for (j = 0; j < left; j++)
      fprintf(stderr, "%c",
              isgraph(buf[i + j - left]) ? buf[i + j - left] : '.');
    fprintf(stderr, "\n");
  }
  fprintf(stderr, "\n");
}

static void handle_signal_cb(struct ev_signal *w, int revents) {
  switch (w->signum) {
  case SIGUSR1:
    nhrp_peer_dump_cache();
    break;
  case SIGINT:
  case SIGTERM:
    ev_unloop(EVUNLOOP_ALL);
    break;
  case SIGHUP:
    nhrp_reload_config();
    break;
  }
}

static int hook_signal[] = {SIGUSR1, SIGHUP, SIGINT, SIGTERM};
static ev_signal signal_event[ARRAY_SIZE(hook_signal)];

static void signal_init(void) {
  int i;

  for (i = 0; i < ARRAY_SIZE(hook_signal); i++) {
    ev_signal_init(&signal_event[i], handle_signal_cb, hook_signal[i]);
    ev_signal_start(&signal_event[i]);
  }
}

static char unread_buf[256];
static int unread_lineno;
static int has_unread = 0;

static void unread_word(const char *word, int lineno) {
  snprintf(unread_buf, sizeof(unread_buf), "%s", word);
  unread_lineno = lineno;
  has_unread = 1;
}

static int read_word(FILE *in, int *lineno, size_t len, char *word) {
  int ch, i, comment = 0;

  if (has_unread) {
    has_unread = 0;
    *lineno = unread_lineno;
    snprintf(word, len, "%s", unread_buf);
    return TRUE;
  }

  ch = fgetc(in);
  while (1) {
    if (ch == EOF)
      return FALSE;
    if (ch == '#')
      comment = 1;
    if (!comment && !isspace(ch))
      break;
    if (ch == '\n') {
      (*lineno)++;
      comment = 0;
    }
    ch = fgetc(in);
  }

  for (i = 0; i < len - 1 && !isspace(ch); i++) {
    word[i] = ch;
    ch = fgetc(in);
    if (ch == EOF)
      break;
    if (ch == '\n')
      (*lineno)++;
  }
  word[i] = 0;

  return TRUE;
}

static int load_config(const char *config_file) {
#define NEED_INTERFACE()                                                       \
  if (iface == NULL) {                                                         \
    rc = 2;                                                                    \
    break;                                                                     \
  }                                                                            \
  peer = NULL;
#define NEED_PEER()                                                            \
  if (peer == NULL || peer->type == NHRP_PEER_TYPE_LOCAL_ADDR) {               \
    rc = 3;                                                                    \
    break;                                                                     \
  }

  static const char *errors[] = {
      "syntax error",
      "missing keyword",
      "keyword valid only for 'interface' definition",
      "keyword valid only for 'map' definition",
      "invalid address",
      "dynamic-map requires a network address",
      "bad multicast destination",
      "keyword valid only for 'interace' and 'shortcut-target' definition",
  };
  struct nhrp_interface *iface = NULL;
  struct nhrp_peer *peer = NULL, *exist = NULL;
  struct nhrp_address paddr, nbma_addr;
  uint8_t prefix_length;
  char word[64], nbma[64], addr[64];
  FILE *in;
  int lineno = 1, rc = -1;

  in = fopen(config_file, "r");
  if (in == NULL) {
    nhrp_error("Unable to open configuration file '%s'.", config_file);
    return FALSE;
  }

  while (read_word(in, &lineno, sizeof(word), word)) {
    if (strcmp(word, "interface") == 0) {
      if (!read_word(in, &lineno, sizeof(word), word)) {
        rc = 1;
        break;
      }
      iface = nhrp_interface_get_by_name(word, TRUE);
      if (iface != NULL)
        iface->flags |= NHRP_INTERFACE_FLAG_CONFIGURED;
      peer = NULL;
    } else if (strcmp(word, "shortcut-target") == 0) {
      NEED_INTERFACE();
      if (!read_word(in, &lineno, sizeof(addr), addr)) {
        rc = 1;
        break;
      }
      if (!nhrp_address_parse(addr, &paddr, &prefix_length)) {
        rc = 4;
        break;
      }
      exist = nhrp_peer_find_marked_static(iface, NHRP_PEER_TYPE_LOCAL_ADDR,
                                           &paddr, NULL, NULL);
      if (exist != NULL) {
        exist->flags &= ~NHRP_PEER_FLAG_MARK;
        exist->flags |= NHRP_PEER_FLAG_CONFIGURED;
        peer = exist;
      } else {
        peer = nhrp_peer_alloc(iface);
        peer->type = NHRP_PEER_TYPE_LOCAL_ADDR;
        peer->afnum = AFNUM_RESERVED;
        peer->protocol_address = paddr;
        peer->prefix_length = prefix_length;
        peer->protocol_type = nhrp_protocol_from_pf(paddr.type);
        peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
        nhrp_peer_insert(peer);
        nhrp_peer_put(peer);
      }
    } else if (strcmp(word, "dynamic-map") == 0) {
      NEED_INTERFACE();
      read_word(in, &lineno, sizeof(addr), addr);
      read_word(in, &lineno, sizeof(nbma), nbma);

      if (!nhrp_address_parse(addr, &paddr, &prefix_length)) {
        rc = 4;
        break;
      }
      if (!nhrp_address_is_network(&paddr, prefix_length)) {
        rc = 5;
        break;
      }
      exist = nhrp_peer_find_marked_static(iface, NHRP_PEER_TYPE_STATIC_DNS,
                                           &paddr, NULL, nbma);
      if (exist != NULL) {
        exist->flags &= ~NHRP_PEER_FLAG_MARK;
        exist->flags |= NHRP_PEER_FLAG_CONFIGURED;
        peer = exist;
      } else {
        peer = nhrp_peer_alloc(iface);
        peer->type = NHRP_PEER_TYPE_STATIC_DNS;
        peer->protocol_address = paddr;
        peer->prefix_length = prefix_length;
        peer->protocol_type = nhrp_protocol_from_pf(paddr.type);
        peer->nbma_hostname = strdup(nbma);
        peer->afnum = nhrp_afnum_from_pf(peer->next_hop_address.type);
        peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
        nhrp_peer_insert(peer);
        nhrp_peer_put(peer);
      }
    } else if (strcmp(word, "map") == 0) {
      NEED_INTERFACE();
      read_word(in, &lineno, sizeof(addr), addr);
      read_word(in, &lineno, sizeof(nbma), nbma);

      if (!nhrp_address_parse(addr, &paddr, &prefix_length)) {
        rc = 4;
        break;
      }
      nhrp_address_set_type(&nbma_addr, PF_UNSPEC);
      char *nbma_host = NULL;
      if (!nhrp_address_parse(nbma, &nbma_addr, NULL))
        nbma_host = nbma;

      exist = nhrp_peer_find_marked_static(iface, NHRP_PEER_TYPE_STATIC, &paddr,
                                           &nbma_addr, nbma_host);
      if (exist != NULL) {
        exist->flags &= ~NHRP_PEER_FLAG_MARK;
        exist->flags &= ~(NHRP_PEER_FLAG_REGISTER | NHRP_PEER_FLAG_CISCO |
                          NHRP_PEER_FLAG_REG_NON_UNIQUE);
        exist->flags |= NHRP_PEER_FLAG_CONFIGURED;
        nhrp_address_set_type(&exist->local_connect_address, PF_UNSPEC);
        peer = exist;
      } else {
        peer = nhrp_peer_alloc(iface);
        peer->type = NHRP_PEER_TYPE_STATIC;
        peer->protocol_address = paddr;
        peer->prefix_length = prefix_length;
        peer->protocol_type = nhrp_protocol_from_pf(paddr.type);
        peer->next_hop_address = nbma_addr;
        if (nbma_host != NULL)
          peer->nbma_hostname = strdup(nbma_host);
        peer->afnum = nhrp_afnum_from_pf(peer->next_hop_address.type);
        peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
        nhrp_peer_insert(peer);
        nhrp_peer_put(peer);
      }
    } else if (strcmp(word, "enable-ha") == 0) {
      struct nhrp_address advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
      char member_id[NHRP_HA_MEMBER_ID_MAX + 1] = {0};
      char next_word[64];
      int have_member = FALSE;
      size_t advertised_count = 0;

      NEED_INTERFACE();
      memset(advertised, 0, sizeof(advertised));
      while (1) {
        int next_lineno = lineno;

        if (!read_word(in, &lineno, sizeof(next_word), next_word))
          break;
        if (strcmp(next_word, "member-id") == 0) {
          if (have_member ||
              !read_word(in, &lineno, sizeof(member_id), member_id)) {
            rc = 4;
            break;
          }
          have_member = TRUE;
        } else if (strcmp(next_word, "advertise") == 0) {
          if (advertised_count >= NHRP_HA_MANAGED_MAX_ENDPOINTS ||
              !read_word(in, &lineno, sizeof(next_word), next_word) ||
              !nhrp_address_parse(next_word, &advertised[advertised_count],
                                  NULL)) {
            rc = 4;
            break;
          }
          advertised_count++;
        } else {
          unread_word(next_word, next_lineno);
          break;
        }
      }
      if (rc >= 0 ||
          !nhrp_ha_config_enable(iface, have_member ? member_id : NULL,
                                 advertised_count != 0 ? advertised : NULL,
                                 advertised_count)) {
        rc = 4;
        break;
      }
      peer = NULL;
    } else if (strcmp(word, "ha-local-nbma") == 0) {
      struct nhrp_address local_nbma;
      char member_id[NHRP_HA_MEMBER_ID_MAX + 1];

      NEED_INTERFACE();
      if (!read_word(in, &lineno, sizeof(member_id), member_id) ||
          !read_word(in, &lineno, sizeof(word), word) ||
          !nhrp_address_parse(word, &local_nbma, NULL) ||
          !nhrp_ha_config_local_nbma(iface, member_id, &local_nbma)) {
        rc = 4;
        break;
      }
      peer = NULL;
    } else if (strcmp(word, "ha-health-target") == 0) {
      struct nhrp_address target;

      NEED_INTERFACE();
      if (!read_word(in, &lineno, sizeof(word), word) ||
          !nhrp_address_parse(word, &target, NULL) ||
          !nhrp_ha_config_health_target(iface, &target)) {
        rc = 4;
        break;
      }
      peer = NULL;
    } else if (strcmp(word, "register") == 0) {
      NEED_PEER();
      peer->flags |= NHRP_PEER_FLAG_REGISTER;
    } else if (strcmp(word, "local-nbma") == 0) {
      NEED_PEER();
      read_word(in, &lineno, sizeof(word), word);
      if (!nhrp_address_parse(word, &peer->local_connect_address, NULL)) {
        rc = 4;
        break;
      }
    } else if (strcmp(word, "cisco") == 0) {
      NEED_PEER();
      peer->flags |= NHRP_PEER_FLAG_CISCO;
    } else if (strcmp(word, "no-unique") == 0) {
      NEED_PEER();
      peer->flags |= NHRP_PEER_FLAG_REG_NON_UNIQUE;
    } else if (strcmp(word, "holding-time") == 0) {
      read_word(in, &lineno, sizeof(word), word);
      if (peer != NULL && peer->type == NHRP_PEER_TYPE_LOCAL_ADDR) {
        peer->holding_time = atoi(word);
      } else if (iface != NULL) {
        iface->holding_time = atoi(word);
        peer = NULL;
      } else {
        rc = 7;
      }
    } else if (strcmp(word, "cisco-authentication") == 0) {
      struct nhrp_buffer *buf;
      struct nhrp_cisco_authentication_extension *auth;

      NEED_INTERFACE();
      read_word(in, &lineno, sizeof(word), word);

      buf = nhrp_buffer_alloc(strlen(word) + sizeof(uint32_t));
      auth = (struct nhrp_cisco_authentication_extension *)buf->data;
      auth->type = NHRP_AUTHENTICATION_PLAINTEXT;
      memcpy(auth->secret, word, strlen(word));

      iface->auth_token = buf;
    } else if (strcmp(word, "route-table") == 0) {
      NEED_INTERFACE();
      read_word(in, &lineno, sizeof(word), word);
      iface->route_table = atoi(word);
    } else if (strcmp(word, "shortcut") == 0) {
      NEED_INTERFACE();
      iface->flags |= NHRP_INTERFACE_FLAG_SHORTCUT;
    } else if (strcmp(word, "redirect") == 0) {
      NEED_INTERFACE();
      iface->flags |= NHRP_INTERFACE_FLAG_REDIRECT;
    } else if (strcmp(word, "non-caching") == 0) {
      NEED_INTERFACE();
      iface->flags |= NHRP_INTERFACE_FLAG_NON_CACHING;
    } else if (strcmp(word, "shortcut-destination") == 0) {
      NEED_INTERFACE();
      iface->flags |= NHRP_INTERFACE_FLAG_SHORTCUT_DEST;
    } else if (strcmp(word, "multicast") == 0) {
      NEED_INTERFACE();
      read_word(in, &lineno, sizeof(word), word);
      if (strcmp(word, "dynamic") == 0) {
        iface->mcast_mask = BIT(NHRP_PEER_TYPE_STATIC) |
                            BIT(NHRP_PEER_TYPE_DYNAMIC_NHS) |
                            BIT(NHRP_PEER_TYPE_DYNAMIC);
      } else if (strcmp(word, "nhs") == 0) {
        iface->mcast_mask =
            BIT(NHRP_PEER_TYPE_STATIC) | BIT(NHRP_PEER_TYPE_DYNAMIC_NHS);
      } else if (nhrp_address_parse(word, &paddr, NULL)) {
        iface->mcast_numaddr++;
        iface->mcast_addr =
            realloc(iface->mcast_addr,
                    iface->mcast_numaddr * sizeof(struct nhrp_address));
        iface->mcast_addr[iface->mcast_numaddr - 1] = paddr;
      } else {
        rc = 6;
        break;
      }
    } else {
      rc = 0;
      break;
    }
  }
  fclose(in);

  if (rc >= 0) {
    nhrp_error("Configuration file %s in %s:%d, near word '%s'", errors[rc],
               config_file, lineno, word);
    return FALSE;
  }
  if (!nhrp_ha_config_validate())
    return FALSE;
  return TRUE;
}

static void remove_pid_file(void) {
  if (pid_file_fd != 0) {
    close(pid_file_fd);
    pid_file_fd = 0;
    remove(nhrp_pid_file);
  }
}

static int open_pid_file(void) {
  if (strlen(nhrp_pid_file) == 0)
    return TRUE;

  pid_file_fd = open(nhrp_pid_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
  if (pid_file_fd < 0)
    goto err;

  fcntl(pid_file_fd, F_SETFD, FD_CLOEXEC);
  if (flock(pid_file_fd, LOCK_EX | LOCK_NB) < 0)
    goto err_close;

  return TRUE;

err_close:
  close(pid_file_fd);
err:
  nhrp_error("Unable to open/lock pid file: %s.", strerror(errno));
  return FALSE;
}

static int write_pid(void) {
  char tmp[16];
  int n;

  if (pid_file_fd >= 0) {
    if (ftruncate(pid_file_fd, 0) < 0)
      return FALSE;

    n = sprintf(tmp, "%d\n", getpid());
    if (write(pid_file_fd, tmp, n) != n)
      return FALSE;

    atexit(remove_pid_file);
  }

  return TRUE;
}

static int daemonize(void) {
  pid_t pid;

  pid = fork();
  if (pid < 0)
    return FALSE;
  if (pid > 0)
    exit(0);

  if (setsid() < 0)
    return FALSE;

  pid = fork();
  if (pid < 0)
    return FALSE;
  if (pid > 0)
    exit(0);

  if (chdir("/") < 0)
    return FALSE;

  umask(0);

  if (freopen("/dev/null", "r", stdin) == NULL ||
      freopen("/dev/null", "w", stdout) == NULL ||
      freopen("/dev/null", "w", stderr) == NULL) {
    nhrp_error("Unable reopen standard file descriptors");
    goto err;
  }

  ev_default_fork();

  return TRUE;

err:
  close(pid_file_fd);
  pid_file_fd = 0;
  return FALSE;
}

int usage(const char *prog) {
  fprintf(
      stderr,
      "usage: opennhrp [-a admin-socket] [-c config-file] [-s script-file]\n"
      "                [-p pid-file] [-H ha-state-dir] [-d] [-v]\n"
      "       opennhrp -V\n"
      "\n"
      "\t-a admin-socket\tspecify management interface socket\n"
      "\t-c config-file\tread configuration from config-file\n"
      "\t-s script-file\tuse specified script-file for event handling\n"
      "\t-p pid-file\tspecify pid-file\n"
      "\t-H ha-state-dir\tload managed HA state from directory\n"
      "\t-d\t\tfork to background after startup\n"
      "\t-v\t\tverbose logging\n"
      "\t-V\t\tshow version number and exit\n"
      "\n");
  return 1;
}

int main(int argc, char **argv) {
  struct nhrp_address any;
  int i, daemonmode = 0;

  nhrp_address_set_type(&any, AF_UNSPEC);

  for (i = 1; i < argc; i++) {
    if (strlen(argv[i]) != 2 || argv[i][0] != '-')
      return usage(argv[0]);

    switch (argv[i][1]) {
    case 'c':
      if (++i >= argc)
        return usage(argv[0]);
      nhrp_config_file = argv[i];
      break;
    case 's':
      if (++i >= argc)
        return usage(argv[0]);
      nhrp_script_file = argv[i];
      break;
    case 'a':
      if (++i >= argc)
        return usage(argv[0]);
      nhrp_admin_socket = argv[i];
      break;
    case 'p':
      if (++i >= argc)
        return usage(argv[0]);
      nhrp_pid_file = argv[i];
      break;
    case 'H':
      if (++i >= argc)
        return usage(argv[0]);
      nhrp_ha_state_dir = argv[i];
      break;
    case 'd':
      daemonmode = 1;
      break;
    case 'v':
      nhrp_verbose = 1;
      break;
    case 'V':
      puts(nhrp_version_string);
      return 0;
    default:
      return usage(argv[0]);
    }
  }

  ha_process_paths_init(argv[0]);

  srandom(time(NULL));
  if (!log_init())
    return 1;
  if (!open_pid_file())
    return 1;

  nhrp_info("%s starting", nhrp_version_string);

  ev_default_loop(0);
  signal_init();
  server_init();
  if (!nhrp_address_init())
    return 3;
  if (!load_config(nhrp_config_file))
    return 4;
  if (!kernel_init())
    return 5;
  if (!nhrp_ha_prepare_managed(nhrp_ha_state_dir))
    return 4;
  if (!admin_init(nhrp_admin_socket))
    return 6;
  if (!forward_init())
    return 7;

  if (daemonmode && !daemonize()) {
    nhrp_error("Failed to daemonize. Exit.");
    return 8;
  }

  write_pid();

  nhrp_running = TRUE;
  ha_process_start();
  nhrp_ha_start();
  ev_loop(0);
  nhrp_running = FALSE;

  ha_process_cleanup();
  forward_cleanup();
  kernel_stop_listening();
  nhrp_ha_cleanup();
  nhrp_peer_cleanup();
  kernel_cleanup();
  nhrp_interface_cleanup();
  nhrp_rate_limit_clear(&any, 0);
  nhrp_address_cleanup();

  ev_default_destroy();

  return 0;
}

int nhrp_reload_config(void) {
  struct nhrp_address old_advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  struct nhrp_address new_advertised[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  struct nhrp_address old_targets[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  struct nhrp_address new_targets[NHRP_HA_MANAGED_MAX_ENDPOINTS];
  size_t old_count =
      nhrp_ha_hub_advertised(old_advertised, ARRAY_SIZE(old_advertised));
  size_t new_count;
  size_t old_target_count =
      nhrp_ha_hub_health_targets(old_targets, ARRAY_SIZE(old_targets));
  size_t new_target_count;

  nhrp_info("Reloading configuration file %s", nhrp_config_file);
  nhrp_peer_mark_static();
  nhrp_ha_mark_configured();
  if (!load_config(nhrp_config_file)) {
    nhrp_ha_config_reload_abort();
    nhrp_error("Failed to reload configuration file %s", nhrp_config_file);
    return FALSE;
  }
  if (!nhrp_ha_prepare_managed(nhrp_ha_state_dir)) {
    nhrp_ha_config_reload_abort();
    nhrp_error("Failed to reload managed HA state from %s", nhrp_ha_state_dir);
    return FALSE;
  }
  nhrp_peer_sweep_marked_static();
  nhrp_ha_sweep_unconfigured();
  nhrp_ha_start();
  new_count =
      nhrp_ha_hub_advertised(new_advertised, ARRAY_SIZE(new_advertised));
  new_target_count =
      nhrp_ha_hub_health_targets(new_targets, ARRAY_SIZE(new_targets));
  if (old_count != new_count ||
      memcmp(old_advertised, new_advertised,
             new_count * sizeof(new_advertised[0])) != 0 ||
      old_target_count != new_target_count ||
      memcmp(old_targets, new_targets,
             new_target_count * sizeof(new_targets[0])) != 0) {
    if (!ha_process_configure_hub()) {
      nhrp_error("Failed to update managed HA advertised addresses");
      return FALSE;
    }
  }
  nhrp_info("Configuration reloaded successfully");
  return TRUE;
}

int nhrp_reload_managed(void) {
  return nhrp_ha_reload_managed(nhrp_ha_state_dir);
}

struct save_ctx {
  FILE *fp;
  struct nhrp_interface *iface;
};

static int save_peer_config(void *ctx, struct nhrp_peer *peer) {
  FILE *fp = ((struct save_ctx *)ctx)->fp;
  char pbuf[64], nbuf[64];

  if (!(peer->flags & NHRP_PEER_FLAG_CONFIGURED))
    return 0;

  nhrp_address_format(&peer->protocol_address, sizeof(pbuf), pbuf);

  switch (peer->type) {
  case NHRP_PEER_TYPE_LOCAL_ADDR:
    fprintf(fp, "  shortcut-target %s/%d\n", pbuf, peer->prefix_length);
    break;
  case NHRP_PEER_TYPE_STATIC_DNS:
    fprintf(fp, "  dynamic-map %s/%d %s\n", pbuf, peer->prefix_length,
            peer->nbma_hostname ? peer->nbma_hostname : "");
    break;
  case NHRP_PEER_TYPE_STATIC:
    if (peer->nbma_hostname != NULL)
      fprintf(fp, "  map %s/%d %s", pbuf, peer->prefix_length,
              peer->nbma_hostname);
    else {
      nhrp_address_format(&peer->next_hop_address, sizeof(nbuf), nbuf);
      fprintf(fp, "  map %s/%d %s", pbuf, peer->prefix_length, nbuf);
    }
    if (peer->local_connect_address.type != PF_UNSPEC) {
      char lbuf[64];
      nhrp_address_format(&peer->local_connect_address, sizeof(lbuf), lbuf);
      fprintf(fp, " local-nbma %s", lbuf);
    }
    if (peer->flags & NHRP_PEER_FLAG_REGISTER)
      fprintf(fp, " register");
    if (peer->flags & NHRP_PEER_FLAG_CISCO)
      fprintf(fp, " cisco");
    if (peer->flags & NHRP_PEER_FLAG_REG_NON_UNIQUE)
      fprintf(fp, " no-unique");
    fprintf(fp, "\n");
    break;
  }
  return 0;
}

static int save_iface_config(void *ctx, struct nhrp_interface *iface) {
  FILE *fp = (FILE *)ctx;
  struct nhrp_peer_selector sel;
  struct save_ctx sctx = {fp, iface};

  if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
    return 0;

  fprintf(fp, "interface %s\n", iface->name);

  memset(&sel, 0, sizeof(sel));
  sel.interface = iface;
  sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL_ADDR) |
                  BIT(NHRP_PEER_TYPE_STATIC_DNS) | BIT(NHRP_PEER_TYPE_STATIC);
  nhrp_peer_foreach(save_peer_config, &sctx, &sel);
  nhrp_ha_save_config(fp, iface);

  if (iface->holding_time != 0)
    fprintf(fp, "  holding-time %u\n", iface->holding_time);
  if (iface->route_table != 0 && iface->route_table != RT_TABLE_MAIN)
    fprintf(fp, "  route-table %u\n", iface->route_table);
  if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT)
    fprintf(fp, "  shortcut\n");
  if (iface->flags & NHRP_INTERFACE_FLAG_REDIRECT)
    fprintf(fp, "  redirect\n");
  if (iface->flags & NHRP_INTERFACE_FLAG_NON_CACHING)
    fprintf(fp, "  non-caching\n");
  if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
    fprintf(fp, "  shortcut-destination\n");

  fprintf(fp, "\n");
  return 0;
}

int nhrp_save_config(void) {
  char tmp_file[1024];
  FILE *fp;

  snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", nhrp_config_file);
  fp = fopen(tmp_file, "w");
  if (fp == NULL) {
    nhrp_error("Unable to open temporary config file %s: %s", tmp_file,
               strerror(errno));
    return FALSE;
  }

  fprintf(fp, "# OpenNHRP Configuration File (saved automatically)\n\n");
  nhrp_interface_foreach(save_iface_config, fp);

  fflush(fp);
  fclose(fp);

  if (rename(tmp_file, nhrp_config_file) != 0) {
    nhrp_error("Failed to rename %s to %s: %s", tmp_file, nhrp_config_file,
               strerror(errno));
    unlink(tmp_file);
    return FALSE;
  }

  nhrp_info("Configuration saved successfully to %s", nhrp_config_file);
  return TRUE;
}
