/* opennhrp_ha_process.c - OpenNHRP HA child process management */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "nhrp_common.h"
#include "nhrp_ha.h"
#include "nhrp_ha_hub.h"
#include "nhrp_ha_managed.h"
#include "nhrp_interface.h"
#include "opennhrp_ha_process.h"

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
static const char *ha_admin_socket;
static const char *ha_state_directory;
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
  if (child->role == NHRP_HA_CHILD_HUB)
    nhrp_ha_hub_fence(child->interface);
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
    arguments[argument++] = (char *)ha_state_directory;
    arguments[argument++] = "-a";
    arguments[argument++] = (char *)ha_admin_socket;
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
    execlp(nhrp_ha_program, nhrp_ha_program, "-a", ha_admin_socket, "-i",
           child->interface->name, (char *)NULL);
  }
  _exit(127);
}

int opennhrp_ha_process_reconfigure(void) {
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
  pid_t parent;
  pid_t pid;

  if (child->role == NHRP_HA_CHILD_NONE || child->pid != 0 || child->stopping)
    return;
  ev_timer_stop(&child->restart);
  parent = getpid();
  pid = fork();
  if (pid < 0) {
    nhrp_error("Unable to start HA coordinator for %s: %s",
               child->interface->name, strerror(errno));
    ev_timer_set(&child->restart, 1.0, 0.0);
    ev_timer_start(&child->restart);
    nhrp_ha_set_coordinator_status(child->interface, "restarting", -errno);
    return;
  }
  if (pid == 0) {
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() != parent)
      _exit(127);
    ha_child_exec(child);
  }
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

void opennhrp_ha_process_init(const char *program, const char *admin_socket,
                              const char *state_directory) {
  char resolved[PATH_MAX];
  size_t socket_length;
  char *slash;

  ha_admin_socket = admin_socket;
  ha_state_directory = state_directory;
  if (realpath(program, resolved) != NULL &&
      (slash = strrchr(resolved, '/')) != NULL) {
    *slash = 0;
    if (snprintf(nhrp_ha_program, sizeof(nhrp_ha_program), "%s/opennhrp-ha",
                 resolved) >= (int)sizeof(nhrp_ha_program))
      snprintf(nhrp_ha_program, sizeof(nhrp_ha_program), "opennhrp-ha");
  }
  snprintf(nhrp_ha_control_socket, sizeof(nhrp_ha_control_socket), "%s",
           ha_admin_socket);
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
void opennhrp_ha_process_start(void) {
  struct nhrp_interface *iface;
  struct nhrp_ha_child *child;
  const char *interface_name = nhrp_ha_hub_interface();

  nhrp_ha_set_coordinator_callback(ha_process_require_spoke);
  if (!nhrp_ha_hub_enabled() || interface_name == NULL)
    return;
  iface = nhrp_interface_get_by_name(interface_name, FALSE);
  nhrp_ha_hub_fence(iface);
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

void opennhrp_ha_process_cleanup(void) {
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
