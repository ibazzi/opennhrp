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
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "nhrp_common.h"
#include "nhrp_ha.h"
#include "nhrp_ha_hub.h"
#include "nhrp_ha_managed.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"
#include "opennhrp_ha_process.h"

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

static void handle_signal_cb(struct ev_signal *w, int revents) {
  switch (w->signum) {
  case SIGUSR1:
    nhrp_peer_dump_cache();
    break;
  case SIGINT:
  case SIGTERM:
    ev_break(EVBREAK_ALL);
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
    snprintf(word, len, "%.*s", (int)(len - 1), unread_buf);
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

struct interface_config {
  struct nhrp_address advertised_forwarding_nbma;
  struct list_head list;
  struct nhrp_interface *interface;
  struct nhrp_buffer *auth_token;
  struct nhrp_address *mcast_addr;
  int mcast_mask, mcast_numaddr;
};

static int save_interface_config(void *ctx, struct nhrp_interface *iface) {
  struct list_head *saved = ctx;
  struct interface_config *entry;

  list_for_each_entry(entry, saved, list) {
    if (entry->interface == iface)
      return 0;
  }
  entry = calloc(1, sizeof(*entry));
  if (entry == NULL)
    return -1;
  entry->interface = iface;
  entry->auth_token = iface->auth_token;
  entry->mcast_addr = iface->mcast_addr;
  entry->mcast_mask = iface->mcast_mask;
  entry->mcast_numaddr = iface->mcast_numaddr;
  entry->advertised_forwarding_nbma = iface->advertised_forwarding_nbma;
  nhrp_address_set_type(&iface->advertised_forwarding_nbma, PF_UNSPEC);
  iface->auth_token = NULL;
  iface->mcast_addr = NULL;
  iface->mcast_mask = iface->mcast_numaddr = 0;
  list_add_tail(&entry->list, saved);
  return 0;
}

static void finish_interface_config(struct list_head *saved, int commit) {
  struct interface_config *entry, *next;

  list_for_each_entry_safe(entry, next, saved, list) {
    struct nhrp_interface *iface = entry->interface;

    nhrp_buffer_free(commit ? entry->auth_token : iface->auth_token);
    free(commit ? entry->mcast_addr : iface->mcast_addr);
    if (!commit) {
      iface->auth_token = entry->auth_token;
      iface->mcast_addr = entry->mcast_addr;
      iface->mcast_mask = entry->mcast_mask;
      iface->mcast_numaddr = entry->mcast_numaddr;
      iface->advertised_forwarding_nbma = entry->advertised_forwarding_nbma;
    } else {
      struct nhrp_peer *peer;

      list_for_each_entry(peer, &iface->peer_list, peer_list_entry) {
        if (peer->flags & NHRP_PEER_FLAG_UP)
          nhrp_peer_update_multicast(peer);
      }
    }
    list_del(&entry->list);
    free(entry);
  }
  if (commit)
    forward_local_addresses_changed();
}

struct peer_config_backup {
  struct list_head list;
  struct nhrp_peer *peer;
  unsigned int flags;
  struct nhrp_address local_nbma;
  struct nhrp_address forwarding_nbma;
  struct nhrp_address effective_forwarding_nbma;
  enum nhrp_forwarding_policy forwarding_policy;
  char *accepted_forwarding_members;
  unsigned int holding_time;
};

static int save_peer_config_fields(void *ctx, struct nhrp_peer *peer) {
  struct list_head *saved = ctx;
  struct peer_config_backup *entry;

  if (!(peer->flags & NHRP_PEER_FLAG_CONFIGURED))
    return 0;
  entry = malloc(sizeof(*entry));
  if (entry == NULL)
    return -1;
  entry->peer = nhrp_peer_get(peer);
  entry->flags = peer->flags;
  entry->local_nbma = peer->local_connect_address;
  entry->forwarding_nbma = peer->forwarding_nbma;
  entry->effective_forwarding_nbma = *nhrp_peer_forwarding_nbma(peer);
  entry->forwarding_policy = peer->forwarding_policy;
  peer->forwarding_policy = NHRP_FORWARDING_DEFAULT;
  entry->accepted_forwarding_members = peer->accepted_forwarding_members;
  peer->accepted_forwarding_members = NULL;
  entry->holding_time = peer->holding_time;
  list_add_tail(&entry->list, saved);
  return 0;
}

static void finish_peer_config(struct list_head *saved,
                               struct list_head *pending, int commit) {
  struct peer_config_backup *entry, *next;
  struct nhrp_peer *peer, *next_peer;

  list_for_each_entry_safe(entry, next, saved, list) {
    if (!commit) {
      entry->peer->flags = entry->flags;
      entry->peer->local_connect_address = entry->local_nbma;
      entry->peer->forwarding_nbma = entry->forwarding_nbma;
      entry->peer->forwarding_policy = entry->forwarding_policy;
      free(entry->peer->accepted_forwarding_members);
      entry->peer->accepted_forwarding_members = entry->accepted_forwarding_members;
      entry->accepted_forwarding_members = NULL;
      entry->peer->holding_time = entry->holding_time;
    } else if (!(entry->peer->flags & NHRP_PEER_FLAG_REMOVED)) {
      peer = entry->peer;
      if (peer->forwarding_policy != NHRP_FORWARDING_ORDINARY)
        nhrp_address_set_type(&peer->advertised_forwarding_nbma, PF_UNSPEC);
      if ((peer->flags & NHRP_PEER_FLAG_LOWER_UP) &&
          !(peer->flags & NHRP_PEER_FLAG_HA_BOOTSTRAP) &&
          peer->protocol_address.type == AF_INET &&
          nhrp_address_cmp(nhrp_peer_forwarding_nbma(peer),
                           &entry->effective_forwarding_nbma)) {
        kernel_inject_neighbor(&peer->protocol_address, nhrp_peer_forwarding_nbma(peer),
                               peer->interface);
        nhrp_peer_update_multicast(peer);
      }
      if (((peer->flags ^ entry->flags) &
           (NHRP_PEER_FLAG_REGISTER | NHRP_PEER_FLAG_CISCO | NHRP_PEER_FLAG_REG_NON_UNIQUE)) ||
          nhrp_address_cmp(&peer->local_connect_address, &entry->local_nbma))
        nhrp_peer_purge(peer, "configuration changed");
      else if ((peer->forwarding_policy == NHRP_FORWARDING_ORDINARY) !=
               (entry->forwarding_policy == NHRP_FORWARDING_ORDINARY))
        nhrp_peer_reregister_matching(NULL, peer);
    }
    free(entry->accepted_forwarding_members);
    nhrp_peer_put(entry->peer);
    list_del(&entry->list);
    free(entry);
  }
  list_for_each_entry_safe(peer, next_peer, pending, peer_list_entry) {
    list_del(&peer->peer_list_entry);
    if (commit)
      nhrp_peer_insert(peer);
    else
      peer->flags |= NHRP_PEER_FLAG_REPLACED;
    nhrp_peer_put(peer);
  }
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
      "unable to allocate interface configuration",
  };
  struct list_head saved_interfaces = LIST_INITIALIZER(saved_interfaces);
  struct list_head saved_peers = LIST_INITIALIZER(saved_peers);
  struct list_head staged_peers = LIST_INITIALIZER(staged_peers);
  struct nhrp_interface *iface = NULL;
  struct nhrp_peer *peer = NULL, *exist = NULL;
  struct nhrp_address paddr, nbma_addr;
  uint8_t prefix_length;
  char word[64], nbma[256], addr[64];
  FILE *in;
  int lineno = 1, rc = -1;

  in = fopen(config_file, "r");
  if (in == NULL) {
    nhrp_error("Unable to open configuration file '%s'.", config_file);
    return FALSE;
  }
  if (nhrp_interface_foreach(save_interface_config, &saved_interfaces) != 0) {
    fclose(in);
    finish_interface_config(&saved_interfaces, FALSE);
    return FALSE;
  }
  if (nhrp_peer_foreach(save_peer_config_fields, &saved_peers, NULL) != 0) {
    fclose(in);
    finish_peer_config(&saved_peers, &staged_peers, FALSE);
    finish_interface_config(&saved_interfaces, FALSE);
    return FALSE;
  }
  nhrp_peer_mark_static();

  while (read_word(in, &lineno, sizeof(word), word)) {
    if (strcmp(word, "interface") == 0) {
      if (!read_word(in, &lineno, sizeof(word), word)) {
        rc = 1;
        break;
      }
      iface = nhrp_interface_get_by_name(word, TRUE);
      if (iface == NULL || save_interface_config(&saved_interfaces, iface) != 0) {
        rc = 8;
        break;
      }
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
        if (peer == NULL) {
          rc = 8;
          break;
        }
        peer->type = NHRP_PEER_TYPE_LOCAL_ADDR;
        peer->afnum = AFNUM_RESERVED;
        peer->protocol_address = paddr;
        peer->prefix_length = prefix_length;
        peer->protocol_type = nhrp_protocol_from_pf(paddr.type);
        peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
        list_add_tail(&peer->peer_list_entry, &staged_peers);
      }
    } else if (strcmp(word, "dynamic-map") == 0) {
      NEED_INTERFACE();
      if (!read_word(in, &lineno, sizeof(addr), addr) ||
          !read_word(in, &lineno, sizeof(nbma), nbma)) {
        rc = 1;
        break;
      }

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
        if (peer == NULL) {
          rc = 8;
          break;
        }
        peer->type = NHRP_PEER_TYPE_STATIC_DNS;
        peer->protocol_address = paddr;
        peer->prefix_length = prefix_length;
        peer->protocol_type = nhrp_protocol_from_pf(paddr.type);
        peer->nbma_hostname = strdup(nbma);
        if (peer->nbma_hostname == NULL) {
          nhrp_peer_put(peer);
          rc = 8;
          break;
        }
        peer->afnum = nhrp_afnum_from_pf(peer->next_hop_address.type);
        peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
        list_add_tail(&peer->peer_list_entry, &staged_peers);
      }
    } else if (strcmp(word, "map") == 0) {
      NEED_INTERFACE();
      if (!read_word(in, &lineno, sizeof(addr), addr) ||
          !read_word(in, &lineno, sizeof(nbma), nbma)) {
        rc = 1;
        break;
      }
      int discover = !strcmp(addr, "dynamic");
      if (discover) {
        if (!read_word(in, &lineno, sizeof(word), word) || strcmp(word, "register")) {
          nhrp_error("'map dynamic' requires 'register'");
          rc = 0;
          break;
        }
        nhrp_address_set_type(&paddr, AF_UNSPEC);
        prefix_length = 32;
      } else if (!nhrp_address_parse(addr, &paddr, &prefix_length)) {
        rc = 4;
        break;
      }
      nhrp_address_set_type(&nbma_addr, PF_UNSPEC);
      char *nbma_host = NULL;
      if (!nhrp_address_parse(nbma, &nbma_addr, NULL))
        nbma_host = nbma;

      if (discover) {
        struct nhrp_peer *candidate;

        exist = NULL;
        list_for_each_entry(candidate, &iface->peer_list, peer_list_entry) {
          if (candidate->type != NHRP_PEER_TYPE_STATIC ||
              (candidate->flags & (NHRP_PEER_FLAG_MARK | NHRP_PEER_FLAG_DISCOVER_NHS)) !=
                  (NHRP_PEER_FLAG_MARK | NHRP_PEER_FLAG_DISCOVER_NHS))
            continue;
          if (nbma_host != NULL
                  ? candidate->nbma_hostname != NULL &&
                        !strcmp(nbma_host, candidate->nbma_hostname)
                  : candidate->nbma_hostname == NULL &&
                        !nhrp_address_cmp(&nbma_addr, &candidate->next_hop_address)) {
            exist = candidate;
            break;
          }
        }
      } else {
        exist = nhrp_peer_find_marked_static(iface, NHRP_PEER_TYPE_STATIC, &paddr,
                                             &nbma_addr, nbma_host);
        if (exist != NULL && (exist->flags & NHRP_PEER_FLAG_DISCOVER_NHS))
          exist = NULL;
      }
      if (exist != NULL) {
        exist->flags &= ~NHRP_PEER_FLAG_MARK;
        exist->flags &= ~(NHRP_PEER_FLAG_REGISTER | NHRP_PEER_FLAG_CISCO |
                          NHRP_PEER_FLAG_REG_NON_UNIQUE);
        exist->flags |= NHRP_PEER_FLAG_CONFIGURED;
        nhrp_address_set_type(&exist->local_connect_address, PF_UNSPEC);
        nhrp_address_set_type(&exist->forwarding_nbma, PF_UNSPEC);
        peer = exist;
      } else {
        peer = nhrp_peer_alloc(iface);
        if (peer == NULL) {
          rc = 8;
          break;
        }
        peer->type = NHRP_PEER_TYPE_STATIC;
        peer->protocol_address = paddr;
        peer->prefix_length = prefix_length;
        peer->protocol_type = nhrp_protocol_from_pf(discover ? AF_INET : paddr.type);
        peer->next_hop_address = nbma_addr;
        if (nbma_host != NULL)
          peer->nbma_hostname = strdup(nbma_host);
        if (nbma_host != NULL && peer->nbma_hostname == NULL) {
          peer->flags |= NHRP_PEER_FLAG_REPLACED;
          nhrp_peer_put(peer);
          rc = 8;
          break;
        }
        peer->afnum = nhrp_afnum_from_pf(peer->next_hop_address.type);
        peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
        list_add_tail(&peer->peer_list_entry, &staged_peers);
      }
      if (discover)
        peer->flags |= NHRP_PEER_FLAG_DISCOVER_NHS | NHRP_PEER_FLAG_REGISTER;
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
      if ((peer->flags & NHRP_PEER_FLAG_DISCOVER_NHS) ||
          !read_word(in, &lineno, sizeof(word), word) ||
          !nhrp_address_parse(word, &peer->local_connect_address, NULL)) {
        rc = 4;
        break;
      }
    } else if (strcmp(word, "accept-data-nbma") == 0) {
      char *members;
      size_t previous;

      NEED_PEER();
      if (!(peer->flags & NHRP_PEER_FLAG_REGISTER) ||
          !read_word(in, &lineno, sizeof(word), word)) {
        rc = 0;
        break;
      }
      if (!strcmp(word, "enable") || !strcmp(word, "disable")) {
        if (peer->forwarding_policy != NHRP_FORWARDING_DEFAULT) {
          rc = 0;
          break;
        }
        peer->forwarding_policy = !strcmp(word, "enable") ? NHRP_FORWARDING_ORDINARY
                                                         : NHRP_FORWARDING_DISABLED;
        continue;
      }
      if (strcmp(word, "ha") ||
          (peer->forwarding_policy != NHRP_FORWARDING_DEFAULT &&
           peer->forwarding_policy != NHRP_FORWARDING_HA) ||
          !read_word(in, &lineno, sizeof(word), word) ||
          strlen(word) > 32 || !isalnum((unsigned char)word[0]) ||
          strspn(word, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") != strlen(word)) {
        rc = 0;
        break;
      }
      previous = peer->accepted_forwarding_members
                     ? strlen(peer->accepted_forwarding_members) : 0;
      members = realloc(peer->accepted_forwarding_members,
                        previous + strlen(word) + 2);
      if (members == NULL) {
        rc = 8;
        break;
      }
      members[previous] = ' ';
      strcpy(members + previous + 1, word);
      peer->accepted_forwarding_members = members;
      peer->forwarding_policy = NHRP_FORWARDING_HA;
    } else if (strcmp(word, "data-nbma") == 0 ||
               strcmp(word, "advertise-data-nbma") == 0) {
      struct nhrp_address *forwarding;

      if (strcmp(word, "advertise-data-nbma") == 0) {
        NEED_INTERFACE();
        forwarding = &iface->advertised_forwarding_nbma;
      } else {
        NEED_PEER();
        if (!(peer->flags & NHRP_PEER_FLAG_REGISTER)) {
          rc = 3;
          break;
        }
        forwarding = &peer->forwarding_nbma;
      }
      if (!read_word(in, &lineno, sizeof(word), word) ||
          !nhrp_address_parse(word, forwarding, NULL) ||
          forwarding->type != AF_INET || !forwarding->addr[0] ||
          forwarding->addr[0] == 127 || forwarding->addr[0] >= 224) {
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

      nhrp_buffer_free(iface->auth_token);
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
        iface->mcast_mask =
            BIT(NHRP_PEER_TYPE_STATIC) | BIT(NHRP_PEER_TYPE_DYNAMIC_NHS) |
            BIT(NHRP_PEER_TYPE_DYNAMIC) | BIT(NHRP_PEER_TYPE_HA_ACTIVE);
      } else if (strcmp(word, "nhs") == 0) {
        iface->mcast_mask = BIT(NHRP_PEER_TYPE_STATIC) |
                            BIT(NHRP_PEER_TYPE_DYNAMIC_NHS) |
                            BIT(NHRP_PEER_TYPE_HA_ACTIVE);
      } else if (nhrp_address_parse(word, &paddr, NULL)) {
        struct nhrp_address *addresses =
            realloc(iface->mcast_addr,
                    (iface->mcast_numaddr + 1) * sizeof(struct nhrp_address));
        if (addresses == NULL) {
          rc = 8;
          break;
        }
        iface->mcast_addr = addresses;
        iface->mcast_addr[iface->mcast_numaddr++] = paddr;
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

  if (rc >= 0)
    nhrp_error("Configuration file %s in %s:%d, near word '%s'", errors[rc],
               config_file, lineno, word);
  int commit = rc < 0 && nhrp_ha_config_validate();
  if (commit)
    nhrp_peer_sweep_marked_static();
  finish_peer_config(&saved_peers, &staged_peers, commit);
  finish_interface_config(&saved_interfaces, commit);
  return commit;
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

  ev_loop_fork();

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
      "\t-H state-dir\tload HA and peer cache state from directory\n"
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

  opennhrp_ha_process_init(argv[0], nhrp_admin_socket, nhrp_ha_state_dir);

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

  nhrp_peer_cache_load(nhrp_ha_state_dir);
  nhrp_running = TRUE;
  opennhrp_ha_process_start();
  nhrp_ha_start();
  ev_run(0);
  nhrp_running = FALSE;

  opennhrp_ha_process_cleanup();
  nhrp_peer_cache_save(nhrp_ha_state_dir);
  forward_cleanup();
  kernel_stop_listening();
  nhrp_ha_cleanup();
  nhrp_peer_cleanup();
  kernel_cleanup();
  nhrp_interface_cleanup();
  nhrp_rate_limit_clear(&any, 0);
  nhrp_address_cleanup();

  ev_loop_destroy();

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
    if (!opennhrp_ha_process_reconfigure()) {
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
  case NHRP_PEER_TYPE_STATIC: {
    const char *nbma = peer->nbma_hostname;
    if (nbma == NULL)
      nbma = nhrp_address_format(&peer->next_hop_address, sizeof(nbuf), nbuf);
    if (peer->flags & NHRP_PEER_FLAG_DISCOVER_NHS)
      fprintf(fp, "  map dynamic %s", nbma);
    else
      fprintf(fp, "  map %s/%d %s", pbuf, peer->prefix_length, nbma);
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
    if (peer->forwarding_nbma.type == AF_INET)
      fprintf(fp, " data-nbma %s", nhrp_address_format(&peer->forwarding_nbma, sizeof(nbuf), nbuf));
    if (peer->forwarding_policy == NHRP_FORWARDING_ORDINARY)
      fprintf(fp, " accept-data-nbma enable");
    else if (peer->forwarding_policy == NHRP_FORWARDING_DISABLED)
      fprintf(fp, " accept-data-nbma disable");
    if (peer->accepted_forwarding_members != NULL) {
      const char *member = peer->accepted_forwarding_members;
      for (; member != NULL; member = strchr(member + 1, ' ')) {
        size_t length = strcspn(member + 1, " ");
        fprintf(fp, " accept-data-nbma ha %.*s", (int)length, member + 1);
      }
    }
    fprintf(fp, "\n");
    break;
  }
  }
  return 0;
}

static int save_iface_config(void *ctx, struct nhrp_interface *iface) {
  FILE *fp = (FILE *)ctx;
  struct nhrp_peer_selector sel;
  struct save_ctx sctx = {fp, iface};
  char addr[64];
  int i;

  if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
    return 0;

  fprintf(fp, "interface %s\n", iface->name);
  if (iface->advertised_forwarding_nbma.type == AF_INET)
    fprintf(fp, "  advertise-data-nbma %s\n",
            nhrp_address_format(&iface->advertised_forwarding_nbma, sizeof(addr), addr));

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
  if (iface->mcast_mask)
    fprintf(fp, "  multicast %s\n",
            iface->mcast_mask & BIT(NHRP_PEER_TYPE_DYNAMIC) ? "dynamic"
                                                            : "nhs");
  for (i = 0; i < iface->mcast_numaddr; i++)
    fprintf(fp, "  multicast %s\n",
            nhrp_address_format(&iface->mcast_addr[i], sizeof(addr), addr));

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
