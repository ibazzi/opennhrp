/* core/nhrp_peer_cache.c - Persistent NHRP peer cache snapshots */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nhrp_common.h"
#include "nhrp_ha_managed.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

#define NHRP_PEER_CACHE_FILE "peer-cache.state"
#define NHRP_PEER_CACHE_HEADER "OPENNHRP-PEER-CACHE 2\n"
#define NHRP_PEER_CACHE_LINE_MAX 256

struct nhrp_peer_cache_record {
  uint8_t type;
  char interface[16];
  struct nhrp_address protocol_address;
  uint8_t prefix_length;
  struct nhrp_address next_hop_address;
  struct nhrp_address next_hop_nat_oa;
  uint16_t mtu;
  unsigned int flags;
  int64_t expires_at;
};

int nhrp_peer_is_persistable(const struct nhrp_peer *peer) {
  if (peer->expire_time <= ev_now() ||
      (peer->flags & (NHRP_PEER_FLAG_REMOVED | NHRP_PEER_FLAG_REPLACED)))
    return FALSE;

  switch (peer->type) {
  case NHRP_PEER_TYPE_DYNAMIC:
    return !(peer->flags &
             (NHRP_PEER_FLAG_HA_CAPABLE | NHRP_PEER_FLAG_HA_PROJECTED));
  case NHRP_PEER_TYPE_CACHED:
  case NHRP_PEER_TYPE_SHORTCUT_ROUTE:
    return TRUE;
  default:
    return FALSE;
  }
}
struct nhrp_peer_cache_save_ctx {
  FILE *file;
  ev_tstamp monotonic_now;
  time_t wall_now;
  int count;
  int failed;
};

static int nhrp_peer_cache_write(void *ctx, struct nhrp_peer *peer) {
  struct nhrp_peer_cache_save_ctx *save = ctx;
  char protocol[64], next_hop[64], nat_oa[64];
  ev_tstamp remaining;
  int64_t seconds;

  if (!nhrp_peer_is_persistable(peer))
    return 0;
  remaining = peer->expire_time - save->monotonic_now;
  if (remaining <= 0.0)
    return 0;
  seconds = (int64_t)remaining;
  if ((ev_tstamp)seconds < remaining)
    seconds++;

  if (fprintf(save->file, "%s %s %s/%u %s %s %u %" PRId64 " %u\n",
              nhrp_peer_type[peer->type], peer->interface->name,
              nhrp_address_format(&peer->protocol_address, sizeof(protocol),
                                  protocol),
              peer->prefix_length,
              nhrp_address_format(&peer->next_hop_address, sizeof(next_hop),
                                  next_hop),
              peer->next_hop_nat_oa.type == PF_UNSPEC
                  ? "-"
                  : nhrp_address_format(&peer->next_hop_nat_oa, sizeof(nat_oa),
                                        nat_oa),
              peer->mtu, (int64_t)save->wall_now + seconds,
              peer->flags & NHRP_PEER_FLAG_UNIQUE) < 0) {
    save->failed = TRUE;
    return 1;
  }
  save->count++;
  return 0;
}

static int nhrp_peer_cache_path(const char *directory, char *path,
                                size_t size) {
  int length;

  if (directory == NULL)
    return FALSE;
  length = snprintf(path, size, "%s/%s", directory, NHRP_PEER_CACHE_FILE);
  return length > 0 && length < (int)size;
}

int nhrp_peer_cache_save(const char *directory) {
  struct nhrp_peer_cache_save_ctx save;
  char path[4096];
  char *data = NULL;
  size_t length = 0;
  int lock_fd = -1;
  int close_ok;
  int ok = FALSE;

  memset(&save, 0, sizeof(save));
  if (!nhrp_peer_cache_path(directory, path, sizeof(path)))
    goto done;
  lock_fd = nhrp_ha_managed_state_lock(directory);
  if (lock_fd < 0)
    goto done;
  save.file = open_memstream(&data, &length);
  save.monotonic_now = ev_now();
  save.wall_now = time(NULL);
  if (save.file == NULL || save.wall_now == (time_t)-1 ||
      fputs(NHRP_PEER_CACHE_HEADER, save.file) == EOF)
    goto done;
  nhrp_peer_foreach(nhrp_peer_cache_write, &save, NULL);
  close_ok = fclose(save.file) == 0;
  save.file = NULL;
  if (save.failed || !close_ok)
    goto done;
  if (!nhrp_ha_secure_file_write(path, data, length))
    goto done;
  ok = TRUE;
  nhrp_info("Saved %d peer cache entries", save.count);

done:
  if (save.file != NULL)
    fclose(save.file);
  free(data);
  nhrp_ha_managed_state_unlock(lock_fd);
  if (!ok)
    nhrp_error("Failed to save peer cache snapshot");
  return ok;
}

static int nhrp_peer_cache_parse_uint(const char *text, uint64_t maximum,
                                      uint64_t *value) {
  char *end;
  unsigned long long parsed;

  if (text[0] < '0' || text[0] > '9')
    return FALSE;
  errno = 0;
  parsed = strtoull(text, &end, 10);
  if (errno != 0 || *end != 0 || parsed > maximum)
    return FALSE;
  *value = parsed;
  return TRUE;
}

static int nhrp_peer_cache_parse_address(const char *text,
                                         struct nhrp_address *address) {
  struct in_addr ipv4;

  if (inet_pton(AF_INET, text, &ipv4) != 1)
    return FALSE;
  return nhrp_address_set(address, PF_INET, sizeof(ipv4), (uint8_t *)&ipv4);
}

static int nhrp_peer_cache_parse_protocol(char *text,
                                          struct nhrp_address *address,
                                          uint8_t *prefix_length) {
  uint64_t prefix;
  char *slash = strrchr(text, '/');

  if (slash == NULL || strchr(text, '/') != slash)
    return FALSE;
  *slash++ = 0;
  if (!nhrp_peer_cache_parse_uint(slash, 32, &prefix) ||
      !nhrp_peer_cache_parse_address(text, address))
    return FALSE;
  *prefix_length = prefix;
  return TRUE;
}

static int nhrp_peer_cache_parse_record(char *line,
                                        struct nhrp_peer_cache_record *record) {
  char type[16], interface[16], protocol[32], next_hop[32], nat_oa[32];
  char mtu_text[16], expiry_text[32], flags_text[16], extra;
  char canonical[NHRP_PEER_CACHE_LINE_MAX];
  char protocol_fmt[64], next_hop_fmt[64], nat_oa_fmt[64];
  uint64_t mtu, expiry, flags;
  int length;

  memset(record, 0, sizeof(*record));
  if (sscanf(line, "%15s %15s %31s %31s %31s %15s %31s %15s %c", type,
             interface, protocol, next_hop, nat_oa, mtu_text, expiry_text,
             flags_text, &extra) != 8 ||
      !nhrp_peer_cache_parse_uint(flags_text, NHRP_PEER_FLAG_UNIQUE, &flags) ||
      !nhrp_peer_cache_parse_uint(mtu_text, UINT16_MAX, &mtu) ||
      !nhrp_peer_cache_parse_uint(expiry_text, INT64_MAX, &expiry) ||
      !nhrp_peer_cache_parse_protocol(protocol, &record->protocol_address,
                                      &record->prefix_length) ||
      !nhrp_peer_cache_parse_address(next_hop, &record->next_hop_address))
    return FALSE;

  if (strcmp(type, "dynamic") == 0)
    record->type = NHRP_PEER_TYPE_DYNAMIC;
  else if (strcmp(type, "cached") == 0)
    record->type = NHRP_PEER_TYPE_CACHED;
  else if (strcmp(type, "shortcut-route") == 0)
    record->type = NHRP_PEER_TYPE_SHORTCUT_ROUTE;
  else
    return FALSE;
  if (strcmp(nat_oa, "-") == 0)
    nhrp_address_set_type(&record->next_hop_nat_oa, PF_UNSPEC);
  else if (!nhrp_peer_cache_parse_address(nat_oa, &record->next_hop_nat_oa))
    return FALSE;
  if (record->type == NHRP_PEER_TYPE_SHORTCUT_ROUTE &&
      (record->next_hop_nat_oa.type != PF_UNSPEC || mtu != 0))
    return FALSE;

  snprintf(record->interface, sizeof(record->interface), "%s", interface);
  record->mtu = mtu;
  record->flags = flags;
  record->expires_at = expiry;
  length =
      snprintf(canonical, sizeof(canonical),
               "%s %s %s/%u %s %s %u %" PRId64 " %u\n", type, record->interface,
               nhrp_address_format(&record->protocol_address,
                                   sizeof(protocol_fmt), protocol_fmt),
               record->prefix_length,
               nhrp_address_format(&record->next_hop_address,
                                   sizeof(next_hop_fmt), next_hop_fmt),
               record->next_hop_nat_oa.type == PF_UNSPEC
                   ? "-"
                   : nhrp_address_format(&record->next_hop_nat_oa,
                                         sizeof(nat_oa_fmt), nat_oa_fmt),
               record->mtu, record->expires_at, record->flags);
  return length > 0 && length < (int)sizeof(canonical) &&
         strcmp(line, canonical) == 0;
}

static int nhrp_peer_cache_conflict(void *ctx, struct nhrp_peer *peer) {
  struct nhrp_peer_cache_record *record = ctx;

  return peer->interface != NULL &&
         !(NHRP_PEER_TYPEMASK_REMOVABLE & BIT(peer->type)) &&
         strcmp(peer->interface->name, record->interface) == 0 &&
         peer->prefix_length == record->prefix_length &&
         nhrp_address_cmp(&peer->protocol_address, &record->protocol_address) ==
             0;
}

static int nhrp_peer_cache_restore(struct nhrp_peer_cache_record *record,
                                   time_t wall_now, int adjacency) {
  struct nhrp_interface *iface;
  struct nhrp_peer *peer;
  int64_t remaining;

  if ((record->type == NHRP_PEER_TYPE_SHORTCUT_ROUTE) == adjacency)
    return 0;
  remaining = record->expires_at - wall_now;
  if (remaining <= 0)
    return 0;
  iface = nhrp_interface_get_by_name(record->interface, FALSE);
  if (iface == NULL || iface->index == 0 ||
      !(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED) ||
      nhrp_peer_foreach(nhrp_peer_cache_conflict, record, NULL))
    return 0;

  peer = nhrp_peer_alloc(iface);
  peer->type = record->type;
  peer->flags |= record->flags;
  peer->afnum = nhrp_afnum_from_pf(record->next_hop_address.type);
  peer->protocol_type = nhrp_protocol_from_pf(record->protocol_address.type);
  peer->protocol_address = record->protocol_address;
  peer->prefix_length = record->prefix_length;
  peer->next_hop_address = record->next_hop_address;
  peer->next_hop_nat_oa = record->next_hop_nat_oa;
  peer->mtu = record->mtu;
  peer->expire_time = ev_now() + remaining;
  nhrp_peer_insert(peer);
  nhrp_peer_put(peer);
  return 1;
}

static int nhrp_peer_cache_consume(const char *directory, const char *path) {
  int directory_fd;
  int ok;

  if (unlink(path) != 0)
    return FALSE;
  directory_fd =
      open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory_fd < 0)
    return FALSE;
  ok = fsync(directory_fd) == 0;
  close(directory_fd);
  return ok;
}

int nhrp_peer_cache_load(const char *directory) {
  struct nhrp_peer_cache_record *records = NULL;
  struct nhrp_peer_cache_record record;
  struct stat status;
  char path[4096];
  char *line = NULL;
  size_t capacity = 0, count = 0, line_size = 0, i;
  ssize_t line_length;
  FILE *file = NULL;
  time_t wall_now;
  int fd = -1, lock_fd = -1;
  int valid = FALSE, restored = 0, consumed = FALSE;

  if (!nhrp_peer_cache_path(directory, path, sizeof(path)))
    goto done;
  lock_fd = nhrp_ha_managed_state_lock(directory);
  if (lock_fd < 0)
    goto done;
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    if (errno == ENOENT) {
      nhrp_info("Peer cache snapshot not found");
      valid = TRUE;
    }
    goto done;
  }
  if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      (status.st_mode & 077) != 0 || status.st_uid != geteuid())
    goto consume;
  file = fdopen(fd, "r");
  if (file == NULL)
    goto consume;
  fd = -1;
  line_length = getline(&line, &line_size, file);
  if (line_length != (ssize_t)strlen(NHRP_PEER_CACHE_HEADER) ||
      memcmp(line, NHRP_PEER_CACHE_HEADER, line_length) != 0) {
    nhrp_error("Unsupported peer cache header; version 2 required to preserve "
               "unique bindings, relearning peers");
    goto consume;
  }
  while ((line_length = getline(&line, &line_size, file)) >= 0) {
    if (line_length <= 0 || line_length >= NHRP_PEER_CACHE_LINE_MAX ||
        line[line_length - 1] != '\n' || strlen(line) != (size_t)line_length ||
        !nhrp_peer_cache_parse_record(line, &record))
      goto consume;
    if (count == capacity) {
      size_t new_capacity = capacity == 0 ? 16 : capacity * 2;
      void *new_records;

      if (new_capacity < capacity || new_capacity > SIZE_MAX / sizeof(*records))
        goto consume;
      new_records = realloc(records, new_capacity * sizeof(*records));
      if (new_records == NULL)
        goto consume;
      records = new_records;
      capacity = new_capacity;
    }
    records[count++] = record;
  }
  if (ferror(file))
    goto consume;
  valid = TRUE;

consume:
  if (file != NULL) {
    fclose(file);
    file = NULL;
  }
  if (fd >= 0) {
    close(fd);
    fd = -1;
  }
  consumed = nhrp_peer_cache_consume(directory, path);
  if (!valid || !consumed)
    goto done;
  wall_now = time(NULL);
  if (wall_now == (time_t)-1) {
    valid = FALSE;
    goto done;
  }
  for (i = 0; i < count; i++)
    restored += nhrp_peer_cache_restore(&records[i], wall_now, TRUE);
  for (i = 0; i < count; i++)
    restored += nhrp_peer_cache_restore(&records[i], wall_now, FALSE);
  nhrp_info("Restored %d of %zu peer cache entries", restored, count);

done:
  if (file != NULL)
    fclose(file);
  else if (fd >= 0)
    close(fd);
  free(line);
  free(records);
  nhrp_ha_managed_state_unlock(lock_fd);
  if (!valid)
    nhrp_error("Peer cache snapshot was invalid and was not restored");
  return valid;
}
