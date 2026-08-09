/* nhrp_ha_store.c - Authenticated atomic HA snapshot storage */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nhrp_ha_control.h"
#include "nhrp_ha_store.h"

static void state_keys(const struct nhrp_ha_auth_keys *keys,
                       struct nhrp_ha_auth_keys *derived) {
  size_t i;

  *derived = *keys;
  for (i = 0; i < NHRP_HA_AUTH_MAX_KEYS; i++)
    if (derived->key[i].present)
      memcpy(derived->key[i].control_key, derived->key[i].state_key,
             NHRP_HA_AUTH_KEY_SIZE);
}

static int read_all(int fd, void *data, size_t length) {
  uint8_t *position = data;

  while (length != 0) {
    ssize_t got = read(fd, position, length);

    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return 0;
    position += got;
    length -= got;
  }
  return 1;
}

void nhrp_ha_store_record_clear(struct nhrp_ha_store_record *record) {
  if (record->payload != NULL) {
    OPENSSL_cleanse(record->payload, record->payload_length);
    free(record->payload);
  }
  OPENSSL_cleanse(record, sizeof(*record));
}

int nhrp_ha_store_load(const char *path, const struct nhrp_ha_auth_keys *keys,
                       const uint8_t cluster_id[16],
                       struct nhrp_ha_store_record *record) {
  struct nhrp_ha_auth_keys derived;
  struct nhrp_ha_control_frame frame;
  struct stat status;
  uint8_t key_id[8];
  uint8_t length_wire[4];
  uint8_t trailing;
  uint8_t *wire = NULL;
  uint32_t body_length;
  size_t wire_size;
  int fd;
  int ok = 0;

  memset(record, 0, sizeof(*record));
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return errno == ENOENT ? 1 : 0;
  if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      (status.st_mode & 077) != 0 || status.st_uid != geteuid() ||
      !read_all(fd, length_wire, sizeof(length_wire)))
    goto done;
  memcpy(&body_length, length_wire, sizeof(body_length));
  wire_size = (size_t)ntohl(body_length) + 4;
  if (wire_size < 4 || wire_size > NHRP_HA_CONTROL_MAX_FRAME)
    goto done;
  wire = malloc(wire_size);
  if (wire == NULL)
    goto done;
  memcpy(wire, length_wire, 4);
  if (!read_all(fd, wire + 4, wire_size - 4) || read(fd, &trailing, 1) != 0)
    goto done;
  state_keys(keys, &derived);
  if (nhrp_ha_control_decode(&derived, wire, wire_size, &frame, key_id) !=
          NHRP_HA_CONTROL_OK ||
      frame.type != NHRP_HA_CONTROL_SNAPSHOT ||
      CRYPTO_memcmp(frame.cluster_id, cluster_id, 16) != 0)
    goto clear_keys;
  record->payload = malloc(frame.payload_length + 1);
  if (record->payload == NULL)
    goto clear_keys;
  memcpy(record->cluster_id, frame.cluster_id, 16);
  record->term = frame.term;
  record->index = frame.index;
  snprintf(record->leader, sizeof(record->leader), "%s", frame.sender);
  memcpy(record->payload, frame.payload, frame.payload_length);
  record->payload[frame.payload_length] = 0;
  record->payload_length = frame.payload_length;
  memcpy(record->key_id, key_id, 8);
  ok = 1;

clear_keys:
  nhrp_ha_auth_keys_clear(&derived);
done:
  if (!ok)
    nhrp_ha_store_record_clear(record);
  if (wire != NULL) {
    OPENSSL_cleanse(wire, wire_size);
    free(wire);
  }
  close(fd);
  return ok;
}

int nhrp_ha_store_save(const char *path, const struct nhrp_ha_auth_keys *keys,
                       const struct nhrp_ha_store_record *record) {
  struct nhrp_ha_auth_keys derived;
  struct nhrp_ha_control_frame frame;
  uint8_t *wire = NULL;
  size_t wire_size;
  int ok = 0;

  if (path[0] == 0 || record->term == 0 || record->leader[0] == 0 ||
      (record->payload_length != 0 && record->payload == NULL))
    return 0;
  memset(&frame, 0, sizeof(frame));
  frame.type = NHRP_HA_CONTROL_SNAPSHOT;
  memcpy(frame.cluster_id, record->cluster_id, 16);
  frame.term = record->term;
  frame.index = record->index;
  snprintf(frame.sender, sizeof(frame.sender), "%s", record->leader);
  frame.payload = record->payload;
  frame.payload_length = record->payload_length;
  state_keys(keys, &derived);
  wire_size = nhrp_ha_control_encoded_size(&derived, &frame);
  wire = malloc(wire_size);
  if (wire_size == 0 || wire == NULL ||
      nhrp_ha_control_encode(&derived, &frame, wire, wire_size) !=
          NHRP_HA_CONTROL_OK)
    goto done;
  ok = nhrp_ha_secure_file_write(path, wire, wire_size);

done:
  if (wire != NULL) {
    OPENSSL_cleanse(wire, wire_size);
    free(wire);
  }
  nhrp_ha_auth_keys_clear(&derived);
  return ok;
}
