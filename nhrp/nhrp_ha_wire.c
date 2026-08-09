/* nhrp_ha_wire.c - Wire helpers for OpenNHRP HA messages */

#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>

#include "nhrp_ha.h"
#include "nhrp_ha_wire.h"

#define HUB_LIST_HEADER_SIZE 16
#define HUB_LIST_ENTRY_HEADER_SIZE 8
#define HUB_LIST_ADDRESS_TYPE_IPV4 1
#define HA_COMPAT_HEADER_SIZE 8

static const uint8_t ha_compat_header[HA_COMPAT_HEADER_SIZE] = {
    /* Locally administered vendor ID followed by "ONHRP". */
    0xae, 0xde, 0x48, 'O', 'N', 'H', 'R', 'P'};

size_t nhrp_ha_compat_encoded_size(size_t payload_size) {
  return payload_size <= SIZE_MAX - HA_COMPAT_HEADER_SIZE
             ? HA_COMPAT_HEADER_SIZE + payload_size
             : 0;
}

int nhrp_ha_compat_encode(const uint8_t *payload, size_t payload_size,
                          uint8_t *wire, size_t wire_size) {
  size_t encoded_size = nhrp_ha_compat_encoded_size(payload_size);

  if (payload == NULL || wire == NULL || encoded_size == 0 ||
      wire_size < encoded_size)
    return 0;
  memcpy(wire, ha_compat_header, sizeof(ha_compat_header));
  memcpy(wire + sizeof(ha_compat_header), payload, payload_size);
  return 1;
}

int nhrp_ha_compat_parse(const uint8_t *wire, size_t wire_size,
                         const uint8_t **payload, size_t *payload_size) {
  if (wire == NULL || payload == NULL || payload_size == NULL ||
      wire_size <= sizeof(ha_compat_header) ||
      memcmp(wire, ha_compat_header, sizeof(ha_compat_header)) != 0)
    return 0;
  *payload = wire + sizeof(ha_compat_header);
  *payload_size = wire_size - sizeof(ha_compat_header);
  return 1;
}

static int member_valid(const char *member) {
  size_t i;
  size_t length = strnlen(member, 64);

  if (length == 0 || length >= 64)
    return 0;
  for (i = 0; i < length; i++) {
    if (!isalnum((unsigned char)member[i]) && member[i] != '-' &&
        member[i] != '_' && member[i] != '.')
      return 0;
  }
  return 1;
}

static int ipv4_unicast_valid(const uint8_t *address) {
  return address[0] != 0 && address[0] < 224 &&
         memcmp(address, "\xff\xff\xff\xff", 4) != 0;
}

static enum nhrp_ha_hub_list_result
validate_list(const struct nhrp_ha_hub_list *list) {
  size_t i;
  size_t j;
  int source_found = 0;

  if (!member_valid(list->source_member) || list->list_generation == 0 ||
      list->prefix_length > 32)
    return NHRP_HA_HUB_LIST_BAD_HEADER;
  if (list->entry_count == 0 ||
      list->entry_count > NHRP_HA_HUB_LIST_MAX_ENTRIES)
    return NHRP_HA_HUB_LIST_TOO_MANY;

  for (i = 0; i < list->entry_count; i++) {
    if (!member_valid(list->entries[i].member) ||
        list->entries[i].priority > INT_MAX ||
        !ipv4_unicast_valid(list->entries[i].nbma))
      return NHRP_HA_HUB_LIST_BAD_ENTRY;
    if (strcmp(list->entries[i].member, list->source_member) == 0)
      source_found = 1;
    for (j = 0; j < i; j++) {
      if (memcmp(list->entries[i].nbma, list->entries[j].nbma,
                 NHRP_HA_HUB_LIST_NBMA_LEN) == 0)
        return NHRP_HA_HUB_LIST_DUPLICATE;
    }
  }
  return source_found ? NHRP_HA_HUB_LIST_OK : NHRP_HA_HUB_LIST_SOURCE_MISSING;
}

size_t nhrp_ha_hub_list_encoded_size(const struct nhrp_ha_hub_list *list) {
  size_t i;
  size_t size = HUB_LIST_HEADER_SIZE + strlen(list->source_member);

  if (validate_list(list) != NHRP_HA_HUB_LIST_OK)
    return 0;
  for (i = 0; i < list->entry_count; i++)
    size += HUB_LIST_ENTRY_HEADER_SIZE + strlen(list->entries[i].member) +
            NHRP_HA_HUB_LIST_NBMA_LEN;
  return size;
}

enum nhrp_ha_hub_list_result
nhrp_ha_hub_list_encode(const struct nhrp_ha_hub_list *list, uint8_t *wire,
                        size_t wire_size) {
  enum nhrp_ha_hub_list_result result = validate_list(list);
  uint16_t wire16;
  uint32_t wire32;
  size_t source_length;
  size_t member_length;
  size_t offset;
  size_t i;

  if (result != NHRP_HA_HUB_LIST_OK)
    return result;
  if (wire_size < nhrp_ha_hub_list_encoded_size(list))
    return NHRP_HA_HUB_LIST_TRUNCATED;

  source_length = strlen(list->source_member);
  wire[0] = NHRP_HA_WIRE_VERSION;
  wire[1] = NHRP_HA_HUB_LIST;
  wire16 = htons(source_length);
  memcpy(&wire[2], &wire16, sizeof(wire16));
  wire32 = htonl(list->request_generation);
  memcpy(&wire[4], &wire32, sizeof(wire32));
  wire32 = htonl(list->list_generation);
  memcpy(&wire[8], &wire32, sizeof(wire32));
  wire16 = htons(list->entry_count);
  memcpy(&wire[12], &wire16, sizeof(wire16));
  wire[14] = list->prefix_length;
  wire[15] = 0;
  memcpy(&wire[HUB_LIST_HEADER_SIZE], list->source_member, source_length);
  offset = HUB_LIST_HEADER_SIZE + source_length;

  for (i = 0; i < list->entry_count; i++) {
    member_length = strlen(list->entries[i].member);
    wire[offset] = member_length;
    wire[offset + 1] = NHRP_HA_HUB_LIST_NBMA_LEN;
    wire[offset + 2] = HUB_LIST_ADDRESS_TYPE_IPV4;
    wire[offset + 3] = 0;
    wire32 = htonl(list->entries[i].priority);
    memcpy(&wire[offset + 4], &wire32, sizeof(wire32));
    offset += HUB_LIST_ENTRY_HEADER_SIZE;
    memcpy(&wire[offset], list->entries[i].member, member_length);
    offset += member_length;
    memcpy(&wire[offset], list->entries[i].nbma, NHRP_HA_HUB_LIST_NBMA_LEN);
    offset += NHRP_HA_HUB_LIST_NBMA_LEN;
  }
  return NHRP_HA_HUB_LIST_OK;
}

enum nhrp_ha_hub_list_result
nhrp_ha_hub_list_parse(const uint8_t *wire, size_t wire_size,
                       struct nhrp_ha_hub_list *list) {
  uint16_t wire16;
  uint32_t wire32;
  size_t source_length;
  size_t member_length;
  size_t offset;
  size_t i;

  memset(list, 0, sizeof(*list));
  if (wire_size < HUB_LIST_HEADER_SIZE)
    return NHRP_HA_HUB_LIST_TRUNCATED;
  if (wire[0] != NHRP_HA_WIRE_VERSION || wire[1] != NHRP_HA_HUB_LIST ||
      wire[15] != 0)
    return NHRP_HA_HUB_LIST_BAD_HEADER;

  memcpy(&wire16, &wire[2], sizeof(wire16));
  source_length = ntohs(wire16);
  memcpy(&wire32, &wire[4], sizeof(wire32));
  list->request_generation = ntohl(wire32);
  memcpy(&wire32, &wire[8], sizeof(wire32));
  list->list_generation = ntohl(wire32);
  memcpy(&wire16, &wire[12], sizeof(wire16));
  list->entry_count = ntohs(wire16);
  list->prefix_length = wire[14];

  if (source_length == 0 || source_length >= sizeof(list->source_member) ||
      source_length > wire_size - HUB_LIST_HEADER_SIZE)
    return NHRP_HA_HUB_LIST_BAD_HEADER;
  if (list->entry_count == 0 ||
      list->entry_count > NHRP_HA_HUB_LIST_MAX_ENTRIES)
    return NHRP_HA_HUB_LIST_TOO_MANY;
  memcpy(list->source_member, &wire[HUB_LIST_HEADER_SIZE], source_length);
  list->source_member[source_length] = 0;
  offset = HUB_LIST_HEADER_SIZE + source_length;

  for (i = 0; i < list->entry_count; i++) {
    if (wire_size - offset < HUB_LIST_ENTRY_HEADER_SIZE)
      return NHRP_HA_HUB_LIST_TRUNCATED;
    member_length = wire[offset];
    if (member_length == 0 ||
        member_length >= sizeof(list->entries[i].member) ||
        wire[offset + 1] != NHRP_HA_HUB_LIST_NBMA_LEN ||
        wire[offset + 2] != HUB_LIST_ADDRESS_TYPE_IPV4 || wire[offset + 3] != 0)
      return NHRP_HA_HUB_LIST_BAD_ENTRY;
    memcpy(&wire32, &wire[offset + 4], sizeof(wire32));
    list->entries[i].priority = ntohl(wire32);
    offset += HUB_LIST_ENTRY_HEADER_SIZE;
    if (member_length + NHRP_HA_HUB_LIST_NBMA_LEN > wire_size - offset)
      return NHRP_HA_HUB_LIST_TRUNCATED;
    memcpy(list->entries[i].member, &wire[offset], member_length);
    list->entries[i].member[member_length] = 0;
    offset += member_length;
    memcpy(list->entries[i].nbma, &wire[offset], NHRP_HA_HUB_LIST_NBMA_LEN);
    offset += NHRP_HA_HUB_LIST_NBMA_LEN;
  }
  if (offset != wire_size)
    return NHRP_HA_HUB_LIST_BAD_ENTRY;
  return validate_list(list);
}
