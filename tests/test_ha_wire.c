#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nhrp_ha_wire.h"

static struct nhrp_ha_hub_list sample_list(void) {
  struct nhrp_ha_hub_list list;

  memset(&list, 0, sizeof(list));
  strcpy(list.source_member, "hub-primary");
  list.request_generation = 7;
  list.list_generation = 42;
  list.prefix_length = 24;
  list.entry_count = 2;
  strcpy(list.entries[0].member, "hub-primary");
  memcpy(list.entries[0].nbma, "\xc0\x00\x02\x0b", 4);
  list.entries[0].priority = 100;
  strcpy(list.entries[1].member, "hub-backup1");
  memcpy(list.entries[1].nbma, "\xc0\x00\x02\x0c", 4);
  list.entries[1].priority = 90;
  return list;
}

int main(void) {
  struct nhrp_ha_hub_list input = sample_list();
  struct nhrp_ha_hub_list output;
  struct nhrp_ha_hub_list duplicate_nbma;
  uint8_t wire[4096];
  uint8_t compat[4104];
  const uint8_t *payload;
  size_t payload_size;
  size_t length = nhrp_ha_hub_list_encoded_size(&input);

  assert(length > 0);
  assert(nhrp_ha_hub_list_encode(&input, wire, length) == NHRP_HA_HUB_LIST_OK);
  assert(nhrp_ha_hub_list_parse(wire, length, &output) == NHRP_HA_HUB_LIST_OK);
  assert(strcmp(output.source_member, "hub-primary") == 0);
  assert(output.request_generation == 7);
  assert(output.list_generation == 42);
  assert(output.prefix_length == 24);
  assert(output.entry_count == 2);
  assert(strcmp(output.entries[1].member, "hub-backup1") == 0);
  assert(output.entries[1].priority == 90);

  input = sample_list();
  strcpy(input.entries[1].member, "hub-primary");
  input.entries[1].priority = 100;
  length = nhrp_ha_hub_list_encoded_size(&input);
  assert(length > 0);
  assert(nhrp_ha_hub_list_encode(&input, wire, length) == NHRP_HA_HUB_LIST_OK);
  assert(nhrp_ha_hub_list_parse(wire, length, &output) == NHRP_HA_HUB_LIST_OK);
  assert(strcmp(output.entries[0].member, output.entries[1].member) == 0);

  input = sample_list();
  length = nhrp_ha_hub_list_encoded_size(&input);
  assert(nhrp_ha_hub_list_encode(&input, wire, length) == NHRP_HA_HUB_LIST_OK);

  assert(nhrp_ha_hub_list_parse(wire, length - 1, &output) ==
         NHRP_HA_HUB_LIST_TRUNCATED);
  wire[length] = 0;
  assert(nhrp_ha_hub_list_parse(wire, length + 1, &output) ==
         NHRP_HA_HUB_LIST_BAD_ENTRY);
  wire[15] = 1;
  assert(nhrp_ha_hub_list_parse(wire, length, &output) ==
         NHRP_HA_HUB_LIST_BAD_HEADER);
  wire[15] = 0;

  input.entries[1] = input.entries[0];
  assert(nhrp_ha_hub_list_encoded_size(&input) == 0);
  assert(nhrp_ha_hub_list_encode(&input, wire, sizeof(wire)) ==
         NHRP_HA_HUB_LIST_DUPLICATE);

  duplicate_nbma = sample_list();
  memcpy(duplicate_nbma.entries[1].nbma, duplicate_nbma.entries[0].nbma, 4);
  assert(nhrp_ha_hub_list_encode(&duplicate_nbma, wire, sizeof(wire)) ==
         NHRP_HA_HUB_LIST_DUPLICATE);

  input = sample_list();
  strcpy(input.source_member, "hub-missing");
  assert(nhrp_ha_hub_list_encode(&input, wire, sizeof(wire)) ==
         NHRP_HA_HUB_LIST_SOURCE_MISSING);

  input = sample_list();
  input.entry_count = NHRP_HA_HUB_LIST_MAX_ENTRIES + 1;
  assert(nhrp_ha_hub_list_encode(&input, wire, sizeof(wire)) ==
         NHRP_HA_HUB_LIST_TOO_MANY);

  input = sample_list();
  input.list_generation = 0;
  assert(nhrp_ha_hub_list_encode(&input, wire, sizeof(wire)) ==
         NHRP_HA_HUB_LIST_BAD_HEADER);

  input = sample_list();
  strcpy(input.entries[1].member, "bad/member");
  assert(nhrp_ha_hub_list_encode(&input, wire, sizeof(wire)) ==
         NHRP_HA_HUB_LIST_BAD_ENTRY);

  input = sample_list();
  memset(input.entries[1].nbma, 0, 4);
  assert(nhrp_ha_hub_list_encode(&input, wire, sizeof(wire)) ==
         NHRP_HA_HUB_LIST_BAD_ENTRY);

  input = sample_list();
  length = nhrp_ha_hub_list_encoded_size(&input);
  assert(nhrp_ha_hub_list_encode(&input, wire, length) == NHRP_HA_HUB_LIST_OK);
  assert(nhrp_ha_compat_encoded_size(length) == length + 8);
  assert(nhrp_ha_compat_encode(wire, length, compat, sizeof(compat)));
  assert(nhrp_ha_compat_parse(compat, length + 8, &payload, &payload_size));
  assert(payload_size == length && memcmp(payload, wire, length) == 0);
  compat[0] ^= 1;
  assert(!nhrp_ha_compat_parse(compat, length + 8, &payload, &payload_size));

  puts("HA Hub List wire tests passed");
  return 0;
}
