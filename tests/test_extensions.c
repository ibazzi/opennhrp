#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nhrp_extension.h"
#include "nhrp_protocol.h"

static size_t add_extension(uint8_t *wire, size_t offset, uint16_t type,
                            uint16_t length) {
  struct nhrp_extension_header header = {
      .type = htons(type),
      .length = htons(length),
  };

  memcpy(wire + offset, &header, sizeof(header));
  memset(wire + offset + sizeof(header), 0xa5, length);
  return offset + sizeof(header) + length;
}

int main(void) {
  uint8_t wire[512];
  size_t length;
  unsigned int i;

  length = add_extension(wire, 0, 0x3801, 8);
  length = add_extension(
      wire, length, NHRP_EXTENSION_END | NHRP_EXTENSION_FLAG_COMPULSORY, 0);
  assert(nhrp_extension_wire_validate(wire, length, 16) ==
         NHRP_EXTENSION_WIRE_OK);

  length = add_extension(wire, 0, 0x3801, 1);
  length = add_extension(wire, length, 0xb801, 1);
  length = add_extension(wire, length, NHRP_EXTENSION_END, 0);
  assert(nhrp_extension_wire_validate(wire, length, 16) ==
         NHRP_EXTENSION_WIRE_DUPLICATE);

  length = 0;
  for (i = 0; i < 17; i++)
    length = add_extension(wire, length, 0x100 + i, 0);
  length = add_extension(wire, length, NHRP_EXTENSION_END, 0);
  assert(nhrp_extension_wire_validate(wire, length, 16) ==
         NHRP_EXTENSION_WIRE_TOO_MANY);

  length = add_extension(wire, 0, 0x3801, 16);
  assert(nhrp_extension_wire_validate(wire, length - 4, 16) ==
         NHRP_EXTENSION_WIRE_TRUNCATED);

  length = add_extension(wire, 0, NHRP_EXTENSION_END, 1);
  assert(nhrp_extension_wire_validate(wire, length, 16) ==
         NHRP_EXTENSION_WIRE_BAD_END);

  puts("extension validation tests passed");
  return 0;
}
