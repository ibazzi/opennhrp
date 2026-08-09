/* nhrp_extension.c - NHRP extension validation helpers */

#include <arpa/inet.h>
#include <string.h>

#include "nhrp_extension.h"
#include "nhrp_protocol.h"

enum nhrp_extension_wire_result
nhrp_extension_wire_validate(const uint8_t *wire, size_t wire_len,
                             unsigned int max_extensions) {
  uint16_t seen[256];
  unsigned int count = 0;

  if (max_extensions > sizeof(seen) / sizeof(seen[0]))
    max_extensions = sizeof(seen) / sizeof(seen[0]);

  while (wire_len >= sizeof(struct nhrp_extension_header)) {
    struct nhrp_extension_header header;
    uint16_t type;
    uint16_t length;
    unsigned int i;

    memcpy(&header, wire, sizeof(header));
    wire += sizeof(header);
    wire_len -= sizeof(header);
    type = ntohs(header.type) & ~NHRP_EXTENSION_FLAG_COMPULSORY;
    length = ntohs(header.length);

    if (type == NHRP_EXTENSION_END)
      return length == 0 ? NHRP_EXTENSION_WIRE_OK : NHRP_EXTENSION_WIRE_BAD_END;
    if (length > wire_len)
      return NHRP_EXTENSION_WIRE_TRUNCATED;
    if (count >= max_extensions)
      return NHRP_EXTENSION_WIRE_TOO_MANY;
    for (i = 0; i < count; i++) {
      if (seen[i] == type)
        return NHRP_EXTENSION_WIRE_DUPLICATE;
    }
    seen[count++] = type;
    wire += length;
    wire_len -= length;
  }

  return NHRP_EXTENSION_WIRE_TRUNCATED;
}
