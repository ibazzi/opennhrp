/* nhrp_extension.h - NHRP extension validation helpers */

#ifndef NHRP_EXTENSION_H
#define NHRP_EXTENSION_H

#include <stddef.h>
#include <stdint.h>

enum nhrp_extension_wire_result {
  NHRP_EXTENSION_WIRE_OK = 0,
  NHRP_EXTENSION_WIRE_TRUNCATED,
  NHRP_EXTENSION_WIRE_TOO_MANY,
  NHRP_EXTENSION_WIRE_DUPLICATE,
  NHRP_EXTENSION_WIRE_BAD_END,
};

enum nhrp_extension_wire_result
nhrp_extension_wire_validate(const uint8_t *wire, size_t wire_len,
                             unsigned int max_extensions);

#endif
