#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nhrp_ha_delta.h"

int main(void) {
  static const uint8_t before[] =
      "entry 10.20.0.2 32 192.0.2.2 - 1400 300 64 1 1 direct\n"
      "entry 10.20.0.3 32 192.0.2.3 - 1400 300 64 1 2 direct\n";
  static const uint8_t after[] =
      "entry 10.20.0.2 32 192.0.2.22 - 1400 300 64 1 3 direct\n"
      "entry 10.20.0.4 32 192.0.2.4 - 1400 300 64 1 4 direct\n";
  uint8_t *delta;
  uint8_t *rebuilt;
  size_t delta_length;
  size_t rebuilt_length;

  assert(nhrp_ha_delta_build(before, sizeof(before) - 1, after,
                             sizeof(after) - 1, &delta, &delta_length));
  assert(delta_length > 0);
  assert(strstr((char *)delta, "-10.20.0.3/32\n") != NULL);
  assert(strstr((char *)delta, "+entry 10.20.0.4 32") != NULL);
  assert(nhrp_ha_delta_apply(before, sizeof(before) - 1, delta, delta_length,
                             &rebuilt, &rebuilt_length));
  assert(rebuilt_length == sizeof(after) - 1);
  assert(memcmp(rebuilt, after, rebuilt_length) == 0);
  free(rebuilt);
  delta[0] = '!';
  assert(!nhrp_ha_delta_apply(before, sizeof(before) - 1, delta, delta_length,
                              &rebuilt, &rebuilt_length));
  free(delta);
  puts("HA registration delta tests passed");
  return 0;
}
