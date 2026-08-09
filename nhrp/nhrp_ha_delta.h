/* nhrp_ha_delta.h - Registration snapshot delta codec */

#ifndef NHRP_HA_DELTA_H
#define NHRP_HA_DELTA_H

#include <stddef.h>
#include <stdint.h>

int nhrp_ha_delta_build(const uint8_t *old_snapshot, size_t old_length,
                        const uint8_t *new_snapshot, size_t new_length,
                        uint8_t **delta, size_t *delta_length);
int nhrp_ha_delta_apply(const uint8_t *old_snapshot, size_t old_length,
                        const uint8_t *delta, size_t delta_length,
                        uint8_t **new_snapshot, size_t *new_length);

#endif
