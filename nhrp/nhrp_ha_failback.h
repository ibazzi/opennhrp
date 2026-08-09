#ifndef NHRP_HA_FAILBACK_H
#define NHRP_HA_FAILBACK_H

#include <stdint.h>

struct nhrp_ha_failback_policy {
  uint32_t recovery_stable_seconds;
  uint32_t probation_seconds;
  uint32_t backoff_seconds[3];
  uint32_t backoff_reset_seconds;
  uint32_t transfer_timeout_ms;
};

struct nhrp_ha_failback_state {
  uint64_t primary_stable_since_ms;
  uint64_t probation_until_ms;
  uint64_t not_before_ms;
  uint64_t backoff_reset_at_ms;
  uint64_t transfer_pending_since_ms;
  unsigned int backoff_level;
  int request;
  int transfer_pending;
};

void nhrp_ha_failback_init(struct nhrp_ha_failback_state *state);
void nhrp_ha_failback_request(struct nhrp_ha_failback_state *state, int force);
void nhrp_ha_failback_observe_primary(struct nhrp_ha_failback_state *state,
                                      int healthy, uint64_t now_ms);
int nhrp_ha_failback_transfer_ready(
    const struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms,
    int primary_healthy, int synchronized);
int nhrp_ha_failback_transfer_waiting(
    const struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms);
void nhrp_ha_failback_transfer_sent(struct nhrp_ha_failback_state *state,
                                    uint64_t now_ms);
int nhrp_ha_failback_transfer_timed_out(
    struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms);
void nhrp_ha_failback_transfer_ack(struct nhrp_ha_failback_state *state,
                                   const struct nhrp_ha_failback_policy *policy,
                                   uint64_t now_ms);
int nhrp_ha_failback_backup_elected(
    struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms);
void nhrp_ha_failback_observe_primary_leader(
    struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms,
    int primary_is_leader, int primary_healthy);

#endif
