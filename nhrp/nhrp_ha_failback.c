#include "nhrp_ha_failback.h"

#include <string.h>

static uint64_t seconds_to_ms(uint32_t seconds) {
  return (uint64_t)seconds * 1000;
}

static void apply_backoff(struct nhrp_ha_failback_state *state,
                          const struct nhrp_ha_failback_policy *policy,
                          uint64_t now_ms) {
  unsigned int index;

  if (state->backoff_level < 3)
    state->backoff_level++;
  index = state->backoff_level == 0 ? 0 : state->backoff_level - 1;
  state->not_before_ms = now_ms + seconds_to_ms(policy->backoff_seconds[index]);
  state->backoff_reset_at_ms = 0;
}

void nhrp_ha_failback_init(struct nhrp_ha_failback_state *state) {
  memset(state, 0, sizeof(*state));
}

void nhrp_ha_failback_request(struct nhrp_ha_failback_state *state, int force) {
  state->request = force ? 2 : 1;
}

void nhrp_ha_failback_observe_primary(struct nhrp_ha_failback_state *state,
                                      int healthy, uint64_t now_ms) {
  if (!healthy) {
    state->primary_stable_since_ms = 0;
    return;
  }
  if (state->primary_stable_since_ms == 0)
    state->primary_stable_since_ms = now_ms;
}

int nhrp_ha_failback_transfer_ready(
    const struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms,
    int primary_healthy, int synchronized) {
  if (state->transfer_pending || !primary_healthy || !synchronized)
    return 0;
  if (state->request == 2)
    return 1;
  if (state->primary_stable_since_ms == 0 ||
      now_ms - state->primary_stable_since_ms <
          seconds_to_ms(policy->recovery_stable_seconds) ||
      now_ms < state->not_before_ms)
    return 0;
  return 1;
}

int nhrp_ha_failback_transfer_waiting(
    const struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms) {
  return state->transfer_pending && now_ms - state->transfer_pending_since_ms <
                                        policy->transfer_timeout_ms;
}

void nhrp_ha_failback_transfer_sent(struct nhrp_ha_failback_state *state,
                                    uint64_t now_ms) {
  state->request = 0;
  state->transfer_pending = 1;
  state->transfer_pending_since_ms = now_ms;
}

int nhrp_ha_failback_transfer_timed_out(
    struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms) {
  if (!state->transfer_pending ||
      now_ms - state->transfer_pending_since_ms < policy->transfer_timeout_ms)
    return 0;
  state->transfer_pending = 0;
  state->transfer_pending_since_ms = 0;
  apply_backoff(state, policy, now_ms);
  return 1;
}

void nhrp_ha_failback_transfer_ack(struct nhrp_ha_failback_state *state,
                                   const struct nhrp_ha_failback_policy *policy,
                                   uint64_t now_ms) {
  state->transfer_pending = 0;
  state->transfer_pending_since_ms = 0;
  state->probation_until_ms = now_ms + seconds_to_ms(policy->probation_seconds);
  state->backoff_reset_at_ms = 0;
}

int nhrp_ha_failback_backup_elected(
    struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms) {
  int failed_probation =
      state->probation_until_ms != 0 && now_ms < state->probation_until_ms;

  if (failed_probation)
    apply_backoff(state, policy, now_ms);
  state->primary_stable_since_ms = 0;
  state->probation_until_ms = 0;
  state->backoff_reset_at_ms = 0;
  state->transfer_pending = 0;
  state->transfer_pending_since_ms = 0;
  return failed_probation;
}

void nhrp_ha_failback_observe_primary_leader(
    struct nhrp_ha_failback_state *state,
    const struct nhrp_ha_failback_policy *policy, uint64_t now_ms,
    int primary_is_leader, int primary_healthy) {
  if (!primary_is_leader || !primary_healthy) {
    state->backoff_reset_at_ms = 0;
    return;
  }
  if (state->transfer_pending) {
    state->transfer_pending = 0;
    state->transfer_pending_since_ms = 0;
    if (state->probation_until_ms == 0)
      state->probation_until_ms =
          now_ms + seconds_to_ms(policy->probation_seconds);
  }
  if (state->probation_until_ms != 0) {
    if (now_ms < state->probation_until_ms)
      return;
    state->probation_until_ms = 0;
  }
  if (state->backoff_level == 0)
    return;
  if (state->backoff_reset_at_ms == 0) {
    state->backoff_reset_at_ms =
        now_ms + seconds_to_ms(policy->backoff_reset_seconds);
    return;
  }
  if (now_ms >= state->backoff_reset_at_ms) {
    state->backoff_level = 0;
    state->not_before_ms = 0;
    state->backoff_reset_at_ms = 0;
  }
}
