#include "../nhrp/nhrp_ha_failback.h"

#include <assert.h>
#include <stdio.h>

static struct nhrp_ha_failback_policy policy(void) {
  return (struct nhrp_ha_failback_policy){
      .recovery_stable_seconds = 120,
      .probation_seconds = 120,
      .backoff_seconds = {300, 900, 1800},
      .backoff_reset_seconds = 1800,
      .transfer_timeout_ms = 5000,
  };
}

static void test_automatic_transfer(void) {
  struct nhrp_ha_failback_policy p = policy();
  struct nhrp_ha_failback_state state;

  nhrp_ha_failback_init(&state);
  nhrp_ha_failback_observe_primary(&state, 1, 1000);
  assert(!nhrp_ha_failback_transfer_ready(&state, &p, 120999, 1, 0));
  assert(state.primary_stable_since_ms == 1000);
  assert(!nhrp_ha_failback_transfer_ready(&state, &p, 121000, 1, 0));
  assert(nhrp_ha_failback_transfer_ready(&state, &p, 121000, 1, 1));

  nhrp_ha_failback_transfer_sent(&state, 121000);
  assert(state.transfer_pending);
  nhrp_ha_failback_observe_primary(&state, 0, 121100);
  assert(state.transfer_pending);
  assert(nhrp_ha_failback_transfer_waiting(&state, &p, 125999));
  assert(!nhrp_ha_failback_transfer_waiting(&state, &p, 126000));
  assert(!nhrp_ha_failback_transfer_ready(&state, &p, 121100, 1, 1));
  assert(!nhrp_ha_failback_transfer_timed_out(&state, &p, 125999));
  assert(nhrp_ha_failback_transfer_timed_out(&state, &p, 126000));
  assert(!state.transfer_pending && state.backoff_level == 1);
  assert(state.not_before_ms == 426000);
}

static void test_health_and_force(void) {
  struct nhrp_ha_failback_policy p = policy();
  struct nhrp_ha_failback_state state;

  nhrp_ha_failback_init(&state);
  nhrp_ha_failback_observe_primary(&state, 1, 1000);
  nhrp_ha_failback_observe_primary(&state, 0, 2000);
  assert(state.primary_stable_since_ms == 0);

  nhrp_ha_failback_request(&state, 0);
  nhrp_ha_failback_observe_primary(&state, 1, 3000);
  assert(!nhrp_ha_failback_transfer_ready(&state, &p, 4000, 1, 1));
  assert(state.request == 1);
  nhrp_ha_failback_request(&state, 1);
  assert(state.request == 2);
  assert(!nhrp_ha_failback_transfer_ready(&state, &p, 4000, 0, 1));
  assert(!nhrp_ha_failback_transfer_ready(&state, &p, 4000, 1, 0));
  assert(nhrp_ha_failback_transfer_ready(&state, &p, 4000, 1, 1));
}

static void test_probation_and_backoff(void) {
  struct nhrp_ha_failback_policy p = policy();
  struct nhrp_ha_failback_state state;

  nhrp_ha_failback_init(&state);
  nhrp_ha_failback_transfer_ack(&state, &p, 1000);
  assert(state.probation_until_ms == 121000);
  assert(nhrp_ha_failback_backup_elected(&state, &p, 120000));
  assert(state.backoff_level == 1 && state.not_before_ms == 420000);

  nhrp_ha_failback_transfer_ack(&state, &p, 500000);
  assert(nhrp_ha_failback_backup_elected(&state, &p, 501000));
  assert(state.backoff_level == 2 && state.not_before_ms == 1401000);

  nhrp_ha_failback_transfer_ack(&state, &p, 1500000);
  assert(nhrp_ha_failback_backup_elected(&state, &p, 1501000));
  assert(state.backoff_level == 3 && state.not_before_ms == 3301000);

  nhrp_ha_failback_transfer_ack(&state, &p, 3400000);
  nhrp_ha_failback_observe_primary_leader(&state, &p, 3520000, 1, 1);
  assert(state.probation_until_ms == 0);
  assert(state.backoff_reset_at_ms == 5320000);
  nhrp_ha_failback_observe_primary_leader(&state, &p, 5319999, 1, 1);
  assert(state.backoff_level == 3);
  nhrp_ha_failback_observe_primary_leader(&state, &p, 5320000, 1, 1);
  assert(state.backoff_level == 0 && state.not_before_ms == 0);
}

int main(void) {
  test_automatic_transfer();
  test_health_and_force();
  test_probation_and_backoff();
  puts("HA automatic failback state tests passed");
  return 0;
}
