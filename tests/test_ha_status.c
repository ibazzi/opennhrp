/* Keep the shared Witness JSON byte-compatible with both admin responses. */
#include "../nhrp/ha/nhrp_ha_coordinator.c"
#include <assert.h>

int main(void) {
  struct managed_runtime runtime = {0};
  char response[1024], expected[1024];
  const char *witness =
      "{\"capable\":true,\"mode\":\"active\",\"policy\":\"manager-witness\","
      "\"voters\":3,\"required\":2,\"votes\":2,"
      "\"epoch\":\"000102030405060708090a0b0c0d0e0f\","
      "\"peer_vote\":false,\"manager_vote\":true,\"quorum_available\":true,"
      "\"lease_holder\":\"hub-primary\",\"lease_term\":7,\"lease_sequence\":9,"
      "\"lease_remaining_ms\":1500,\"fallback_remaining_ms\":29000,"
      "\"digest\":\"0123456789abcdef\"}";
  size_t used = 0, i;
  uint64_t now = 10000;

  runtime.state.member_count = 2;
  runtime.state.members[0].state = NHRP_HA_MANAGED_ACTIVE;
  runtime.state.members[1].state = NHRP_HA_MANAGED_ACTIVE;
  strcpy(runtime.state.local_member, "hub-primary");
  strcpy(runtime.state.members[0].member, "hub-primary");
  strcpy(runtime.state.leader, "hub-primary");
  runtime.state.term = 7;
  runtime.state.witness_mode = NHRP_HA_WITNESS_ACTIVE;
  for (i = 0; i < sizeof(runtime.witness_epoch); i++)
    runtime.witness_epoch[i] = i;
  strcpy(runtime.witness_lease_holder, "hub-primary");
  runtime.witness_lease_term = 7;
  runtime.witness_lease_sequence = 9;
  runtime.witness_lease_deadline_ms = now + 1500;
  runtime.witness_fallback_since_ms = now - 1000;
  strcpy(runtime.local_digest, "0123456789abcdef");

  response_append(response, sizeof(response), &used, "Status: ok\n\n");
  render_witness(&runtime, response, sizeof(response), &used, now, 0, 1, 1);
  response_append(response, sizeof(response), &used, "\n");
  snprintf(expected, sizeof(expected), "Status: ok\n\n%s\n", witness);
  assert(strcmp(response, expected) == 0 && used == strlen(expected));

  used = 0;
  response_append(response, sizeof(response), &used, "{\"witness\":");
  render_witness(&runtime, response, sizeof(response), &used, now, 0, 1, 1);
  response_append(response, sizeof(response), &used, ",\"members\":[]}\n");
  snprintf(expected, sizeof(expected), "{\"witness\":%s,\"members\":[]}\n",
           witness);
  assert(strcmp(response, expected) == 0 && used == strlen(expected));

  used = 0;
  render_witness(&runtime, response, 8, &used, now, 0, 1, 1);
  assert(used == 8 && strcmp(response, "{\"capab") == 0);
  puts("HA Witness status formatting tests passed");
  return 0;
}
