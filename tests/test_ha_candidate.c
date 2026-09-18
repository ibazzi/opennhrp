/* Exercise production probe miss accounting without network side effects. */
#include "../nhrp/ha/nhrp_ha.c"
#include <assert.h>

int nhrp_running, nhrp_verbose;
void nhrp_log(int level, const char *format, ...) {}
void admin_ha_notify(struct nhrp_interface *iface) {}
struct nhrp_interface *nhrp_interface_get_by_name(const char *name,
                                                  int create) {
  return NULL;
}

int main(void) {
  struct nhrp_interface iface = {0};
  struct nhrp_ha_service service = {.interface = &iface};
  struct nhrp_ha_candidate candidate = {.service = &service,
                                        .endpoint_count = 1,
                                        .registered = TRUE,
                                        .serviceable = TRUE,
                                        .state = NHRP_HA_CANDIDATE_READY,
                                        .rto = 0.25,
                                        .endpoint_ready = {TRUE},
                                        .registration_generation = 7,
                                        .registration_request_id = 42,
                                        .last_registration_reply = 10.0};
  struct nhrp_ha_auth_profile profile = {.interface = &iface,
                                         .auth_required = 1};
  unsigned int i;
  char output[4096];

  ev_default_loop(0);
  service.active = &candidate;
  list_init(&service.candidates);
  list_add(&candidate.list_entry, &service.candidates);
  list_add(&service.list_entry, &services);
  assert(candidate_quality_eligible(&candidate));
  for (i = 0; i < 3; i++) {
    candidate.probe_pending = TRUE;
    candidate_probe_missed(&candidate);
    assert(!candidate.probe_pending);
    assert(candidate.registered && candidate.registration_generation == 7);
    assert(candidate.registration_request_id == 42);
    assert(candidate.last_registration_reply == 10.0);
    assert(!service.switching && service.switch_target == NULL);
    assert(!ev_is_active(&candidate.registration_timer));
  }
  assert(candidate.state == NHRP_HA_CANDIDATE_SUSPECT);
  assert(!candidate.endpoint_ready[0]);
  assert(!candidate_quality_eligible(&candidate));

  /* A fresh response must also say serviceable, even after a renewal. */
  candidate.endpoint_ready[0] = TRUE;
  candidate.serviceable = FALSE;
  candidate.state = NHRP_HA_CANDIDATE_READY;
  assert(!candidate_quality_eligible(&candidate));
  nhrp_ha_render(output, sizeof(output), NULL, TRUE);
  assert(strstr(output, "\"registered\":true,\"ready\":false"));
  assert(strstr(output, "\"score\":0"));
  nhrp_ha_render(output, sizeof(output), NULL, FALSE);
  assert(strstr(output, "score 0\n"));
  candidate_probe_missed(&candidate);
  assert(!candidate_quality_eligible(&candidate));
  candidate.endpoint_ready[0] = TRUE;
  candidate.serviceable = TRUE;
  candidate.consecutive_misses = 0;
  candidate.state = NHRP_HA_CANDIDATE_READY;
  assert(candidate_quality_eligible(&candidate));

  list_add(&profile.list_entry, &auth_profiles);
  assert(!candidate_quality_eligible(&candidate));
  candidate.auth_valid = TRUE;
  assert(candidate_quality_eligible(&candidate));
  list_del(&profile.list_entry);

  /* Three misses do not override a still-fresh successful probe. */
  candidate.last_probe_reply = ev_now();
  for (i = 0; i < 3; i++)
    candidate_probe_missed(&candidate);
  assert(candidate.endpoint_ready[0]);
  assert(candidate.registered && !service.switching);
  puts("HA candidate probe accounting and score eligibility tests passed");
  ev_default_destroy();
  return 0;
}
