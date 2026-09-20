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

static void test_quality_window(void) {
  struct nhrp_ha_quality quality = {0};
  struct nhrp_ha_quality active = {0}, standby = {0};
  struct nhrp_ha_quality invalid;
  unsigned int i;

  for (i = 0; i < 60; i++)
    quality_record(&quality, 100.0 + i * 0.5, i == 20, 0.01);
  assert(quality.samples == 60 && quality.failures == 1);
  quality_expire(&quality, 129.999);
  assert(quality.samples == 60);
  quality_expire(&quality, 130.0);
  assert(quality.samples == 58 && quality.failures == 1);
  quality_expire(&quality, 140.0);
  assert(quality.samples == 38 && quality.failures == 0);
  quality_expire(&quality, 159.0);
  assert(quality.samples == 0);
  quality_record(&quality, 160.0, FALSE, 0.08);
  assert(quality.rtt == 0.08 && quality.samples == 1);
  for (i = 1; i <= 30; i++)
    quality_record(&quality, 160.0 + i, TRUE, 0.0);
  assert(quality.samples == 30 && quality.failures == 30);

  invalid = quality;
  quality_record(&quality, 191.0, FALSE, NAN);
  quality_record(&quality, 191.0, FALSE, INFINITY);
  quality_record(&quality, 191.0, FALSE, -1.0);
  quality_record(&quality, NAN, FALSE, 0.01);
  assert(memcmp(&quality, &invalid, sizeof(quality)) == 0);

  quality_record(&active, 100.0, FALSE, 0.01);
  quality_record(&standby, 100.0, FALSE, 0.01);
  for (i = 1; i <= 53; i++)
    quality_record(&active, 100.0 + i * 0.15, FALSE, 0.08);
  for (i = 1; i <= 16; i++)
    quality_record(&standby, 100.0 + i * 0.5, FALSE, 0.08);
  assert(fabs(active.rtt - standby.rtt) < 0.002);
  assert(active.rtt > 0.078 && standby.rtt > 0.078);
  /* Change sampling rates without resetting either path's history. */
  quality_record(&active, 108.45, FALSE, 0.01);
  quality_record(&standby, 108.15, FALSE, 0.01);
  assert(active.rtt > 0.06 && standby.rtt > 0.07);
  quality_record(&active, 139.0, FALSE, 0.02);
  assert(active.rtt == 0.02);
}

static void test_probe_identity(struct nhrp_ha_candidate *candidate) {
  struct nhrp_ha_probe_request request = {.candidate = candidate};
  candidate->probe_pending = TRUE;
  request.endpoint_generation = candidate->endpoint_generation;
  request.sequence = candidate->probe_sequence;
  request.generation = candidate->probe_generation;
  request.nonce = candidate->probe_nonce;
  assert(probe_request_current(&request));
  request.endpoint_generation++;
  assert(!probe_request_current(&request));
  request.endpoint_generation--;
  request.sequence++;
  assert(!probe_request_current(&request));
  request.sequence--;
  request.generation++;
  assert(!probe_request_current(&request));
  request.generation--;
  request.nonce++;
  assert(!probe_request_current(&request));
  request.nonce--;
  candidate->probe_pending = FALSE;
  assert(!probe_request_current(&request));
}

static void test_equal_owner_version_recovery(void) {
  struct nhrp_ha_service service = {.owner_term = 169, .owner_index = 268};

  assert(owner_version_at_least(&service, 170, 1));
  assert(owner_version_at_least(&service, 169, 268));
  assert(!owner_version_at_least(&service, 169, 267));
  assert(!owner_version_at_least(&service, 168, UINT64_MAX));
}

static void test_full_candidate_status(struct nhrp_ha_service *service) {
  struct nhrp_ha_candidate candidates[NHRP_HA_MANAGED_MAX_MEMBERS - 1] = {0};
  char *buffer = malloc(NHRP_HA_STATUS_BUFFER_SIZE);
  double now = monotonic_nanoseconds() / 1e9;
  size_t i, length;

  assert(buffer != NULL);
  /* Include long member/leader names and every endpoint at the supported limit. */
  for (i = 0; i < ARRAY_SIZE(candidates); i++) {
    struct nhrp_ha_candidate *candidate = &candidates[i];
    candidate->service = service;
    memset(candidate->member_id, 'a' + i % 26, NHRP_HA_MEMBER_ID_MAX);
    memset(candidate->auth_leader, 'z', NHRP_HA_AUTH_LEADER_MAX);
    candidate->auth_valid = TRUE;
    candidate->endpoint_count = NHRP_HA_MANAGED_MAX_ENDPOINTS;
    candidate->priority = 100;
    candidate->serviceable = TRUE;
    candidate->state = NHRP_HA_CANDIDATE_READY;
    candidate->endpoint_ready[0] = TRUE;
    quality_record(&candidate->quality, now, FALSE, 0.03);
    list_add(&candidate->list_entry, &service->candidates);
  }
  length = nhrp_ha_render(buffer, NHRP_HA_STATUS_BUFFER_SIZE, NULL, TRUE);
  assert(length > 16384 && length < NHRP_HA_STATUS_BUFFER_SIZE - 1);
  assert(strcmp(buffer + length - 3, "]}\n") == 0);
  for (i = 0; i < ARRAY_SIZE(candidates); i++)
    list_del(&candidates[i].list_entry);
  free(buffer);
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

  test_quality_window();
  test_probe_identity(&candidate);
  test_equal_owner_version_recovery();
  ev_default_loop(0);
  service.active = &candidate;
  list_init(&service.candidates);
  list_add(&candidate.list_entry, &service.candidates);
  list_add(&service.list_entry, &services);
  assert(candidate_quality_eligible(&candidate));
  test_full_candidate_status(&service);
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

  /* Measurement validity and service eligibility are separate gates. */
  {
    double now = monotonic_nanoseconds() / 1e9;
    struct candidate_quality_view quality;
    candidate.priority = 100;
    quality = candidate_quality_view(&candidate, now);
    assert(!quality.valid && quality.score == 0);
    nhrp_ha_render(output, sizeof(output), NULL, TRUE);
    assert(strstr(output, "\"quality_rtt_ms\":null"));
    assert(strstr(output, "\"last_quality_reply_age_ms\":null"));
    assert(strstr(output, "\"quality_valid\":false"));
    quality_record(&candidate.quality, now, FALSE, 0.03);
    quality = candidate_quality_view(&candidate, now);
    assert(quality.valid && quality.score == 95);
    nhrp_ha_render(output, sizeof(output), NULL, TRUE);
    assert(strstr(output, "\"quality_rtt_ms\":30.000"));
    assert(strstr(output, "\"quality_samples\":1,\"quality_failures\":0"));
    assert(strstr(output, "\"loss_score\":60.000,\"latency_score\":24.545"));
    assert(strstr(output, "\"priority_score\":10.000"));
    assert(strstr(output, "\"score\":95"));
    nhrp_ha_render(output, sizeof(output), NULL, FALSE);
    assert(strstr(output, "quality-rtt-ms 30.000 quality-samples 1"));
    assert(strstr(output, "loss-score 60.000 latency-score 24.545"));
    assert(strstr(output, "score 95\n"));
    candidate.serviceable = FALSE;
    quality = candidate_quality_view(&candidate, now);
    assert(quality.valid && quality.score == 0 && quality.parts.total == 95);
    candidate.serviceable = TRUE;
    quality = candidate_quality_view(&candidate, now + 31.0);
    assert(!quality.valid && quality.score == 0);
    quality_record(&candidate.quality, now + 32.0, FALSE, 0.06);
    assert(candidate.quality.rtt == 0.06);
    candidate_reset_quality(&candidate);
    assert(!candidate.quality.has_rtt && candidate.quality.samples == 0);
    candidate.serviceable = TRUE;
  }

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
