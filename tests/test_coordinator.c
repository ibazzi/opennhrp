#include <assert.h>
#include <string.h>

int opennhrp_ha_managed_hub_main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  return 1;
}

#define main opennhrp_ha_program_main
#include "../nhrp/opennhrp-ha.c"
#undef main

static void test_latency_score(void) {
  static const struct {
    double rtt;
    unsigned int score;
  } cases[] = {
      {-1.0, 100}, {0.0, 100},  {5.0, 100},   {9.9, 100},  {10.0, 100},
      {10.1, 100}, {30.0, 100}, {60.0, 99},   {100.0, 95}, {150.0, 90},
      {200.0, 86}, {300.0, 82}, {1000.0, 80},
  };
  unsigned int previous = 100;
  size_t i;

  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    assert(nhrp_ha_quality_score(0.0, cases[i].rtt, 100) == cases[i].score);
  for (i = 0; i <= 3000; i++) {
    unsigned int score = nhrp_ha_quality_score(0.0, i / 10.0, 100);
    assert(score >= 80 && score <= previous);
    previous = score;
  }
  assert(nhrp_ha_quality_score(0.15, 150.0, 50) == 33);
  /* Round the combined score, not the latency and priority separately. */
  assert(nhrp_ha_quality_score(0.0, 150.0, 95) == 90);
}

static void test_latency_migration(void) {
  struct service_view view = {0};
  struct decision_state decision = {0};
  const char *reason;
  size_t i;

  view.candidate_count = 2;
  strcpy(view.active_member, "hub-a");
  strcpy(view.candidates[0].member, "hub-a");
  strcpy(view.candidates[1].member, "hub-b");
  for (i = 0; i < 2; i++) {
    view.candidates[i].ready = 1;
    view.candidates[i].priority = 100;
  }
  view.candidates[1].score = nhrp_ha_quality_score(0.0, 30.0, 100);
  view.candidates[0].score = nhrp_ha_quality_score(0.0, 100.0, 100);
  assert(select_migration(&view, &decision, 1.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 200.0, &reason) == NULL);
  assert(decision.superior_member[0] == 0);

  view.candidates[0].score = nhrp_ha_quality_score(0.0, 200.0, 100);
  assert(select_migration(&view, &decision, 201.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 215.9, &reason) == NULL);
  /* A short spike or an interrupted advantage must restart the hold. */
  view.candidates[0].score = nhrp_ha_quality_score(0.0, 100.0, 100);
  assert(select_migration(&view, &decision, 216.0, &reason) == NULL);
  assert(decision.superior_member[0] == 0);
  view.candidates[0].score = nhrp_ha_quality_score(0.0, 200.0, 100);
  assert(select_migration(&view, &decision, 217.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 231.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 232.0, &reason) ==
         &view.candidates[1]);
  assert(strcmp(reason, "quality") == 0);

  strcpy(view.active_member, "hub-b");
  decision.cooldown_until = 262.0;
  view.candidates[0].score = nhrp_ha_quality_score(0.0, 30.0, 100);
  view.candidates[1].score = nhrp_ha_quality_score(0.0, 200.0, 100);
  assert(select_migration(&view, &decision, 261.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 262.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 276.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 277.0, &reason) ==
         &view.candidates[0]);
}

static void test_sticky_target(void) {
  struct service_view view = {0};
  struct decision_state decision = {0};
  const char *reason;
  FILE *log = tmpfile();
  long size;
  int i;

  assert(log != NULL);
  view.candidate_count = 3;
  view.auth_required = 1;
  strcpy(view.active_member, "a");
  for (i = 0; i < 3; i++) {
    view.candidates[i].member[0] = 'a' + i;
    view.candidates[i].ready = 1;
    view.candidates[i].authenticated = 1;
    view.candidates[i].priority = 100;
    view.candidates[i].term = 1;
    strcpy(view.candidates[i].selected_address, "192.0.2.1");
  }
  view.candidates[0].score = 70;
  for (i = 1; i <= 15; i++) {
    view.candidates[1].score = 91 - (i / 5) % 2;
    view.candidates[2].score = 90 + (i / 5) % 2;
    assert(select_migration(&view, &decision, i, &reason) == NULL);
    assert(strcmp(decision.superior_member, "b") == 0);
    assert(decision.superior_since == 1.0);
    debug = 1;
    log_decision(log, &view, &decision, i);
  }
  size = ftell(log);
  assert(size > 0);
  log_decision(log, &view, &decision, 15.5);
  assert(ftell(log) == size);
  assert(select_migration(&view, &decision, 16.0, &reason) == &view.candidates[1]);
  assert(strcmp(reason, "quality") == 0);
  log_decision(log, &view, &decision, 16.0);
  assert(ftell(log) > size);
  size = ftell(log);
  debug = 0;
  decision.decision_reason = "cooldown";
  log_decision(log, &view, &decision, 17.0);
  assert(ftell(log) == size);
  fclose(log);

  /* Authentication loss drops the pinned target, then the endpoint resets it. */
  view.candidates[1].authenticated = 0;
  assert(select_migration(&view, &decision, 20.0, &reason) == NULL);
  assert(strcmp(decision.superior_member, "c") == 0);
  strcpy(view.candidates[2].selected_address, "192.0.2.2");
  assert(select_migration(&view, &decision, 34.0, &reason) == NULL);
  assert(decision.superior_since == 34.0);
  assert(select_migration(&view, &decision, 48.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 49.0, &reason) == &view.candidates[2]);
  view.candidates[2].ready = 0;
  assert(select_migration(&view, &decision, 50.0, &reason) == NULL);
  assert(decision.superior_member[0] == 0);
  view.candidates[2].ready = 1;
  assert(select_migration(&view, &decision, 51.0, &reason) == NULL);
  view.candidates[0].term = view.candidates[2].term = 2;
  assert(select_migration(&view, &decision, 60.0, &reason) == NULL);
  assert(decision.superior_since == 60.0);
  strcpy(view.candidates[0].selected_address, "192.0.2.3");
  assert(select_migration(&view, &decision, 70.0, &reason) == NULL);
  assert(decision.superior_since == 70.0);

  /* Quality/failback transitions never borrow elapsed time from each other. */
  view.candidates[0].priority = 90;
  view.candidates[2].score = 75;
  assert(select_migration(&view, &decision, 80.0, &reason) == NULL);
  assert(decision.superior_since == 80.0);
  assert(decision.superior_hold == SCORE_FAILBACK_HOLD);
  view.candidates[2].score = 90;
  assert(select_migration(&view, &decision, 190.0, &reason) == NULL);
  assert(decision.superior_since == 190.0);
  assert(decision.superior_hold == SCORE_SWITCH_HOLD);
  assert(select_migration(&view, &decision, 204.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 205.0, &reason) == &view.candidates[2]);
  view.candidates[2].score = 75;
  assert(select_migration(&view, &decision, 206.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 325.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 326.0, &reason) == &view.candidates[2]);
  assert(strcmp(reason, "failback") == 0);

  /* A better-scored but ineligible challenger must not hide a valid failback. */
  decision_reset_superior(&decision);
  view.candidates[1].authenticated = 1;
  view.candidates[1].term = 2;
  view.candidates[1].priority = 90;
  view.candidates[1].score = 79;
  assert(select_migration(&view, &decision, 400.0, &reason) == NULL);
  assert(strcmp(decision.superior_member, "c") == 0);
}

int main(void) {
  static const char event[] =
      "{\"event_sequence\":9,\"interface\":\"gre-ha\","
      "\"protocol\":\"10.20.0.1\",\"prefix_length\":24,"
      "\"generation\":3,\"switching\":false,"
      "\"active_member\":\"hub-primary\",\"candidates\":["
      "{\"member\":\"hub-primary\",\"nbma\":\"150.158.214.148\","
      "\"priority\":100,\"state\":\"offline\",\"registered\":true,"
      "\"ready\":false,\"active\":true,\"score\":0},"
      "{\"member\":\"hub-backup1\",\"nbma\":\"49.234.145.47\","
      "\"priority\":90,\"state\":\"ready\",\"registered\":true,"
      "\"ready\":true,\"active\":false,\"score\":85,\"selected_address\":\"192.0.2.2\"}]}";
  struct service_view view;
  struct candidate_view *candidate;
  struct decision_state decision = {0};
  struct decision_state *first_service;
  struct decision_state *second_service;
  const char *reason;
  static const char authenticated_event[] =
      "{\"protocol\":\"10.20.0.1\",\"generation\":1,"
      "\"switching\":false,\"auth_mode\":\"required\","
      "\"active_member\":\"hub-primary\",\"candidates\":["
      "{\"member\":\"hub-primary\",\"priority\":100,"
      "\"state\":\"offline\",\"ready\":false,"
      "\"authenticated\":true,\"score\":0,\"term\":2,"
      "\"leader\":\"hub-primary\"},"
      "{\"member\":\"hub-backup1\",\"priority\":90,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":true,\"score\":80,\"term\":2,"
      "\"leader\":\"hub-primary\"}]}";
  static const char disabled_event[] =
      "{\"protocol\":\"10.20.0.1\",\"generation\":1,"
      "\"switching\":false,\"auth_mode\":\"disabled\","
      "\"active_member\":\"hub-primary\",\"candidates\":["
      "{\"member\":\"hub-primary\",\"priority\":100,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":true,\"score\":70,\"term\":2,"
      "\"leader\":\"hub-backup1\"},"
      "{\"member\":\"hub-backup1\",\"priority\":90,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":true,\"score\":90,\"term\":2,"
      "\"leader\":\"hub-backup1\"}]}";
  static const char legacy_disabled_event[] =
      "{\"protocol\":\"10.20.0.1\",\"generation\":1,"
      "\"switching\":false,\"auth_mode\":\"disabled\","
      "\"active_member\":\"hub-backup1\",\"candidates\":["
      "{\"member\":\"hub-primary\",\"priority\":100,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":false,\"score\":80,\"term\":0,\"leader\":\"\"},"
      "{\"member\":\"hub-backup1\",\"priority\":90,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":false,\"score\":90,\"term\":0,\"leader\":\"\"}]}";
  static const char transfer_transition_event[] =
      "{\"protocol\":\"10.20.0.1\",\"generation\":3,"
      "\"switching\":false,\"auth_mode\":\"disabled\","
      "\"active_member\":\"hub-primary\",\"candidates\":["
      "{\"member\":\"hub-primary\",\"priority\":100,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":true,\"score\":95,\"term\":12,"
      "\"leader\":\"hub-backup1\"},"
      "{\"member\":\"hub-backup1\",\"priority\":90,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":true,\"score\":60,\"term\":13,"
      "\"leader\":\"hub-primary\"}]}";
  static const char quality_event[] =
      "{\"protocol\":\"10.20.0.1\",\"generation\":5,"
      "\"switching\":false,\"auth_mode\":\"required\","
      "\"active_member\":\"hub-primary\",\"candidates\":["
      "{\"member\":\"hub-primary\",\"priority\":100,"
      "\"state\":\"suspect\",\"ready\":false,"
      "\"authenticated\":true,\"score\":50,\"term\":5000000000},"
      "{\"member\":\"hub-backup1\",\"priority\":90,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":true,\"score\":60,\"term\":5000000000}]}";
  static const char manual_event[] =
      "{\"protocol\":\"10.20.0.1\",\"generation\":7,"
      "\"switching\":false,\"auth_mode\":\"required\","
      "\"selection_mode\":\"manual\","
      "\"manual_member\":\"hub-backup1\","
      "\"manual_leader\":\"hub-primary\","
      "\"active_member\":\"hub-primary\",\"candidates\":["
      "{\"member\":\"hub-primary\",\"priority\":100,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":true,\"score\":100,\"term\":20,"
      "\"leader\":\"hub-primary\"},"
      "{\"member\":\"hub-backup1\",\"priority\":90,"
      "\"state\":\"ready\",\"ready\":true,"
      "\"authenticated\":true,\"score\":40,\"term\":20,"
      "\"leader\":\"hub-primary\"}]}";
  static const uint8_t snapshot[] = "entry 10.20.0.1 32 192.0.2.1 -\n";
  static const uint8_t stale_snapshot[] = "entry 10.20.0.2 32 192.0.2.2 -\n";
  struct nhrp_ha_managed_state current_manifest;
  struct nhrp_ha_managed_state next_manifest;

  assert(parse_service(event, &view));
  assert(strcmp(view.protocol, "10.20.0.1") == 0);
  assert(strcmp(view.active_member, "hub-primary") == 0);
  assert(view.generation == 3);
  assert(!view.switching);
  assert(view.candidate_count == 2);
  assert(view.candidates[0].selected_address[0] == 0);
  assert(strcmp(view.candidates[1].selected_address, "192.0.2.2") == 0);
  candidate = find_candidate(&view, "hub-primary");
  assert(candidate != NULL);
  assert(strcmp(candidate->state, "offline") == 0);
  assert(candidate->score == 0);
  candidate = best_ready_candidate(&view);
  assert(candidate != NULL);
  assert(strcmp(candidate->member, "hub-backup1") == 0);

  assert(parse_service(authenticated_event, &view));
  assert(view.auth_required);
  candidate = best_ready_candidate(&view);
  assert(candidate != NULL);
  assert(strcmp(candidate->member, "hub-backup1") == 0);
  assert(candidate->term == 2);
  assert(strcmp(candidate->leader, "hub-primary") == 0);

  assert(parse_service(disabled_event, &view));
  assert(!view.auth_required);
  candidate = best_ready_candidate(&view);
  assert(candidate != NULL);
  assert(strcmp(candidate->member, "hub-backup1") == 0);

  assert(parse_service(legacy_disabled_event, &view));
  assert(!view.auth_required);
  candidate = best_ready_candidate(&view);
  assert(candidate != NULL);
  assert(strcmp(candidate->member, "hub-backup1") == 0);

  assert(parse_service(transfer_transition_event, &view));
  candidate = best_ready_candidate(&view);
  assert(candidate != NULL);
  assert(strcmp(candidate->member, "hub-backup1") == 0);
  candidate = find_candidate(&view, view.active_member);
  assert(candidate_usable(&view, candidate));

  assert(nhrp_ha_quality_score(0.0, 0.0, 100) == 100);
  assert(nhrp_ha_quality_score(0.20, 300.0, 100) == 12);
  assert(nhrp_ha_quality_score(0.15, 150.0, 50) == 33);
  assert(nhrp_ha_quality_score(0.0, 0.0, 200) == 100);
  test_latency_score();
  test_latency_migration();
  test_sticky_target();

  assert(parse_service(quality_event, &view));
  candidate = find_candidate(&view, "hub-primary");
  assert(candidate != NULL && candidate->term == UINT64_C(5000000000));
  assert(candidate_usable(&view, candidate));
  view.candidates[1].authenticated = 0;
  assert(best_ready_candidate(&view) == NULL);
  view.candidates[1].authenticated = 1;
  view.candidates[0].ready = 1;
  view.candidates[0].score = 60;
  view.candidates[0].priority = 90;
  assert(strcmp(best_ready_candidate(&view)->member, "hub-backup1") == 0);
  view.candidates[0].ready = 0;
  view.candidates[0].score = 50;
  view.candidates[0].priority = 100;
  assert(select_migration(&view, &decision, 100.0, &reason) == NULL);
  assert(strcmp(decision.superior_member, "hub-backup1") == 0);
  assert(select_migration(&view, &decision, 114.9, &reason) == NULL);
  candidate = select_migration(&view, &decision, 115.0, &reason);
  assert(candidate != NULL && strcmp(candidate->member, "hub-backup1") == 0);
  assert(strcmp(reason, "quality") == 0);
  view.candidates[1].score = 59;
  assert(select_migration(&view, &decision, 116.0, &reason) == NULL);
  assert(decision.superior_member[0] == 0);
  view.candidates[1].score = 60;
  assert(select_migration(&view, &decision, 117.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 131.9, &reason) == NULL);
  candidate = select_migration(&view, &decision, 132.0, &reason);
  assert(candidate != NULL && strcmp(reason, "quality") == 0);
  decision.cooldown_until = 145.0;
  decision_reset_superior(&decision);
  assert(select_migration(&view, &decision, 144.9, &reason) == NULL);
  assert(decision.superior_member[0] == 0);
  assert(select_migration(&view, &decision, 145.0, &reason) == NULL);
  candidate = select_migration(&view, &decision, 160.0, &reason);
  assert(candidate != NULL && strcmp(reason, "quality") == 0);

  memset(&decision, 0, sizeof(decision));
  assert(parse_service(legacy_disabled_event, &view));
  view.candidates[0].score = 100;
  view.candidates[1].score = 96;
  assert(select_migration(&view, &decision, 200.0, &reason) == NULL);
  assert(strcmp(decision.superior_member, "hub-primary") == 0);
  assert(select_migration(&view, &decision, 319.9, &reason) == NULL);
  candidate = select_migration(&view, &decision, 320.0, &reason);
  assert(candidate != NULL && strcmp(candidate->member, "hub-primary") == 0);
  assert(strcmp(reason, "failback") == 0);

  memset(&decision, 0, sizeof(decision));
  assert(parse_service(authenticated_event, &view));
  assert(select_migration(&view, &decision, 1.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 15.9, &reason) == NULL);
  candidate = select_migration(&view, &decision, 16.0, &reason);
  assert(candidate != NULL && strcmp(candidate->member, "hub-backup1") == 0);
  assert(strcmp(reason, "quality") == 0);

  /* Zero score obeys cooldown; a recovery or no READY target resets the hold. */
  decision.cooldown_until = 50.0;
  assert(select_migration(&view, &decision, 49.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 50.0, &reason) == NULL);
  view.candidates[0].ready = 1;
  view.candidates[0].score = 100;
  assert(select_migration(&view, &decision, 52.56, &reason) == NULL);
  view.candidates[0].ready = 0;
  view.candidates[0].score = 0;
  view.candidates[1].ready = 0;
  assert(select_migration(&view, &decision, 60.0, &reason) == NULL);
  view.candidates[1].ready = 1;
  view.candidates[1].score = 0;
  assert(best_ready_candidate(&view) == NULL);
  assert(select_migration(&view, &decision, 60.5, &reason) == NULL);
  view.candidates[1].score = 80;
  assert(select_migration(&view, &decision, 61.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 75.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 76.0, &reason) == &view.candidates[1]);

  /* A failed manually selected Hub uses the same score hold. */
  view.selection_manual = 1;
  assert(select_migration(&view, &decision, 80.0, &reason) == NULL);
  assert(select_migration(&view, &decision, 94.9, &reason) == NULL);
  assert(select_migration(&view, &decision, 95.0, &reason) == &view.candidates[1]);
  assert(strcmp(reason, "quality") == 0);

  memset(&decision, 0, sizeof(decision));
  assert(parse_service(transfer_transition_event, &view));
  assert(select_migration(&view, &decision, 1.0, &reason) == NULL);
  snprintf(view.candidates[1].leader, sizeof(view.candidates[1].leader), "%s",
           view.candidates[1].member);
  candidate = select_migration(&view, &decision, 2.0, &reason);
  assert(candidate != NULL && strcmp(candidate->member, "hub-backup1") == 0);
  assert(strcmp(reason, "stale-term") == 0);

  memset(&decision, 0, sizeof(decision));
  assert(parse_service(manual_event, &view));
  assert(view.selection_manual);
  assert(strcmp(view.manual_member, "hub-backup1") == 0);
  candidate = select_migration(&view, &decision, 1.0, &reason);
  assert(candidate != NULL && strcmp(candidate->member, "hub-backup1") == 0);
  assert(strcmp(reason, "manual") == 0);
  snprintf(view.active_member, sizeof(view.active_member), "%s", "hub-backup1");
  view.candidates[0].score = 100;
  view.candidates[1].score = 1;
  assert(select_migration(&view, &decision, 1000.0, &reason) == NULL);
  snprintf(view.manual_member, sizeof(view.manual_member), "%s", "hub-primary");
  snprintf(view.candidates[0].leader, sizeof(view.candidates[0].leader), "%s",
           "hub-backup1");
  snprintf(view.candidates[1].leader, sizeof(view.candidates[1].leader), "%s",
           "hub-backup1");
  assert(select_migration(&view, &decision, 1001.0, &reason) == NULL);
  snprintf(view.candidates[0].leader, sizeof(view.candidates[0].leader), "%s",
           "hub-primary");
  snprintf(view.candidates[1].leader, sizeof(view.candidates[1].leader), "%s",
           "hub-primary");
  candidate = select_migration(&view, &decision, 1002.0, &reason);
  assert(candidate != NULL && strcmp(candidate->member, "hub-primary") == 0);
  assert(strcmp(reason, "manual") == 0);
  snprintf(view.active_member, sizeof(view.active_member), "%s", "hub-primary");
  view.candidates[1].term = 21;
  snprintf(view.candidates[1].leader, sizeof(view.candidates[1].leader), "%s",
           "hub-backup1");
  candidate = select_migration(&view, &decision, 1003.0, &reason);
  assert(candidate != NULL && strcmp(candidate->member, "hub-backup1") == 0);
  assert(strcmp(reason, "stale-term") == 0);
  snprintf(view.active_member, sizeof(view.active_member), "%s", "hub-backup1");
  view.candidates[0].term = 22;
  view.candidates[1].term = 22;
  snprintf(view.candidates[0].leader, sizeof(view.candidates[0].leader), "%s",
           "hub-primary");
  snprintf(view.candidates[1].leader, sizeof(view.candidates[1].leader), "%s",
           "hub-primary");
  candidate = select_migration(&view, &decision, 1004.0, &reason);
  assert(candidate != NULL && strcmp(candidate->member, "hub-primary") == 0);
  assert(strcmp(reason, "manual") == 0);

  first_service = decision_state_find("10.20.0.1");
  second_service = decision_state_find("10.30.0.1");
  assert(first_service != NULL && second_service != NULL);
  assert(first_service != second_service);
  assert(decision_state_find("10.20.0.1") == first_service);

  assert(!opennhrp_ha_snapshot_resync_needed(10, "leader", 9, "peer"));
  assert(!opennhrp_ha_snapshot_resync_needed(10, "leader", 10, "leader"));
  assert(opennhrp_ha_snapshot_resync_needed(10, "leader", 10, "peer"));
  assert(opennhrp_ha_snapshot_resync_needed(10, "leader", 11, "peer"));
  assert(opennhrp_ha_snapshot_cache_matches(snapshot, sizeof(snapshot) - 1,
                                            "same", snapshot,
                                            sizeof(snapshot) - 1, "same"));
  assert(!opennhrp_ha_snapshot_cache_matches(
      stale_snapshot, sizeof(stale_snapshot) - 1, "same", snapshot,
      sizeof(snapshot) - 1, "same"));
  assert(strcmp(opennhrp_ha_reconnect_target("hub-backup1", "hub-backup1",
                                             "hub-primary"),
                "hub-primary") == 0);
  assert(strcmp(opennhrp_ha_reconnect_target("hub-backup1", "hub-primary",
                                             "hub-primary"),
                "hub-primary") == 0);
  assert(opennhrp_ha_reconnect_target("hub-primary", "hub-primary",
                                      "hub-primary") == NULL);
  assert(strcmp(opennhrp_ha_split_recovery_leader("hub-primary", "hub-primary",
                                                  "hub-backup1", 1, 1),
                "hub-backup1") == 0);
  assert(strcmp(opennhrp_ha_split_recovery_leader("hub-backup1", "hub-primary",
                                                  "hub-primary", 1, 1),
                "hub-backup1") == 0);
  assert(opennhrp_ha_split_recovery_leader("hub-backup1", "hub-primary",
                                           "hub-primary", 1, 0) == NULL);
  assert(strcmp(opennhrp_ha_startup_leader("hub-backup1", "hub-primary",
                                           "hub-backup1"),
                "hub-primary") == 0);
  assert(strcmp(opennhrp_ha_startup_leader("hub-backup1", "hub-primary",
                                           "hub-primary"),
                "hub-primary") == 0);
  assert(strcmp(opennhrp_ha_startup_leader("hub-primary", "hub-primary",
                                           "hub-primary"),
                "hub-primary") == 0);
  assert(opennhrp_ha_replace_with_incoming("hub-primary", "hub-backup1", 1));
  assert(!opennhrp_ha_replace_with_incoming("hub-backup1", "hub-primary", 1));
  assert(!opennhrp_ha_replace_with_incoming("hub-primary", "hub-backup1", 0));
  assert(opennhrp_ha_witness_quorum(1, NHRP_HA_WITNESS_ACTIVE, 0, 0));
  assert(!opennhrp_ha_witness_quorum(0, NHRP_HA_WITNESS_LEGACY, 0, 0));
  assert(opennhrp_ha_witness_quorum(2, NHRP_HA_WITNESS_LEGACY, 0, 0));
  assert(!opennhrp_ha_witness_quorum(2, NHRP_HA_WITNESS_PREPARING, 0, 0));
  assert(opennhrp_ha_witness_quorum(2, NHRP_HA_WITNESS_ACTIVE, 1, 0));
  assert(opennhrp_ha_witness_quorum(2, NHRP_HA_WITNESS_ACTIVE, 0, 1));
  assert(opennhrp_ha_witness_single_hub_fallback(1, NHRP_HA_WITNESS_ACTIVE,
                                                 "hub-primary", "hub-primary"));
  assert(!opennhrp_ha_witness_single_hub_fallback(1, NHRP_HA_WITNESS_ACTIVE,
                                                  "hub-backup", "hub-primary"));
  assert(!opennhrp_ha_witness_single_hub_fallback(
      2, NHRP_HA_WITNESS_ACTIVE, "hub-primary", "hub-primary"));
  assert(opennhrp_ha_hub_majority_required(3) == 2);
  assert(opennhrp_ha_hub_majority_required(4) == 3);
  assert(!opennhrp_ha_hub_majority(2, 2));
  assert(!opennhrp_ha_hub_majority(3, 1));
  assert(opennhrp_ha_hub_majority(3, 2));
  assert(!opennhrp_ha_hub_majority(4, 2));
  assert(opennhrp_ha_hub_majority(4, 3));
  assert(opennhrp_ha_autonomous_election_allowed(1, NHRP_HA_WITNESS_ACTIVE, 0));
  assert(opennhrp_ha_autonomous_election_allowed(2, NHRP_HA_WITNESS_LEGACY, 0));
  assert(!opennhrp_ha_autonomous_election_allowed(2, NHRP_HA_WITNESS_PREPARING,
                                                  0));
  assert(
      !opennhrp_ha_autonomous_election_allowed(2, NHRP_HA_WITNESS_ACTIVE, 1));
  assert(!opennhrp_ha_autonomous_election_allowed(2, NHRP_HA_WITNESS_DISABLING,
                                                  1));
  assert(
      !opennhrp_ha_autonomous_election_allowed(3, NHRP_HA_WITNESS_LEGACY, 0));
  assert(opennhrp_ha_autonomous_election_allowed(3, NHRP_HA_WITNESS_LEGACY, 1));
  assert(!opennhrp_ha_witness_lease_acceptable(NHRP_HA_WITNESS_PREPARING, 1, 3,
                                               3, 8, 9, 3000));
  assert(opennhrp_ha_witness_lease_acceptable(NHRP_HA_WITNESS_ACTIVE, 1, 3, 3,
                                              8, 9, 3000));
  assert(!opennhrp_ha_witness_lease_acceptable(NHRP_HA_WITNESS_ACTIVE, 0, 3, 3,
                                               8, 9, 3000));
  assert(!opennhrp_ha_witness_lease_acceptable(NHRP_HA_WITNESS_ACTIVE, 1, 3, 3,
                                               9, 9, 3000));
  assert(!opennhrp_ha_witness_lease_acceptable(NHRP_HA_WITNESS_ACTIVE, 1, 4, 3,
                                               8, 9, 3000));
  assert(!opennhrp_ha_witness_lease_acceptable(NHRP_HA_WITNESS_ACTIVE, 1, 3, 3,
                                               8, 9, 3001));
  assert(opennhrp_ha_term_evidence_covers(8, 8));
  assert(opennhrp_ha_term_evidence_covers(8, 7));
  assert(!opennhrp_ha_term_evidence_covers(8, 6));
  assert(!opennhrp_ha_term_evidence_covers(0, UINT64_MAX));
  assert(opennhrp_ha_witness_peer_mode_compatible(
      NHRP_HA_WITNESS_PREPARING, NHRP_HA_WITNESS_LEGACY, 0, 0));
  assert(!opennhrp_ha_witness_peer_mode_compatible(
      NHRP_HA_WITNESS_ACTIVE, NHRP_HA_WITNESS_LEGACY, 0, 0));
  assert(opennhrp_ha_witness_peer_mode_compatible(
      NHRP_HA_WITNESS_ACTIVE, NHRP_HA_WITNESS_LEGACY, 0, 1));
  assert(opennhrp_ha_witness_peer_mode_compatible(
      NHRP_HA_WITNESS_ACTIVE, NHRP_HA_WITNESS_ACTIVE, 1, 0));
  memset(&current_manifest, 0, sizeof(current_manifest));
  current_manifest.member_count = 1;
  current_manifest.members[0].state = NHRP_HA_MANAGED_ACTIVE;
  next_manifest = current_manifest;
  next_manifest.witness_mode = NHRP_HA_WITNESS_PREPARING;
  next_manifest.commit_index++;
  next_manifest.manifest_revision++;
  assert(!opennhrp_ha_manifest_core_reload_needed(&current_manifest,
                                                  &next_manifest));
  next_manifest.members[0].state = NHRP_HA_MANAGED_DISABLED;
  assert(opennhrp_ha_manifest_core_reload_needed(&current_manifest,
                                                 &next_manifest));
  current_manifest.members[0].state = NHRP_HA_MANAGED_DISABLED;
  next_manifest.members[0].state = NHRP_HA_MANAGED_LEARNER;
  assert(!opennhrp_ha_manifest_core_reload_needed(&current_manifest,
                                                  &next_manifest));
  next_manifest.members[0].state = NHRP_HA_MANAGED_ACTIVE;
  assert(opennhrp_ha_manifest_core_reload_needed(&current_manifest,
                                                 &next_manifest));
  assert(opennhrp_ha_backup_became_leader("hub-backup1", "hub-primary",
                                          "hub-primary", "hub-backup1"));
  assert(!opennhrp_ha_backup_became_leader("hub-backup1", "hub-primary",
                                           "hub-backup1", "hub-backup1"));
  assert(!opennhrp_ha_backup_became_leader("hub-primary", "hub-primary",
                                           "hub-backup1", "hub-primary"));
  assert(!opennhrp_ha_backup_became_leader("hub-backup1", "hub-primary",
                                           "hub-primary", "hub-primary"));
  assert(opennhrp_ha_witness_reprepare_needed(NHRP_HA_WITNESS_ACTIVE, 0, 0));
  assert(!opennhrp_ha_witness_reprepare_needed(NHRP_HA_WITNESS_ACTIVE, 0, 1));
  assert(opennhrp_ha_witness_reprepare_needed(NHRP_HA_WITNESS_DISABLING, 1, 0));
  assert(!opennhrp_ha_witness_reprepare_needed(NHRP_HA_WITNESS_ACTIVE, 1, 0));
  assert(opennhrp_ha_witness_fallback_safe(
      1, 1, 4, 4, "hub-primary", "hub-primary", 12, 12, "same", "same"));
  assert(!opennhrp_ha_witness_fallback_safe(
      1, 1, 4, 4, "hub-primary", "hub-primary", 12, 12, "left", "right"));
  assert(opennhrp_ha_witness_transition_allowed(NHRP_HA_WITNESS_LEGACY,
                                                NHRP_HA_WITNESS_LEGACY));
  assert(!opennhrp_ha_witness_transition_allowed(NHRP_HA_WITNESS_LEGACY,
                                                 NHRP_HA_WITNESS_ACTIVE));
  assert(opennhrp_ha_witness_transition_allowed(NHRP_HA_WITNESS_PREPARING,
                                                NHRP_HA_WITNESS_ACTIVE));
  assert(opennhrp_ha_witness_transition_allowed(NHRP_HA_WITNESS_ACTIVE,
                                                NHRP_HA_WITNESS_DISABLING));
  assert(opennhrp_ha_witness_transition_allowed(NHRP_HA_WITNESS_DISABLING,
                                                NHRP_HA_WITNESS_LEGACY));
  assert(opennhrp_ha_witness_transition_allowed(NHRP_HA_WITNESS_DISABLING,
                                                NHRP_HA_WITNESS_ACTIVE));
  assert(!opennhrp_ha_witness_transition_allowed(NHRP_HA_WITNESS_ACTIVE,
                                                 NHRP_HA_WITNESS_LEGACY));
  assert(opennhrp_ha_witness_manifest_transition_allowed(
      NHRP_HA_WITNESS_ACTIVE, NHRP_HA_WITNESS_LEGACY, 3, 1));
  assert(opennhrp_ha_witness_manifest_transition_allowed(
      NHRP_HA_WITNESS_ACTIVE, NHRP_HA_WITNESS_LEGACY, 1, 1));
  assert(!opennhrp_ha_witness_manifest_transition_allowed(
      NHRP_HA_WITNESS_ACTIVE, NHRP_HA_WITNESS_LEGACY, 2, 1));
  assert(!opennhrp_ha_witness_manifest_transition_allowed(
      NHRP_HA_WITNESS_LEGACY, NHRP_HA_WITNESS_ACTIVE, 2, 1));
  assert(opennhrp_ha_witness_manifest_transition_allowed(
      NHRP_HA_WITNESS_LEGACY, NHRP_HA_WITNESS_ACTIVE, 2, 0));
  return 0;
}
