/* Exercise owner reports with no successful Spoke-to-old-Hub Purge. */
#include "../nhrp/ha/nhrp_ha_hub.c"
#include <assert.h>

static struct nhrp_peer *cached;
static unsigned int removed, projected;
int nhrp_verbose;
void nhrp_log(int level, const char *format, ...) {}
void admin_ha_notify(struct nhrp_interface *iface) {}
int nhrp_peer_is_persistable(const struct nhrp_peer *peer) { return FALSE; }
int nhrp_peer_foreach(nhrp_peer_enumerator callback, void *ctx,
                      struct nhrp_peer_selector *selector) {
  if (cached != NULL && nhrp_address_cmp(&cached->protocol_address,
                                         &selector->protocol_address) == 0)
    return callback(ctx, cached);
  return 0;
}
void nhrp_peer_remove(struct nhrp_peer *peer) {
  assert(peer == cached);
  cached = NULL;
  removed++;
}
struct nhrp_peer *nhrp_peer_alloc(struct nhrp_interface *iface) {
  projected++;
  return NULL;
}
void nhrp_peer_insert(struct nhrp_peer *peer) { assert(FALSE); }
int nhrp_peer_put(struct nhrp_peer *peer) { return 0; }

int main(void) {
  struct nhrp_interface iface = {0};
  struct nhrp_peer peer = {.interface = &iface,
                           .prefix_length = 32,
                           .holding_time = 7200,
                           .flags = NHRP_PEER_FLAG_HA_CAPABLE,
                           .ha_registration_id = 42};
  struct nhrp_ha_hub_binding owner;
  struct nhrp_ha_hub_state *state;
  struct nhrp_ha_hub_entry *entry, *other;
  ev_tstamp expires;

  ev_default_loop(0);
  strcpy(iface.ha_member_id, "primary");
  assert(nhrp_address_parse("10.164.0.25", &peer.protocol_address, NULL));
  assert(nhrp_address_parse("192.168.1.25", &peer.next_hop_address, NULL));
  assert(nhrp_ha_hub_set_role(&iface, NHRP_HA_HUB_LEADER, 197, 83053));
  peer.expire_time = ev_now() + 7200;
  assert(nhrp_ha_hub_capture_direct(&peer) == 1);
  cached = &peer;
  state = hub_state_find(&iface, FALSE);
  entry = hub_entry_find(state, &peer.protocol_address, 32);
  assert(entry->direct.binding.index == 1);
  owner = entry->direct.binding;
  owner.index = 13;
  owner.registration_id = 43;
  strcpy(owner.owner_member, "backup");

  /* An unrelated replica must survive the partial owner report. */
  other = hub_entry_get(state, &peer.next_hop_address, 32);
  other->replica = entry->direct;
  assert(nhrp_ha_hub_sync_begin(&iface, 197, 83053, TRUE));
  assert(nhrp_ha_hub_sync_apply(&iface, &peer.protocol_address, 32, &owner));
  assert(nhrp_ha_hub_sync_end(&iface));
  assert(entry->direct.retired && removed == 1 && projected == 0);
  assert(hub_entry_value(entry) == &entry->replica);
  assert(other->replica.present && state->index == 83053);

  /* Duplicate/older reports cannot replace the new owner or extend its TTL. */
  expires = entry->replica.expires;
  assert(nhrp_ha_hub_sync_begin(&iface, 197, 83053, TRUE));
  assert(nhrp_ha_hub_sync_apply(&iface, &peer.protocol_address, 32, &owner));
  owner.index = 12;
  strcpy(owner.owner_member, "stale-backup");
  assert(nhrp_ha_hub_sync_apply(&iface, &peer.protocol_address, 32, &owner));
  assert(nhrp_ha_hub_sync_end(&iface));
  assert(entry->replica.binding.index == 13);
  assert(strcmp(entry->replica.binding.owner_member, "backup") == 0);
  assert(entry->replica.expires == expires && removed == 1);
  /* A fresh registration token renews the shadow without reclaiming it. */
  owner.index = 13;
  owner.registration_id = 44;
  strcpy(owner.owner_member, "backup");
  entry->replica.expires -= 10;
  assert(nhrp_ha_hub_sync_begin(&iface, 197, 83053, TRUE));
  assert(nhrp_ha_hub_sync_apply(&iface, &peer.protocol_address, 32, &owner));
  assert(nhrp_ha_hub_sync_end(&iface));
  assert(entry->replica.expires == expires);
  assert(entry->replica.binding.registration_id == 44 && removed == 1);
  assert(!nhrp_ha_hub_retire_direct(&iface, &peer.protocol_address, 32,
                                    &peer.next_hop_address, 99, 0, 0));
  assert(nhrp_ha_hub_sync_begin(&iface, 197, 83054, FALSE));
  assert(nhrp_ha_hub_sync_end(&iface));
  assert(hub_entry_find(state, &peer.next_hop_address, 32) == NULL);
  nhrp_ha_hub_cleanup();
  ev_loop_destroy();
  puts("HA owner report retirement and stale-version tests passed");
  return 0;
}
