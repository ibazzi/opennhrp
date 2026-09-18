/* nhrp_ha_hub.h - Hub registration shadow and projection state */

#ifndef NHRP_HA_HUB_H
#define NHRP_HA_HUB_H

#include <stddef.h>
#include <stdint.h>

#include "nhrp_address.h"
#include "nhrp_ha.h"

#define NHRP_HA_HUB_MAX_REGISTRATIONS 4096

enum nhrp_ha_hub_role {
  NHRP_HA_HUB_UNMANAGED = 0,
  NHRP_HA_HUB_LEADER,
  NHRP_HA_HUB_FOLLOWER,
  NHRP_HA_HUB_STANDBY,
};

struct nhrp_interface;
struct nhrp_peer;

struct nhrp_ha_hub_binding {
  struct nhrp_address nbma;
  struct nhrp_address nat_oa;
  uint16_t mtu;
  uint16_t holding_time;
  uint32_t flags;
  uint32_t registration_id;
  uint64_t term;
  uint64_t index;
  char owner_member[NHRP_HA_MEMBER_ID_MAX + 1];
};

void nhrp_ha_hub_cleanup(void);
void nhrp_ha_hub_fence(struct nhrp_interface *iface);
int nhrp_ha_hub_capture_direct(struct nhrp_peer *peer);
int nhrp_ha_hub_retire_direct(struct nhrp_interface *iface,
                              const struct nhrp_address *protocol,
                              uint8_t prefix_length,
                              const struct nhrp_address *nbma,
                              uint32_t registration_id, uint64_t term,
                              uint64_t index);
int nhrp_ha_hub_serviceable(struct nhrp_interface *iface);
int nhrp_ha_hub_takeover_version(struct nhrp_interface *iface,
                                  const struct nhrp_address *protocol,
                                  uint8_t prefix_length,
                                  uint64_t *term, uint64_t *index);
int nhrp_ha_hub_set_role(struct nhrp_interface *iface,
                         enum nhrp_ha_hub_role role, uint64_t term,
                         uint64_t index);
int nhrp_ha_hub_sync_begin(struct nhrp_interface *iface, uint64_t term,
                           uint64_t index);
int nhrp_ha_hub_sync_apply(struct nhrp_interface *iface,
                           const struct nhrp_address *protocol,
                           uint8_t prefix_length,
                           const struct nhrp_ha_hub_binding *binding);
int nhrp_ha_hub_sync_end(struct nhrp_interface *iface);
size_t nhrp_ha_hub_snapshot_render(struct nhrp_interface *iface, char *buffer,
                                   size_t size, size_t offset, size_t limit,
                                   size_t *total, char digest[65]);
size_t nhrp_ha_hub_status_render(struct nhrp_interface *iface, char *buffer,
                                 size_t size, int json);

#endif
