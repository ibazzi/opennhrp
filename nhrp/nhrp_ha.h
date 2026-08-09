/* nhrp_ha.h - Shared protocol address HA for pure mGRE */

#ifndef NHRP_HA_H
#define NHRP_HA_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "nhrp_address.h"

#define NHRP_EXTENSION_HA 0x3801
#define NHRP_HA_WIRE_VERSION 1
#define NHRP_HA_MEMBER_ID_MAX 63

enum nhrp_ha_message_type {
  NHRP_HA_MEMBER = 1,
  NHRP_HA_PROBE = 2,
  NHRP_HA_PROBE_REPLY = 3,
  NHRP_HA_HUB_LIST = 4,
};

struct nhrp_interface;
struct nhrp_packet;
struct nhrp_peer;

typedef void (*nhrp_ha_activate_callback)(void *ctx, int status,
                                          const char *reason,
                                          uint32_t generation);
typedef void (*nhrp_ha_coordinator_callback)(struct nhrp_interface *iface);

void nhrp_ha_start(void);
void nhrp_ha_cleanup(void);
void nhrp_ha_mark_configured(void);
void nhrp_ha_config_reload_abort(void);
void nhrp_ha_sweep_unconfigured(void);
int nhrp_ha_load_managed(const char *directory);
int nhrp_ha_prepare_managed(const char *directory);
int nhrp_ha_reload_managed(const char *directory);
int nhrp_ha_config_enable(struct nhrp_interface *iface, const char *member_id,
                          const struct nhrp_address *advertised,
                          size_t advertised_count);
int nhrp_ha_hub_enabled(void);
const char *nhrp_ha_hub_interface(void);
size_t nhrp_ha_hub_advertised(struct nhrp_address *addresses, size_t maximum);
int nhrp_ha_config_health_target(struct nhrp_interface *iface,
                                 const struct nhrp_address *target);
size_t nhrp_ha_hub_health_targets(struct nhrp_address *targets, size_t maximum);
void nhrp_ha_set_coordinator_callback(nhrp_ha_coordinator_callback callback);
void nhrp_ha_set_coordinator_status(struct nhrp_interface *iface,
                                    const char *state, int last_exit);

int nhrp_ha_config_member(struct nhrp_interface *iface, const char *member_id);
int nhrp_ha_config_validate(void);
int nhrp_ha_set_cluster_state(struct nhrp_interface *iface, uint64_t term,
                              uint64_t commit_index, const char *leader);
int nhrp_ha_config_map(struct nhrp_interface *iface,
                       const struct nhrp_address *protocol,
                       uint8_t prefix_length, const char *member_id,
                       const struct nhrp_address *nbma, int priority);
int nhrp_ha_config_local_nbma(struct nhrp_interface *iface,
                              const char *member_id,
                              const struct nhrp_address *local_nbma);
int nhrp_ha_config_advertise(struct nhrp_interface *iface,
                             const struct nhrp_address *protocol,
                             uint8_t prefix_length, uint32_t list_generation,
                             const char *member_id,
                             const struct nhrp_address *nbma, int priority);
void nhrp_ha_save_config(FILE *file, struct nhrp_interface *iface);

int nhrp_ha_prepare_registration_reply(struct nhrp_packet *packet);
int nhrp_ha_prepare_probe_reply(struct nhrp_packet *packet);
int nhrp_ha_prepare_outgoing(struct nhrp_packet *packet);
int nhrp_ha_prepare_registration_discovery(struct nhrp_peer *peer,
                                           struct nhrp_packet *packet);
int nhrp_ha_handle_registration_discovery(struct nhrp_peer *peer,
                                          struct nhrp_packet *reply);

size_t nhrp_ha_render(char *buffer, size_t size, const char *interface_name,
                      int json);
int nhrp_ha_activate(const char *interface_name,
                     const struct nhrp_address *protocol, const char *member_id,
                     uint32_t expect_generation,
                     nhrp_ha_activate_callback callback, void *ctx,
                     const char **reason);

#endif
