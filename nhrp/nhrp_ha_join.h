/* nhrp_ha_join.h - Secure online OpenNHRP HA enrollment */

#ifndef NHRP_HA_JOIN_H
#define NHRP_HA_JOIN_H

#include <netinet/in.h>
#include <stddef.h>

#include "nhrp_ha_managed.h"

#define NHRP_HA_JOIN_MAGIC "ONHJ"

int nhrp_ha_join_is_request(const void *prefix, size_t length);
int nhrp_ha_join_client(const struct nhrp_ha_managed_invite_token *token,
                        const char *interface,
                        const struct in_addr *advertised_addresses,
                        size_t advertised_address_count, const char *directory);
int nhrp_ha_join_client_fd(int fd,
                           const struct nhrp_ha_managed_invite_token *token,
                           const char *interface,
                           const struct in_addr *advertised_addresses,
                           size_t advertised_address_count,
                           const char *directory);
int nhrp_ha_join_server(int fd, const char *directory);

#endif
