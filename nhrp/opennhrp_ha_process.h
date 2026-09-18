/* opennhrp_ha_process.h - OpenNHRP HA child process management */

#ifndef OPENNHRP_HA_PROCESS_H
#define OPENNHRP_HA_PROCESS_H

void opennhrp_ha_process_init(const char *program, const char *admin_socket,
                              const char *state_directory);
void opennhrp_ha_process_start(void);
int opennhrp_ha_process_reconfigure(void);
void opennhrp_ha_process_cleanup(void);

#endif
