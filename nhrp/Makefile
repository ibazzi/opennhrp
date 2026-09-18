progs-y			+= opennhrp
opennhrp-objs		+= platform/libev.o opennhrp.o \
			   opennhrp_ha_process.o core/nhrp_address.o \
			   core/nhrp_packet.o core/nhrp_peer.o \
			   core/nhrp_peer_cache.o core/nhrp_server.o \
			   core/nhrp_interface.o admin.o \
			   core/nhrp_extension.o ha/nhrp_ha_wire.o \
			   ha/nhrp_ha_auth.o ha/nhrp_ha_seen.o \
			   ha/nhrp_ha_managed.o ha/nhrp_ha_hub.o \
			   ha/nhrp_ha.o platform/sysdep_netlink.o \
			   platform/sysdep_pfpacket.o platform/sysdep_syslog.o

CFLAGS_libev.o		+= -Wno-unused -Wno-comment -Wno-parentheses \
			   -Wno-unused-result
CFLAGS_opennhrp.o	+= -DOPENNHRP_VERSION=\"$(FULL_VERSION)\" \
			   -DOPENNHRP_ADMIN_SOCKET=\"$(STATEDIR)/opennhrp.socket\"
LIBS_opennhrp		+= -lm -lcrypto
ifeq ($(shell pkg-config --exists libcares && echo "yes"),yes)
CFLAGS			+=$(shell pkg-config --cflags libcares)
LIBS_opennhrp  		+=$(shell pkg-config --libs libcares)
else
LIBS_opennhrp  		+= -lcares
endif

progs-y			+= opennhrpctl
opennhrpctl-objs	+= opennhrpctl.o ha/nhrp_ha_auth.o \
			   ha/nhrp_ha_managed.o ha/nhrp_ha_join.o \
			   ha/nhrp_ha_seen.o ha/nhrp_ha_control.o \
			   ha/nhrp_ha_store.o
CFLAGS_opennhrpctl.o	+= $(CFLAGS_opennhrp.o)
LIBS_opennhrpctl	+= -lcrypto

progs-y			+= opennhrp-ha
opennhrp-ha-objs	+= opennhrp-ha.o ha/nhrp_ha_auth.o \
			   ha/nhrp_ha_control.o ha/nhrp_ha_store.o \
			   ha/nhrp_ha_managed.o ha/nhrp_ha_join.o \
			   ha/nhrp_ha_failback.o ha/opennhrp-ha-managed-hub.o \
			   ha/nhrp_ha_delta.o
LIBS_opennhrp-ha	+= -lcrypto

CFLAGS_EXTRA		+= -I$(srctree)/include -I$(srctree)/nhrp/core \
			   -I$(srctree)/nhrp/ha -I$(srctree)/nhrp/platform \
			   -Wno-strict-aliasing

install:
	$(INSTALLDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) $(addprefix $(obj)/,$(progs-y)) $(DESTDIR)$(SBINDIR)
