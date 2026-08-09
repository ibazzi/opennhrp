progs-y			+= opennhrp
opennhrp-objs		+= libev.o opennhrp.o nhrp_address.o nhrp_packet.o \
			   nhrp_peer.o nhrp_server.o nhrp_interface.o admin.o \
			   nhrp_extension.o nhrp_ha_wire.o nhrp_ha_auth.o \
			   nhrp_ha_seen.o nhrp_ha_managed.o \
			   nhrp_ha_hub.o nhrp_ha.o \
			   sysdep_netlink.o sysdep_pfpacket.o \
			   sysdep_syslog.o

CFLAGS_libev.o		+= -Wno-unused -Wno-comment -Wno-parentheses
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
opennhrpctl-objs	+= opennhrpctl.o nhrp_ha_auth.o nhrp_ha_managed.o \
			   nhrp_ha_join.o nhrp_ha_seen.o nhrp_ha_control.o \
			   nhrp_ha_store.o
CFLAGS_opennhrpctl.o	+= $(CFLAGS_opennhrp.o)
LIBS_opennhrpctl	+= -lcrypto

progs-y			+= opennhrp-ha
opennhrp-ha-objs	+= opennhrp-ha.o nhrp_ha_auth.o nhrp_ha_control.o \
			   nhrp_ha_store.o nhrp_ha_managed.o nhrp_ha_join.o \
			   nhrp_ha_failback.o opennhrp-ha-managed-hub.o
opennhrp-ha-objs	+= nhrp_ha_delta.o
LIBS_opennhrp-ha	+= -lcrypto

CFLAGS_EXTRA		+= -I$(srctree)/include -Wno-strict-aliasing

install:
	$(INSTALLDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) $(addprefix $(obj)/,$(progs-y)) $(DESTDIR)$(SBINDIR)
