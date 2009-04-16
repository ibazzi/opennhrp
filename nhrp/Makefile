progs-y			+= opennhrp
opennhrp-objs		+= opennhrp.o nhrp_address.o nhrp_packet.o \
			   nhrp_peer.o nhrp_interface.o signal.o admin.o \
			   sysdep_netlink.o sysdep_pfpacket.o \
			   sysdep_poll.o sysdep_syslog.o

CFLAGS_opennhrp.o	+= -DOPENNHRP_VERSION=\"$(FULL_VERSION)\" \
			   -DOPENNHRP_ADMIN_SOCKET=\"$(STATEDIR)/opennhrp.socket\"
LIBS_opennhrp		+= -lrt
ifeq ($(shell pkg-config --exists libcares && echo "yes"),yes)
CFLAGS			+=$(shell pkg-config --cflags libcares)
LIBS_opennhrp  		+=$(shell pkg-config --libs libcares)
else
LIBS_opennhrp  		+= -lcares
endif

progs-y			+= opennhrpctl
opennhrpctl-objs	+= opennhrpctl.o
CFLAGS_opennhrpctl.o	+= $(CFLAGS_opennhrp.o)

CFLAGS			+= -I$(src)/include

install::
	$(INSTALLDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) $(addprefix $(obj)/,$(progs-y)) $(DESTDIR)$(SBINDIR)

