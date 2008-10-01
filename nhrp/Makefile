# Makefile - one file to rule them all, one file to bind them
#
# Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# See http://www.gnu.org/ for details.

TARGETS = opennhrp opennhrpctl

opennhrp_OBJS = \
	opennhrp.o \
	nhrp_address.o \
	nhrp_packet.o \
	nhrp_peer.o \
	nhrp_interface.o \
	signal.o \
	admin.o \
	sysdep_netlink.o \
	sysdep_pfpacket.o \
	sysdep_poll.o \
	sysdep_syslog.o

opennhrpctl_OBJS = \
	opennhrpctl.o

ALL_OBJS = $(opennhrp_OBJS) $(opennhrpctl_OBJS)

CFLAGS += -I../include -DOPENNHRP_ADMIN_SOCKET=\"$(STATEDIR)/opennhrp.socket\"

all: $(TARGETS)

opennhrp: $(opennhrp_OBJS)

opennhrpctl: $(opennhrpctl_OBJS)

clean::
	@rm -f $(TARGETS) $(ALL_OBJS)

install::
	$(INSTALLDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) $(TARGETS) $(DESTDIR)$(SBINDIR)

