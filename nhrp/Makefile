# Makefile - one file to rule them all, one file to bind them
#
# Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it 
# under the terms of the GNU General Public License version 3 as published
# by the Free Software Foundation. See http://www.gnu.org/ for details.

TARGETS = opennhrp

opennhrp_OBJS = \
	opennhrp.o \
	nhrp_address.o \
	nhrp_packet.o \
	nhrp_peer.o \
	nhrp_interface.o \
	signal.o \
	sysdep_netlink.o \
	sysdep_poll.o \
	sysdep_syslog.o

ALL_OBJS = $(opennhrp_OBJS)

CFLAGS += -I../include

opennhrp: $(opennhrp_OBJS)

clean::
	@rm -f $(TARGETS) $(ALL_OBJS)

install::
	$(INSTALLDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) $(TARGETS) $(DESTDIR)$(SBINDIR)

