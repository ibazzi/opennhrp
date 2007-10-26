# Makefile - one file to rule them all, one file to bind them
#
# Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it 
# under the terms of the GNU General Public License version 3 as published
# by the Free Software Foundation. See http://www.gnu.org/ for details.

CC=colorgcc
CFLAGS=-Wall -Wstrict-prototypes -std=gnu99 -g
LDFLAGS=-g

TARGETS=opennhrp

OPENNHRP_OBJ=\
	opennhrp.o \
	nhrp_packet.o \
	nhrp_peer.o \
	nhrp_interface.o \
	sysdep_netlink.o \
	sysdep_poll.o \
	sysdep_syslog.o

ALL_OBJ=$(OPENNHRP_OBJ)

all: $(TARGETS)

opennhrp: $(OPENNHRP_OBJ)

clean:
	rm -f $(ALL_OBJ) $(TARGETS)
