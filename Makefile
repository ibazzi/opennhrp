# Makefile - one file to rule them all, one file to bind them
#
# Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it 
# under the terms of the GNU General Public License version 3 as published
# by the Free Software Foundation. See http://www.gnu.org/ for details.

VERSION=0.2

ifneq ($(shell which colorgcc),)
CC=colorgcc
else
CC=gcc
endif
INSTALL=install
INSTALLDIR=$(INSTALL) -d

CFLAGS=-Wall -Wstrict-prototypes -std=gnu99 -O -g
LDFLAGS=-g

DESTDIR=
SBINDIR=/usr/sbin
CONFDIR=/etc/opennhrp
MANDIR=/usr/share/man
DOCDIR=/usr/share/doc/opennhrp

SUBDIRS=nhrp etc man

.PHONY: compile install clean all

all: compile

compile install clean::
	@for i in $(SUBDIRS); do $(MAKE) $(MFLAGS) -C $$i $(MAKECMDGOALS); done

install::
	$(INSTALLDIR) $(DESTDIR)$(DOCDIR)
	$(INSTALL) README $(DESTDIR)$(DOCDIR)

dist:
	svn-clean
	(TOP=`pwd` && cd .. && ln -s $$TOP opennhrp-$(VERSION) && \
	 tar --exclude '*/.svn*' -cjvf opennhrp-$(VERSION).tar.bz2 opennhrp-$(VERSION)/* && \
	 rm opennhrp-$(VERSION))

.EXPORT_ALL_VARIABLES:
