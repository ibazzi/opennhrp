# Makefile - one file to rule them all, one file to bind them
#
# Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it 
# under the terms of the GNU General Public License version 3 as published
# by the Free Software Foundation. See http://www.gnu.org/ for details.

MAN5PAGES = opennhrp.conf.5
MAN8PAGES = opennhrp.8 opennhrp-script.8

compile::

install::
	$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man5 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) $(MAN5PAGES) $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) $(MAN8PAGES) $(DESTDIR)$(MANDIR)/man8

clean::
