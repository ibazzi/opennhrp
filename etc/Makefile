# Makefile - one file to rule them all, one file to bind them
#
# Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it 
# under the terms of the GNU General Public License version 3 as published
# by the Free Software Foundation. See http://www.gnu.org/ for details.

TARGETS = opennhrp.conf opennhrp-script racoon-ph1down.sh

compile::

install::
	$(INSTALLDIR) $(DESTDIR)$(CONFDIR)
	$(INSTALL) $(TARGETS) $(DESTDIR)$(CONFDIR)

clean::
