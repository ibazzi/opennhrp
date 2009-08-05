ETCFILES := opennhrp.conf opennhrp-script racoon-ph1down.sh

install:
	$(INSTALLDIR) $(DESTDIR)$(CONFDIR)
	$(INSTALL) $(addprefix $(src)/,$(ETCFILES)) $(DESTDIR)$(CONFDIR)
