##
# Building opennhrp

PACKAGE := opennhrp
VERSION := 0.15

##
# Default directories

DESTDIR?=
SBINDIR=/usr/sbin
CONFDIR=/etc/opennhrp
MANDIR=/usr/share/man
DOCDIR=/usr/share/doc/opennhrp
STATEDIR=/var/run

export DESTDIR SBINDIR CONFDIR MANDIR DOCDIR STATEDIR

##
# Top-level rules and targets

targets		:= nhrp/ etc/ man/

##
# Include all rules and stuff

include Make.rules

##
# Top-level targets

CLANG_FORMAT ?= clang-format-18
FORMAT_FILES := nhrp/core/nhrp_extension.c nhrp/core/nhrp_extension.h \
		nhrp/opennhrp.c nhrp/opennhrp_ha_process.c \
		nhrp/opennhrp_ha_process.h nhrp/platform/sysdep_syslog.c \
		nhrp/ha/nhrp_ha.c nhrp/ha/nhrp_ha.h nhrp/ha/nhrp_ha_wire.c \
		nhrp/ha/nhrp_ha_wire.h nhrp/ha/nhrp_ha_auth.c \
		nhrp/ha/nhrp_ha_auth.h nhrp/ha/nhrp_ha_seen.c \
		nhrp/ha/nhrp_ha_seen.h nhrp/ha/nhrp_ha_control.c \
		nhrp/ha/nhrp_ha_control.h nhrp/ha/nhrp_ha_store.c \
		nhrp/ha/nhrp_ha_store.h nhrp/ha/nhrp_ha_delta.c \
		nhrp/ha/nhrp_ha_delta.h nhrp/ha/nhrp_ha_failback.c \
		nhrp/ha/nhrp_ha_failback.h nhrp/ha/nhrp_ha_managed.c \
		nhrp/ha/nhrp_ha_managed.h nhrp/ha/nhrp_ha_join.c \
		nhrp/ha/nhrp_ha_join.h nhrp/ha/nhrp_ha_hub.c \
		nhrp/ha/nhrp_ha_hub.h nhrp/opennhrpctl.c \
		nhrp/opennhrp-ha.c nhrp/ha/opennhrp-ha-managed-hub.c \
		nhrp/ha/opennhrp-ha-managed-hub.h \
		tests/test_extensions.c tests/test_ha_wire.c \
		tests/test_ha_auth.c tests/test_ha_seen.c tests/test_ha_control.c \
		tests/test_ha_store.c \
		tests/test_ha_delta.c \
		tests/test_ha_failback.c \
		tests/test_ha_managed.c \
		tests/test_ha_join.c \
		tests/test_coordinator.c

.PHONY: test format check-format tests-clean


test:
	$(MAKE) compile
	$(MAKE) -C tests test

format:
	$(CLANG_FORMAT) -i $(FORMAT_FILES)

check-format:
	$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_FILES)

install:
	$(INSTALLDIR) $(DESTDIR)$(DOCDIR)
	$(INSTALL) README $(DESTDIR)$(DOCDIR)

deb:
	rm -rf build/src
	mkdir -p build/src
	find . -maxdepth 1 ! -name '.' ! -name 'build' ! -name '.git' -exec cp -a {} build/src/ \;
	cd build/src && dpkg-buildpackage -us -uc -b
	rm -rf build/src

clean: clean-build tests-clean

tests-clean:
	$(MAKE) -C tests clean

clean-build:
	rm -rf build
