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
FORMAT_FILES := $(shell find . -type f \( -name '*.c' -o -name '*.h' \) \
		-not -path './.git/*' -not -path './build/*' -print)

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
	$(INSTALL) README.md $(DESTDIR)$(DOCDIR)

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
