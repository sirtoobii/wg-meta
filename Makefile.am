#  Copyright (C) 2020 Tobias Bossert

AUTOMAKE_OPTIONS =  foreign

SUBDIRS = bin lib .debian

PERLTESTS := $(shell find -L t -name "*.t")
PM := $(shell find -L lib -name "*.pm")

EXTRA_DIST = VERSION cpanfile COPYRIGHT LICENSE CHANGES AUTHORS $(wildcard t/*.t) $(POD) $(wildcard t/Data/test/*.conf) t/Data/test/wg_show_dump
YEAR := $(shell date +%Y)
DATE := $(shell date +%Y-%m-%d)

datadir = $(prefix)

README.md COPYRIGHT: VERSION
	$(PERL) -i -p -e 's/(#VERSION#|\d+\.\d+\.\d+[^.\s]*)/$(PACKAGE_VERSION)/g;s/(#YEAR#|20[1-9]\d)/$(YEAR)/g;s/(#DATE#|20[1-9]\d-[01]\d-[0-3]\d)/$(DATE)/g;' $@


test:
	prove -w