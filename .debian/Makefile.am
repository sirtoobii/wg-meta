DEBIAN/control: ../VERSION
	$(PERL) -i -p -e 's/\d\.\d.\d/'$(PACKAGE_VERSION)'/g;' $@

copy_files:
	test -d wg-meta-$(PACKAGE_VERSION) || mkdir wg-meta-$(PACKAGE_VERSION)
	test -d wg-meta-$(PACKAGE_VERSION)/usr || mkdir wg-meta-$(PACKAGE_VERSION)/usr
	test -d wg-meta-$(PACKAGE_VERSION)/usr/local || mkdir wg-meta-$(PACKAGE_VERSION)/usr/local
	test -d wg-meta-$(PACKAGE_VERSION)/usr/local/bin || mkdir wg-meta-$(PACKAGE_VERSION)/usr/local/bin

	cp ../bin/wg-meta wg-meta-$(PACKAGE_VERSION)/usr/local/bin

	test -d wg-meta-$(PACKAGE_VERSION)/usr/share || mkdir wg-meta-$(PACKAGE_VERSION)/usr/share
	test -d wg-meta-$(PACKAGE_VERSION)/usr/share/perl5 || mkdir wg-meta-$(PACKAGE_VERSION)/usr/share/perl5

	cp -r ../lib/Wireguard wg-meta-$(PACKAGE_VERSION)/usr/share/perl5

	# bash completion
	test -d wg-meta-$(PACKAGE_VERSION)/usr/share || mkdir wg-meta-$(PACKAGE_VERSION)/usr/share
	test -d wg-meta-$(PACKAGE_VERSION)/usr/share/bash-completion || mkdir wg-meta-$(PACKAGE_VERSION)/usr/share/bash-completion
	test -d wg-meta-$(PACKAGE_VERSION)/usr/share/bash-completion/completions || mkdir wg-meta-$(PACKAGE_VERSION)/usr/share/bash-completion/completions

	cp -r ../wg-meta_completions.sh wg-meta-$(PACKAGE_VERSION)/usr/share/bash-completion/completions/wg-meta

deb: copy_files DEBIAN/control
	test -d wg-meta-$(PACKAGE_VERSION)/DEBIAN | mkdir wg-meta-$(PACKAGE_VERSION)/DEBIAN
	cp DEBIAN/control wg-meta-$(PACKAGE_VERSION)/DEBIAN
	dpkg-deb --build wg-meta-$(PACKAGE_VERSION)

deb-clean:
	rm -f -r wg-meta-$(PACKAGE_VERSION)
	rm -f wg-meta-$(PACKAGE_VERSION).deb
