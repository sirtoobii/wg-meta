DEBIAN/control:
	$(PERL) -i -p -e 's/\d\.\d.\d/'$(PACKAGE_VERSION)'/g;' $@

copy_files:
	test -d wg-meta-$(PACKAGE_VERSION) || mkdir wg-meta-$(PACKAGE_VERSION)
	test -d wg-meta-$(PACKAGE_VERSION)/usr || mkdir wg-meta-$(PACKAGE_VERSION)/usr
	test -d wg-meta-$(PACKAGE_VERSION)/usr/local || mkdir wg-meta-$(PACKAGE_VERSION)/usr/local
	test -d wg-meta-$(PACKAGE_VERSION)/usr/local/bin || mkdir wg-meta-$(PACKAGE_VERSION)/usr/local/bin

	cp ../bin/wg-meta wg-meta-$(PACKAGE_VERSION)/usr/local/bin
	
	test -d wg-meta-$(PACKAGE_VERSION)/usr/share || mkdir wg-meta-$(PACKAGE_VERSION)/usr/share
	test -d wg-meta-$(PACKAGE_VERSION)/usr/share/perl5 || mkdir wg-meta-$(PACKAGE_VERSION)/usr/share/perl5
	
	cp -r ../lib/WGmeta wg-meta-$(PACKAGE_VERSION)/usr/share/perl5

deb: copy_files DEBIAN/control
	test -d wg-meta-$(PACKAGE_VERSION)/DEBIAN | mkdir wg-meta-$(PACKAGE_VERSION)/DEBIAN
	cp DEBIAN/control wg-meta-$(PACKAGE_VERSION)/DEBIAN
	dpkg-deb --build wg-meta-$(PACKAGE_VERSION)

	
deb-clean:
	rm -f -r wg-meta-$(PACKAGE_VERSION)
	rm -f wg-meta-$(PACKAGE_VERSION).deb
