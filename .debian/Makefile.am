DEBIAN/control:
	$(PERL) -i -p -e 's/\d\.\d.\d/'$(PACKAGE_VERSION)'/g;' $@

copy_files:
	test -d wg-meta_$(PACKAGE_VERSION) || mkdir wg-meta_$(PACKAGE_VERSION)
	test -d wg-meta_$(PACKAGE_VERSION)/usr || mkdir wg-meta_$(PACKAGE_VERSION)/usr
	test -d wg-meta_$(PACKAGE_VERSION)/usr/local || mkdir wg-meta_$(PACKAGE_VERSION)/usr/local
	test -d wg-meta_$(PACKAGE_VERSION)/usr/local/bin || mkdir wg-meta_$(PACKAGE_VERSION)/usr/local/bin

	cp ../bin/wg-meta wg-meta_$(PACKAGE_VERSION)/usr/local/bin
	
	test -d wg-meta_$(PACKAGE_VERSION)/usr/share || mkdir wg-meta_$(PACKAGE_VERSION)/usr/share
	test -d wg-meta_$(PACKAGE_VERSION)/usr/share/perl5 || mkdir wg-meta_$(PACKAGE_VERSION)/usr/share/perl5
	
	cp -r ../lib/WGmeta wg-meta_$(PACKAGE_VERSION)/usr/share/perl5

deb: copy_files DEBIAN/control
	test -d wg-meta_$(PACKAGE_VERSION)/DEBIAN | mkdir wg-meta_$(PACKAGE_VERSION)/DEBIAN
	cp DEBIAN/control wg-meta_$(PACKAGE_VERSION)/DEBIAN
	dpkg-deb --build wg-meta_$(PACKAGE_VERSION)

	
deb-clean:
	rm -f -r wg-meta_$(PACKAGE_VERSION)
	rm -f wg-meta_$(PACKAGE_VERSION).deb
