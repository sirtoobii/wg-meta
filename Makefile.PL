use 5.022000;

use strict;
use warnings;
use ExtUtils::MakeMaker;
use FindBin;

WriteMakefile(
	NAME           => 'Wireguard::WGmeta',
	VERSION   => `cat VERSION`,
	ABSTRACT       => 'An approach to add metadata to the main Wireguard config',
	AUTHOR         => 'Tobias Bossert <tobib at cpan.org>',
	LICENSE        => 'mit',
	PREREQ_PM      => {},
	BUILD_REQUIRES => {},
	EXE_FILES      => [
		"bin/wg-meta"
	],
	META_MERGE     => {
		requires  => { perl => '5.22' },
		resources => {
			license    => 'https://opensource.org/licenses/mit',
			repository => 'https://github.com/sirtoobii/wg-meta',
			bugtracker => 'https://github.com/sirtoobii/wg-meta/issues'
		},
		no_index  => { directory => [ 't' ] }
	},
	test           => { TESTS => 't/*.t' }
);

sub MY::postamble {
	my $self = shift;
	return <<"EOF";

bin/wg-meta lib/Wireguard/WGmeta/Wrapper/Config.pm lib/Wireguard/WGmeta/Wrapper/Show.pm: VERSION
	\$(PERL) -i -p -e 's/\$VERSION\\s*=\\s*"[\\d|\.]*[A-z]*"/\$VERSION = "\$(VERSION)"/;' \$\@

EOF
}
