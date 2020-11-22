package wg_meta::Utils;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use base 'Exporter';
our @EXPORT = qw(read_dir);


sub read_dir($path, $pattern) {
    opendir(DIR, $path) or die "Could not open $path\n";
    my @files;

    while (my $file = readdir(DIR)) {
        if ($file =~ $pattern) {
            push @files, $path . $file;
        }
    }
    closedir(DIR);
    return @files;
}

1;