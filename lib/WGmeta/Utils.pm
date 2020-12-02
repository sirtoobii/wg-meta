package WGmeta::Utils;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use base 'Exporter';
our @EXPORT = qw(read_dir read_file);


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

sub read_file($path) {
    open my $fh, '<', $path or die "Can't open file $!";
    my $file_content = do {
        local $/;
        <$fh>
    };
    return $file_content;
}

1;