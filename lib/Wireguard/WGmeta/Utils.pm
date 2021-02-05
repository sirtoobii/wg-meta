package Wireguard::WGmeta::Utils;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use Time::HiRes qw(stat);
use Digest::MD5 qw(md5);
use base 'Exporter';
our @EXPORT = qw(read_dir read_file write_file generate_ip_list get_mtime compute_md5_checksum);

use constant LOCK_SH => 1;
use constant LOCK_EX => 2;

use Scalar::Util qw (openhandle);

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

=head3 read_file($path)

Reads a file given by a C<$path> into a string. Applies a shared lock on the file while reading

B<Parameters>

=over 1

=item

C<$path> Path to file

=back

B<Raises>

Exception if the file is somehow inaccessible.

B<Returns>

File contents as string

=cut
sub read_file($path, $path_is_fh = undef) {
    my $fh;
    unless (defined $path_is_fh) {
        open $fh, '<', $path or die "Can't open `$path`: $!";
        # try to get a shared lock
        flock $fh, LOCK_SH or die "Could not get shared lock on file `$path`: $!";
    } else {
        $fh = $path;
    }
    my $file_content = do {
        local $/;
        <$fh>
    };
    close $fh unless (defined $path_is_fh);
    return $file_content;
}

=head3 write_file($path, $content)

Writes C<$content> to C<$file> while having an exclusive lock.

B<Parameters>

=over 1

=item

C<$path> Path to file

=item

C<$content> File content

=back

B<Returns>

None

=cut
sub write_file($path, $content, $path_is_fh = undef) {
    my $fh;
    unless (defined $path_is_fh) {
        open $fh, '>', $path or die "Could not open `$path` for writing: $!";

        # try to get an exclusive lock
        flock $fh, LOCK_EX or die "Could not get an exclusive lock on file `$path`: $!";
    } else {
        $fh = $path;
    }
    my $s = openhandle($fh);
    my $p = tell($fh);
    if ($p != 0){
        print "fatal";
    }
    print $fh $content;
    close $fh unless (defined $path_is_fh);
}

sub get_mtime($path) {
    my @stat = stat($path);
    return (defined($stat[9])) ? "$stat[9]" : "0";
}

sub compute_md5_checksum($input) {
    my $str = substr(md5($input), 0, 4);
    return unpack 'L', $str; # Convert to 4-byte integer
}

sub generate_ip_list($network_id, $subnet_size) {
    # thanks to https://www.perl.com/article/creating-ip-address-tools-from-scratch/

    my %ip_list;
    my @bytes = split /\./, $network_id;
    my $start_decimal = $bytes[0] * 2 ** 24 + $bytes[1] * 2 ** 16 + $bytes[2] * 2 ** 8 + $bytes[3];
    my $bits_remaining = 32 - $subnet_size;
    my $end_decimal = $start_decimal + 2 ** $bits_remaining - 1;

    while ($start_decimal <= $end_decimal) {
        my @bytes = unpack 'CCCC', pack 'N', $start_decimal;
        my $ipv4 = (join '.', @bytes) . '/32';
        $ip_list{$ipv4} = undef;
        $start_decimal++;
    }
    return \%ip_list;
}

1;