package Wireguard::WGmeta::Utils;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use Time::HiRes qw(stat);
use Digest::MD5 qw(md5);
use base 'Exporter';
our @EXPORT = qw(read_dir read_file write_file generate_ipv4_list get_mtime compute_md5_checksum);

use constant LOCK_SH => 1;
use constant LOCK_EX => 2;

=head3 read_dir($path, $pattern)

Returns a list of all files in a director matching C<$pattern>

B<Parameters>

=over 1

=item

C<$path> Path to directory

=item

C<$pattern> Regex pattern (and make sure to escape with `qr` -> e.g I<qr/.*\.conf$/>)

=back

B<Returns>

A list of matching files, possibly empty

=cut
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

=head3 read_file($path [, $path_is_fh = undef])

Reads a file given by a C<$path> into a string. Applies a shared lock on the file while reading. C<$path> can also
reference an open filehandle for external control over locks and cursor. If this is the case, set C<$path_is_fh> to True.

B<Parameters>

=over 1

=item

C<$path> Path to file

=item

C[$path_is_fh = undef]> Set to True if C<$path> is an open filehandle (at least for reading).

=back

B<Raises>

Exception if the file is somehow inaccessible or it was unable to acquire the lock

B<Returns>

File contents as string

=cut
sub read_file($path, $path_is_fh = undef) {
    my $fh;
    unless (defined $path_is_fh) {
        open $fh, '<', $path or die "Can't open `$path`: $!";
        # try to get a shared lock
        flock $fh, LOCK_SH or die "Could not get shared lock on file `$path`: $!";
    }
    else {
        $fh = $path;
    }
    my $file_content = do {
        local $/;
        <$fh>
    };
    close $fh unless (defined $path_is_fh);
    return $file_content;
}

=head3 write_file($path, $content [, $path_is_fh = undef])

Writes C<$content> to C<$file> while having an exclusive lock. C<$path> can also
reference an open filehandle for external control over locks and cursor. If this is the case, set C<$path_is_fh> to True.

B<Parameters>

=over 1

=item

C<$path> Path to file

=item

C<$content> File content

=item

C<[$path_is_fh = undef]> Set to True if C<$path> is an open filehandle (write!)

=back

B<Raises>

Exception if the file is somehow inaccessible or it was unable to acquire the lock

B<Returns>

None

=cut
sub write_file($path, $content, $path_is_fh = undef) {
    my $fh;
    unless (defined $path_is_fh) {
        open $fh, '>', $path or die "Could not open `$path` for writing: $!";

        # try to get an exclusive lock
        flock $fh, LOCK_EX or die "Could not get an exclusive lock on file `$path`: $!";
    }
    else {
        $fh = $path;
    }
    print $fh $content;
    close $fh unless (defined $path_is_fh);
}

=head3 get_mtime($path)

Tries to extract mtime from a file. If supported by the system in milliseconds resolution.

B<Parameters>

=over 1

=item

C<$path> Path to file

=back

B<Returns>

mtime of the file. If something went wrong, "0";

=cut
sub get_mtime($path) {
    my @stat = stat($path);
    return (defined($stat[9])) ? "$stat[9]" : "0";
}

sub compute_md5_checksum($input) {
    my $str = substr(md5($input), 0, 4);
    return unpack 'L', $str; # Convert to 4-byte integer
}

sub generate_ipv4_list($network_id, $subnet_size) {
    # thanks to https://www.perl.com/article/creating-ip-address-tools-from-scratch/

    my %ip_list;
    my @bytes = split /\./, $network_id;
    my $start_decimal = $bytes[0] * 2 ** 24 + $bytes[1] * 2 ** 16 + $bytes[2] * 2 ** 8 + $bytes[3];
    my $bits_remaining = 32 - $subnet_size;
    my $end_decimal = $start_decimal + 2 ** $bits_remaining - 1;

    # exclude network_id & broadcast address
    if ($subnet_size < 31) {
        $start_decimal += 1;
        $end_decimal -= 1;
    }
    while ($start_decimal <= $end_decimal) {
        my @bytes = unpack 'CCCC', pack 'N', $start_decimal;
        my $ipv4 = (join '.', @bytes);
        $ip_list{$ipv4} = 1;
        $start_decimal++;
    }
    return \%ip_list;
}

sub extract_ipv4($ip_string) {
    my @ips = split /\,/, $ip_string;
    chomp(@ips);
    my @result;
    for my $possible_ip (@ips) {
        my @a = $possible_ip =~ /(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/g;
        push @result, [ $a[0], $a[1] ] if @a;
    }
    return \@result;
}

1;