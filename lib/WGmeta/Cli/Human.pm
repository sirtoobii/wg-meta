=pod

=head1 NAME

A small collection of utility functions to convert machine-readable out to human friendly

=head1 METHODS

=cut
package WGmeta::Cli::Human;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use base 'Exporter';
our @EXPORT = qw(disabled2human bits2human return_self timestamp2human);


sub disabled2human($state) {
    if ($state == 1) {
        return "yes";
    }
    return "no";
}

=head3 bits2human($n_bits)

Takes a number of bits and coverts it to a human readable amount of MiB

B<Parameters>

=over 1

=item

C<$n_bits> A number of bits

=back

B<Returns>

$n_bits * 1_000_000 . "MiB"

=cut
sub bits2human($n_bits) {
    # this calculation is probably not correct, however, I found no reference on what is actually the unit of the wg show dump...
    return sprintf("%.2f %s", $n_bits / 1_000_000, "MiB");
}

=head3 timestamp2human($timestamp)

Takes a unix timestamp and puts it in a human relatable form (delta from now)

B<Parameters>

=over 1

=item

C<$timestamp> Int or string containing a unix timestamp

=back

B<Returns>

A string describing how long ago this timestamp was

=cut
sub timestamp2human($timestamp) {
    my $int_timestamp = int($timestamp);
    if ($int_timestamp == 0) {
        return "never"
    }
    my $delta = time - $int_timestamp;
    if ($delta > 2592000) {
        return ">month ago";
    }
    if ($delta > 604800) {
        return ">week ago";
    }
    if ($delta > 86400) {
        return ">day ago";
    }
    if ($delta < 86400) {
        return sprintf("%.2f minutes ago", $delta / 60);
    }
    return $delta;
}

=head3 return_self($x)

The famous C<id()> function

B<Parameters>

=over 1

=item

C<$x> Some value or object

=back

B<Returns>

C<$x>

=cut
sub return_self($x) {
    return $x;
}

1;