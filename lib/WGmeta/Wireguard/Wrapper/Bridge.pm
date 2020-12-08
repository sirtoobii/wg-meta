package WGmeta::Wireguard::Wrapper::Bridge;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

use base 'Exporter';
our @EXPORT = qw(gen_keypair);

use Symbol 'gensym';
use IPC::Open3;

use constant FALSE => 0;
use constant TRUE => 1;


=head3 gen_keypair()

Runs the C<wg genkey> command and returns a private and the corresponding public-key

B<Returns>

Two strings private-key and public-key

=cut
sub gen_keypair() {
    my $cmd = 'priv_key=$(wg genkey) && echo $priv_key | wg pubkey && echo $priv_key';
    my (@out, undef) = run_external($cmd);
    chomp @out;
    return $out[0], $out[1];
}

=head3 run_external($command_line [, $soft_fail])

Runs an external program and throws an exception (or a warning if C<$soft_fail> is true) if the return code is != 0

B<Parameters>

=over 1

=item *

C<$command_line> Complete commandline for the external program to execute.

=item *

C<[, $soft_fail]> If set to true, a warning is thrown instead of an exception

=back

B<Returns>

Returns two lists if all lines of I<STDout> and I<STDerr>

=cut
sub run_external($command_line, $soft_fail = FALSE) {
    my $pid = open3(my $std_in, my $std_out, my $std_err = gensym, $command_line);
    close $std_in;
    my @output = <$std_out>;
    my @err = <$std_err>;
    close $std_out;
    close $std_err;

    waitpid($pid, 0);

    my $child_exit_status = $? >> 8;
    if ($child_exit_status != 0) {
        if ($soft_fail == TRUE) {
            warn "Command `$command_line` failed";
        }
        else {
            die "Command `$command_line` failed";
        }

    }
    return @output, @err;
}

1;