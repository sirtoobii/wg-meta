package WGmeta::Cli::Router;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use WGmeta::Cli::Commands::Show;
use WGmeta::Cli::Commands::Set;
use WGmeta::Cli::Commands::Help;

use base 'Exporter';
our @EXPORT = qw(route_command);

=head3 route_command($ref_list_input_args)

Routes the cmd (first argument of C<@ARGV>) to their implementation. The case of the commands to not matter.
Any unknown command is forwarded to L<WGmeta::Cli::Commands::Help>.

B<Parameters>

=over 1

=item

C<$ref_list_input_args> Reference to C<@ARGV>)

=back

B<Returns>

None

=cut
sub route_command($ref_list_input_args) {
    my ($cmd,@cmd_args) = @$ref_list_input_args;
    for ($cmd) {
        /^show$/ && do {
            WGmeta::Cli::Commands::Show->new(@cmd_args)->entry_point();
            last;
        };
        /^set$/ && do {
            WGmeta::Cli::Commands::Set->new(@cmd_args)->entry_point();
            last;
        };
        WGmeta::Cli::Commands::Help->new->entry_point;
    }
}

1;