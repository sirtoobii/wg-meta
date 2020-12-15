package WGmeta::Cli::Router;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use WGmeta::Cli::Commands::Show;
use WGmeta::Cli::Commands::Set;
#use WGmeta::Cli::Commands::Help;

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
    my @cmd_args = @{$ref_list_input_args};
    if (lc $cmd_args[0] eq 'show') {
        WGmeta::Cli::Commands::Show->new(splice @cmd_args, 1)->entry_point();
    }
    elsif (lc $cmd_args[0] eq 'set') {
        WGmeta::Cli::Commands::Set->new(splice @cmd_args, 1)->entry_point();
    }
    else {
        WGmeta::Cli::Commands::Help->new(splice @cmd_args, 1)->entry_point();
    }
}

1;