package Wireguard::WGmeta::Cli::Router;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use Wireguard::WGmeta::Cli::Commands::Show;
use Wireguard::WGmeta::Cli::Commands::Set;
use Wireguard::WGmeta::Cli::Commands::Help;
use Wireguard::WGmeta::Cli::Commands::Enable;
use Wireguard::WGmeta::Cli::Commands::Disable;
use Wireguard::WGmeta::Cli::Commands::Apply;
use Wireguard::WGmeta::Cli::Commands::Add;

use base 'Exporter';
our @EXPORT = qw(route_command);

=head3 route_command($ref_list_input_args)

Routes the cmd (first argument of C<@ARGV>) to their implementation. The case of the commands to not matter.
Any unknown command is forwarded to L<Wireguard::WGmeta::Cli::Commands::Help>.

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
    if (!defined $cmd){
        Wireguard::WGmeta::Cli::Commands::Help->new->entry_point;
    }
    for ($cmd) {
        /^show$/ && do {
            Wireguard::WGmeta::Cli::Commands::Show->new(@cmd_args)->entry_point();
            last;
        };
        /^set$/ && do {
            Wireguard::WGmeta::Cli::Commands::Set->new(@cmd_args)->entry_point();
            last;
        };
        /^enable$/ && do {
            Wireguard::WGmeta::Cli::Commands::Enable->new(@cmd_args)->entry_point();
            last;
        };
        /^disable$/ && do {
            Wireguard::WGmeta::Cli::Commands::Disable->new(@cmd_args)->entry_point();
            last;
        };
        /^addpeer$/ && do {
            Wireguard::WGmeta::Cli::Commands::Add->new(@cmd_args)->entry_point();
            last;
        };
        /^apply$/ && do {
            Wireguard::WGmeta::Cli::Commands::Apply->new(@cmd_args)->entry_point();
            last;
        };
        Wireguard::WGmeta::Cli::Commands::Help->new->entry_point;
    }
}

1;