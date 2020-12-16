package WGmeta::Cli::Commands::Help;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

require WGmeta::Cli::Commands::Command;
our @ISA = qw(WGmeta::Cli::Commands::Command);


sub entry_point($self) {
    $self->cmd_help();
}

sub cmd_help($self) {
    print "wg-meta - An approach to add meta data to the Wireguard configuration\n";
    print "Usage: wg-meta <cmd> [<args>]\n";
    print "Available subcommands:\n";
    print "\t show: Shows the current configuration paired with available metadata\n";
    print "\t set:  Sets configuration attributes\n";
    print "You may pass `help` to any of these subcommands to view their usage";
    exit();
}
1;