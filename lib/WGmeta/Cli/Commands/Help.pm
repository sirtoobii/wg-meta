package WGmeta::Cli::Commands::Help;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

require WGmeta::Cli::Commands::Command;
our @ISA = qw(WGmeta::Cli::Commands::Command);


sub entry_point($self) {
    print "placeholder show\n";
}

sub cmd_help($self) {}
1;