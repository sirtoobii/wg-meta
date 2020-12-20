package WGmeta::Cli::Commands::Apply;
use strict;
use warnings FATAL => 'all';

use experimental 'signatures';

use parent 'WGmeta::Cli::Commands::Command';

use WGmeta::Wireguard::Wrapper::Bridge;


sub entry_point($self) {
    if ($self->_retrieve_or_die($self->{input_args}, 0) eq 'help') {
        $self->cmd_help();
    }
    $self->_run_command();
}

sub _run_command($self){
    my $interface = $self->_retrieve_or_die($self->{input_args}, 0);
    # this line is a work-around since `wg syncconf` does not accept from STD_IN (anymore?).
    # However, activating this line does potentially leaks the interface private-key to unprivileged users...
    # my $cmd_line = "sudo wg-quick strip $interface > /tmp/stripped_conf && sudo wg syncconf $interface /tmp/stripped_conf && rm /tmp/stripped_conf";
    my $cmd_line = "wg syncconf $interface <(wg-quick strip $interface)";
    run_external($cmd_line);
}

sub cmd_help($self) {
    print "Usage: wg-meta apply <interface>\n";
    exit;
}

1;