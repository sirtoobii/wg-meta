package Wireguard::WGmeta::Cli::Commands::Command;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

use Wireguard::WGmeta::Utils;
use constant WIREGUARD_HOME => '/etc/wireguard/';

sub new($class, @input_arguments) {
    my $self = {
        'input_args' => \@input_arguments
    };
    # check if env var is available
    if (defined($ENV{'WIREGUARD_HOME'})) {
        $self->{wireguard_home} = $ENV{'WIREGUARD_HOME'};
    }
    else {
        $self->{wireguard_home} = WIREGUARD_HOME;
    }
    bless $self, $class;
    return $self;
}

sub entry_point($self) {
    die 'Please instantiate the actual implementation';
}

sub cmd_help($self) {
    die 'Please instantiate the actual implementation';
}

sub check_privileges($self) {
    if (not -w $self->{wireguard_home}) {
        my $username = getpwuid($<);
        die "Insufficient privileges - `$username` has rw no permissions to `$self->{wireguard_home}`. You probably forgot `sudo`";
    }
}

sub _retrieve_or_die($self, $ref_array, $idx) {
    my @arr = @{$ref_array};
    eval {return $arr[$idx]} or $self->cmd_help();
}

1;