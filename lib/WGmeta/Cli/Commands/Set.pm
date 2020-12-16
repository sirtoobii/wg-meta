package WGmeta::Cli::Commands::Set;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

require WGmeta::Cli::Commands::Command;
use WGmeta::Wireguard::Wrapper::Config;
our @ISA = qw(WGmeta::Cli::Commands::Command);

use constant WIREGUARD_HOME => '/home/tobias/Documents/wg-meta/t/Data/';
use constant TRUE => 1;
use constant FALSE => 0;

sub new($class, @input_arguments) {
    my $self = $class->SUPER::new(@input_arguments);

    bless $self, $class;

    return $self;
}

sub entry_point($self) {
    if ($self->_retrieve_or_die($self->{input_args}, 0) eq 'help') {
        $self->cmd_help();
        return
    }
    else {
        my $wg_home;
        # check if env var is available
        if (defined($ENV{'WIREGUARD_HOME'})) {
            $wg_home = $ENV{'WIREGUARD_HOME'};
        }
        else {
            $wg_home = WIREGUARD_HOME;
        }

        # would be very nice if we can set a type hint here...possible?
        $self->{'wg_meta'} = WGmeta::Wireguard::Wrapper::Config->new($wg_home);
        $self->_run_command();
    }
}

sub _run_command($self) {
    my $interface = $self->_retrieve_or_die($self->{input_args}, 0);
    my $offset = -1;
    my $cur_start = 0;
    my @input_args = @{$self->{input_args}};
    for my $value (@{$self->{input_args}}) {
        if ($value eq 'peer') {

            # if there is just one peer we skip here
            if ($offset != 0) {
                $self->_apply_change_set($interface, @input_args[$cur_start ... $offset]);
                $cur_start = $offset;
            }
        }
        $offset++;
    }
    $self->_apply_change_set($interface, @input_args[$cur_start ... $offset]);
    $self->{wg_meta}->commit();
}

# internal method to split commandline args into "change-sets".
# This method is fully* compatible with the `wg set`-syntax.
# *exception: remove
sub _apply_change_set($self, $interface, @change_set) {
    my $offset = 1;
    my $identifier;
    if ($self->_retrieve_or_die(\@change_set, 1) eq 'peer') {
        # this could be either a public key or alias
        $identifier = $self->_retrieve_or_die(\@change_set, 2);

        # try to resolve alias
        eval {
            $identifier = $self->{wg_meta}->translate_alias($interface, $identifier);
        };

        $offset += 2;
    }
    else {
        $identifier = $interface;
    }
    my @value_keys = splice @change_set, $offset;

    if (@value_keys % 2 != 0) {
        die "Odd number of value/key-pairs";
    }
    # parse key/value - pairs into a hash
    my %args;
    my $idx = 0;

    while ($idx < @value_keys) {
        $args{$value_keys[$idx]} = $value_keys[$idx + 1];
        $idx += 2;
    }
    #     print "Got command set:
    #     interface: $interface
    #     ident: $identifier
    #     attrs: @value_keys
    # ";

    $self->_set_values($interface, $identifier, \%args);
}
sub cmd_help($self) {
    print "Usage: wg-meta set <interface> [attr1 value1] [attr2 value2] [peer {alias|public-key}] [attr1 value1] [attr2 value2] ...\n"
}

sub _set_values($self, $interface, $identifier, $ref_hash_values) {
    for my $key (keys %{$ref_hash_values}) {
        $self->{wg_meta}->set($interface, $identifier, $key, $ref_hash_values->{$key}, TRUE, \&_forward);
    }
}

sub _forward($interface, $identifier, $attribute, $value) {
    # this is just as stub
    print("Forwarded to original wg command: `$attribute = $value`");
}