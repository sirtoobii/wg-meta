package WGmeta::Cli::Commands::Set;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

require WGmeta::Cli::Commands::Command;
use WGmeta::Wireguard::Wrapper::Config;
our @ISA = qw(WGmeta::Cli::Commands::Command);

use constant WIREGUARD_HOME => '/home/tobias/Documents/wg-meta/t/Data/';

sub new($class, @input_arguments) {
    my $self = $class->SUPER::new(@input_arguments);

    my $wg_home;
    # check if env var is available
    if (defined($ENV{'WIREGUARD_HOME'})) {
        $wg_home = $ENV{'WIREGUARD_HOME'};
    }
    else {
        $wg_home = WIREGUARD_HOME;
    }

    $self->{'wg_meta'} = WGmeta::Wireguard::Wrapper::Config->new($wg_home);

    bless $self, $class;

    return $self;
}

sub entry_point($self) {
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
sub cmd_help($self) {}

sub _set_values($self, $interface, $identifier, $ref_hash_values) {
    for my $key (keys %{$ref_hash_values}) {
        $self->{wg_meta}->set($interface, $identifier, $key, $ref_hash_values->{$key});
    }
}