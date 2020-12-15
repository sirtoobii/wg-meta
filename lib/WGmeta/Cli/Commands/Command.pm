package WGmeta::Cli::Commands::Command;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

use base 'Exporter';
our @EXPORT = qw(entry_point);


sub new($class, @input_arguments) {
    my $self = {
        'input_args' => \@input_arguments
    };

    bless $self, $class;

    return $self;
}

sub entry_point($self) {
    die 'Please instantiate the actual implementation';
}

sub cmd_help() {
    die 'Please instantiate the actual implementation';
}

sub _retrieve_or_die($self, $ref_array, $idx) {
    my @arr = @{$ref_array};
    eval {return $arr[$idx]} or $self->cmd_help();
}

1;