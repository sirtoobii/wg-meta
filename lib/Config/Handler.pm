package Config::Handler;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use Data::Dumper;

use Kwalify qw(validate);
use YAML;

use constant FALSE => 0;
use constant TRUE => 1;


sub new($class, $config_path) {
    my $self = {
        'parsed_config' => read_config($config_path)
    };

    bless $self, $class;

    return $self;
}

sub get_config_entry($self, $key) {
    return $self->{parsed_config}->{config}->{$key};
}
sub dump_config($self){
    Dump $self->{parsed_config};
}

sub read_config($path) {
    return YAML::LoadFile($path);
}
1;