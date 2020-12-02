package WGmeta::Wireguard::Wrapper::Show;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

use constant FALSE => 0;
use constant TRUE => 1;
use Data::Dumper;
use WGmeta::Utils;

sub new($class) {
    my $self = {
        'parsed_show' => wg_show_dump_parser(read_wg_show('/home/tobias/Documents/wg-meta/t/Data/wg_show_dump'))
    };

    bless $self, $class;

    return $self;
}

sub read_wg_show($dummy_path = undef) {
    if (defined($dummy_path)) {
        return read_file($dummy_path);
    }
    else {
        die("Not supported yet");
    }
}

sub wg_show_dump_parser($input) {
    my $interface = '';
    my $parsed_show = {};
    my @keys_interface = qw(interface private-key public-key listen-port fwmark);
    my @keys_peer = qw(interface public-key preshared-key endpoint allowed-ips latest-handshake transfer-rx transfer-tx persistent-keepalive);
    for my $line (split /\n/, $input) {
        my @split_line = split /\s/, $line;
        unless ($split_line[0] eq $interface) {
            $interface = $split_line[0];
            # handle interface
            my $idx = 0;
            map {$parsed_show->{$interface}->{$interface}->{$_} = $split_line[$idx];
                $idx++} @keys_interface;
        }
        else {
            my %peer;
            my $idx = 0;
            map {$peer{$_} = $split_line[$idx];
                $idx++;} @keys_peer;
            $parsed_show->{$interface}->{$peer{'public-key'}} = \%peer;
        }
    }
    return $parsed_show;
}

sub get_interface_list($self) {
    return keys %{$self->{parsed_show}};
}

sub get_interface_section($self, $interface, $identifier) {
    if (exists($self->{parsed_show}{$interface}{$identifier})) {
        return %{$self->{parsed_show}{$interface}{$identifier}};
    }
    else {
        return ();
    }
}

sub get_section_list($self, $interface) {
    if (exists($self->{parsed_show}{$interface})) {
        return keys %{$self->{parsed_show}{$interface}};
    }
    else {
        return {};
    }
}

sub dump($self) {
    print Dumper $self->{parsed_show};
}


1;