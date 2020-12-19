#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../thirdparty/lib/perl5";
use experimental 'signatures';
use Test::More;

use WGmeta::Wireguard::Wrapper::Config;

my $wg_meta = WGmeta::Wireguard::Wrapper::Config->new($FindBin::Bin . '/Data/test/');


# parser tests
# interfaces
my @interface_list = ('mini_wg0', 'mini_wg1');
my @output = $wg_meta->get_interface_list();
ok eq_array(\@output, \@interface_list), 'interface_list';

# sections
my @sections = ('mini_wg0', 'WG_0_PEER_A_PUBLIC_KEY');
@output = $wg_meta->get_section_list('mini_wg0');
ok eq_array(\@output, \@sections), 'section_list';

# section of non existent interface
@output = $wg_meta->get_section_list('mini_wg0s');
@sections = ();
ok eq_array(\@output, \@sections), 'unknown interface';

# set
my $expected = '[Interface]
Address = 10.0.0.2/24, fdc9:281f:04d7:9ee9::2/64
ListenPort = 60000
PrivateKey = OHLK9lBHFqnu+9olAnyUN11pCeKP4uW6fwMAeRSy2F8=

[Peer]
PublicKey = WG_0_PEER_A_PUBLIC_KEY
PresharedKey = PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs = fdc9:281f:04d7:9ee9::1/128
Endpoint = 198.51.100.101:60001
#+Name = Name_by_test1

';
$wg_meta->set('mini_wg0', 'mini_wg0', 'listen-port', 60000, 1);
$wg_meta->set('mini_wg0', 'mini_wg0', 'private-key', 'OHLK9lBHFqnu+9olAnyUN11pCeKP4uW6fwMAeRSy2F8=', 1);
$wg_meta->set('mini_wg0', 'WG_0_PEER_A_PUBLIC_KEY', 'endpoint', '198.51.100.101:60001', 1);
$wg_meta->set('mini_wg0', 'WG_0_PEER_A_PUBLIC_KEY', 'name', 'Name_by_test1');

my $actual = $wg_meta->_create_config('mini_wg0', 1);
ok $actual eq $expected, 'set valid attrs';

done_testing();

