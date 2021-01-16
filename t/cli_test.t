#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../thirdparty/lib/perl5";
use experimental 'signatures';
use Test::More;

use constant TEST_DIR => $FindBin::Bin . '/Data/test/';

use Wireguard::WGmeta::Cli::Router;
use Wireguard::WGmeta::Utils;


# set wireguard home to test data
$ENV{'WIREGUARD_HOME'} = TEST_DIR;
$ENV{'IS_TESTING'} = 1;

my $initial_wg0 = '[Interface]
Address = 10.0.0.2/24, fdc9:281f:04d7:9ee9::2/64
ListenPort = 51888
PrivateKey = WG_0_PEER_B_PRIVATE_KEY

[Peer]
PublicKey = WG_0_PEER_A_PUBLIC_KEY
PresharedKey = PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs = fdc9:281f:04d7:9ee9::1/128
Endpoint = 198.51.100.101:51871
';
my $initial_wg1 = '[Interface]
Address = 10.0.0.2/24
ListenPort = 51860
PrivateKey = WG_1_PEER_B_PRIVATE_KEY

[Peer]
PublicKey = WG_1_PEER_A_PUBLIC_KEY
#+Alias = Alias1
PresharedKey = WG_1_PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs = 10.0.0.1/32
Endpoint = 198.51.100.101:51871
';


# set command
my $expected = '[Interface]
Address = 10.0.6.0/24
ListenPort = 51860
PrivateKey = WG_1_PEER_B_PRIVATE_KEY

[Peer]
PublicKey = WG_1_PEER_A_PUBLIC_KEY
#+Alias = Alias1
PresharedKey = WG_1_PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs = 10.0.6.10/32
Endpoint = test.tester.com:11234

';
# mixed cmd line
my @cmd_line = qw(set mini_wg1 address 10.0.6.0/24 peer WG_1_PEER_A_PUBLIC_KEY endpoint test.tester.com:11234 allowed-ips 10.0.6.10/32);
route_command(\@cmd_line);

my $actual = read_file(TEST_DIR . 'mini_wg1.conf');
ok $actual eq $expected, 'set command mixed';



$expected = '[Interface]
Address = 10.0.6.0/24
ListenPort = 51860
PrivateKey = WG_1_PEER_B_PRIVATE_KEY

[Peer]
PublicKey = WG_1_PEER_A_PUBLIC_KEY
#+Alias = Alias1
PresharedKey = WG_1_PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs = 10.0.6.11/32
Endpoint = test.test1.com:8324
#+Name = set_through_cli

';
# just peers but also with alias
@cmd_line = qw(set mini_wg1 peer WG_1_PEER_A_PUBLIC_KEY name set_through_cli allowed-ips 10.0.6.11/32 peer Alias1 endpoint test.test1.com:8324);
route_command(\@cmd_line);

$actual = read_file(TEST_DIR . 'mini_wg1.conf');
ok $actual eq $expected, 'set command peers with alias';

$expected = '[Interface]
Address = 10.0.6.0/24
ListenPort = 51860
PrivateKey = WG_1_PEER_B_PRIVATE_KEY

#-[Peer]
#-PublicKey = WG_1_PEER_A_PUBLIC_KEY
#-#+Alias = Alias1
#-PresharedKey = WG_1_PEER_A-PEER_B-PRESHARED_KEY
#-AllowedIPs = 10.0.6.11/32
#-Endpoint = test.test1.com:8324
#-#+Name = set_through_cli
#-#+Disabled = 1

';

# disable a peer
@cmd_line = qw(disable mini_wg1 Alias1);
route_command(\@cmd_line);

$actual = read_file(TEST_DIR . 'mini_wg1.conf');
ok $actual eq $expected, 'disable peer';

$expected = '[Interface]
Address = 10.0.6.0/24
ListenPort = 51860
PrivateKey = WG_1_PEER_B_PRIVATE_KEY

[Peer]
PublicKey = WG_1_PEER_A_PUBLIC_KEY
#+Alias = Alias1
PresharedKey = WG_1_PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs = 10.0.6.11/32
Endpoint = test.test1.com:8324
#+Name = set_through_cli
#+Disabled = 0

';

# enable a peer
@cmd_line = qw(enable mini_wg1 Alias1);
route_command(\@cmd_line);

$actual = read_file(TEST_DIR . 'mini_wg1.conf');
ok $actual eq $expected, 'and enable again peer';


done_testing();

# write back initial configs
open my $fh1, '>', TEST_DIR.'mini_wg1.conf' or die;
open my $fh2, '>', TEST_DIR.'mini_wg0.conf' or die;
# write down to file
print $fh1 $initial_wg1;
close $fh1;
# write down to file
print $fh2 $initial_wg0;
close $fh2;

1;
