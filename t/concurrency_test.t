#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../thirdparty/lib/perl5";
use experimental 'signatures';
use Test::More;

use Wireguard::WGmeta::Wrapper::ConfigT;
use Wireguard::WGmeta::Utils;

use constant TEST_DIR => $FindBin::Bin . '/test_data/';

my $THREADS_PRESENT;
BEGIN {
    eval {
        use threads;
        use threads::shared;
        $THREADS_PRESENT = 1;
    };
}

my $initial_wg0 = read_file(TEST_DIR . 'mini_wg0.conf');
my $initial_wg1 = read_file(TEST_DIR . 'mini_wg1.conf');

my $wg_meta_outside = Wireguard::WGmeta::Wrapper::ConfigT->new(TEST_DIR);

$wg_meta_outside->add_peer('mini_wg1', 'added_outside_thread', '10.0.3.56/32', 'PUBLIC_KEY_PEER_OUTSIDE_THREAD', 'alias_out');
$wg_meta_outside->commit(1);

# multithreading test
if (defined $THREADS_PRESENT) {

    my $sync :shared;

    my $thr1 = threads->create(\&run_in_thread_1);
    my $thr2 = threads->create(\&run_in_thread_2);
    $thr1->join();
    $thr2->join();

    sub run_in_thread_1 {
        {
            lock $sync;
            my $wg_meta_t = Wireguard::WGmeta::Wrapper::ConfigT->new(TEST_DIR);
            my %integrity_hashes = (
                'WG_1_PEER_A_PUBLIC_KEY' => $wg_meta_t->calculate_sha_from_internal('mini_wg1', 'WG_1_PEER_A_PUBLIC_KEY')
            );
            $wg_meta_t->set('mini_wg1', 'WG_1_PEER_A_PUBLIC_KEY', 'name', 'Name_set_in_thread_1');
            cond_wait $sync;
            $wg_meta_t->commit(1, 0, \%integrity_hashes);
        }

    }
    sub run_in_thread_2 {
        {
            lock $sync;
            my $wg_meta_t = Wireguard::WGmeta::Wrapper::ConfigT->new(TEST_DIR);
            $wg_meta_t->set('mini_wg1', 'PUBLIC_KEY_PEER_OUTSIDE_THREAD', 'name', 'Name_set_in_thread_2');
            $wg_meta_t->commit(1);
            cond_signal $sync;
        }
    }
    my $expected_after_thread = "# This config is generated and maintained by wg-meta.
# It is strongly recommended to edit this config only through a supporting wg-meta
# implementation (e.g the wg-meta cli interface)
#
# Changes to this header are always overwritten, you can add normal comments in [Peer] and [Interface] section though.
#
# Support and issue tracker: https://github.com/sirtoobii/wg-meta
#+Checksum = 974226613

[Interface]
Address = 10.0.0.2/24
ListenPort = 51860
PrivateKey = WG_1_PEER_B_PRIVATE_KEY

[Peer]
PublicKey = WG_1_PEER_A_PUBLIC_KEY
#+Alias = Alias1
PresharedKey = WG_1_PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs = 10.0.0.1/32
Endpoint = 198.51.100.101:51871
#+Name = Name_set_in_thread_1

[Peer]
PublicKey = WG_1_PEER_B_PUBLIC_KEY
#+Alias = Alias2
PresharedKey = WG_1_PEER_B-PEER_B-PRESHARED_KEY
AllowedIPs = 10.0.0.2/32
Endpoint = 198.51.100.102:51871

[Peer]
#+Name = Name_set_in_thread_2
PublicKey = PUBLIC_KEY_PEER_OUTSIDE_THREAD
AllowedIPs = 10.0.3.56/32
#+Alias = alias_out

";
    my $s = read_file(TEST_DIR.'mini_wg1.conf');
    ok read_file(TEST_DIR.'mini_wg1.conf') eq $expected_after_thread, 'Thread merge_modify';

    my $test_result : shared = 0;
    my $thr3 = threads->create(\&run_in_thread_3);
    my $thr4 = threads->create(\&run_in_thread_4);
    $thr3->join();
    $thr4->join();
    ok $test_result, 'Thread modify conflict';


    sub run_in_thread_3 {
        local $SIG{__WARN__} = sub {
            $test_result = 1;
        };
        {
            lock $sync;
            my $wg_meta_t = Wireguard::WGmeta::Wrapper::ConfigT->new(TEST_DIR);
            $wg_meta_t->set('mini_wg1', 'PUBLIC_KEY_PEER_OUTSIDE_THREAD', 'name', 'Name_set_in_thread_3');
            cond_wait $sync;
            my %integrity_hashes = (
                'PUBLIC_KEY_PEER_OUTSIDE_THREAD' => $wg_meta_t->calculate_sha_from_internal('mini_wg1', 'PUBLIC_KEY_PEER_OUTSIDE_THREAD')
            );
            $wg_meta_t->commit(1, 0, \%integrity_hashes);
        }

    }
    sub run_in_thread_4 {
        {
            lock $sync;
            my $wg_meta_t = Wireguard::WGmeta::Wrapper::ConfigT->new(TEST_DIR);
            $wg_meta_t->set('mini_wg1', 'PUBLIC_KEY_PEER_OUTSIDE_THREAD', 'name', 'Name_set_in_thread_4');
            $wg_meta_t->commit(1);
            cond_signal $sync;
        }
    }
}
else{
    ok 1, 'skip....no thread support present';
}

done_testing();

# write back initial configs
my ($filename_1, $filename_2) = (TEST_DIR . 'mini_wg1.conf', TEST_DIR . 'mini_wg0.conf');
write_file($filename_1, $initial_wg1);
write_file($filename_2, $initial_wg0);

