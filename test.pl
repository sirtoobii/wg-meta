#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use WGmeta::Wireguard::Wrapper::Config;
use WGmeta::Wireguard::Wrapper::Show;
use WGmeta::Wireguard::Wrapper::Bridge;
use WGmeta::ValidAttributes;
use WGmeta::Utils;
use Digest::MD5 qw(md5);
use Data::Dumper;
use experimental 'signatures';


#$wg_meta->set('wg1', 'WG_1_PEER_A_PUBLIC_KEY', 'Name', 'new name');
# my $out = read_file('/home/tobias/Documents/wg-meta/t/Data/wg_show_dump');
# my $wg_show = WGmeta::Wireguard::Wrapper::Show->new($out);
# print $wg_show->dump();
#
# my %has = $wg_meta->get_interface_section('wg0', 'WG_0_PEER_A_PUBLIC_KEY');
# print Dumper \%has;
#$wg_meta->commit(0);

#print command_show();
#
#my $wg_meta = WGmeta::Wireguard::Wrapper::Config->new('/home/tobias/Documents/wg-meta/t/Data/', '#+', '#-');
# $wg_meta->enable('wg0', 'WG_0_PEER_D_PUBLIC_KEY');
# $wg_meta->disable('wg0', 'WG_0_PEER_A_PUBLIC_KEY');
#$wg_meta->set('wg0', 'WG_0_PEER_A_PUBLIC_KEY', 'name', 'Testerqwdqwd');
# $wg_meta->set('wg0', 'WG_0_PEER_D_PUBLIC_KEY', 'name', 'Hello There');
# $wg_meta->set_by_alias('wg0', 'IPv6_only3', 'name', 'hellop');
# $wg_meta->commit();
# #
# #$wg_meta->dump();
#
# sub split_and_trim($line, $separator) {
#     # my @values = split($separator, $line, 2);
#     # $values[0] =~ s/^\s+|\s+$//g;
#     # $values[1] =~ s/^\s+|\s+$//g;
#     # return @values;
#     return map {  s/^\s+|\s+$//g; $_  } split $separator, $line, 2;
# }
#
# my @list = split_and_trim('wefwef = ewfwef', '=');
# print Dumper \@list;

#print $wg_meta->add_peer('wg0', 'Added like a test', '10.0.0.6/32', 'PUBLIC_KEY_NEW', 'ALiasXYX');
#$wg_meta->commit(1);

#sub add_interface($self, $interface_name, $ip_address, $listen_port, $private_key)
# $wg_meta->add_interface('wgtest', '10.0.0.0/24', 55004, 'wgtest_iface_key');
# #sub add_peer($self, $interface, $name, $ip_address, $public_key, $alias = undef, $preshared_key = undef)
# $wg_meta->add_peer('wgtest','test_iface_peer', '10.0.0.89/32', 'public_key_test_iface');
# $wg_meta->commit(1);
# print $wg_meta->dump();

# my @test = qw(A A B B C C D D);
# #
# # sub _retrieve_or_die($ref_array, $idx){
# #     my @arr = @{$ref_array};
# #     eval{return $arr[$idx]} or print "error";
# # }
# #
# # print _retrieve_or_die(\@dwarfs, 3);
#
# my $ctr = 0;
# for my $val (@test){
#     $ctr++;
#     splice @test, 2;
# }
# print $ctr;

#print gen_keypair();

my $t = {
    'wg_meta_attrs'           => WGmeta::ValidAttributes::WG_META_DEFAULT,
    'wg_orig_interface_attrs' => WGmeta::ValidAttributes::WG_ORIG_INTERFACE,
    'wg_orig_peer_attrs'      => WGmeta::ValidAttributes::WG_ORIG_PEER,
    'wg_quick_attrs'          => WGmeta::ValidAttributes::WG_QUICK
};

print Dumper $t->{wg_quick_attrs}{address}{in_config_name};