#!/usr/bin/perl
use v5.22;
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../thirdparty/lib/perl5";
use experimental 'signatures';

use Config::Handler;
use Wireguard::Wrapper;
use wg_meta::Commands;
use wg_meta::Utils;

use constant FALSE => 0;
use constant TRUE => 1;

use constant WG_META_CONF_PATH => "/home/tobias/Documents/wg-meta/etc/";
use constant WG_CONF_PATH => "/home/tobias/Documents/wg-meta/t/Data/";
use constant CONFIG_FILE => "wg-meta.yaml";
use constant SCHEMA_FILE => "wg-meta.v1.schema.yaml";

our $VERSION = 0.01;

# command line argument parser
my $command_line = join('_', @ARGV);
if ($command_line eq 'show' | $command_line eq 'show_all') {
    my @wg_interfaces = read_dir(WG_CONF_PATH, qr/.*\.conf/);
    show(\@wg_interfaces, TRUE);

}
elsif ($command_line eq 'show_dump' | $command_line eq 'show_all_dump') {
    my @wg_interfaces = read_dir(WG_CONF_PATH, qr/.*\.conf/);
    show(\@wg_interfaces, FALSE);

}
elsif ($command_line =~ /show\_\w+/) {
    my (undef, $interface) = split(/\_/, $command_line);
    my @wg_interfaces = read_dir(WG_CONF_PATH, qr/$interface\.conf/);
    show(\@wg_interfaces, TRUE);

}
elsif ($command_line eq 'help') {
    help();
}
else {
    help();
}

sub show($ref_interface_list, $human_readable) {
    my $cnf = Config::Handler->new(WG_META_CONF_PATH . CONFIG_FILE);
    my $wg_meta_prefix = $cnf->get_config_entry('comment-prefix');
    my $disabled_prefix = $cnf->get_config_entry('disabled-prefix');
    my @wg_interfaces = @{$ref_interface_list};
    if (@wg_interfaces == 0) {
        die("No matching interface configuration(s) in " . WG_CONF_PATH);
    }
    my $parsed_configs = read_wg_configs(\@wg_interfaces, $wg_meta_prefix, $disabled_prefix);
    open(FILE, "/home/tobias/Documents/wg-meta/t/Data/wg_show_dump") or die "Error: no file found.";
    my $output = do {
        local $/;
        <FILE>
    };
    my $parsed_show = wg_show_dump_parser($output);
    print command_show($wg_meta_prefix, $parsed_configs, $parsed_show, $human_readable);
}

sub help() {
    print "wg-meta - An approach to add meta data to the Wireguard configuration\n";
    print "Version: " . $VERSION . "\n\n";
    print "Usage: wg-meta <cmd> [<args>]\n";
    print "Available subcommands:\n";
    print "\t show: [interface|all] [dump]  Shows the current configuration paired with available metadata, when specifying dump, the output is TAB separated";
    exit();
}





