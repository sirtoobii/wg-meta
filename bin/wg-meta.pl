#!/usr/bin/perl
use v5.22;
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../thirdparty/lib/perl5";
use experimental 'signatures';

use WGmeta::Cli::Router;

use constant FALSE => 0;
use constant TRUE => 1;

use constant WG_META_CONF_PATH => "/home/tobias/Documents/wg-meta/etc/";
use constant WG_CONF_PATH => "/home/tobias/Documents/wg-meta/t/Data/";
use constant CONFIG_FILE => "wg-meta.yaml";
use constant SCHEMA_FILE => "wg-meta.v1.schema.yaml";

our $VERSION = 0.01;

# command line argument parser

route_command(\@ARGV);

sub help() {
    print "wg-meta - An approach to add meta data to the Wireguard configuration\n";
    print "Version: " . $VERSION . "\n\n";
    print "Usage: wg-meta <cmd> [<args>]\n";
    print "Available subcommands:\n";
    print "\t show: [interface|all] [dump]  Shows the current configuration paired with available metadata, when specifying dump, the output is TAB separated";
    exit();
}





