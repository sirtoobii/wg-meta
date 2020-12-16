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


if ($ARGV[0] eq '--version') {
    print "wg-meta v$VERSION - https://github.com/sirtoobii/wg-meta\n";
    exit();
}

# command line argument parser
route_command(\@ARGV);





