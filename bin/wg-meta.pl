#!/usr/bin/perl
use v5.22;
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../thirdparty/lib/perl5";
use Data::Dumper;

use Config::Handler;
use Wireguard::Wrapper;
use wg_meta::Commands;

use constant FALSE => 0;
use constant TRUE => 1;

use constant WG_CONF_PATH => "/home/tobias/Documents/wg-meta/etc/";
use constant ENFORCE_CONTRACT => TRUE;
use constant CONFIG_FILE => "wg-meta.yaml";
use constant SCHEMA_FILE => "wg-meta.v1.schema.yaml";

our $VERSION = 0.01;

my $cnf = Config::Handler->new(WG_CONF_PATH . CONFIG_FILE);
my $wg_meta_prefix = $cnf->get_config_entry('comment-prefix');
my $disabled_prefix = $cnf->get_config_entry('disabled-prefix');

my @file_list = ("/home/tobias/Documents/wg-meta/t/Data/wg0.conf","/home/tobias/Documents/wg-meta/t/Data/wg1.conf");
my $parsed_configs = read_wg_configs(\@file_list, $wg_meta_prefix, $disabled_prefix);


#write_wg_config($wg_meta_prefix, $disabled_prefix, $parsed_configs);

open(FILE, "/home/tobias/Documents/wg-meta/t/Data/wg_show_dump") or die "Error: no file found.";
my $output = do {local $/; <FILE> };
my $parsed_show =  wg_show_dump_parser($output);


print command_show($wg_meta_prefix, $parsed_configs, $parsed_show);




