#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../thirdparty/lib/perl5";
use Data::Dumper;

use Config::Handler;
use Wireguard::Wrapper;

use constant FALSE => 0;
use constant TRUE => 1;

use constant WG_CONF_PATH => "/home/tobias/Documents/wg-meta/etc/";
use constant ENFORCE_CONTRACT => TRUE;
use constant CONFIG_FILE => "wg-meta.yaml";
use constant SCHEMA_FILE => "wg-meta.v1.schema.yaml";

our $VERSION = 0.01;

my $cnf = Config::Handler->new(WG_CONF_PATH . CONFIG_FILE);
my $comment_prefix = $cnf->get_config_entry('comment-prefix');
my $disabled_prefix = $cnf->get_config_entry('disabled-prefix');
my $comment_separator = $cnf->get_config_entry('separator');

my $data = read_wg_config("/home/tobias/Documents/wg-meta/etc/wg_dummy_config", $comment_prefix, $comment_separator, $disabled_prefix, \$cnf);


