package WGmeta::Constants;
use strict;
use warnings FATAL => 'all';

# Attribute configurations
use constant WG_META_DEFAULT => (
    'Name'        => undef,
    'Alias'       => undef,
    'Description' => undef,
    'Disabled'    => undef
);
use constant WG_QUICK => (
    'Address'    => 1,
    'DNS'        => 1,
    'MTU'        => 1,
    'Table'      => 1,
    'PreUp'      => 1,
    'PostUp'     => 1,
    'PreDown'    => 1,
    'PostDown'   => 1,
    'SaveConfig' => 1
);
use constant WG_ORIG_INTERFACE => (
    'listen-port' => 1,
    'fwmark'      => 1,
    'private-key' => 1
);
use constant WG_ORIG_PEER => (
    'preshared-key'        => 1,
    'endpoint'             => 1,
    'persistent-keepalive' => 1,
    'allowed-ips'          => 1
);

1;