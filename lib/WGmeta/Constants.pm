package WGmeta::Constants;
use strict;
use warnings FATAL => 'all';

# Attribute configurations
use constant WG_META_DEFAULT => {
    'name'        => {
        'in_config_name' => 'Name'
    },
    'alias'       => {
        'in_config_name' => 'Alias'
    },
    'description' => {
        'in_config_name' => 'Description'
    },
    'disabled'    => {
        'in_config_name' => 'Disabled'
    }
};
use constant WG_QUICK => {
    'address'     => {
        'in_config_name' => 'Address'
    },
    'dns'         => {
        'in_config_name' => 'DNS'
    },
    'mtu'         => {
        'in_config_name' => 'MTU'
    },
    'table'       => {
        'in_config_name' => 'Table'
    },
    'pre-up'      => {
        'in_config_name' => 'PreUp'
    },
    'post-up'     => {
        'in_config_name' => 'PostUP'
    },
    'pre-down'    => {
        'in_config_name' => 'PreDown'
    },
    'post-down'   => {
        'in_config_name' => 'PostDown'
    },
    'save-config' => {
        'in_config_name' => 'SaveConfig'
    }
};
use constant WG_ORIG_INTERFACE => {
    'listen-port' => {
        'in_config_name' => 'ListenPort'
    },
    'fwmark'      => {
        'in_config_name' => 'Fwmark'
    },
    'private-key' => {
        'in_config_name' => 'PrivateKey'
    }
};
use constant WG_ORIG_PEER => {
    'public-key'           => {
        'in_config_name' => 'PublicKey'
    },
    'preshared-key'        => {
        'in_config_name' => 'PresharedKey'
    },
    'endpoint'             => {
        'in_config_name' => 'Endpoint'
    },
    'persistent-keepalive' => {
        'in_config_name' => 'PresistentKeepAlive'
    },
    'allowed-ips'          => {
        'in_config_name' => 'AllowedIPs'
    },
};

1;