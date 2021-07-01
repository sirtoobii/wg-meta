=head1 NAME

WGmeta::ValidAttributes - Supported attribute configurations

=head1 DESCRIPTION

In this module all supported attributes are configured (and as well their possible validation function). Attributes configured
here affect how the parser stores them and which attributes are supported by the
L<Wireguard::WGmeta::Wrapper::Config/set($interface, $identifier, $attribute, $value [, $allow_non_meta, $forward_function])>.

=head1 SYNOPSIS

Add your own attributes to L</WG_META_ADDITIONAL>

=cut

package Wireguard::WGmeta::ValidAttributes;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

use Wireguard::WGmeta::Validator;

our $VERSION = "0.0.0";

=head1 ATTRIBUTE TYPES

=cut

=head3 ATTR_TYPE_IS_WG_META

(Default) - wg-meta attributes

=cut
use constant ATTR_TYPE_IS_WG_META => 10;

use constant ATTR_TYPE_IS_RESERVED => 9;
=head3 ATTR_TYPE_IS_WG_META_CUSTOM

Your custom wg-meta attributes

=cut
use constant ATTR_TYPE_IS_WG_META_CUSTOM => 11;
=head3 ATTR_TYPE_IS_WG_QUICK

wg-quick attribute

=cut
use constant ATTR_TYPE_IS_WG_QUICK => 12;
=head3 ATTR_TYPE_IS_WG_ORIG_INTERFACE

Original Wireguard attribute, valid for C<[Interface]> sections.

=cut
use constant ATTR_TYPE_IS_WG_ORIG_INTERFACE => 13;
=head3 ATTR_TYPE_IS_WG_ORIG_PEER

Original Wireguard attribute, valid for C<[Peer]> sections.

=cut
use constant ATTR_TYPE_IS_WG_ORIG_PEER => 14;
=head3 ATTR_TYPE_IS_UNKNOWN

Any unknown attribute types

=cut
use constant ATTR_TYPE_IS_UNKNOWN => 15;

use constant TRUE => 1;
use constant FALSE => 0;

use base 'Exporter';
our @EXPORT = qw(
    ATTR_TYPE_IS_WG_META
    ATTR_TYPE_IS_WG_META_CUSTOM
    ATTR_TYPE_IS_WG_QUICK
    ATTR_TYPE_IS_WG_ORIG_INTERFACE
    ATTR_TYPE_IS_WG_ORIG_PEER
    ATTR_TYPE_IS_UNKNOWN
    NAME_2_KEYS_MAPPING
    KNOWN_ATTRIBUTES
    get_attr_type
);

=head1 ATTRIBUTE SETS

General remark: If you want to add your own attributes add them to L</WG_META_ADDITIONAL> - all other config sets
should only be modified on (possible) future changes in attribute configurations in Wireguard or wg-quick!

=cut

use constant KNOWN_ATTRIBUTES => {
    'alias'                => {
        'type'           => ATTR_TYPE_IS_WG_META,
        'in_config_name' => 'Alias',
        'validator'      => \&accept_any
    },
    'disabled'             => {
        'type'           => ATTR_TYPE_IS_WG_META,
        'in_config_name' => 'Disabled',
        'validator'      => \&accept_any
    },
    'checksum'             => {
        'type'           => ATTR_TYPE_IS_WG_META,
        'in_config_name' => 'Checksum',
        'validator'      => \&accept_any
    },
    'address'              => {
        'in_config_name' => 'Address',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'dns'                  => {
        'in_config_name' => 'DNS',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'mtu'                  => {
        'in_config_name' => 'MTU',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'table'                => {
        'in_config_name' => 'Table',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'pre-up'               => {
        'in_config_name' => 'PreUp',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'post-up'              => {
        'in_config_name' => 'PostUP',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'pre-down'             => {
        'in_config_name' => 'PreDown',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'post-down'            => {
        'in_config_name' => 'PostDown',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'save-config'          => {
        'in_config_name' => 'SaveConfig',
        'type'           => ATTR_TYPE_IS_WG_QUICK,
        'validator'      => \&accept_any
    },
    'listen-port'          => {
        'in_config_name' => 'ListenPort',
        'type'           => ATTR_TYPE_IS_WG_ORIG_INTERFACE,
        'validator'      => \&is_number
    },
    'fwmark'               => {
        'in_config_name' => 'Fwmark',
        'type'           => ATTR_TYPE_IS_WG_ORIG_INTERFACE,
        'validator'      => \&accept_any
    },
    'private-key'          => {
        'in_config_name' => 'PrivateKey',
        'type'           => ATTR_TYPE_IS_WG_ORIG_INTERFACE,
        'validator'      => \&accept_any
    },
    'public-key'           => {
        'in_config_name' => 'PublicKey',
        'type'           => ATTR_TYPE_IS_WG_ORIG_PEER,
        'validator'      => \&accept_any
    },
    'preshared-key'        => {
        'in_config_name' => 'PresharedKey',
        'type'           => ATTR_TYPE_IS_WG_ORIG_PEER,
        'validator'      => \&accept_any
    },
    'endpoint'             => {
        'in_config_name' => 'Endpoint',
        'type'           => ATTR_TYPE_IS_WG_ORIG_PEER,
        'validator'      => \&accept_any
    },
    'persistent-keepalive' => {
        'in_config_name' => 'PresistentKeepAlive',
        'type'           => ATTR_TYPE_IS_WG_ORIG_PEER,
        'validator'      => \&accept_any
    },
    'allowed-ips'          => {
        'in_config_name' => 'AllowedIPs',
        'type'           => ATTR_TYPE_IS_WG_ORIG_PEER,
        'validator'      => \&accept_any
    },
};


use constant KNOWN_WG_SHOW => {

};

sub _create_inconfig_name_mapping() {
    my $names2key = {};
    map {$names2key->{KNOWN_ATTRIBUTES->{$_}{in_config_name}} = $_;} (keys %{+KNOWN_ATTRIBUTES});
    return $names2key;
}


=head3 NAME_2_KEYS_MAPPING

[Generated] Static mapping from I<in_config_name> to I<attr_key>.

=cut
use constant NAME_2_KEYS_MAPPING => _create_inconfig_name_mapping;

sub get_attr_type($attr_name) {
    return KNOWN_ATTRIBUTES->{$attr_name}{type} if exists KNOWN_ATTRIBUTES->{$attr_name};
    return ATTR_TYPE_IS_UNKNOWN;
}

1;