package Wireguard::WGmeta::Parser::Middleware;
use strict;
use warnings FATAL => 'all';
use experimental qw(signatures);

use Wireguard::WGmeta::Parser::Conf;
use Wireguard::WGmeta::ValidAttributes;
use Wireguard::WGmeta::Utils;

use base 'Exporter';
our @EXPORT = qw(parse_wg_config2 create_wg_config2);

sub parse_wg_config2($config_file_content, $interface_name, $wg_meta_prefix = '#+', $disabled_prefix = '#-', $use_checksum = 1) {

    return undef unless ($config_file_content =~ /\[Interface\]/);

    my %alias_map;
    my %observed_wg_meta_attrs;
    my $peer_count = 0;
    my $alias_to_consume;
    my $old_checksum;

    my $entry_handler = sub($raw_key, $raw_value, $is_wg_meta) {
        my $final_key = $raw_key;
        my $final_value = $raw_value;


        # Convert known Keys to attr-name style
        $final_key = NAME_2_KEYS_MAPPING->{$raw_key} if exists NAME_2_KEYS_MAPPING->{$raw_key};

        $observed_wg_meta_attrs{$final_key} = 1 if $is_wg_meta;
        # register alias to consume (if any)
        $alias_to_consume = $raw_value if $raw_key eq 'Alias';

        if ($raw_key eq 'Checksum') {
            $old_checksum = $raw_value;
            # discard old checksum
            return undef, undef, 1;
        }

        return $final_key, $final_value, 0;
    };

    my $new_section_handler = sub($identifier, $section_type, $is_active) {
        $peer_count++ if $section_type eq 'Peer';

        # Consume alias (if any)
        if (defined $alias_to_consume) {
            die "Alias `$alias_to_consume` is already defined on $interface_name" if exists $alias_map{$alias_to_consume};
            $alias_map{$alias_to_consume} = $identifier;
            $alias_to_consume = undef;
        }

        return ($section_type eq 'Interface') ? $interface_name : $identifier;

    };

    my $parsed_config = parse_raw_wg_config($config_file_content, $entry_handler, $new_section_handler, 0, $wg_meta_prefix, $disabled_prefix);
    $parsed_config->{alias_map} = \%alias_map;
    $parsed_config->{n_peers} = $peer_count;
    $parsed_config->{interface_name} = $interface_name;
    $parsed_config->{observed_wg_meta_attrs} = \%observed_wg_meta_attrs;

    if ($use_checksum == 1 && defined $old_checksum) {
        my $new_checksum = compute_md5_checksum(create_wg_config2($parsed_config, $wg_meta_prefix, $disabled_prefix, 1));
        warn("Checksum mismatch `$interface_name` has been altered in the meantime") if not $new_checksum eq $old_checksum;
    }

    return $parsed_config;
}

sub _write_line($attr_name, $attr_value, $is_disabled, $is_wg_meta) {
    my $cfg_line = '';
    # if we have a comment
    if (substr($attr_name, 0, 7) eq 'comment') {
        $cfg_line .= $attr_value . "\n";
    }
    else {
        my $inconfig_name = exists KNOWN_ATTRIBUTES->{$attr_name} ? KNOWN_ATTRIBUTES->{$attr_name}{in_config_name} : $attr_name;
        $cfg_line .= "$is_disabled$is_wg_meta$inconfig_name = $attr_value\n";
    }
    return $cfg_line;
}



sub create_wg_config2($ref_interface_config, $wg_meta_prefix = '#+', $disabled_prefix = '#-', $no_checksum = 0) {
    my $new_config = "";

    for my $identifier (@{$ref_interface_config->{INTERNAL_KEY_PREFIX . 'section_order'}}) {
        if (not ref($ref_interface_config->{$identifier}) eq 'HASH') {
            # We are in root section
            $new_config .= _write_line($identifier, $ref_interface_config->{$identifier}, '', $wg_meta_prefix);
        }
        else {
            # First lets check if the following section is active'int_disabled'
            my $is_disabled = (exists $ref_interface_config->{$identifier}{INTERNAL_KEY_PREFIX . 'disabled'}
                and $ref_interface_config->{$identifier}{INTERNAL_KEY_PREFIX . 'disabled'} == 1) ? $disabled_prefix : '';

            # Add [Interface] or [Peer]
            my $t = $is_disabled;
            $new_config .= "\n$is_disabled" . "[$ref_interface_config->{$identifier}{INTERNAL_KEY_PREFIX . 'type'}]\n";

            # Add config lines
            for my $attr_name (@{$ref_interface_config->{$identifier}{INTERNAL_KEY_PREFIX . 'order'}}) {

                my $is_wg_meta = (exists $ref_interface_config->{observed_wg_meta_attrs}{$attr_name}) ? $wg_meta_prefix : '';
                $new_config .= _write_line($attr_name, $ref_interface_config->{$identifier}{$attr_name}, $is_disabled, $is_wg_meta);
            }
        }
    }
    if ($no_checksum == 0) {
        return "#+Checksum = " . compute_md5_checksum($new_config) . "\n" . $new_config;
    }
    return $new_config;
}

1;