package wg_meta::Commands;
use strict;
use warnings FATAL => 'all';

use experimental 'signatures';
use base 'Exporter';
our @EXPORT = qw(command_show);

use constant PLACEHOLDER => "\t";
use constant WG_CONFIG => 1;
use constant WG_SHOW => 2;


sub command_show($wg_meta_prefix, $ref_parsed_config, $ref_parsed_show) {

    # There is maybe better way to solve this:
    # Requirements: The solution shouldn't be dependent on external modules, should preserve order and provide a mapping
    # from where the value is sourced

    my %attr_dest = (
        $wg_meta_prefix . 'Name'     => WG_CONFIG,
        $wg_meta_prefix . 'Alias'    => WG_CONFIG,
        'PublicKey'                  => WG_CONFIG,
        'endpoint'                   => WG_SHOW,
        'allowed-ips'                => WG_SHOW,
        'latest-handshake'           => WG_SHOW,
        'transfer-rx'                => WG_SHOW,
        'transfer-tx'                => WG_SHOW,
        $wg_meta_prefix . 'Disabled' => WG_CONFIG
    );
    my @attr_list = (
        $wg_meta_prefix . 'Name',
        $wg_meta_prefix . 'Alias',
        'PublicKey',
        'endpoint',
        'allowed-ips',
        'latest-handshake',
        'transfer-rx',
        'transfer-tx',
        $wg_meta_prefix . 'Disabled'
    );

    # the config files are our reference, otherwise we would miss inactive peers
    my $output = '';
    for my $interface (keys %{$ref_parsed_config}) {
        $output .= "interface: $interface ($ref_parsed_show->{$interface}->{$interface}->{qq(public-key)}) config_version: $ref_parsed_config->{$interface}->{serial}\n";
        $output .= join(PLACEHOLDER, (map {_prepare_attr($_, $wg_meta_prefix)} @attr_list));
        $output .= "\n";
        for my $identifier (@{$ref_parsed_config->{$interface}->{section_order}}) {
            if ($ref_parsed_config->{$interface}->{$identifier}->{type} eq 'Peer') {
                $output .= join(PLACEHOLDER,
                    map {
                        _get_value($_,
                            $ref_parsed_config->{$interface}->{$identifier},
                            $ref_parsed_show->{$interface}->{$identifier},
                            \%attr_dest
                        )
                    }
                        @attr_list
                );
                $output .= "\n";
            }

        }

    }
    return $output;
}

sub _prepare_attr($attr, $wg_meta_prefix) {
    $wg_meta_prefix = quotemeta($wg_meta_prefix);
    # remove possible wg meta prefix
    $attr =~ s/$wg_meta_prefix//g;
    # make first char uppercase
    return uc $attr;
}

sub _get_value($key, $ref_config_section, $ref_show_section, $ref_dest_map) {
    # first decide if wg show or config
    if ($ref_dest_map->{$key} == WG_CONFIG) {
        # config
        if (exists($ref_config_section->{$key})) {
            return $ref_config_section->{$key};
        }
        else {
            return "#not_present";
        }
    }
    else {
        # wg show
        if (exists($ref_show_section->{$key})) {
            return $ref_show_section->{$key};
        }
        else {
            return "#not_present";
        }
    }
}

1;