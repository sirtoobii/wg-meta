package WGmeta::Cli::Commands;
use strict;
use warnings FATAL => 'all';

use experimental 'signatures';
use base 'Exporter';
our @EXPORT = qw(command_show);

use WGmeta::Cli::Human;
use WGmeta::Wireguard::Wrapper::Config;
use WGmeta::Wireguard::Wrapper::Show;

use constant TRUE => 1;
use constant FALSE => 0;
use constant WG_CONFIG => 1;
use constant WG_SHOW => 2;


sub command_show($interface = undef, $human_readable = TRUE, $wg_meta_prefix = '#+', $wg_meta_disabled_prefix = '#-') {
    my $wg_meta = WGmeta::Wireguard::Wrapper::Config->new('/home/tobias/Documents/wg-meta/t/Data/', $wg_meta_prefix, $wg_meta_disabled_prefix);
    my $wg_show = WGmeta::Wireguard::Wrapper::Show->new();

    my $spacer = "\t";
    if ($human_readable == TRUE) {
        $spacer = "";
    }

    # the individual attributes are configured here
    my $attrs = {
        $wg_meta_prefix . 'Name'     => {
            human_readable => \&id,
            dest           => WG_CONFIG,
            len            => 15,
        },
        $wg_meta_prefix . 'Alias'    => {
            human_readable => \&id,
            dest           => WG_CONFIG,
            len            => 20
        },
        'PublicKey'                  => {
            human_readable => \&id,
            dest           => WG_CONFIG,
            len            => 45
        },
        'endpoint'                   => {
            human_readable => \&id,
            dest           => WG_SHOW,
            len            => 23
        },
        'AllowedIPs'                 => {
            human_readable => \&id,
            dest           => WG_CONFIG,
            len            => 30
        },
        'latest-handshake'           => {
            human_readable => \&timestamp2human,
            dest           => WG_SHOW,
            len            => 20
        },
        'transfer-rx'                => {
            human_readable => \&bits2human,
            dest           => WG_SHOW,
            len            => 14
        },
        'transfer-tx'                => {
            human_readable => \&bits2human,
            dest           => WG_SHOW,
            len            => 14
        },
        $wg_meta_prefix . 'Disabled' => {
            human_readable => \&disabled2Human,
            dest           => WG_CONFIG,
            len            => 15
        }
    };

    # this list defines a) the order of the attrs and b) which one are actually displayed
    my @attr_list = (
        $wg_meta_prefix . 'Name',
        $wg_meta_prefix . 'Alias',
        'PublicKey',
        'endpoint',
        'AllowedIPs',
        'latest-handshake',
        'transfer-rx',
        'transfer-tx',
        $wg_meta_prefix . 'Disabled'
    );

    # There is maybe better way to solve this:
    # Requirements: The solution shouldn't be dependent on external modules, should preserve order and provide a mapping
    # from where the value is sourced

    # the config files are our reference, otherwise we would miss inactive peers


    my $output = '';
    my @interface_list;
    if (defined($interface)) {
        @interface_list = ($interface);
    }
    else {
        @interface_list = $wg_meta->get_interface_list()
    }

    for my $iface (sort @interface_list) {
        # interface "header"
        $output .= "interface: $iface \n";
        # Attributes
        $output .= join $spacer, map {_prepare_attr($_, $wg_meta_prefix, $attrs, $human_readable)} @attr_list;
        $output .= "\n";

        # Attribute values
        for my $identifier ($wg_meta->get_section_list($iface)) {
            my %interface_section = $wg_meta->get_interface_section($iface, $identifier);
            unless (%interface_section) {
                die "Interface `$iface` does not exist";
            }

            # skip if type interface
            if ($interface_section{type} eq 'Peer') {
                my %show_section = $wg_show->get_interface_section($iface, $identifier);
                $output .= join($spacer,
                    map {
                        _get_value($_,
                            \%interface_section,
                            \%show_section,
                            $attrs,
                            $human_readable
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

sub _prepare_attr($attr, $wg_meta_prefix, $ref_attrs, $human_readable = TRUE) {
    my $len = $ref_attrs->{$attr}->{len};
    $wg_meta_prefix = quotemeta $wg_meta_prefix;
    # remove possible wg meta prefix
    $attr =~ s/$wg_meta_prefix//g;
    # make first char uppercase
    if ($human_readable == TRUE) {
        return sprintf "%-*s", $len, uc $attr;
    }
    else {
        return uc $attr;
    }

}

=head3 _get_value($key, $ref_config_section, $ref_show_section, $ref_attrs [, $human_readable])

This takes a C<$key> and decides using C<< $ref_attrs->{$key}->{dest} >> where to source the requested value.
If C<$human> is set to true (default), it takes also care of formatting the values.
If there is no value present in the respective config file I<#not_avail> is returned as placeholder instead.

B<Parameters>

=over 1

=item

C<$key> Key to access the value

=item

C<$ref_config_section> Reference to hash containing the current config section. For more details on the structure refer to L<WGmeta::Wireguard::Wrapper::Config>

=item

C<$ref_show_section> Reference to hash containing the current show section. For more details on the structure refer to L<WGmeta::Wireguard::Wrapper::Show>

=item

C<$ref_attrs > Reference to the attribute configs, specified in C<command_show()>

=item

C<[, $human_readable] > If set to 1 (default), the output is formatted and aligned according to the config in C<$ref_attrs>

=back

B<Returns>

Value behind C<$key> or if not available I<#not_avail>

=cut
sub _get_value($key, $ref_config_section, $ref_show_section, $ref_attrs, $human_readable = TRUE) {
    # first decide if wg show or config
    if ($ref_attrs->{$key}->{dest} == WG_CONFIG) {
        # config
        if (defined($ref_config_section) && exists $ref_config_section->{$key}) {
            if ($human_readable == TRUE) {
                return sprintf "%-*s", $ref_attrs->{$key}->{len}, $ref_attrs->{$key}->{human_readable}($ref_config_section->{$key});
            }
            return $ref_config_section->{$key};
        }
        else {
            return sprintf "%-*s", $ref_attrs->{$key}->{len}, "#not_avail";
        }
    }
    else {
        # wg show
        if (defined($ref_show_section) && exists $ref_show_section->{$key}) {
            if ($human_readable == TRUE) {
                return sprintf "%-*s", $ref_attrs->{$key}->{len}, $ref_attrs->{$key}->{human_readable}($ref_show_section->{$key});
            }
            return $ref_show_section->{$key};
        }
        else {
            return sprintf "%-*s", $ref_attrs->{$key}->{len}, "#not_avail";
        }
    }
}

1;