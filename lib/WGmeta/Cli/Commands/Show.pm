package WGmeta::Cli::Commands::Show;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

use parent 'WGmeta::Cli::Commands::Command';

use WGmeta::Cli::Human;
use WGmeta::Wireguard::Wrapper::Config;
use WGmeta::Wireguard::Wrapper::Show;
use WGmeta::Wireguard::Wrapper::Bridge;
use WGmeta::Utils;

use constant TRUE => 1;
use constant FALSE => 0;
use constant WG_CONFIG => 1;
use constant WG_SHOW => 2;
use constant NA_PLACEHOLDER => '#na';

sub entry_point($self) {
    # set defaults
    $self->{human_readable} = TRUE;
    $self->{wg_meta_prefix} = '#+';

    my $len = @{$self->{input_args}};

    if ($len > 0) {
        if ($self->_retrieve_or_die($self->{input_args}, 0) eq 'help') {
            $self->cmd_help();
            return
        }
        if ($self->_retrieve_or_die($self->{input_args}, -1) eq 'dump') {
            $self->{human_readable} = FALSE;
            if ($len == 2) {
                $self->{interface} = $self->_retrieve_or_die($self->{input_args}, 0)
            }
            $self->_run_command();
        }
        $self->{interface} = $self->_retrieve_or_die($self->{input_args}, 0)
    }
    $self->_run_command();
}

sub _run_command($self) {
    my $wg_meta = WGmeta::Wireguard::Wrapper::Config->new($self->{wireguard_home});
    if (exists $self->{interface} && !$wg_meta->_is_valid_interface($self->{interface})){
        die "Invalid interface `$self->{interface}`";
    }
    my $out;
    if (defined $ENV{IS_TESTING}) {
        use FindBin;
        $out = read_file($FindBin::Bin . '/../t/Data/test/wg_show_dump');
    }
    else {
        my @std_out = run_external('wg show all dump');
        $out = join '', @std_out;
    }
    my $wg_show = WGmeta::Wireguard::Wrapper::Show->new($out);

    my $spacer = "\t";
    if ($self->{human_readable} == TRUE) {
        $spacer = "";
    }

    # the individual attributes are configured here
    my $attrs = {
        $self->{wg_meta_prefix} . 'Name'     => {
            human_readable => \&return_self,
            dest           => WG_CONFIG,
            compact        => 'NAME',
            len            => 15,
        },
        $self->{wg_meta_prefix} . 'Alias'    => {
            human_readable => \&return_self,
            dest           => WG_CONFIG,
            compact        => 'ALIAS',
            len            => 12
        },
        'PublicKey'                          => {
            human_readable => \&return_self,
            dest           => WG_CONFIG,
            compact        => 'PUBKEY',
            len            => 45
        },
        'endpoint'                           => {
            human_readable => \&return_self,
            dest           => WG_SHOW,
            compact        => 'ENDPOINT',
            len            => 23
        },
        'AllowedIPs'                         => {
            human_readable => \&return_self,
            dest           => WG_CONFIG,
            compact        => 'IPS',
            len            => 30
        },
        'latest-handshake'                   => {
            human_readable => \&timestamp2human,
            dest           => WG_SHOW,
            compact        => 'L-HANDS',
            len            => 13
        },
        'transfer-rx'                        => {
            human_readable => \&bits2human,
            dest           => WG_SHOW,
            compact        => 'RX',
            len            => 12
        },
        'transfer-tx'                        => {
            human_readable => \&bits2human,
            dest           => WG_SHOW,
            compact        => 'TX',
            len            => 12
        },
        $self->{wg_meta_prefix} . 'Disabled' => {
            human_readable => \&disabled2human,
            dest           => WG_CONFIG,
            compact        => 'ACTIVE',
            len            => 6
        }
    };

    # this list defines a) the order of the attrs and b) which one are actually displayed
    my @attr_list = (
        $self->{wg_meta_prefix} . 'Name',
        $self->{wg_meta_prefix} . 'Alias',
        'PublicKey',
        'endpoint',
        'AllowedIPs',
        'latest-handshake',
        'transfer-rx',
        'transfer-tx',
        $self->{wg_meta_prefix} . 'Disabled'
    );

    # There is maybe better way to solve this:
    # Requirements: The solution shouldn't be dependent on external modules, should preserve order and provide a mapping
    # from where the value is sourced

    # the config files are our reference, otherwise we would miss inactive peers

    my $output = '';
    my @interface_list;
    if (defined($self->{interface})) {
        @interface_list = ($self->{interface});
    }
    else {
        @interface_list = $wg_meta->get_interface_list()
    }

    for my $iface (sort @interface_list) {
        # interface "header"
        $output .= "interface: $iface \n";
        # Attributes (header row)
        $output .= join $spacer, map {$self->_prepare_attr($_, $attrs)} @attr_list;
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
                        $self->_get_value($_,
                            \%interface_section,
                            \%show_section,
                            $attrs,
                        )
                    }
                        @attr_list
                );
                $output .= "\n";
            }
        }
    }
    print $output;
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
sub _get_value($self, $key, $ref_config_section, $ref_show_section, $ref_attrs) {
    # first decide if wg show or config
    if ($ref_attrs->{$key}{dest} == WG_CONFIG) {
        # config
        if (defined($ref_config_section) && exists $ref_config_section->{$key}) {
            if ($self->{human_readable} == TRUE) {
                return sprintf "%-*s", $ref_attrs->{$key}->{len}, $ref_attrs->{$key}->{human_readable}($ref_config_section->{$key});
            }
            return $ref_config_section->{$key};
        }
        else {
            return sprintf "%-*s", $ref_attrs->{$key}->{len}, NA_PLACEHOLDER;
        }
    }
    else {
        # wg show
        if (defined($ref_show_section) && exists $ref_show_section->{$key}) {
            if ($self->{human_readable} == TRUE) {
                return sprintf "%-*s", $ref_attrs->{$key}->{len}, $ref_attrs->{$key}->{human_readable}($ref_show_section->{$key});
            }
            return $ref_show_section->{$key};
        }
        else {
            return sprintf "%-*s", $ref_attrs->{$key}->{len}, NA_PLACEHOLDER;
        }
    }
}

sub _prepare_attr($self, $attr, $ref_attrs) {
    my $len = $ref_attrs->{$attr}{len};
    my $wg_meta_prefix = quotemeta $self->{wg_meta_prefix};
    # # remove possible wg meta prefix
    # $attr =~ s/$wg_meta_prefix//g;
    # make first char uppercase
    if ($self->{human_readable} == TRUE) {
        return sprintf "%-*s", $len, $ref_attrs->{$attr}{compact};
    }
    else {
        return $ref_attrs->{$attr}{compact};
    }

}

sub cmd_help($self) {
    print "Usage: wg-meta show {interface | all} [dump]\n"
}

1;
