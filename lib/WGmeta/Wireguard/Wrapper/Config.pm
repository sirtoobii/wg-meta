use v5.22;
package WGmeta::Wireguard::Wrapper::Config;
use strict;
use warnings;
use experimental 'signatures';
use base 'Exporter';
our @EXPORT = qw(read_wg_configs write_wg_config read_wg_show wg_show_dump_parser);
use WGmeta::Utils;
use Data::Dumper;
use Time::Piece;
use File::Basename;
use Digest::MD5 qw(md5);

use constant FALSE => 0;
use constant TRUE => 1;

# constants for states of the config parser
use constant IS_EMPTY => -1;
use constant IS_COMMENT => 0;
use constant IS_WG_META => 1;
use constant IS_SECTION => 2;
use constant IS_NORMAL => 3;


# note-for-later: the trailing backslash is important in $wireguard_home!
sub new($class, $wireguard_home, $wg_meta_prefix = '#+', $wg_meta_disabled_prefix = '#-', $ref_hash_additional_attrs = undef) {
    my %default_attrs = (
        'Name'     => undef,
        'Alias'    => undef,
        'Disabled' => undef
    );
    if (defined $ref_hash_additional_attrs) {
        map {$default_attrs{$_} = undef} keys %{$ref_hash_additional_attrs};
    }
    else {
        $ref_hash_additional_attrs = \%default_attrs;
    }

    if ($wg_meta_prefix eq $wg_meta_disabled_prefix) {
        die '`$wg_meta_prefix` and `$wg_meta_disabled_prefix` have to be different';
    }

    my $self = {
        'wireguard_home'          => $wireguard_home,
        'wg_meta_prefix'          => $wg_meta_prefix,
        'wg_meta_disabled_prefix' => $wg_meta_disabled_prefix,
        'valid_attrs'             => $ref_hash_additional_attrs,
        'has_changed'             => FALSE,
        'parsed_config'           => read_wg_configs($wireguard_home, $wg_meta_prefix, $wg_meta_disabled_prefix)
    };

    bless $self, $class;
    return $self;
}

sub set($self, $interface, $identifier, $attribute, $value) {
    $attribute = ucfirst $attribute;
    if ($self->_decide_attr_type($attribute) == IS_WG_META) {
        if ($self->_is_valid_interface($interface)) {
            if ($self->_is_valid_identifier($interface, $identifier)) {
                unless (exists $self->{parsed_config}{$interface}{$identifier}{$self->{wg_meta_prefix} . $attribute}) {
                    # the attribute does not (yet) exist in the configuration, lets add it to the list
                    push @{$self->{parsed_config}{$interface}{$identifier}{order}}, $self->{wg_meta_prefix} . $attribute;
                }
                $self->{parsed_config}{$interface}{$identifier}{$self->{wg_meta_prefix} . $attribute} = $value;
                $self->{has_changed} = TRUE;
            }
            else {
                die "Invalid identifier `$identifier` for interface `$interface`";
            }
        }
        else {
            die "Invalid interface name `$interface`";
        }
    }
    else {
        _forward($interface, $identifier, $attribute, $value)
    }

}

sub set_by_alias($self, $interface, $alias, $attribute, $value) {
    my $identifier = $self->translate_alias($interface, $alias);
    $self->set($interface, $identifier, $attribute, $value);
}

sub disable($self, $interface, $identifier,) {
    $self->_toggle($interface, $identifier, TRUE);
}

sub enable($self, $interface, $identifier) {
    $self->_toggle($interface, $identifier, FALSE);
}

sub disable_by_alias($self, $interface, $alias,) {
    $self->_toggle($interface, $self->translate_alias($interface, $alias), FALSE);
}

sub enable_by_alias($self, $interface, $alias,) {
    $self->_toggle($interface, $self->translate_alias($interface, $alias), TRUE);
}

sub _toggle($self, $interface, $identifier, $enable) {
    if (exists $self->{parsed_config}{$interface}{$identifier}{Disabled}) {
        if ($self->{parsed_config}{$interface}{$identifier}{Disabled} == "$enable") {
            warn "Section `$identifier` in `$interface` is already $enable";
        }
    }
    $self->set($interface, $identifier, 'Disabled', $enable);
}


sub _forward($interface, $identifier, $attribute, $value) {
    # this is just as stub
    print("Forwarded to wg original wg command");
}

sub _decide_attr_type($self, $attr_name) {
    if (exists $self->{valid_attrs}{ucfirst $attr_name}) {
        return IS_WG_META;
    }
    else {
        return IS_NORMAL;
    }
}

sub _is_valid_interface($self, $interface) {
    return (exists $self->{parsed_config}{$interface});
}

sub _is_valid_identifier($self, $interface, $identifier) {
    return (exists $self->{parsed_config}{$interface}{$identifier});
}

sub translate_alias($self, $interface, $alias) {
    if (exists $self->{parsed_config}{$interface}{alias_map}{$alias}) {
        return $self->{parsed_config}{$interface}{alias_map}{$alias};
    }
    else {
        die "Invalid alias `$alias` in interface $interface";
    }
}

sub read_wg_configs($wireguard_home, $wg_meta_prefix, $disabled_prefix) {
    my @config_files = read_dir($wireguard_home, qr/.*\.conf$/);

    if (@config_files == 0) {
        die "No matching interface configuration(s) in " . $wireguard_home ;
    }

    # create file-handle
    my $parsed_wg_config = {};
    for my $config_path (@config_files) {

        # read interface name
        my $i_name = basename($config_path);
        $i_name =~ s/\.conf//g;
        open my $fh, '<', $config_path or die "Could not open config file at $config_path";

        my %alias_map;
        my $current_state = -1;

        # state variables
        my $STATE_INIT_DONE = FALSE;
        my $STATE_READ_SECTION = FALSE;
        my $STATE_READ_ID = FALSE;
        my $STATE_EMPTY_SECTION = TRUE;
        my $STATE_READ_ALIAS = FALSE;

        # data of current section
        my $section_type;
        my $is_disabled = FALSE;
        my $comment_counter = 0;
        my $identifier;
        my $alias;
        my $section_data = {};
        my $checksum = '';
        my @section_data_order;
        my @section_order;

        while (my $line = <$fh>) {
            $current_state = _decide_state($line, $wg_meta_prefix, $disabled_prefix);

            # remove disabled prefix if any
            $line =~ s/^$disabled_prefix//g;

            if ($current_state == -1) {
                # empty line
            }
            elsif ($current_state == IS_SECTION) {
                # strip-off [] and whitespaces
                $line =~ s/^\[|\]\s*$//g;
                if (_is_valid_section($line) == TRUE) {
                    if ($STATE_EMPTY_SECTION == TRUE && $STATE_INIT_DONE == TRUE) {
                        die 'Found empty section, aborting';
                    }
                    else {
                        $STATE_READ_SECTION = TRUE;

                        if ($STATE_INIT_DONE == TRUE) {
                            # we are at the end of a section and therefore we can store the data

                            # first check if we read an private or public-key
                            if ($STATE_READ_ID == FALSE) {
                                die 'Section without identifying information found (Private -or PublicKey field)'
                            }
                            else {
                                $STATE_READ_ID = FALSE;
                                $STATE_EMPTY_SECTION = TRUE;
                                $parsed_wg_config->{$i_name}{$identifier} = $section_data;
                                $parsed_wg_config->{$i_name}{$identifier}{type} = $section_type;

                                # we have to use a copy of the array here - otherwise the reference stays the same in all sections.
                                $parsed_wg_config->{$i_name}{$identifier}{order} = [ @section_data_order ];
                                push @section_order, $identifier;

                                # reset vars
                                $section_data = {};
                                $is_disabled = FALSE;
                                @section_data_order = ();
                                $section_type = $line;
                                if ($STATE_READ_ALIAS == TRUE) {
                                    $alias_map{$alias} = $identifier;
                                    $STATE_READ_ALIAS = FALSE;
                                }
                            }
                        }
                        $section_type = $line;
                        $STATE_INIT_DONE = TRUE;
                    }
                }
                else {
                    die "Invalid section found: $line";
                }
            }
            # skip comments before sections -> we replace these with our header anyways...
            elsif ($current_state == IS_COMMENT) {
                unless ($STATE_INIT_DONE == FALSE) {
                    my $comment_id = "comment_" . $comment_counter++;
                    push @section_data_order, $comment_id;

                    $line =~ s/^\s+|\s+$//g;
                    $section_data->{$comment_id} = $line;
                }
            }
            elsif ($current_state == IS_WG_META) {
                # a special wg-meta attribute
                if ($STATE_INIT_DONE == FALSE) {
                    # this is already a wg-meta config and therefore we expect a checksum
                    (undef, $checksum) = split_and_trim($line, "=");
                }
                else {
                    if ($STATE_READ_SECTION == TRUE) {
                        $STATE_EMPTY_SECTION = FALSE;
                        my ($attr_name, $attr_value) = split_and_trim($line, "=");
                        if ($attr_name eq $wg_meta_prefix . "Alias") {
                            if (exists $alias_map{$attr_value}) {
                                die "Alias '$attr_value' already exists, aborting" ;
                            }
                            $STATE_READ_ALIAS = TRUE;
                            $alias = $attr_value;
                        }
                        push @section_data_order, $attr_name;
                        $section_data->{$attr_name} = $attr_value;
                    }
                    else {
                        die 'Attribute without a section encountered, aborting';
                    }
                }
            }
            else {
                # normal attribute
                if ($STATE_READ_SECTION == TRUE) {
                    $STATE_EMPTY_SECTION = FALSE;
                    my ($attr_name, $attr_value) = split_and_trim($line, '=');
                    if (_is_identifying($attr_name)) {
                        $STATE_READ_ID = TRUE;
                        $identifier = $attr_value;
                    }
                    push @section_data_order, $attr_name;
                    $section_data->{$attr_name} = $attr_value;
                }
                else {
                    die 'Attribute without a section encountered, aborting';
                }
            }
        }
        # store last section
        if ($STATE_READ_ID == FALSE) {
            die 'Section without identifying information found (Private -or PublicKey field'
        }
        else {
            $parsed_wg_config->{$i_name}{$identifier} = $section_data;
            $parsed_wg_config->{$i_name}{$identifier}{type} = $section_type;
            $parsed_wg_config->{$i_name}{checksum} = $checksum;
            $parsed_wg_config->{$i_name}{section_order} = \@section_order;
            $parsed_wg_config->{$i_name}{alias_map} = \%alias_map;

            $parsed_wg_config->{$i_name}{$identifier}{order} = \@section_data_order;
            push @section_order, $identifier;
            if ($STATE_READ_ALIAS == TRUE) {
                $alias_map{$alias} = $identifier;
            }
        }
        #print Dumper(\%alias_map);
        #print Dumper(\@section_order);
        #print Dumper($parsed_wg_config);
        close $fh ;
        # checksum
        my $current_hash = _compute_checksum(create_wg_config($parsed_wg_config->{$i_name}, $wg_meta_prefix, $disabled_prefix, TRUE));
        unless ("$current_hash" eq $checksum) {
            warn "Config `$i_name.conf` has been changed by an other program or user. This is just a warning.";
        }
    }

    return ($parsed_wg_config);
}

sub _decide_state($line, $comment_prefix, $disabled_prefix) {

    #remove leading and tailing white space
    $line =~ s/^\s+|\s+$//g;
    if ($line eq "") {
        return IS_EMPTY;
    }
    # Is it the start of a section
    if (substr($line, 0, 1) eq "[") {
        return IS_SECTION;
    }
    # is it a special wg-meta attribute
    if (substr($line, 0, length $comment_prefix) eq $comment_prefix) {
        return IS_WG_META;
    }
    # is it a deactivated line
    if (substr($line, 0, length $disabled_prefix) eq $disabled_prefix) {
        $line =~ s/^$disabled_prefix//g;
        # lets do a little bit of recursion here ;)
        return _decide_state($line, $comment_prefix, $disabled_prefix);
    }
    # Is it a normal comment
    if (substr($line, 0, 1) eq "#") {
        return IS_COMMENT;
    }
    # normal attribute
    return IS_NORMAL;
}

sub _is_valid_section($section) {
    return {
        Peer      => 1,
        Interface => 1
    }->{$section};
}

sub _is_identifying($attr_name) {
    return {
        PrivateKey => 1,
        PublicKey  => 1
    }->{$attr_name};
}

sub split_and_trim($line, $separator) {
    return map {s/^\s+|\s+$//g; $_} split $separator, $line, 2;
}

sub create_wg_config($ref_interface_config, $wg_meta_prefix, $disabled_prefix, $plain = FALSE) {
    my $new_config = "\n";

    for my $identifier (@{$ref_interface_config->{section_order}}) {
        if (_is_disabled($ref_interface_config->{$identifier}, $wg_meta_prefix . "Disabled")) {
            $new_config .= $disabled_prefix;
        }
        # write down [section_type]
        $new_config .= "[$ref_interface_config->{$identifier}{type}]\n";
        for my $key (@{$ref_interface_config->{$identifier}{order}}) {
            if (_is_disabled($ref_interface_config->{$identifier}, $wg_meta_prefix . "Disabled")) {
                $new_config .= $disabled_prefix;
            }
            if (substr($key, 0, 7) eq 'comment') {
                $new_config .= $ref_interface_config->{$identifier}{$key} . "\n";
            }
            else {
                $new_config .= $key . " = " . $ref_interface_config->{$identifier}{$key} . "\n";
            }
        }
        $new_config .= "\n";
    }
    if ($plain == FALSE) {
        my $new_hash = _compute_checksum($new_config);
        my $config_header =
            "# This config is generated and maintained by wg-meta.
# It is strongly recommended to edit this config only through a supporting wg-meta
# implementation (e.g the wg-meta cli interface)
#
# Changes to this header are always overwritten, you can add normal comments in [Peer] and [Interface] section though.
#
# Support and issue tracker: https://github.com/sirtoobii/wg-meta
#+Checksum = $new_hash
";

        return $config_header . $new_config;
    }
    else {
        return $new_config;
    }
}

sub commit($self, $is_hot_config = FALSE) {
    for my $interface (keys %{$self->{parsed_config}}) {
        my $new_config = create_wg_config($self->{parsed_config}{$interface}, $self->{wg_meta_prefix}, $self->{wg_meta_disabled_prefix});
        my $fh;
        if ($is_hot_config == TRUE) {
            open $fh, '>', $self->{wireguard_home} . $interface . '.conf'  or die $!;
        }
        else {
            open $fh, '>', $self->{wireguard_home} . $interface . '.conf_dryrun'  or die $!;
        }
        # write down to file
        print $fh $new_config;
        close $fh;
    }
}

sub _is_disabled($ref_parsed_config_section, $key) {
    if (exists $ref_parsed_config_section->{$key}) {
        return $ref_parsed_config_section->{$key} == TRUE;
    }
}

sub _compute_checksum($input) {
    my $str = substr(md5($input), 0, 4);
    return unpack 'L', $str; # Convert to 4-byte integer
}

sub get_interface_list($self) {
    return keys %{$self->{parsed_config}};
}

sub get_interface_section($self, $interface, $identifier) {
    if (exists $self->{parsed_config}{$interface}{$identifier} ) {
        return %{$self->{parsed_config}{$interface}{$identifier}};
    }
    else {
        return ();
    }
}

sub get_section_list($self, $interface) {
    if (exists $self->{parsed_config}{$interface}) {
        return @{$self->{parsed_config}{$interface}{section_order}};
    }
    else {
        return {};
    }
}

sub get_wg_meta_prefix($self) {
    return $self->{wg_meta_prefix};
}

sub get_disabled_prefix($self) {
    return $self->{wg_meta_disabled_prefix};
}

sub dump($self) {
    print Dumper $self->{parsed_config};
}