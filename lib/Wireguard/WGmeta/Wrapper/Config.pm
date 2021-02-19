=pod

=head1 NAME

WGmeta::Wrapper::Config - Class for interfacing the wireguard configs

=head1 SYNOPSIS

 use Wireguard::WGmeta::Wrapper::Config;
 my $wg_meta = Wireguard::WGmeta::Wrapper::Config->new('<path to wireguard configuration>');

 # or when you need just the parser component
 use Wireguard::WGmeta::Utils;

 my $content = read_file('<path_to_wireguard_conf_file');
 my $hash_parsed_configs = parse_wg_config($content, '<interface_name>', '#+', '#-');

 # and similarly to transform the parsed config into a wireguard compatible format again
 my $iface_config = create_wg_config($hash_parsed_configs->{<interface_name>}, '#+', '#-')

=head1 DESCRIPTION

This class serves as wrapper around the Wireguard configurations files.
It is able to parse, modify, add and write Wireguard I<.conf> files. In addition, support for metadata is built in. As a small
bonus, the parser and encoder are exported and usable as standalone methods.

=head1 CONCURRENCY

Please refer to L<Wireguard::WGmeta::Wrapper::ConfigT>

=head1 EXAMPLES

 use Wireguard::WGmeta::Wrapper::Config;
 my $wg-meta = Wireguard::WGmeta::Wrapper::Config->new('<path to wireguard configuration>');

 # set an attribute (non wg-meta attributes forwarded to the original `wg set` command)
 wg_meta->set('wg0', 'WG_0_PEER_A_PUBLIC_KEY', '<attribute_name>', '<attribute_value>');

 # set an alias for a peer
 wg_meta->set('wg0', 'WG_0_PEER_A_PUBLIC_KEY', 'alias', 'some_fancy_alias');

 # disable peer (this comments out the peer in the configuration file
 wg_meta->disable_by_alias('wg0', 'some_fancy_alias');

 # write config (if parameter is set to True, the config is overwritten, if set to False the resulting file is suffixed with '_not_applied'
 wg_meta->commit(1);

=head1 METHODS

=cut

use v5.20.0;
package Wireguard::WGmeta::Wrapper::Config;
use strict;
use warnings;
use experimental 'signatures';
use File::Basename;
use Wireguard::WGmeta::Wrapper::Bridge;
use Wireguard::WGmeta::ValidAttributes;
use Wireguard::WGmeta::Utils;
use Digest::MD5 qw(md5);
use List::Util qw(sum);

use base 'Exporter';
our @EXPORT = qw(parse_wg_config create_wg_config);

our $VERSION = "0.0.0"; # do not change manually, this variable is updated when calling make

use constant FALSE => 0;
use constant TRUE => 1;

# constants for states of the config parser
use constant IS_EMPTY => -1;
use constant IS_COMMENT => 0;
use constant IS_SECTION => 2;
use constant IS_NORMAL => 3;


=head3 new($wireguard_home [, $wg_meta_prefix = '#+', $wg_meta_disabled_prefix = '#-'])

Creates a new instance of this class.

B<Parameters>

=over 1

=item *

C<$wireguard_home> Path to Wireguard configuration files. Make sure the path ends with a `/`.

=item *

C<[, $wg_meta_prefix]> A custom wg-meta comment prefix, has to begin with either `;` or `#`.
It is recommended to not change this setting, especially in a already deployed installation.

=item *

C<[, $wg_meta_disabled_prefix]> A custom prefix for the commented out (disabled) sections,
has to begin with either `;` or `#` and must not be equal with C<$wg_meta_prefix>! (This is enforced and an exception is thrown if violated)
It is recommended to not change this setting, especially in a ready deployed installation.

=back

B<Returns>

An instance of Wrapper::Config

=cut
sub new($class, $wireguard_home, $wg_meta_prefix = '#+', $wg_meta_disabled_prefix = '#-') {

    if ($wg_meta_prefix eq $wg_meta_disabled_prefix) {
        die '`$wg_meta_prefix` and `$wg_meta_disabled_prefix` have to be different';
    }

    my ($parsed_config, $count) = _read_configs_from_folder($wireguard_home, $wg_meta_prefix, $wg_meta_disabled_prefix);
    my $self = {
        'wireguard_home'           => $wireguard_home,
        'wg_meta_prefix'           => $wg_meta_prefix,
        'wg_meta_disabled_prefix'  => $wg_meta_disabled_prefix,
        'n_conf_files'             => $count,
        'parsed_config'            => $parsed_config,
        'wg_meta_attrs'            => Wireguard::WGmeta::ValidAttributes::WG_META_DEFAULT,
        'wg_meta_additional_attrs' => Wireguard::WGmeta::ValidAttributes::WG_META_ADDITIONAL,
        'wg_orig_interface_attrs'  => Wireguard::WGmeta::ValidAttributes::WG_ORIG_INTERFACE,
        'wg_orig_peer_attrs'       => Wireguard::WGmeta::ValidAttributes::WG_ORIG_PEER,
        'wg_quick_attrs'           => Wireguard::WGmeta::ValidAttributes::WG_QUICK,
    };
    bless $self, $class;
    return $self;
}

sub _read_configs_from_folder($wireguard_home, $wg_meta_prefix, $wg_meta_disabled_prefix) {
    my $parsed_configs = {};
    my ($all_dot_conf, $count) = get_all_conf_files($wireguard_home);
    for my $possible_config_path (@{$all_dot_conf}) {
        my $contents = read_file($possible_config_path);
        my $interface = $possible_config_path;
        $interface =~ s/^\/|\\|.*\/|.*\\|.conf$//g;
        my $parsed_config = parse_wg_config($contents, $interface, $wg_meta_prefix, $wg_meta_disabled_prefix);
        if (defined $parsed_config) {
            # additional data
            $parsed_config->{config_path} = $possible_config_path;
            $parsed_config->{mtime} = get_mtime($possible_config_path);
            $parsed_configs->{$interface} = $parsed_config;
        }
    }
    return $parsed_configs, $count;
}

=head3 set($interface, $identifier, $attribute, $value [, $allow_non_meta, $forward_function])

Sets a value on a specific interface section. If C<$attribute> == C<$value> this sub is essentially a No-Op.

B<Parameters>

=over 1

=item *

C<$interface> Valid interface identifier (e.g 'wg0')

=item *

C<$identifier> If the target section is a peer, this is usually the public key of this peer. If target is an interface,
its again the interface name

=item *

C<$attribute> Attribute name (Case does not not matter)

=item *

C<[$allow_non_meta = FALSE]> If set to TRUE, non wg-meta attributes are not forwarded to C<$forward_function>.

=item *

C<[$forward_function = undef]> A reference to a callback function when C<$allow_non_meta = TRUE>. The following signature
is expected: C<forward_fun($interface, $identifier, $attribute, $value)>

=back

B<Raises>

Exception if either the interface or identifier is invalid.

B<Returns>

None

=cut
sub set($self, $interface, $identifier, $attribute, $value, $allow_non_meta = FALSE, $forward_function = undef) {
    my $attr_type = decide_attr_type($attribute, TRUE);
    unless (defined $value) {
        warn "Undefined value for `$attribute` in interface `$interface` NOT SET";
        return;
    }
    if ($self->is_valid_interface($interface)) {
        if ($self->is_valid_identifier($interface, $identifier)) {

            # skip if same value
            if (exists $self->{parsed_config}{$interface}{$identifier}{$attribute} && $self->{parsed_config}{$interface}{$identifier}{$attribute} eq $value) {
                return;
            }
            if ($attr_type == ATTR_TYPE_IS_WG_META || $attr_type == ATTR_TYPE_IS_WG_META_CUSTOM) {

                unless (attr_value_is_valid($attribute, $value, get_attr_config($attr_type))) {
                    die "Invalid attribute value `$value` for `$attribute`";
                }
                unless (exists $self->{parsed_config}{$interface}{$identifier}{$attribute}) {
                    # the attribute does not (yet) exist in the configuration, lets add it to the list
                    push @{$self->{parsed_config}{$interface}{$identifier}{order}}, $attribute;
                }
                if ($attribute eq 'alias') {
                    $self->_update_alias_map($interface, $identifier, $value);
                }
                $self->{parsed_config}{$interface}{$identifier}{$attribute} = $value;
            }
            else {
                if ($allow_non_meta == TRUE) {
                    if (_fits_wg_section($interface, $identifier, $attr_type)) {
                        unless (attr_value_is_valid($attribute, $value, get_attr_config($attr_type))) {
                            die "Invalid attribute value `$value` for `$attribute`";
                        }
                        unless (exists $self->{parsed_config}{$interface}{$identifier}{$attribute}) {
                            # the attribute does not (yet) exist in the configuration, lets add it to the list
                            push @{$self->{parsed_config}{$interface}{$identifier}{order}}, $attribute;
                        }
                        # the attribute does already exist and therefore we just set it to the new value
                        $self->{parsed_config}{$interface}{$identifier}{$attribute} = $value;
                    }
                    else {
                        die "The supplied attribute `$attribute` is not valid for this section type (this most likely means you've tried to set a peer attribute in the interface section or vice-versa)";
                    }
                }
                else {
                    if (defined($forward_function)) {
                        &{$forward_function}($interface, $identifier, $attribute, $value);
                    }
                    else {
                        die 'No forward function defined';
                    }
                }
            }
            $self->_set_changed($interface);
        }
        else {
            die "Invalid identifier `$identifier` for interface `$interface`";
        }
    }
    else {
        die "Invalid interface name `$interface`";
    }

}

# internal method to check if a non-meta attribute is valid for the target section
sub _fits_wg_section($interface, $identifier, $attr_type) {
    # if we have an interface
    if ($interface eq $identifier) {
        return $attr_type == ATTR_TYPE_IS_WG_ORIG_INTERFACE || $attr_type == ATTR_TYPE_IS_WG_QUICK
    }
    else {
        return $attr_type == ATTR_TYPE_IS_WG_ORIG_PEER;
    }
}

=head3 attr_value_is_valid($attribute, $value, $ref_valid_attrs)

Simply calls the C<validate()> function defined in L<Wireguard::WGmeta::Validator>

B<Parameters>

=over 1

=item

C<$attribute> Attribute name

=item

C<$value> Attribute value

=item

C<$ref_valid_attrs> Reference to the corresponding L<Wireguard::WGmeta::Validator> section.

=back

B<Returns>

True if validation was successful, False if not

=cut
sub attr_value_is_valid($attribute, $value, $ref_valid_attrs) {
    return $ref_valid_attrs->{$attribute}{validator}($value);
}

sub _update_alias_map($self, $interface, $identifier, $alias) {
    unless (exists $self->{parsed_config}{$interface}{alias_map}{$alias}) {
        $self->{parsed_config}{$interface}{alias_map}{$alias} = $identifier;
    }
    else {
        die "Alias `$alias` is already defined on interface `$interface`";
    }
}

=head3 set_by_alias($interface, $alias, $attribute, $value [, $allow_non_meta = FALSE, $forward_function = undef])

Same as L</set($interface, $identifier, $attribute, $value [, $allow_non_meta, $forward_function])> - just with alias support.

B<Raises>

Exception if alias is invalid

=cut
sub set_by_alias($self, $interface, $alias, $attribute, $value, $allow_non_meta = FALSE, $forward_function = undef) {
    my $identifier = $self->translate_alias($interface, $alias);
    $self->set($interface, $identifier, $attribute, $value, $allow_non_meta, $forward_function);
}

=head3 disable($interface, $identifier)

Disables an interface/peer (by prefixing C<$wg_meta_disabled_prefix>) and setting the wg-meta attribute `Disabled` to C<1>.

B<Parameters>

=over 1

=item *

C<$interface> Valid interface name (e.g 'wg0').

=item *

C<$identifier> A valid identifier: If the target section is a peer, this is usually the public key of this peer. If target is an interface,
its again the interface name.

=back

B<Returns>

None

=cut
sub disable($self, $interface, $identifier,) {
    $self->_toggle($interface, $identifier, TRUE);
}

=head3 enable($interface, $identifier)

Inverse method if L</disable($interface, $identifier)>

=cut
sub enable($self, $interface, $identifier) {
    $self->_toggle($interface, $identifier, FALSE);
}

=head3 disable_by_alias($interface, $alias)

Same as L</disable($interface, $identifier)> just with alias support

B<Raises>

Exception if alias is invalid

=cut
sub disable_by_alias($self, $interface, $alias,) {
    $self->_toggle($interface, $self->translate_alias($interface, $alias), FALSE);
}

=head3 disable_by_alias($interface, $alias)

Same as L</enable($interface, $identifier)>ust with alias support

B<Raises>

Exception if alias is invalid

=cut
sub enable_by_alias($self, $interface, $alias,) {
    $self->_toggle($interface, $self->translate_alias($interface, $alias), TRUE);
}

# internal toggle method (DRY)
sub _toggle($self, $interface, $identifier, $enable) {
    if (exists $self->{parsed_config}{$interface}{$identifier}{Disabled}) {
        if ($self->{parsed_config}{$interface}{$identifier}{Disabled} == "$enable") {
            warn "Section `$identifier` in `$interface` is already $enable";
        }
    }
    $self->set($interface, $identifier, 'disabled', $enable);
}

=head3 is_valid_interface($interface)

Checks if an interface name is valid (present in parsed config)

B<Parameters>

=over 1

=item

C<$interface> An interface name

=back

B<Returns>

True if present, undef if not.

=cut
sub is_valid_interface($self, $interface) {
    return (exists $self->{parsed_config}{$interface});
}

=head3 is_valid_identifier($interface, $identifier)

Checks if an identifier is valid for a given interface

B<Parameters>

=over 1

=item

C<$interface> An interface name

=item

C<$identifier> An identifier (no alias!)

=back

B<Returns>

True if present, undef if not.

=cut
sub is_valid_identifier($self, $interface, $identifier) {
    return (exists $self->{parsed_config}{$interface}{$identifier});
}

=head3 translate_alias($interface, $alias)

Translates an alias to a valid identifier.

B<Parameters>

=over 1

=item *

C<$interface> A valid interface name (e.g 'wg0').

=item *

C<$alias> An alias to translate

=back

B<Raises>

Exception if alias is invalid

B<Returns>

A valid identifier.

=cut
sub translate_alias($self, $interface, $alias) {
    if (exists $self->{parsed_config}{$interface}{alias_map}{$alias}) {
        return $self->{parsed_config}{$interface}{alias_map}{$alias};
    }
    else {
        die "Invalid alias `$alias` on interface $interface";
    }
}
=head3 try_translate_alias($interface, $may_alias)

Tries to translate an identifier (which may be an alias).
However, unlike L</translate_alias($interface, $alias)>, no
exception is thrown on failure, instead the C<$may_alias> is returned.

B<Parameters>

=over 1

=item

C<$interface> A valid interface name (is not validated)

=item

C<$may_alias> An identifier which could be a valid alias for this interface

=back

B<Returns>

If the alias is valid for the specified interface, the corresponding identifier is returned, else C<$may_alias>

=cut
sub try_translate_alias($self, $interface, $may_alias) {
    if (exists $self->{parsed_config}{$interface}{alias_map}{$may_alias}) {
        return $self->{parsed_config}{$interface}{alias_map}{$may_alias};
    }
    else {
        return $may_alias;
    }
}

=head3 get_all_conf_files($wireguard_home)

Returns a list of all files in C<$wireguard_home> matching I<r/.*\.conf$/>.

B<Parameters>

=over 1

=item

C<$wireguard_home> Path to a folder where wireguard configuration files are located

=back

B<Returns>

A reference to a list with absolute paths to the config files (possibly empty)

=cut
sub get_all_conf_files($wireguard_home) {
    my @config_files = read_dir($wireguard_home, qr/.*\.conf$/);
    if (@config_files == 0) {
        die "No matching interface configuration(s) in " . $wireguard_home;
    }
    my $count = @config_files;
    return \@config_files, $count;
}

=head3 parse_wg_config($config_file_content, $interface_name, $wg_meta_prefix, $disabled_prefix [, $use_checksum])

Parses the contents of C<$config_file_content> and returns a hash with the following structure:

    {
        'interface_name' => {
            'section_order' => <list_of_available_section_identifiers>,
            'alias_map'     => <mapping_alias_to_identifier>,
            'checksum'      => <calculated_checksum_of_this_interface_config>,
            'n_peers'       => <number_of_peers_for_this_interface>,
            'interface_name' => <interface_name>,
            'a_identifier'    => {
                'type'  => <'Interface' or 'Peer'>,
                'order' => <list_of_attributes_in_their_original_order>,
                'attr0' => <value_of_attr0>,
                'attrN' => <value_of_attrN>
            },
            'an_other_identifier => {
                [...]
            }
        }
    }

B<Remarks>

=over 1

=item *

All attributes listed in L<Wireguard::WGmeta::ValidAttributes> are referenced by their key. This means, if you want for
example access I<PublicKey> the key would be I<public-key>. Any attribute not present in L<Wireguard::WGmeta::ValidAttributes>
is stored (and written back) as they appear in Config.

=item *
This method can be used as stand-alone together with the corresponding L</create_wg_config($ref_interface_config, $wg_meta_prefix, $disabled_prefix [, $plain = FALSE])>.

=item *

If the section is of type 'Peer' the identifier equals to its public-key, otherwise its the interface name again.

=item *

wg-meta attributes are always prefixed with C<$wg_meta_prefix>.

=item *

If a section is marked as "disabled", this is represented in the attribute I<$wg_meta_prefix. 'Disabled' >.
However, does only exist if this section has been enabled/disabled once.

=item *

To check whether a file is actually a Wireguard interface config, the parser first checks the presence of the string
I<[Interface]>. If not present, the file is skipped (without warning!). And in this case the parser returns undefined!

=back

B<Parameters>

=over 1

=item *

C<$config_file_content> String containing the contents of a Wireguard configuration file.

=item *

C<$interface_name> Interface name

=item *

C<$wg_meta_prefix> wg-meta prefix. Must start with '#' or ';'

=item *

C<$disabled_prefix> disabled prefix. Must start with '#' or ';'

=item *

C<[$use_checksum = TRUE]> If set to False, checksum is not checked


=back

B<Raises>

An exceptions if:

=over 1

=item *

If the parser ends up in an invalid state (e.g a section without information).

=back

A warning:

=over 1

=item *

On a checksum mismatch

=back

B<Returns>

A reference to a hash with the structure described above. Or if the configuration file is not a Wireguard configuration: undef.

=cut
sub parse_wg_config($config_file_content, $interface_name, $wg_meta_prefix, $disabled_prefix, $use_checksum = TRUE) {
    my $regex_friendly_meta_prefix = quotemeta $wg_meta_prefix;

    my $parsed_wg_config = {};

    return undef unless ($config_file_content =~ /\[Interface\]/);

    my %alias_map;
    my $current_state = -1;
    my $peer_count = 0;

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

    for my $line (split "\n", $config_file_content) {
        $current_state = _decide_state($line, $wg_meta_prefix, $disabled_prefix);

        # remove disabled prefix if any
        $line =~ s/^$disabled_prefix//g;

        if ($current_state == IS_EMPTY) {
            # empty line
        }
        elsif ($current_state == IS_SECTION) {
            # strip-off [] and whitespaces
            $line =~ s/^\[|\]\s*$//g;
            if (_is_valid_section($line)) {
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
                            $parsed_wg_config->{$identifier} = $section_data;
                            $parsed_wg_config->{$identifier}{type} = $section_type;

                            # update peer count if we have type [Peer]
                            $peer_count++ if ($section_type eq 'Peer');

                            # we have to use a copy of the array here - otherwise the reference stays the same in all sections.
                            $parsed_wg_config->{$identifier}{order} = [ @section_data_order ];
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
        elsif ($current_state == ATTR_TYPE_IS_WG_META) {
            # a special wg-meta attribute
            if ($STATE_INIT_DONE == FALSE) {
                # this is already a wg-meta config and therefore we expect a checksum
                (undef, $checksum) = split_and_trim($line, "=");
            }
            else {
                if ($STATE_READ_SECTION == TRUE) {
                    $STATE_EMPTY_SECTION = FALSE;
                    my ($attr_name, $attr_value) = split_and_trim($line, "=");

                    # remove wg-meta prefix
                    $attr_name =~ s/^$regex_friendly_meta_prefix//g;
                    $attr_name = _attr_to_internal_name($attr_name);
                    if ($attr_name eq 'alias') {
                        if (exists $alias_map{$attr_value}) {
                            die "Alias '$attr_value' already exists, aborting";
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
                $attr_name = _attr_to_internal_name($attr_name);
                if (_is_identifying($attr_name)) {
                    $STATE_READ_ID = TRUE;
                    if ($section_type eq 'Interface') {
                        $identifier = $interface_name;
                    }
                    else {
                        $identifier = $attr_value;
                    }

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
        die "Section without identifying information found (Private -or PublicKey field) in config file `$interface_name`";
    }
    else {
        $peer_count++ if ($section_type eq 'Peer');
        $parsed_wg_config->{$identifier} = $section_data;
        $parsed_wg_config->{$identifier}{type} = $section_type;
        $parsed_wg_config->{checksum} = $checksum;
        $parsed_wg_config->{section_order} = \@section_order;
        $parsed_wg_config->{alias_map} = \%alias_map;
        $parsed_wg_config->{n_peers} = $peer_count;
        $parsed_wg_config->{interface_name} = $interface_name;

        $parsed_wg_config->{$identifier}{order} = \@section_data_order;
        push @section_order, $identifier;
        if ($STATE_READ_ALIAS == TRUE) {
            $alias_map{$alias} = $identifier;
        }
    }
    # checksum
    unless ($use_checksum == FALSE) {
        my $current_hash = compute_md5_checksum(create_wg_config($parsed_wg_config, $wg_meta_prefix, $disabled_prefix, TRUE));
        if ($checksum ne '' && "$current_hash" ne $checksum) {
            warn "Config `$interface_name.conf` has been changed by an other program or user. This is just a warning.";
        }
    }

    return $parsed_wg_config;
}

# internal method to decide that current state using a line of input
sub _decide_state($line, $comment_prefix, $disabled_prefix) {
    #remove leading white space
    $line =~ s/^\s+//;
    for ($line) {
        $_ eq '' && return IS_EMPTY;
        (substr $_, 0, 1) eq '[' && return IS_SECTION;
        /^\Q${comment_prefix}/ && return ATTR_TYPE_IS_WG_META;
        /^\Q${disabled_prefix}/ && do {
            $line =~ s/^$disabled_prefix//g;
            # lets do a little bit of recursion here ;)
            return _decide_state($line, $comment_prefix, $disabled_prefix);
        };
        (substr $_, 0, 1) eq '#' && return IS_COMMENT;
        return IS_NORMAL;
    }
}

# internal method to whether a section has a valid type
sub _is_valid_section($section) {
    return {
        Peer      => 1,
        Interface => 1
    }->{$section};
}

# internal method to check if an attribute fulfills identifying properties
sub _is_identifying($attr_name) {
    return {
        'private-key' => 1,
        'public-key'  => 1
    }->{$attr_name};
}

sub _attr_to_internal_name($attr_name) {
    if (exists Wireguard::WGmeta::ValidAttributes::NAME_2_KEYS_MAPPING->{$attr_name}) {
        return Wireguard::WGmeta::ValidAttributes::NAME_2_KEYS_MAPPING->{$attr_name};
    }
    else {
        return $attr_name;
    }
}

=head3 split_and_trim($line, $separator)

Utility method to split and trim a string separated by C<$separator>.

B<Parameters>

=over 1

=item *

C<$line> Input string (e.g 'This = That   ')

=item *

C<$separator> String separator (e.v '=')

=back

B<Returns>

Two strings. With example values given in the parameters this would be 'This' and 'That'.

=cut
sub split_and_trim($line, $separator) {
    return map {s/^\s+|\s+$//g;
        $_} split $separator, $line, 2;
}

=head3 create_wg_config($ref_interface_config, $wg_meta_prefix, $disabled_prefix [, $plain = FALSE])

Turns a reference of interface-config hash (just a single interface)
(as defined in L</parse_wg_config($config_file_content, $interface_name, $wg_meta_prefix, $disabled_prefix [, $use_checksum])>) back into a wireguard config.

B<Parameters>

=over 1

=item *

C<$ref_interface_config> Reference to hash containing B<one> interface config.

=item *

C<$wg_meta_prefix> Has to start with a '#' or ';' character and is optimally the
same as in L</parse_wg_config($config_file_content, $interface_name, $wg_meta_prefix, $disabled_prefix [, $use_checksum])>

=item *

C<$wg_meta_prefix> Same restrictions as parameter C<$wg_meta_prefix>

=item *

C<[, $plain = FALSE]> If set to true, no header is added (useful for checksum calculation)

=back

B<Returns>

A string, ready to be written down as a config file.

=cut
sub create_wg_config($ref_interface_config, $wg_meta_prefix, $disabled_prefix, $plain = FALSE) {
    my $new_config = "";

    for my $identifier (@{$ref_interface_config->{section_order}}) {
        if (_is_disabled($ref_interface_config->{$identifier})) {
            $new_config .= $disabled_prefix;
        }
        # write down [section_type]
        $new_config .= "[$ref_interface_config->{$identifier}{type}]\n";
        for my $attr_name (@{$ref_interface_config->{$identifier}{order}}) {
            if (_is_disabled($ref_interface_config->{$identifier})) {
                $new_config .= $disabled_prefix;
            }
            if (substr($attr_name, 0, 7) eq 'comment') {
                $new_config .= $ref_interface_config->{$identifier}{$attr_name} . "\n";
            }
            else {
                my $attr_type = decide_attr_type($attr_name, TRUE);
                my $meta_prefix = '';
                if ($attr_type == ATTR_TYPE_IS_WG_META_CUSTOM || $attr_type == ATTR_TYPE_IS_WG_META) {
                    $meta_prefix = $wg_meta_prefix;
                }
                unless ($attr_type == ATTR_TYPE_IS_UNKNOWN) {
                    $new_config .= $meta_prefix . get_attr_config($attr_type)->{$attr_name}{in_config_name}
                        . " = " . $ref_interface_config->{$identifier}{$attr_name} . "\n";
                }
                else {
                    $new_config .= "$attr_name = $ref_interface_config->{$identifier}{$attr_name}\n";
                }

            }
        }
        $new_config .= "\n";
    }
    if ($plain == FALSE) {
        my $new_hash = compute_md5_checksum($new_config);
        my $config_header = "# This config is generated and maintained by wg-meta.\n"
            . "# It is strongly recommended to edit this config only through a supporting wg-meta\n"
            . "# implementation (e.g the wg-meta cli interface)\n"
            . "#\n"
            . "# Changes to this header are always overwritten, you can add normal comments in [Peer] and [Interface] section though.\n"
            . "#\n"
            . "# Support and issue tracker: https://github.com/sirtoobii/wg-meta\n"
            . "#+Checksum = $new_hash\n\n";

        return $config_header . $new_config;
    }
    else {
        return $new_config;
    }
}

=head3 commit([$is_hot_config = FALSE, $plain = FALSE])

Writes down the parsed config to the wireguard configuration folder

B<Parameters>

=over 1

=item

C<[$is_hot_config = FALSE])> If set to TRUE, the existing configuration is overwritten. Otherwise,
the suffix '_not_applied' is appended to the filename

=item

C<[$plain = FALSE])> If set to TRUE, no header is generated

=back

B<Raises>

Exception if: Folder or file is not writeable

B<Returns>


None

=cut
sub commit($self, $is_hot_config = FALSE, $plain = FALSE) {
    for my $interface (keys %{$self->{parsed_config}}) {
        if ($self->_has_changed($interface)) {
            my $new_config = create_wg_config($self->{parsed_config}{$interface}, $self->{wg_meta_prefix}, $self->{wg_meta_disabled_prefix}, $plain);
            my $fh;
            if ($is_hot_config == TRUE) {
                open $fh, '>', $self->{wireguard_home} . $interface . '.conf' or die $!;
            }
            else {
                open $fh, '>', $self->{wireguard_home} . $interface . '.conf_not_applied' or die $!;
            }
            # write down to file
            print $fh $new_config;
            $self->_reset_changed($interface);
            close $fh;
        }
    }
}

# internal method to check if a section is disabled
sub _is_disabled($ref_parsed_config_section) {
    if (exists $ref_parsed_config_section->{disabled}) {
        return $ref_parsed_config_section->{disabled} == TRUE;
    }
    return FALSE;
}

=head3 get_interface_list()

Return a list of all interfaces.

B<Returns>

A list of all valid interface names. If no interfaces are available, an empty list is returned

=cut
sub get_interface_list($self) {
    return sort keys %{$self->{parsed_config}};
}

=head3 get_interface_section($interface, $identifier)

Returns a hash representing a section of a given interface

B<Parameters>

=over 1

=item *

C<$interface> Valid interface name

=item *

C<$identifier> Valid section identifier

=back

B<Returns>

A hash containing the requested section. If the requested section/interface is not present, an empty hash is returned.

=cut
sub get_interface_section($self, $interface, $identifier) {
    if (exists $self->{parsed_config}{$interface}{$identifier}) {
        my %r = %{$self->{parsed_config}{$interface}{$identifier}};
        return %r;
    }
    else {
        return ();
    }
}

=head3 get_section_list($interface)

Returns a list of valid sections of an interface (ordered as in the original config file).

B<Parameters>

=over 1

=item *

C<$interface> A valid interface name

=back

B<Returns>

A list of all sections of an interface. If interface is not present, an empty list is returned.

=cut
sub get_section_list($self, $interface) {
    if (exists $self->{parsed_config}{$interface}) {
        return @{$self->{parsed_config}{$interface}{section_order}};
    }
    else {
        return ();
    }
}

sub get_wg_meta_prefix($self) {
    return $self->{wg_meta_prefix};
}

sub get_disabled_prefix($self) {
    return $self->{wg_meta_disabled_prefix};
}

=head3 add_interface($interface_name, $ip_address, $listen_port, $private_key)

Adds a (minimally configured) interface. If more attributes are needed, please set them using the C<set()> method.

B<Caveat:> No validation is performed on the values!

B<Parameters>

=over 1

=item *

C<$interface_name> A new interface name, must be unique.

=item *

C<$ip_address> A string describing the ip net(s) (e.g '10.0.0.0/24, fdc9:281f:04d7:9ee9::2/64')

=item *

C<$listen_port> The listen port for this interface.

=item *

C<$private_key> A private key for this interface

=back

B<Raises>

An exception if the interface name already exists.

B<Returns>

None

=cut
sub add_interface($self, $interface_name, $ip_address, $listen_port, $private_key) {
    if ($self->is_valid_interface($interface_name)) {
        die "Interface `$interface_name` already exists";
    }
    my %interface = (
        'Address'    => $ip_address,
        'ListenPort' => $listen_port,
        'PrivateKey' => $private_key,
        'type'       => 'Interface',
        'order'      => [ 'Address', 'ListenPort', 'PrivateKey' ]
    );
    $self->{parsed_config}{$interface_name}{$interface_name} = \%interface;
    $self->{parsed_config}{$interface_name}{alias_map} = {};
    $self->{parsed_config}{$interface_name}{section_order} = [ $interface_name ];
    $self->{parsed_config}{$interface_name}{checksum} = 'none';
    $self->{parsed_config}{$interface_name}{mtime} = 0.0;
    $self->{parsed_config}{$interface_name}{config_path} = $self->{wireguard_home} . $interface_name . '.conf';
    $self->{parsed_config}{$interface_name}{has_changed} = 1;

}

=head3 add_peer($interface, $name, $ip_address, $public_key [, $alias, $preshared_key])

Adds a peer to an exiting interface.

B<Parameters>

=over 1

=item *

C<$interface> A valid interface.

=item *

C<$name> A name for this peer (wg-meta).

=item *

C<$ip_address> A string describing the ip-address(es) of this this peer.

=item *

C<$public_key> Public-key for this interface. This becomes the identifier of this peer.

=item *

C<[$preshared_key]> Optional argument defining the psk.

=item *

C<[$alias]> Optional argument defining an alias for this peer (wg-meta)

=back

B<Raises>

An exception if either the interface is invalid, the alias is already assigned or the public-key is
already present on an other peer.

B<Returns>

A tuple consisting of the iface private-key and listen port

=cut
sub add_peer($self, $interface, $name, $ip_address, $public_key, $alias = undef, $preshared_key = undef) {
    # generate new key pair if not defined
    if ($self->is_valid_interface($interface)) {
        if ($self->is_valid_identifier($interface, $public_key)) {
            die "An interface with this public-key already exists on `$interface`";
        }
        # generate peer config
        my %peer = ();
        $self->{parsed_config}{$interface}{$public_key} = \%peer;
        $self->set($interface, $public_key, 'name', $name);
        $self->set($interface, $public_key, 'public-key', $public_key, 1);
        $self->set($interface, $public_key, 'allowed-ips', $ip_address, 1);
        if (defined $alias) {
            $self->set($interface, $public_key, 'alias', $alias);
        }
        if (defined $preshared_key) {
            $self->set($interface, $public_key, 'preshared-key', $preshared_key);
        }

        # set type to to Peer
        $self->{parsed_config}{$interface}{$public_key}{type} = 'Peer';
        # add section to global section list
        push @{$self->{parsed_config}{$interface}{section_order}}, $public_key;
        return $self->{parsed_config}{$interface}{$interface}{'private-key'}, $self->{parsed_config}{$interface}{$interface}{'listen-port'};
    }
    else {
        die "Invalid interface `$interface`";
    }
}

=head3 remove_peer($interface, $identifier)

Removes a peer (identified by it's public key or alias) from an interface.

B<Parameters>

=over 1

=item

C<$interface> A valid interface name

=item

C<$identifier> A valid identifier (or an alias)

=back

B<Raises>

Exception if interface or identifier is invalid

B<Returns>

None

=cut
sub remove_peer($self, $interface, $identifier) {
    if ($self->is_valid_interface($interface)) {
        $identifier = $self->try_translate_alias($interface, $identifier);
        if ($self->is_valid_identifier($interface, $identifier)) {

            # delete section
            delete $self->{parsed_config}{$interface}{$identifier};

            # delete from section list
            $self->{parsed_config}{$interface}{section_order} = [ grep {$_ ne $identifier} @{$self->{parsed_config}{$interface}{section_order}} ];

            # decrease peer count
            $self->{parsed_config}{$interface}{n_peers}--;

            # delete alias (if exists)
            while (my ($alias, $a_identifier) = each %{$self->{parsed_config}{$interface}{alias_map}}) {
                if ($a_identifier eq $identifier) {
                    delete $self->{parsed_config}{$interface}{alias_map}{$alias};
                }
            }
            $self->_set_changed($interface);
        }
        else {
            die "Invalid identifier `$identifier` for `$interface`";
        }
    }
    else {
        die "Invalid interface `$interface`";
    }
}

=head3 remove_interface($interface [, $keep_file = FALSE])

Removes an interface. This command deletes the config file immediately. I.e no rollback possible!

B<Parameters>

=over 1

=item

C<$interface> A valid interface name

=back

B<Raises>

Exception if interface or identifier is invalid

B<Returns>

None

=cut
sub remove_interface($self, $interface) {
    if ($self->is_valid_interface($interface)) {
        # delete interface
        delete $self->{parsed_config}{$interface};
        unlink "$self->{wireguard_home}$interface.conf" or warn "Could not delete `$self->{wireguard_home}$interface.conf` do you have the needed permissions?";
        $self->{n_conf_files}--;
    }
}

=head3 get_peer_count([$interface = undef])

Returns the number of peers.

B<Caveat:> Does return the count represented  in the current (parsed) configuration state.

B<Parameters>

=over 1

=item

C<[$interface = undef]> If defined, only return counts for this specific interface

=back

B<Returns>

Number of peers

=cut
sub get_peer_count($self, $interface = undef) {
    if (defined $interface && $self->is_valid_interface($interface)) {
        return $self->{parsed_config}{$interface}{n_peers};
    }
    else {
        my $count = 0;
        for ($self->get_interface_list()) {
            $count += $self->{parsed_config}{$_}{n_peers};
        }
        return $count;
    }
}

sub reload_from_disk($self, $interface, $new = FALSE) {
    my $config_path;
    if ($new == FALSE) {
        $config_path = $self->{wireguard_home} . $interface . '.conf';
        my $contents = read_file($self->{parsed_config}{$interface}{config_path});
        $self->{parsed_config}{$interface} = parse_wg_config($contents, $interface, $self->{wg_meta_prefix}, $self->{wg_meta_disabled_prefix}, FALSE);
        $self->{parsed_config}{$interface}{config_path} = $config_path;
        $self->{parsed_config}{$interface}{mtime} = get_mtime($config_path);
    }
    else {
        $config_path = $self->{wireguard_home} . $interface . '.conf';
        my $contents = read_file($config_path);
        my $maybe_new_config = parse_wg_config($contents, $interface, $self->{wg_meta_prefix}, $self->{wg_meta_disabled_prefix}, FALSE);
        if (defined $maybe_new_config) {
            $self->{n_conf_files}++;
            $self->{parsed_config}{$interface} = $maybe_new_config;
            $self->{parsed_config}{$interface}{config_path} = $config_path;
            $self->{parsed_config}{$interface}{mtime} = get_mtime($config_path);
        }
    }

}

# internal method to add to hash if value is defined
sub _add_to_hash_if_defined($ref_hash, $key, $value) {
    if (defined($value)) {
        $ref_hash->{$key} = $value;
    }
    return $ref_hash;
}

# internal method to create a configuration file (this method exists primarily for testing purposes)
sub _create_config($self, $interface, $plain = FALSE) {
    return create_wg_config(
        $self->{parsed_config}{$interface},
        $self->{wg_meta_prefix},
        $self->{disabled_prefix},
        $plain = $plain)
}

sub _has_changed($self, $interface) {
    return exists $self->{parsed_config}{$interface}{has_changed};
}

sub _set_changed($self, $interface) {
    $self->{parsed_config}{$interface}{has_changed} = 1;
}

sub _reset_changed($self, $interface){
    delete $self->{parsed_config}{$interface}{has_changed} if (exists $self->{parsed_config}{$interface}{has_changed});
}

1;