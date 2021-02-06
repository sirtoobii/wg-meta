package Wireguard::WGmeta::Wrapper::ConfigT;
use strict;
use warnings FATAL => 'all';
use Digest::SHA qw(sha1_hex);
use Fcntl qw(:flock);
use File::Basename;
use experimental 'signatures';

use Wireguard::WGmeta::Wrapper::Config;
use Wireguard::WGmeta::ValidAttributes;
use Wireguard::WGmeta::Utils;

use parent 'Wireguard::WGmeta::Wrapper::Config';

use constant FALSE => 0;
use constant TRUE => 1;
use constant INTEGRITY_HASH_SALT => 'wefnwioefh9032ur3';


sub is_valid_interface($self, $interface) {
    $self->_scan_for_new_interfaces();
    return $self->SUPER::is_valid_interface($interface);
}

sub is_valid_identifier($self, $interface, $identifier) {
    $self->_may_reload_from_disk($interface);
    return $self->SUPER::is_valid_identifier($interface, $identifier);
}

sub translate_alias($self, $interface, $alias) {
    $self->_may_reload_from_disk($interface);
    return $self->SUPER::translate_alias($interface, $alias);
}

sub try_translate_alias($self, $interface, $may_alias) {
    $self->_may_reload_from_disk($interface);
    return $self->SUPER::try_translate_alias($interface, $may_alias);
}

sub get_interface_section($self, $interface, $identifier) {
    $self->_may_reload_from_disk($interface);
    if (exists $self->{parsed_config}{$interface}{$identifier}) {
        my %r = %{$self->{parsed_config}{$interface}{$identifier}};
        $r{integrity_hash} = calculate_sha1_from_section($self->{parsed_config}{$interface}{$identifier});
        return %r;
    }
    else {
        return ();
    }
}

sub get_section_list($self, $interface) {
    $self->_may_reload_from_disk($interface);
    return $self->SUPER::get_section_list($interface);
}

sub get_peer_count($self, $interface = undef) {
    $self->_may_reload_from_disk($interface);
    return $self->SUPER::get_peer_count($interface);
}

sub get_all_conf_files($wireguard_home) {
    my @config_files = read_dir($wireguard_home, qr/.*\.conf$/);
    if (@config_files == 0) {
        die "No matching interface configuration(s) in " . $wireguard_home;
    }
    my $count = @config_files;
    return \@config_files, $count;
}

sub get_interface_list($self) {
    $self->_scan_for_new_interfaces();
    return sort keys %{$self->{parsed_config}};
}

=head3 commit([$is_hot_config = FALSE, $plain = FALSE])

Writes down the parsed config to the wireguard configuration folder.
Does have an exclusive lock on the file while writing!

B<Caveat> The is a very small chance for a race condition:

    $self->_die_if_not_latest_data($interface);
    ...
    # an other instance starts writing somewhere between these lines
    ...
    write_file($file_name, $new_config); # ->BOOM!

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
sub commit($self, $is_hot_config = FALSE, $plain = FALSE, $ref_hash_integrity_keys = undef) {
    for my $interface_name (keys %{$self->{parsed_config}}) {
        my $file_name;
        if ($is_hot_config == TRUE) {
            $file_name = $self->{parsed_config}{$interface_name}{config_path};
        }
        else {
            $file_name = $self->{parsed_config}{$interface_name}{config_path} . '_not_applied';
        }
        my $on_disk_config = undef;
        my $fh;

        # check if interface exists - if not, we have a new interface
        if (-e $self->{parsed_config}{$interface_name}{config_path}) {

            # in this case open the file for RW
            open $fh, '+<', $self->{parsed_config}{$interface_name}{config_path};
            flock $fh, LOCK_EX;
            unless ($self->_is_latest_data($interface_name)) {
                $on_disk_config = read_wg_configs([ $fh ], $self->{wg_meta_prefix}, $self->{wg_meta_disabled_prefix}, FALSE, TRUE, [ $interface_name ]);
            }
            else {
                open $fh, '>', $self->{parsed_config}{$interface_name}{config_path};
                flock $fh, LOCK_EX;
            }
        }
        else {
            open $fh, '>', $self->{parsed_config}{$interface_name}{config_path};
            flock $fh, LOCK_EX;
        }
        seek $fh, 0, 0;
        truncate $fh, 0;
        my $new_config = $self->create_wg_configT(
            $interface_name,
            $plain,
            $on_disk_config,
            $ref_hash_integrity_keys
        );
        # write down to file
        print $fh $new_config;
        $self->{parsed_config}{$interface_name}{mtime} = get_mtime($self->{parsed_config}{$interface_name}{config_path});
        close $fh;
    }
}

sub _create_config($self, $interface, $plain = 0) {
    $self->_may_reload_from_disk();
    return $self->SUPER::_create_config($interface, $plain);
}

sub create_wg_configT($self, $interface, $plain = FALSE, $ref_on_disk_config = undef, $ref_hash_integrity_keys = undef) {
    my $new_config = "";
    my $ref_current_internal_config = $self->{parsed_config}{$interface};
    my $reference_config = $ref_current_internal_config;
    if (defined $ref_on_disk_config) {
        $reference_config = $ref_on_disk_config->{$interface};
    }
    my @may_conflict;
    my @exclusive_disk;
    my @exclusive_internal;
    if (defined $ref_on_disk_config) {
        for my $identifier_internal (@{$self->{parsed_config}{$interface}{section_order}}) {
            if (exists $ref_on_disk_config->{$interface}{$identifier_internal}) {
                push @may_conflict, $identifier_internal;
            }
            else {
                push @exclusive_internal, $identifier_internal;
            }
        }
        for my $identifier_ondisk (@{$ref_on_disk_config->{$interface}{section_order}}) {
            unless (exists $self->{parsed_config}{$interface}{$identifier_ondisk}) {
                push @exclusive_disk, $identifier_ondisk;
            }
        }
    }
    else {
        @may_conflict = @{$self->{parsed_config}{$interface}{section_order}};
    }

    for my $identifier (@may_conflict) {
        my $section_data = $ref_current_internal_config->{$identifier};
        if (defined $ref_on_disk_config) {
            my $on_disk_sha = calculate_sha1_from_section($ref_on_disk_config->{$interface}{$identifier});
            my $internal_sha = calculate_sha1_from_section($ref_current_internal_config->{$identifier});
            if ($on_disk_sha ne $internal_sha) {
                # we may have a hash which allows us to modify
                if (defined $ref_hash_integrity_keys && exists $ref_hash_integrity_keys->{$identifier}) {
                    if ($on_disk_sha eq $ref_hash_integrity_keys->{$identifier}) {
                        # take from internal
                        $section_data = $ref_current_internal_config->{$identifier};
                    }
                    else {
                        warn "your changes for `$identifier` were not applied";
                        $section_data = $ref_on_disk_config->{$interface}{$identifier}
                    }
                }
                else {
                    # take from disk
                    $section_data = $ref_on_disk_config->{$interface}{$identifier}
                }
            }
            else {
                # take from disk
                $section_data = $ref_on_disk_config->{$interface}{$identifier}
            }
        }
        $new_config .= $self->_create_section($section_data);

    }
    # exclusive mode
    $new_config .= join '', map{$self->_create_section($self->{parsed_config}{$interface}{$_});} @exclusive_internal;
    $new_config .= join '', map{$self->_create_section($ref_on_disk_config->{$interface}{$_});} @exclusive_disk;
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

sub _create_section($self, $section_data) {
    my $new_config;
    if (_is_disabled($section_data)) {
        $new_config .= $self->{wg_meta_disabled_prefix};
    }
    # write down [section_type]
    $new_config .= "[$section_data->{type}]\n";
    for my $attr_name (@{$section_data->{order}}) {
        if (_is_disabled($section_data)) {
            $new_config .= $self->{wg_meta_disabled_prefix};
        }
        if (substr($attr_name, 0, 7) eq 'comment') {
            $new_config .= $section_data->{$attr_name} . "\n";
        }
        else {
            my $attr_type = decide_attr_type($attr_name, TRUE);
            my $meta_prefix = '';
            if ($attr_type == ATTR_TYPE_IS_WG_META_CUSTOM || $attr_type == ATTR_TYPE_IS_WG_META) {
                $meta_prefix = $self->{wg_meta_prefix};
            }
            unless ($attr_type == ATTR_TYPE_IS_UNKNOWN) {
                $new_config .= $meta_prefix . get_attr_config($attr_type)->{$attr_name}{in_config_name}
                    . " = " . $section_data->{$attr_name} . "\n";
            }
            else {
                $new_config .= "$attr_name = $section_data->{$attr_name}\n";
            }

        }
    }
    $new_config .= "\n";
    return $new_config;
}

=head3 _may_reload_from_disk([$interface = undef])

This method is called before any data is returned from one of the C<get_*()> methods. It behaves as follows:

=over 1

=item *

If the interface is not defined, it loops through the known interfaces and reloads them individually (if needed).

=item *

If the interface is defined (and known), the modify timestamps are compared an if the on-disk version is newer, a reload is triggered.

=item *

If the interface is defined (but not known -> this could be the case if a new interface has been added), first we check if there is
actually a matching config file on disk and if yes, its loaded and parsed from disk.

=back

Remark: This method is not meant for public access, there is just this extensive documentation block since its behaviour
is crucial to the function of this wrapper class.

B<Parameters>

=over 1

=item

C<$interface> A (possibly) invalid (or new) interface name

=back

B<Returns>

None

=cut
sub _may_reload_from_disk($self, $interface = undef) {
    unless (defined $interface) {
        for my $known_interface ($self->get_interface_list()) {
            # my $s = $self->_get_my_mtime($known_interface);
            # my $t = get_mtime($self->{parsed_config}{$known_interface}{config_path});
            if ($self->_get_my_mtime($known_interface) < get_mtime($self->{parsed_config}{$known_interface}{config_path})) {
                $self->reload_from_disk($known_interface);
            }
        }
    }
    elsif (exists $self->{parsed_config}{$interface}) {
        # my $s = $self->_get_my_mtime($interface);
        # my $t = get_mtime($self->{parsed_config}{$interface}{config_path});
        if ($self->_get_my_mtime($interface) < get_mtime($self->{parsed_config}{$interface}{config_path})) {
            $self->reload_from_disk($interface);
        }
    }
    else {
        # we may have a new interface added in the meantime so we probe if there is actually a config file first
        if (-e $self->{wireguard_home} . $interface . '.conf') {
            $self->reload_from_disk($interface, TRUE);
        }
    }

}

sub _get_my_mtime($self, $interface) {
    if (exists $self->{parsed_config}{$interface}) {
        return $self->{parsed_config}{$interface}{mtime};
    }
    else {
        return 0;
    }
}

sub _is_latest_data($self, $interface) {
    my $conf_path = $self->{wireguard_home} . $interface . ".conf";
    return $self->_get_my_mtime($interface) ge get_mtime($conf_path);
}

sub _scan_for_new_interfaces($self) {
    # check if theres maybe a new interface by comparing the file counts
    my ($conf_files, $count) = get_all_conf_files($self->{wireguard_home});
    if ($self->{n_conf_files} != $count) {
        for my $conf_path (@{$conf_files}) {
            # read interface name
            my $i_name = basename($conf_path);
            $i_name =~ s/\.conf$//;
            $self->_may_reload_from_disk($i_name);
        }
    }
}

sub _is_disabled($ref_parsed_config_section) {
    if (exists $ref_parsed_config_section->{disabled}) {
        return $ref_parsed_config_section->{disabled} == TRUE;
    }
    return FALSE;
}

sub calculate_sha1_from_section($ref_to_hash) {
    my $s = 'wefwef';
    my %h = %{$ref_to_hash};
    return sha1_hex INTEGRITY_HASH_SALT . join '', map {$h{$_}} @{$ref_to_hash->{order}};
}

sub calculate_sha_from_internal($self, $interface, $identifier) {
    return calculate_sha1_from_section($self->{parsed_config}{$interface}{$identifier});
}

1;