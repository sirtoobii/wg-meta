package Wireguard::Wrapper;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use base 'Exporter';
our @EXPORT = qw(read_wg_config write_wg_config read_wg_show);
use Data::Dumper;

use constant FALSE => 0;
use constant TRUE => 1;

# constants for config the config parser
use constant IS_EMPTY => -1;
use constant IS_COMMENT => 0;
use constant IS_WG_META => 1;
use constant IS_SECTION => 2;
use constant IS_NORMAL => 3;



sub read_wg_config($config_path, $wg_meta_prefix, $disabled_prefix) {
    # create file-handle
    open(my $fh, '<', $config_path) or die $!;

    my $parsed_wg_config = {};
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
    my @section_data_order;
    my @section_order;

    while (my $line = readline($fh)) {
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
                    close($fh);
                    die("Found empty section, aborting");
                }
                else {
                    $STATE_READ_SECTION = TRUE;

                    if ($STATE_INIT_DONE == TRUE) {
                        # we are at the end of a section and therefore we can store the data

                        #first check if we read an private or public-key
                        if ($STATE_READ_ID == FALSE) {
                            close($fh);
                            die("Section without identifying information found (Private -or PublicKey field")
                        }
                        else {
                            $STATE_READ_ID = FALSE;
                            $STATE_EMPTY_SECTION = TRUE;
                            $parsed_wg_config->{$identifier} = $section_data;
                            # we have to use a copy of the array here.
                            $parsed_wg_config->{$identifier}->{type} = $section_type;
                            push @section_order, $identifier;
                            $parsed_wg_config->{$identifier}->{order} = [ @section_data_order ];

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
                close($fh);
                die("Invalid section found: $line");
            }
        }
        elsif ($current_state == IS_COMMENT) {
            my $comment_id = "comment_" . $comment_counter++;
            push @section_data_order, $comment_id;

            $line =~ s/^\s+|\s+$//g;
            $section_data->{$comment_id} = $line;
        }
        elsif ($current_state == IS_WG_META) {
            # a special wg-meta attribute
            if ($STATE_READ_SECTION == TRUE) {
                $STATE_EMPTY_SECTION = FALSE;
                my ($attr_name, $attr_value) = split_and_trim($line, "=");
                if ($attr_name eq $wg_meta_prefix . "Alias") {
                    if (exists($alias_map{$attr_value})) {
                        close($fh);
                        die("Alias '$attr_value' already exists, aborting");
                    }
                    $STATE_READ_ALIAS = TRUE;
                    $alias = $attr_value;
                }
                push @section_data_order, $attr_name;
                $section_data->{$attr_name} = $attr_value;
            }
            else {
                close($fh);
                die("Attribute without a section encountered, aborting");
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
                close($fh);
                die("Attribute without a section encountered, aborting");
            }
        }
    }
    # store last section
    if ($STATE_READ_ID == FALSE) {
        die("Section without identifying information found (Private -or PublicKey field")
    }
    else {
        $parsed_wg_config->{$identifier} = $section_data;
        $parsed_wg_config->{$identifier}->{type} = $section_type;

        $parsed_wg_config->{$identifier}->{order} = \@section_data_order;
        push @section_order, $identifier;
        if ($STATE_READ_ALIAS == TRUE) {
            $alias_map{$alias} = $identifier;
        }
    }
    #print Dumper(\%alias_map);
    #print Dumper(\@section_order);
    #print Dumper($parsed_wg_config);
    close($fh);
    return ($parsed_wg_config, \@section_order, \%alias_map);
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
    if (substr($line, 0, length($comment_prefix)) eq $comment_prefix) {
        return IS_WG_META;
    }
    # is it a deactivated line
    if (substr($line, 0, length($disabled_prefix)) eq $disabled_prefix) {
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
    my %valid_sections;
    @valid_sections{
        "Peer",
        "Interface"
    } = ();
    return exists($valid_sections{$section});
}

sub _is_identifying($attr_name) {
    my %valid_ids;
    @valid_ids{
        "PrivateKey",
        "PublicKey"
    } = ();
    return exists($valid_ids{$attr_name});
}

sub split_and_trim($line, $separator) {
    my @values = split($separator, $line, 2);
    $values[0] =~ s/^\s+|\s+$//g;
    $values[1] =~ s/^\s+|\s+$//g;
    return @values;
}

sub write_wg_config($filename, $wg_meta_prefix, $disabled_prefix, $ref_parsed_config, $ref_section_order) {
    my $new_config =
        '# This config is generated and maintained by wg-meta.
# It is strongly recommended to edit this config only through a supporting wg-meta
# implementation (e.g the wg-meta cli interface)
#
# Support and issue tracker: https://github.com/sirtoobii/wg-meta

';
    for my $identifier (@{$ref_section_order}) {
        if (_is_disabled($ref_parsed_config->{$identifier}, $wg_meta_prefix . "Disabled")) {
            $new_config .= $disabled_prefix;
        }
        # write down [section_type]
        $new_config .= "[$ref_parsed_config->{$identifier}->{type}]\n";
        for my $key (@{$ref_parsed_config->{$identifier}->{order}}) {
            if (_is_disabled($ref_parsed_config->{$identifier}, $wg_meta_prefix . "Disabled")) {
                $new_config .= $disabled_prefix;
            }
            if (substr($key, 0, 7) eq 'comment') {
                $new_config .= $ref_parsed_config->{$identifier}->{$key} . "\n";
            }
            else {
                $new_config .= $key . " = " . $ref_parsed_config->{$identifier}->{$key} . "\n";
            }
        }
        $new_config .= "\n";
    }

    open(my $fh, '>', $filename) or die $!;
    # write down to file
    print $fh $new_config;
    close($fh);
}

sub _is_disabled($ref_parsed_config_section, $key) {
    if (exists($ref_parsed_config_section->{$key})) {
        return $ref_parsed_config_section->{$key} == TRUE;
    }
}

sub read_wg_show($input) {
    # Caveat: This parser assumes empty line = end of section
    my $parsed_show = {};
    foreach my $section (split /\n{2}/, $input) {
        if ($section =~ /peer/) {
            my ($identifier, $section_data) = _handle_section($section, 'peer');
            $parsed_show->{$identifier} = $section_data;
        }
        elsif ($section =~ /interface/) {
            my ($identifier, $section_data) = _handle_section($section, 'interface');
            $parsed_show->{$identifier} = $section_data;
        }
        else {
            die("Invalid section found")
        }
    }
    return $parsed_show;
}

sub _handle_section($input, $ident_key) {
    my %section_data;
    foreach my $line (split /\n/, $input) {
        my ($key, $value) = split_and_trim($line, ':');
        $section_data{$key} = $value;
    }
    return ($section_data{$ident_key}, \%section_data);
}