package Wireguard::Wrapper;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';
use base 'Exporter';
our @EXPORT = qw(read_wg_config);
use Data::Dumper;

use constant FALSE => 0;
use constant TRUE => 1;

use constant IS_EMPTY => -1;
use constant IS_COMMENT => 0;
use constant IS_WG_META => 1;
use constant IS_SECTION => 2;
use constant IS_NORMAL => 3;



sub read_wg_config($config_path, $comment_prefix, $comment_separator, $disabled_prefix, $ref_wg_meta_attrs) {
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

    while (my $line = readline($fh)) {
        my $is_line_disabled;
        ($current_state, $is_line_disabled) = _decide_state($line, $comment_prefix, $disabled_prefix);

        # set disabled section flag
        if ($is_disabled == FALSE && $is_line_disabled == TRUE) {$is_disabled = TRUE};

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
                    $section_type = $line;

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
                            $parsed_wg_config->{$identifier}->{order} = [@section_data_order];
                            $parsed_wg_config->{$identifier}->{type} = $section_type;
                            $parsed_wg_config->{$identifier}->{$comment_prefix."Disabled"} = $is_disabled;

                            # reset vars
                            $section_data = {};
                            $is_disabled = FALSE;
                            @section_data_order = ();
                            if ($STATE_READ_ALIAS == TRUE) {
                                $alias_map{$alias} = $identifier;
                                $STATE_READ_ALIAS = FALSE;
                            }
                        }
                    }
                    $STATE_INIT_DONE = TRUE;
                }
            }
            else {
                close($fh);
                die("Invalid section found: $line");
            }
        }
        elsif ($current_state == IS_COMMENT) {
            my $comment_id ="comment".$comment_counter++;
            push @section_data_order, $comment_id;

            $line =~ s/^\s+|\s+$//g;
            $section_data->{$comment_id} = $line;
        }
        elsif ($current_state == IS_WG_META) {
            # a special wg-meta attribute
            if ($STATE_READ_SECTION == TRUE) {
                $STATE_EMPTY_SECTION = FALSE;
                my ($attr_name, $attr_value) = split_and_trim($line, $comment_separator);
                if ($attr_name eq $comment_prefix . "Alias") {
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
        $parsed_wg_config->{$identifier}->{order} = \@section_data_order;
        $parsed_wg_config->{$identifier}->{type} = $section_type;
        $parsed_wg_config->{$identifier}->{$comment_prefix."Disabled"} = $is_disabled;
        if ($STATE_READ_ALIAS == TRUE) {
            $alias_map{$alias} = $identifier;
        }
    }
    print Dumper(\%alias_map);
    print Dumper($parsed_wg_config);
    close($fh);
}

sub _decide_state($line, $comment_prefix, $disabled_prefix, $is_disabled = FALSE) {
    #remove leading and tailing white space
    $line =~ s/^\s+|\s+$//g;
    if ($line eq "") {
        return (IS_EMPTY, $is_disabled);
    }
    # Is it the start of a section
    if (substr($line, 0, 1) eq "[") {
        return (IS_SECTION, $is_disabled);
    }
    # is it a special wg-meta attribute
    if (substr($line, 0, length($comment_prefix)) eq $comment_prefix) {
        return (IS_WG_META, $is_disabled);
    }
    # is it a deactivated line
    if (substr($line, 0, length($disabled_prefix)) eq $disabled_prefix) {
        $line =~ s/^$disabled_prefix//g;
        # lets do a little bit of recursion here ;)
        return _decide_state($line, $comment_prefix, $disabled_prefix, TRUE);
    }
    # Is it a normal comment
    if (substr($line, 0, 1) eq "#") {
        return (IS_COMMENT, $is_disabled);
    }
    # normal attribute
    return (IS_NORMAL, $is_disabled);
}

sub _is_valid_section($section) {
    $section =~ s/^\s+|\s+$//g;
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