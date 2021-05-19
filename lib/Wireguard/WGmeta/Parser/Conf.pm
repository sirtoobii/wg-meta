package Wireguard::WGmeta::Parser::Conf;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

use base 'Exporter';
our @EXPORT = qw(parse);

sub parse($file_content, $on_every_value, $wg_meta_prefix = '#+', $wg_disabled_prefix = '#-') {
    my $IDENT_KEY = '';
    my $IS_ACTIVE = 1;
    my $IS_HEADER = 1;

    my $parsed_config = {};
    my @config_order;

    my $section_data = {};
    my @section_order;

    my $generic_autokey = 0;

    my $section_handler = sub {
        $section_data->{section_order} = [ @section_order ];
        $section_data->{is_active} = $IS_ACTIVE;
        if ($IS_HEADER) {
            $parsed_config = $section_data;
            $section_data = {};
        }
        else {
            $parsed_config->{$section_data->{$IDENT_KEY}} = { %$section_data };
            push @config_order, $section_data->{$IDENT_KEY};
            $section_data = {};
        }

        @section_order = ();
        $IDENT_KEY = 'PublicKey';
        $IS_ACTIVE = 1;
    };

    for my $line (split "\n", $file_content) {
        # Strip-of any leading or trailing whitespace
        $line =~ s/^\s+|\s+$//g;

        # Also slice off possible wg-meta prefixes
        $line = (substr $line, 2) if (substr $line, 0, 2) eq $wg_meta_prefix;
        if ((substr $line, 0, 2) eq $wg_disabled_prefix) {
            $line = substr $line, 2;
            $IS_ACTIVE = 0;
        }

        # skip empty lines
        next unless $line;

        # Simply decide if we are in an interface or peer section
        if ((substr $line, 0, 11) eq '[Interface]') {
            &$section_handler();
            $IDENT_KEY = 'PrivateKey';
            $IS_HEADER = 0;
            next;
        }
        if ((substr $line, 0, 6) eq '[Peer]') {
            &$section_handler();
            $IDENT_KEY = 'PublicKey';
            $IS_HEADER = 0;
            next;
        }
        unless ((substr $line, 0, 1) eq '#') {
            my ($raw_key, $raw_value) = split_and_trim($line, '=');
            my ($key, $value) = &$on_every_value($raw_key, $raw_value);
            $section_data->{$key} = $value;

            # Update identity key if changed
            $IDENT_KEY = $key if $raw_key eq $IDENT_KEY;
            push @section_order, $key;
        }
        else {
            # Handle "normal" comments
            my $comment_key = "comment_$generic_autokey";
            $section_data->{$comment_key} = $line;
            push @section_order, $comment_key;
        }
        $generic_autokey++;
    }
    # and finalize
    &$section_handler();
    $parsed_config->{config_order} = \@config_order;

    return $parsed_config;
}

sub split_and_trim($line, $separator) {
    return map {s/^\s+|\s+$//g;
        $_} split $separator, $line, 2;
}
1;