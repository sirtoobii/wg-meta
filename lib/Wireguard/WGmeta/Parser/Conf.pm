package Wireguard::WGmeta::Parser::Conf;
use strict;
use warnings FATAL => 'all';
use experimental 'signatures';

use base 'Exporter';
our @EXPORT = qw(parse);


sub parse ($file_content, $on_every_value, $skip = 0, $wg_meta_prefix = '#+', $wg_disabled_prefix = '#-') {
    my $IDENT_KEY = '';
    my $IS_ACTIVE = 0;
    my $IS_ROOT = 1;
    my $IS_WG_META = 0;

    my $parsed_config = {};
    my @config_order;

    my $section_data = {};
    my @section_order;
    my @wg_meta;

    my $generic_autokey = 0;
    my $line_count = 0;

    my $section_handler = sub {
        if ($IS_ROOT) {
            $parsed_config = $section_data;
            $section_data = {};
        }
        else {
            $section_data->{section_order} = [ @section_order ];
            $section_data->{wg_meta} = [ @wg_meta ];
            $section_data->{is_active} = $IS_ACTIVE == 1 ? 0 : 1;
            $parsed_config->{$section_data->{$IDENT_KEY}} = { %$section_data };
            push @config_order, $section_data->{$IDENT_KEY};
            $section_data = {};
        }

        @section_order = ();
        @wg_meta = ();
        $IDENT_KEY = 'PublicKey';
        $IS_ACTIVE--;
        $IS_ROOT = 0;
    };

    for my $line (split "\n", $file_content) {
        $line_count++;
        next if $line_count <= $skip;

        # Strip-of any leading or trailing whitespace
        $line =~ s/^\s+|\s+$//g;

        if ((substr $line, 0, 2) eq $wg_disabled_prefix) {
            $line = substr $line, 2;
            $IS_ACTIVE = 2 if $IS_ACTIVE != 1;
        }
        if ((substr $line, 0, 2) eq $wg_meta_prefix) {
            # Also slice-off wg-meta prefixes
            $line = substr $line, 2;
            $IS_WG_META = 1;
        }
        else {
            $IS_WG_META = 0;
        }

        # skip empty lines
        next unless $line;

        # Simply decide if we are in an interface or peer section
        if ((substr $line, 0, 11) eq '[Interface]') {
            &$section_handler();
            $IDENT_KEY = 'PrivateKey';
            next;
        }
        if ((substr $line, 0, 6) eq '[Peer]') {
            &$section_handler();
            $IDENT_KEY = 'PublicKey';
            next;
        }
        my ($definitive_key, $definitive_value);
        unless ((substr $line, 0, 1) eq '#') {
            my ($raw_key, $raw_value) = _split_and_trim($line, '=');
            ($definitive_key, $definitive_value) = &$on_every_value($raw_key, $raw_value);

            # Update identity key if changed
            $IDENT_KEY = $definitive_key if $raw_key eq $IDENT_KEY;
        }
        else {
            # Handle "normal" comments
            $definitive_key = "comment_$generic_autokey";
            $definitive_value = $line;
        }
        $section_data->{$definitive_key} = $definitive_value;
        $IS_ROOT ? push @config_order, $definitive_key : push @section_order, $definitive_key;
        push @wg_meta, $definitive_key if $IS_WG_META;
        $generic_autokey++;
    }
    # and finalize
    &$section_handler();
    $parsed_config->{config_order} = \@config_order;

    return $parsed_config;
}

sub _split_and_trim ($line, $separator) {
    return map {s/^\s+|\s+$//g;
        $_} split $separator, $line, 2;
}
1;