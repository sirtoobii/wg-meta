package Wireguard::WGmeta::Cli::Commands::Add;
use strict;
use warnings FATAL => 'all';

use experimental 'signatures';

use parent 'Wireguard::WGmeta::Cli::Commands::Command';

use Wireguard::WGmeta::Wrapper::Bridge;
use Wireguard::WGmeta::ValidAttributes;
use Wireguard::WGmeta::Parser::Middleware;

sub entry_point($self) {
    if ($self->_retrieve_or_die($self->{input_args}, 0) eq 'help') {
        $self->cmd_help();
    }
    $self->check_privileges();
    # read input parameters
    my $len = @{$self->{input_args}};
    $self->{interface} = $self->_retrieve_or_die($self->{input_args}, 0);
    $self->{ips} = $self->_retrieve_or_die($self->{input_args}, 1);
    if ($len > 2) {
        # We hav additional arguments
        my @additional_args = @{$self->{input_args}}[2 .. $len - 1];
        die 'Uneven number of elements (one pair would be without value!)' if scalar @additional_args % 2 != 0;
        $self->{additional_args} = \@additional_args;
    }
    # generate private/public keypair
    my ($privkey, $pubkey) = gen_keypair();
    $self->{pub_key} = $pubkey;
    $self->{priv_key} = $privkey;

    $self->_run_command();
}


sub _run_command($self) {
    my ($iface_privkey, $iface_listen) = $self->wg_meta->add_peer(
        $self->{interface},
        $self->{ips},
        $self->{pub_key}
    );
    # get pubkey of iface priv-key
    my $iface_pubkey = get_pub_key($iface_privkey);

    # get interface config
    my %host_interface = $self->wg_meta->get_interface_section($self->{interface}, $self->{interface});
    my $fqdn = exists($host_interface{FQDN}) ? $host_interface{FQDN} : 'insert.valid.fqdn.not.valid';

    # lets create a temporary interface
    $self->wg_meta->add_interface('temp', $self->{ips}, 44544, $self->{priv_key});
    $self->wg_meta->add_peer('temp', '0.0.0.0/0, ::/0', $iface_pubkey);
    $self->wg_meta->set('temp', $iface_pubkey, 'endpoint', "$fqdn:$iface_listen");
    if (exists($host_interface{DNSHost})){
        $self->wg_meta->set('temp', 'temp', 'dns', $host_interface{DNSHost});
    }
    $self->wg_meta->set('temp', $iface_pubkey, 'persistent-keepalive', 25);

    my $unknown_handler_temp = sub($attribute, $value) {
        my $prefix = substr $attribute, 0, 1;
        $prefix eq '+' ? return (substr $attribute, 1), $value : return $attribute, $value;
    };

    if (defined $self->{additional_args}) {
        my @additional_args = @{$self->{additional_args}};
        for (my $i = 0; $i < scalar @additional_args; $i += 2) {
            my $attribute = $additional_args[$i];
            my $value = $additional_args[$i + 1];
            my $attr_type = get_attr_type($attribute);
            if ($attr_type == ATTR_TYPE_IS_WG_META) {
                $self->wg_meta->set($self->{interface}, $self->{pub_key}, $attribute, $value);
                $self->wg_meta->set('temp', 'temp', $attribute, $value);
            }
            elsif ($attr_type == ATTR_TYPE_IS_WG_ORIG_INTERFACE) {
                $self->wg_meta->set('temp', 'temp', $attribute, $value);
            }
            else {
                $self->wg_meta->set($self->{interface}, $self->{pub_key}, $attribute, $value, \&Wireguard::WGmeta::Cli::Commands::Command::_unknown_attr_handler);
                $self->wg_meta->set('temp', 'temp', $attribute, $value, $unknown_handler_temp) if $attr_type != ATTR_TYPE_IS_WG_ORIG_PEER;
            }

        }
    }

    print "#Generated by wg-meta\n" . $self->wg_meta->create_config('temp', 0);
    # remove our temp interface again
    $self->wg_meta->remove_interface('temp');
    $self->wg_meta->commit(1);
}

sub cmd_help($self) {
    print "Usage: wg-meta addpeer <interface> <ip-address> [attr1 value1] [attr2 value2] ...\n\n"
        . "Notes: \nAttributes meant to reside in the [Interface] section are only applied to the peer's interface\n"
        . "wg-meta attributes are applied to the host's peer config and the client interface config\n"
        . "and finally, attributes meant to be in the [Peer] section are only applied to the host's peer entry.\n\n"
        . "To automatically fill in dns and endpoint name, make sure #+DNSHost and #+FQDN is present in [Interface]\n"
        . "Do not forget to reload the configuration afterwards!\n";

    exit();
}

1;