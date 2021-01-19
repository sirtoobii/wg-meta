package Wireguard::WGmeta::Cli::Commands::Add;
use strict;
use warnings FATAL => 'all';

use experimental 'signatures';

use parent 'Wireguard::WGmeta::Cli::Commands::Command';

use Wireguard::WGmeta::Wrapper::Bridge;

sub entry_point($self) {
    if ($self->_retrieve_or_die($self->{input_args}, 0) eq 'help') {
        $self->cmd_help();
    }
    # read input parameters
    my $len = @{$self->{input_args}};
    $self->{interface} = $self->_retrieve_or_die($self->{input_args}, 0);
    $self->{name} = $self->_retrieve_or_die($self->{input_args}, 1);
    $self->{ips} = $self->_retrieve_or_die($self->{input_args}, 2);
    if ($len > 3) {
        $self->{alias} = $self->_retrieve_or_die($self->{input_args}, 3);
    }
    # generate private/public keypair
    my ($privkey, $pubkey) = gen_keypair();
    $self->{pub_key} = $pubkey;
    $self->{priv_key} = $privkey;

    # would be very nice if we can set a type hint here...possible?
    $self->{'wg_meta'} = Wireguard::WGmeta::Wrapper::Config->new($self->{wireguard_home});
    $self->_run_command();
}


sub _run_command($self) {
    my ($iface_privkey, $iface_listen) = $self->{wg_meta}->add_peer(
        $self->{interface},
        $self->{name},
        $self->{ips},
        $self->{pub_key},
        $self->{alias}
    );

    # get pubkey of iface priv-key
    my $iface_pubkey = get_pub_key($iface_privkey);
    print "# generated by wg-meta
[Interface]
#+Name = $self->{name}
Address = $self->{ips}
ListenPort = 44544
PrivateKey = $self->{priv_key}

[Peer]
PublicKey = $iface_pubkey
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = <replace-with-your-fqdn-or-ip>:$iface_listen
PersistentKeepalive = 25
";

    $self->{wg_meta}->commit(1);
}

sub cmd_help($self) {
    print "Usage: wg-meta addpeer <interface> <name> <ip-address> [alias]\n";
    exit();
}

1;