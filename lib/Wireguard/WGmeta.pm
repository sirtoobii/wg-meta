=head1 NAME

wg-meta

=head1 DESCRIPTION

An approach to add metadata to the main wireguard config, written in Perl.

=head1 HIGHLIGHTS

=over 1

=item *

Compatible with your existing setup (no configuration changes needed).

=item *

A CLI interface with abilities to I<set>, I<enable>, I<disable> and I<apply> your wireguard config(s).

=item *

A fancy C<show> output which combines the meta-data, running-config and static-configs

=item *

Modular structure: The whole parser is independent of the CLI module - and can be used as a standalone library.

=item *

The config parser/writer and as well as the C<wg show dump> parser are independent too.
For more info, please refer to L<Wireguard::WGmeta::Wrapper::Config> and L<Wireguard::WGmeta::Wrapper::Show>

=item *

No external dependencies, runs on plain Perl (>=v5.22)!

=back

=head1 INSTALLATION

	# Build from source
	perl Makefile.PL
	make test
	make install

	# Using `.deb` package (available in the linked git repo)
	sudo dpkg -i wg-meta_X.X.X.deb

=head1 ENVIRONMENT VARS

=over 1

=item *

I<WIREGUARD_HOME>: Directory containing the Wireguard configuration -> Make sure the path ends with a `/`. Defaults to I</etc/wireguard/>.

=item *

I<IS_TESTING>: When defined, it has the following effects:

=over 2

=item *

I<Commands::Set|Enable|Disable> omits the header of the generated configuration files.

=item *

Line of code is shown for warnings and errors.

=back

=item *

I<WG_NO_COLOR>: If defined, the show command does not prettify the output with colors.

=back

=head1 SYNOPSIS (Parser)

Please refer to the respective modules L<Wireguard::WGmeta::Wrapper::Config> and L<Wireguard::WGmeta::Wrapper::Show>

=head1 SYNOPSIS (CLI)

Intended to use as command wrapper for the C<wg show> and C<wg set> commands. Support for C<wg-quick> is enabled by default.

Please note that B<all> attributes have to be specified in the `wg set` _syntax_, which means _AllowedIPs_ becomes
allowed-ips and so on.

	sudo wg-meta show

	# output
	interface: wg0
	  State: UP
	  ListenPort: 51888
	  PublicKey: +qz742hzxD3E5z5QF7VOvleVS1onavQpXBK3NdTh40g=

	+peer: WG_0_PEER_A_PUBLIC_KEY
	  Name: testero
	  Alias: Dual_stack_peer1
	  AllowedIPs: fdc9:281f:04d7:9ee9::1/128, 10.0.3.43/32
	  endpoint: 147.86.207.49:10400  latest-handshake: >month ago  transfer-rx: 0.26 MiB  transfer-tx: 1.36 MiB

	# Access using peer
	sudo wg-meta set wg0 peer +qz742hzxD3E5z5QF7VOvleVS1onavQpXBK3NdTh40g= name Fancy_meta_name

	# Access using alias
	sudo wg-meta set wg0 some_alias description "Some Desc"

	# Disable peer
	sudo wg-meta disable wg0 some_alias

	# Enable peer
	sudo wg-meta enable wg0 +qz742hzxD3E5z5QF7VOvleVS1onavQpXBK3NdTh40g=

	# Apply config
	sudo wg-meta apply wg0

=head1 UNDER THE HOOD

The main advantage is that this tool is not dependent on any other storage, metadata is stored inside the corresponding
I<wgXX.conf> file (Metadata is prefixed with I<#+>):

	[Interface]
	#+Alias = some_alias
	#+Description = Some Desc
	Address = 10.0.0.7/24
	ListenPort = 6666
	PrivateKey = WEkEJW3b4TDmRvN+G+K9elzq52/djAXT+LAB6BSEUmM=

	[Peer]
	#+Name = Fancy_meta_name
	PublicKey = +qz742hzxD3E5z5QF7VOvleVS1onavQpXBK3NdTh40g=
	AllowedIPs = 0.0.0.0/0
	Endpoint = wg.example.com

=head1 AUTHORS

S<Tobias Bossert E<lt>tobib at cpan.orgE<gt>>

=head1 COPYRIGHT AND LICENSE

MIT License

Copyright (c) 2020 Tobias Bossert

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

=cut

package Wireguard::WGmeta;

1;