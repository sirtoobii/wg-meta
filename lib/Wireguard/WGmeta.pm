=head1 NAME

wg-meta - A toolkit to manage Wireguard configurations.

=head1 DESCRIPTION

An approach to add metadata to the main wireguard config, written in Perl.

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

use strict;
use warnings FATAL => 'all';
package Wireguard::WGmeta;

1;