# wg-meta

An approach to add metadata to the main wireguard config, written in Perl.

## Highlights

- Compatible with your existing setup (no configuration changes needed).
- A CLI interface with abilities to _set_, _enable_, _disable_ and _apply_ your wireguard config(s).
- A fancy _show_ output which combines the meta-data, running-config and static-configs
- Modular structure: The whole parser is independent of the CLI module - and can be used as a standalone library.
- The config parser/writer and as well as the `wg show dump` parser are independent too. For more info, please refer to the respective POD.
- No external dependencies, runs on plain Perl (>=v5.22)!

## Installation

### Build from source
```shell
./autoreconf --install
./configure
make test
make install
```

### From tar-ball
```shell
tar xvf wg-meta-X.X.X.tar.gz
cd wg-meta-X.X.X
make test
make install
```

## Environment variables

- `WIREGUARD_HOME`: Directory containing the Wireguard configuration -> Make sure the path ends with a `/`.
- `IS_TESTING`: When defined, it has the following effects:
    - `Commands::Set|Enable|Disable` omits the header of the generated configuration files.

## Usage

Intended to use as command wrapper for the `wg show` and `wg set` commands. Support for `wg-quick`is enabled by default.

Please note that **all** attributes have to be specified in the `wg set` _syntax_, which means _AllowedIPs_ becomes
allowed-ips and so on.

```bash
sudo wg-meta show
# Some fancy output (tbd.)

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
```

## Under the hood

The main advantage is that this tool is not dependent on any other storage, metadata is stored inside the corresponding
`wgXX.conf` file (Comments prefixed with `#+`):

```text
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
```

