# wg-meta
An approach to add metadata to the main wireguard config, written in Perl.

## Configuration
There is only one config file: `wg-meta.yaml` which defines the additional (meta-) attributes.:
```yaml
# according to wg-meta.schema.json
default_attributes:
  name:
    mandatory: true
  alias:
    mandatory: true
x-custom_attributes:
- name: some_custom_name
  mandatory: true
- name: some_other_custom_attribute
  mandatory: false
- name: some_super_custom_attribute
  mandatory: true
  x-custom_property: true
  x-an_other_custom_p: "Contents of this custom property" 
```
## Usage
Intended to use as command wrapper for the `wg show` and `wg set` commands from [wireguard-tools](https://manpages.debian.org/unstable/wireguard-tools/wg.8.en.html).
```bash
wg-meta show
# Some fancy output (tbd.)

# Access using peer
wg-meta set wg0 peer +qz742hzxD3E5z5QF7VOvleVS1onavQpXBK3NdTh40g= name Fancy_meta_name

# Access using alias
wg-meta set wg0 alias some_alias description "Some Desc"

# Some "default" operation -> forwarded to the original wg command
wg-meta set wg0 [alias|peer] +qz742hzxD3E5z5QF7VOvleVS1onavQpXBK3NdTh40g= allowed-ips 0.0.0.0/0
```
## Under the hood
The main advantage is that this tool is not dependent on any other storage, metadata is stored inside the corresponding
`wgXX.conf` file (Comments prefixed with `#-`):
```text
[Interface]
#-Alias = some_alias
#-Description = Some Desc
Address = 10.0.0.7/24
ListenPort = 6666
PrivateKey = WEkEJW3b4TDmRvN+G+K9elzq52/djAXT+LAB6BSEUmM=

[Peer]
#-Name = Fancy_meta_name
PublicKey = +qz742hzxD3E5z5QF7VOvleVS1onavQpXBK3NdTh40g=
AllowedIPs = 0.0.0.0/0
Endpoint = wg.example.com
```

