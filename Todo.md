# Functional
- Command to set attribute (very inefficient though -> read config -> set arg -> write config for each attr)
- Command to apply config
- Forwarding to the original `wg`? -> is this actually expected by the user?
- Command-line parser too static -> offload to seperate module where each `<cmd>` is handled separately
# Internal
- actually get `wg show dump` output from terminal
- Documentation (user and dev)
- According to [Wireguard config example](https://manpages.debian.org/unstable/wireguard-tools/wg.8.en.html), it is possible to have
no newline after an attribute - is this actually a thing in "the wild"?
- Make api of the wrapper module more abstract? E.g wrap it in a class instead of exposing the parsed hashes
directly  
-> Conclusion: Yes, suggested interface:
```text
set($interface, $key, $value)
commit($dry_run = True)
discard()
refresh()
get_interface($interface_name)
get_peer_by_id($interface_name, $peer_id)
get_peer_by_alias($alias)
```
- Config file format -> The yaml parser is currently the only external dependency.
- Tests?


