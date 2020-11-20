# Functional
- Commandline arg support
- Help page
- Command to set attribute (very inefficient though -> read config -> set arg -> write config for each attr)
- Command to apply config
- Forwarding to the original `wg show`? -> is this actually expected by the user?
# Internal
- Documentation (user and dev)
- According to [Wireguard config example](https://manpages.debian.org/unstable/wireguard-tools/wg.8.en.html), it is possible to have
no newline after an attribute - is this actually a thing in "the wild"?
- Make api of the wrapper module more abstract? E.g wrap it in a class instead of exposing the parsed hashes
directly.
- Config file format -> The yaml parser is currently the only external dependency.
- Tests?


