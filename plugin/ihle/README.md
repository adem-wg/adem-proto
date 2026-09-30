# IHLE additional processing

This CoreDNS plugin includes the complete IHLE RRset for the original QNAME
and QCLASS in Additional, unless it is already in Answer. It obtains records
by making an internal IHLE query to the next plugin, so there is no separate
zone parser or token store. Records remain opaque DNS RDATA; token validation
belongs to the ADEM client.

Configure the plugin before the `file` backend in the compiled plugin order:

```text
example.org:8053 {
    bind 127.0.0.1
    ihle 65297
    file example.zone
}
```

`ihle TYPE` requires the numeric IHLE type. Until IANA assigns one, the
prototype uses the private-use value 65297. Store records using RFC 3597's
`TYPE65297 \# LENGTH HEX` syntax. The `records -name OWNER` command produces
this format from a token bundle.

Oversized responses omit the entire IHLE RRset and set TC. A TCP retry
returns the complete set if it fits within the DNS message size limit.
The plugin also applies this rule to direct IHLE queries.

The `nameserver` command includes this plugin and the standard `file`, `bind`,
`root`, `log`, and `errors` plugins. It serves UDP and TCP. The example in
`exm/dns` exercises the configuration and ordinary DNS queries with `dig`.
