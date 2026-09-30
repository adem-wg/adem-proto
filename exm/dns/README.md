# Distribution over the DNS

The `nameserver` command runs CoreDNS with the IHLE plugin and serves a normal
zone file over UDP and TCP. At a marked owner name, other query types receive
the complete IHLE RRset in Additional. Direct IHLE queries return it in Answer.

From this directory, start the example server:

```sh
go run ../../cmd/nameserver -conf Corefile
```

In another terminal, query it with ordinary DNS tools:

```sh
dig @127.0.0.1 -p 8053 www.example.com A
dig @127.0.0.1 -p 8053 www.example.com AAAA
dig @127.0.0.1 -p 8053 www.example.com TYPE65297
dig @127.0.0.1 -p 8053 www.example.com A +tcp
```

The example zone contains A, AAAA, TXT, SOA, and NS records, and one example
IHLE public-key record. `dig` displays IHLE as `TYPE65297` with generic
hexadecimal RDATA. The provisional type number is configured with `ihle 65297`
in the Corefile.

To publish your own signed tokens and public keys, use the `records` command and
append its output to the resulting zone entries (replace the owner with the
asset name in your emblem):

```sh
go run ../../cmd/records -name www.example.com. *.cbor >> example.zone
```

Increment the SOA serial to reload a changed zone, or restart the server.
Zone-file paths are relative to the working directory; use absolute paths
or the CoreDNS `root` directive when starting from elsewhere. A prebuilt
`nameserver` binary accepts the same `-conf Corefile` argument.

Run `./check.sh` with Go and `dig` installed to build the server, check its A
answer, and compare the public-key bytes discovered by `probe` with the zone
fixture. Stop any server on port 8053 first. `go test ./plugin/ihle` from the
repository root covers multiple records and complete RRset delivery after
UDP truncation and TCP retry.

These examples query the authoritative server directly. Existing recursive
resolvers may omit IHLE from Additional; they do not acquire the plugin's
behavior merely by forwarding to this server.
