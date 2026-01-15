# Distribution and Validation over the DNS

Emblems can be distributed and validated with the DNS.
As of writing, `emblem.felixlinker.de` is marked with ADEM.
You can check [dns.google](https://dns.google/query?name=emblem.felixlinker.de&rr_type=TXT&ecs=) to convince yourself of that.
Look for the records starting with `adem=`.

The `probe` utility, provided in this repository can detect and fetch ADEM emblems from the DNS.
The `emblemcheck` then can verify such emblems.
If you run:

```sh
go run github.com/adem-wg/adem-proto/cmd/probe emblem.felixlinker.de > tokens
cat tokens | go run github.com/adem-wg/adem-proto/cmd/emblemcheck
```

You should see the following:

```
2026/01/15 14:58:45 probed 3 token(s) via DNS
2026/01/15 14:58:49 Verified set of tokens. Results:
- Security levels:    SIGNED, ORGANIZATIONAL, ENDORSED
- Protected assets:   [2a01:4f9:c010:d8e4::1]
- Issuer of emblem:   https://emblem.felixlinker.de
- Issuer endorsed by: https://auth.felixlinker.de
```

You can also run `check.sh` to the same effect.
