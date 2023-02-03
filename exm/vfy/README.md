# Token Verification

This directory contains three tokens:

- An external endorsement (`auth.felixlinker.de.jws`) signed by the "authority" https://auth.felixlinker.de for the "protected party" https://emblem.felixlinker.de.
- An internal endorsement (`emblem.felixlinker.de.jws`) signed by the "protected party" for an emblem generation key.
- An emblem (`emblem.jws`) signed by the "protected party."

You can verify all these tokens by executing `check.sh`, which should result in the following:

```sh
$ ./check.sh
2023/02/03 11:21:08 Verified set of tokens. Results:
- Security levels:    SIGNED, ORGANIZATIONAL, ENDORSED
- Protected assets:   [2a01:4f9:c010:d8e4::1]
- Issuer of emblem:   https://emblem.felixlinker.de
- Issuer endorsed by: https://auth.felixlinker.de
```

Alternatively, you can provide `auth.felixlinker.de_pub.pem` as trusted public key, as is done in `check_trusted.sh`:

```sh
$ ./check_trusted.sh
2023/02/03 11:22:45 Verified set of tokens. Results:
- Security levels:    SIGNED, ORGANIZATIONAL, ENDORSED, ENDORSED_TRUSTED
- Protected assets:   [2a01:4f9:c010:d8e4::1]
- Issuer of emblem:   https://emblem.felixlinker.de
- Issuer endorsed by: https://auth.felixlinker.de
```
