# Example Deployment

A personal prototype-site, https://emblem.felixlinker.de, is labelled with ADEM using DNS.
This folder contains the example's keys, certificates, token protos, and scripts to set it up and test it.
It combines token generation, root key commitments, and token verification in one example.
Run the commands below from this directory, which requires to have Go and OpenSSL installed.

## Keys and Tokens

The emblem issuer is identified by the organizational identifier (OI) `https://emblem.felixlinker.de`.
The example uses a hierarchy of two keys, which, however, are not published here:

- `keys/emblem.felixlinker.de.pem` is the emblem issuer's root key.
- `keys/emblem.pem` is its emblem key.

`sh key_gen.sh` generates these keys if they do not exist and exports their public keys to `certs/*.pub.pem`.
If you would like to replicate this example, you can use this script to create your own key material.
The script `sign.sh` generates the following:

- An emblem (`tokens/emblem.cbor`) marking the DNS name `emblem.felixlinker.de.`, signed by the emblem key.
- An internal endorsement (`tokens/emblem.felixlinker.de.cbor`) signed by the emblem issuer's root key, endorsing the emblem key and carrying the root key's CT log information.
- The public verification keys (`tokens/*.key.cbor`).

The JSON claims protos are in `protos/`.
Note that `sign.sh` relies on the root key commitment having been configured correctly.
This has already been done for this example, and the outputs are stored in `certs/`, however, you may need to repeat the configuration should you have generated your own key material.

## Root Key Commitments

A root key commitment binds a root key to an OI through a certificate recorded in the [Certificate Transparency (CT)](https://datatracker.ietf.org/doc/html/rfc6962) infrastructure.
The certificate must be valid for both the OI's domain and a subdomain encoding the hash of the root public key.

Calculate the emblem issuer's key identifier with:

```sh
go run github.com/adem-wg/adem-proto/cmd/kid \
  -pk-pem certs/emblem.felixlinker.de.pub.pem
```

This prints the base32-encoded COSE Key Thumbprint to stdout.
To commit to the root key, you must request a certificate that is both valid for `<kid>.adem-configuration.emblem.felixlinker.de` (`<kid>` is the output from the command above) and `emblem.felixlinker.de`.

Configure both domains on your webserver and request a certificate covering both, for example using [certbot](https://certbot.eff.org/):

```sh
kid=$(go run github.com/adem-wg/adem-proto/cmd/kid \
  -pk-pem certs/emblem.felixlinker.de.pub.pem)
certbot --expand -d emblem.felixlinker.de \
  -d "$kid.adem-configuration.emblem.felixlinker.de"
```

Certbot will save the website's certificate followed by its issuer's certificate in a `fullchain.pem` file, which we stored in `certs/emblem.felixlinker.de.fullchain.pem`.
Then run:

```sh
sh logs.sh
sh check_setup.sh
```

`logs.sh` reads the certificate chain and writes the CBOR log claim to `certs/emblem.felixlinker.de.logs.cbor`.
For RFC 6962 logs, this contains leaf hashes needed to verify inclusion; for Static CT logs, it contains leaf indices.
`check_setup.sh` reads that claim and verifies the root key commitment against the CT logs.
Successful checks report `root key correctly committed to log`, followed by the log URL and identifier.
These checks require network access to fetch known CT logs and verify inclusion.

## Token Verification

After generating the tokens, run:

```sh
sh check.sh
```

The script bundles the CBOR arrays in `tokens/` and verifies their signatures, the root key commitment, and whether the emblem marks `emblem.felixlinker.de`.
With valid tokens and a verifiable commitment, the results include `SIGNED` and `ORGANIZATIONAL`, the marked DNS name, and issuer `https://emblem.felixlinker.de`.
