# ADEM Prototypes

This repository contains libraries and command line utilities that provide prototypes for *An Authentic Digital Emblem* (ADEM) as specified in the internet drafts:

- https://www.ietf.org/archive/id/draft-linker-diem-adem-core-00.html
- https://www.ietf.org/archive/id/draft-linker-diem-adem-dns-00.html

## Prerequisites

### Binaries

Some binaries are available at the [releases page](https://github.com/adem-wg/adem-proto/releases).

### Compilation from Source

All prototypes are written in the [Go programming language](https://go.dev/), version 1.24.0.
To compile this project, you will naturally have to install that programming language.
After you have done so, clone this repository such that it is available on `$GOPATH`.

You can then compile a binary by running:

```sh
go build github.com/adem-wg/adem-proto/cmd/XXXXX
```

You can also run a command without producing a binary by running:

```sh
go run github.com/adem-wg/adem-proto/cmd/XXXXX
```

## Usage

Below we provide a general overview of how to use these prototypes.
Further examples are in the `exm` directory.
In the following, we will reference a number of commands.
We assume that you either compiled the respective binaries (see above) or prefix them with `go run github.com/adem-wg/adem-proto/cmd/...`.

### Validators

As a validator, you can use these prototypes to check whether an asset is marked with ADEM.
You will need the two commands `probe` and `emblemcheck`.

- `probe` can query a domain name's associated TXT records, and will print each token to stdout, separated by a newline character.
  `probe` takes the domain name to query as its first argument.
- `emblemcheck` reads newline-separated tokens from stdin or from a file provided as the `-tokens` parameter.
  `emblemcheck` prints the verification results to stdout.

A natural way to use these two commands is by running:

```sh
probe example.com | emblemcheck
```

Note that it is your responsibility to verify whether the results from `emblemcheck` indeed mark the asset you probed.
For example, `emblemcheck` could print that `a.example.com` is marked with ADEM although you initially probed `b.example.com`.

### Emblem Issuers

Emblem issuers can use these prototypes to issue emblems that mark their infrastructure as protected.
In the following, we describe how to issue such emblems.
For that, you will need a domain name that identifies your organization.
Here, we will use `example.com` as a placeholder domain name.
Critically, you must be able to request Web PKI certificates for that domain name, e.g., using the `certbot` utility.
Furthermore, we will use `openssl` to generate keys.

Concretely, we will describe below how to:

- Generate a root key that cryptographically identifies your organization, and bind this root key to your domain name.
- Generate emblems.
- Generate endorsements which attest that emblems have been issued by your organization.
- Distribute emblems in the DNS.


#### Organization Setup

ADEM provides multiple modes of deployment.
In this section, we describe how organizations can configure their ADEM deployment such that they can be endorsed by external organizations, which is the recommended mode of deployment.

Organizations that want to mark their infrastructure with ADEM are called "emblem issuers".
Every emblem issuer is identified by a domain name and has a root key.
To generate the root key, we suggest running the command:

```sh
openssl ecparam -genkey -name secp521r1 -noout -out root.pem
```

**NOTE:** You just generated a private key that uniquely identifies you as an emblem issuer.
Store this key in a secure place and ensure that only authorized people have access to it.
Concretely, you generated a key for ECDSA using P-521 and SHA-512.
You can generate keys of different types.
In the following, we will sometimes use the `-pk-alg` option.
This option takes the algorithm of the provided public or private key as a JSON Web Algorithm (see [RFC 7518, Section 3.1](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1)).
If you choose a different key format, you will need to adjust the `-pk-alg` option accordingly.

Organizations are required to commit to their root key.
This allows emblem issuers to be held accountable in case of key misuse.
To do so, you must request a specifically formatted Web PKI certificate.
In preparation for that, run the command:

```sh
kid -pk root.pem -pk-alg ES512
```

This command will print the corresponding public key of your root key, in the JSON Web Key format.
The output will look something like:

```json
{
  "alg": "ES512",
  "crv": "P-521",
  "kid": "eun2quayfhnkfdljsv2rgetx3o5l6xsphsiy4nxbm77fra72pp7q",
  "kty": "EC",
  "x": "ALJKm3-lwCAHxngV7F976rEUiARvxK66f--3WG_noHteDpoA9GnA6iBoCkO6pcJa8Uz_3QJnWKByx2PZ76aZO-t5",
  "y": "AVucrJFaz0F7rUP-BjjPkC7HByRibY6BLCO0O1W5KB3ym_TIUgIkGJmEbTBNmb_ZCBWi557kjDl1HXnwVrA2ji0Z"
}
```

Importantly, observe that the output includes the key identifier (`kid`), which you will need in the following.
For the sake of the example, let's assume your root key's `kid` is `d34db44f`.

Say your organization's domain name is `example.com`.
To commit to your organization's root key, you must request a Web PKI certificate that is valid for both:

- `example.com`, and
- `d34db33f.adem-configuration.example.com` (more generally, `ROOT_KEY_KID.adem-configuration.example.com`).

You can request such a certificate using Let's Encrypt and the [`certbot`](https://certbot.eff.org/) utility.
On a web server that can request certificates for `example.com`, you can run:

```sh
certbot -d example.com -d d34db33f.adem-configuration.example.com
```

Once you have obtained the certificate, run `certbot certificates` and look up the "Certificate Path" where it is stored.
This should be a file called `fullchain.pem`.
To run the next command, you will likely need to wait some time until the certificate is included in the Certificate Transparency (CT) logs.
The command will compute information to check whether the certificate associated with your root key is included in the CT logs.

```sh
leafhash -precert-fullchain path/to/fullchain.pem > root_log.json
```

When the command runs successfully, the contents of `root_log.json` should look something like:

```json
[
  {
    "ver": "v1",
    "id": "GYbUxyiqb/66A294Kk0BkarOLXIxD67OXXBBLSVMx9Q=",
    "hash": "oqfKzfh+fai7fezCTj2+3dj7KEVGK5LpFQ/75A6UqTk="
  },
  {
    "ver": "v1",
    "id": "yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc=",
    "hash": "To3CUbqyD/0NmgotCOteSY+QIHGyN4y5JTnqitqL2Mg="
  }
]
```

You have now successfully configured your organization to issue emblems.
Importantly, you have:

- A root signing key in `root.pem`
- Information about your commitment to using this key in `root_log.json`

#### Emblem Issuance

Emblems can be generated with the `emblemgen` tool.
To keep domains separated and mitigate the damage from leaked private keys, we strongly recommend using separate keys to sign emblems.
In this section, we explain how you can mark an asset with an emblem using ADEM.
For the sake of this example, we assume that you want to mark an asset that has the domain name `asset.example.com`, which has the associated IPv4 address `192.0.2.123`.

First, generate a signing key for the asset.
Again, our example uses an ECDSA key with P-521 and SHA-512, but you can use different key types.

```sh
openssl ecparam -genkey -name secp521r1 -noout -out asset_key.pem
```

Next, generate the emblem's "skeleton" file, which is a JSON file containing all relevant information about the emblem, e.g., the issuer, the marked assets, and the purpose of the emblem.
Below is an example of the skeleton file, which we assume is stored in `emblem.json`:

```json
{
  "assets": [
    "[::FFFF:192.0.2.123]",
    "asset.example.com"
  ],
  "emb": {
    "prp": [ "protective" ]
  },
  "iss": "https://example.com",
  "ver": "v1"
}
```

This skeleton file marks the asset as protected (the *purpose* (`prp`) is `protective`), by referencing its IPv4 address (as an IPv4-mapped IPv6 address) and domain name, and identifies the emblem issuer.
See https://www.ietf.org/archive/id/draft-linker-diem-adem-core-00.html#name-emblems for a full list of supported attributes.
Note that some attributes (such as lifetime-related attributes) will be automatically set by `emblemgen`.

You can sign this skeleton file by running the command:

```sh
emblemgen -skey asset_key.pem -alg ES512 -proto emblem.json -lifetime 3600 > emblem.jws
```

This command stores the emblem in `emblem.jws`, and signs it as valid for 24 hours, starting immediately.
If you would like to choose a specific starting point of validity, you can add the `nbf` field to the skeleton file.
The tool will compute the `exp` field based on the `-lifetime` option provided.

#### Endorsement Issuance

The emblem that you signed cannot be authenticated as belonging to your organization.
It only *claims* that it was signed by `example.com`, but validators cannot (yet) verify this.
To allow validators to verify that the emblem signing key belongs to your organization, you must issue an *endorsement* for that key that was signed by the root key.
Similar to before, you require a skeleton file that provides basic information about the endorsement:

```json
{
  "end": false,
  "assets": [
    "[::FFFF:192.0.2.123]",
    "asset.example.com"
  ],
  "iss": "https://example.com",
  "sub": "https://example.com",
  "ver": "v1"
}
```

This endorsement will state that it was both issued by and for `example.com`.
The `end` field being `false` encodes that the endorsed key may not endorse further.
An `emb` field includes constraints on emblems that can be issued using the key.
This can help mitigate the consequences of key compromise.
Here, the key is endorsed to issue emblems only for the asset it is currently being used for.
You can find more information about other fields and constraints of endorsements here: https://www.ietf.org/archive/id/draft-linker-diem-adem-core-00.html#name-endorsements

Assume that the above skeleton file is stored in `endorsement.json`.
You can endorse your emblem signing key by running the following command:

```sh
emblemgen -skey root.pem -alg ES512 -proto endorsement.json -logs root_log.json -pk asset_key.pem -lifetime 31536000 > endorsement.jws
```

This command signs an endorsement that is valid for one year and endorses the emblem signing key.
It stores it in `endorsement.jws`.
As this endorsement was signed with your root key, you must provide the `-logs` option, which points to the file that stores information on how to verify your root key commitment.

You can also request endorsements from external organizations.
Such organizations must also configure a root key as described in the setup section above, but their endorsements will contain an `iss` field different from the `sub` field and must set `end` to `true`.

You need not directly endorse your emblem signing key with your root key.
You can also create a key hierarchy of intermediate endorsement keys.
You must **not** commit to these keys (as described above).
Such intermediate endorsement keys can help scale ADEM to larger organizations, but are not required.
When you sign endorsements using intermediate keys, do **not** provide the `-logs` option.

#### Distribution over the DNS

You have now signed an emblem and a root endorsement.
You can distribute the emblem and its endorsement via the DNS.
For that, add TXT records to `asset.example.com` that contain the emblem and endorsement, respectively, and that start with `adem=...`.
With that, validators can now check and verify that `asset.example.com` is marked with an emblem.

## Acknowledgements

The original work on this project was funded by the Werner Siemens-Stiftung (WSS).
We thank the WSS for their generous support.
