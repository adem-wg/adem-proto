# Root Key Commitments

The example in `exm/vfy` relies on root keys that have been committed to the [Certificate Transparency (CT)](https://datatracker.ietf.org/doc/html/rfc6962) infrastructure.
This directory provides example code that helps with the correct configuration of a domain such that root key commitments are recognized.
It contains scripts to commit to the root key of https://auth.felixlinker.de and to check such commitments.

Root key commitments are provided by certificates that bind a root key to an *organizational identifier* (OI), a domain that identifies a party (in this case https://auth.felixlinker.de).
A certificate binds a root key to an OI by being valid for both the OI and a subdomain that encodes the hash of the root key.
Let us first calculate the hash of `https://auth.felixlinker.de`'s root key:

```sh
$ ./kid.sh
{
  "alg": "ES512",
  "crv": "P-521",
  "kid": "g5qt5cpf2pn7jwdny42n6lwvzqyy47xtt7o3ndpuvkgptez3at6q",
  "kty": "EC",
  "x": "AZz_WXKOL4dR51QYmOxoAZL3LPK9czDpWzv6zIz_C6yiVUC33UOQW1o4gMCP_u5cokF1Y3oOSbjpairVtjKsG4Ll",
  "y": "AdIeKnSMvbvqVVIYxd44nhozIJD2N4z3xP1P2gFFZtOKK754IMTYhLZ7v8F4-Zg8iU5vQpGaIP_wUBCsZKrT_tXp"
}
```

The output of this script is the root public key represented as a [JWK](https://datatracker.ietf.org/doc/html/rfc7517).
The field `"kid"` is the hash of the root key.
If you go to https://g5qt5cpf2pn7jwdny42n6lwvzqyy47xtt7o3ndpuvkgptez3at6q.adem-configuration.auth.felixlinker.de, you will see the same public key.

The certificate for aforementioned website is also valid for https://auth.felixlinker.de.
  Assuming that both auth.felixlinker.de and g5qt5cpf2pn7jwdny42n6lwvzqyy47xtt7o3ndpuvkgptez3at6q.adem-configuration.auth.felixlinker.de are configured on a webserver, one can easily request a certificate that is valid for both domains using [`certbot`](https://certbot.eff.org/):

```sh
certbot --expand -d auth.felixlinker.de -d g5qt5cpf2pn7jwdny42n6lwvzqyy47xtt7o3ndpuvkgptez3at6q.adem-configuration.auth.felixlinker.de
```

If you navigate to either of these domains now, you can download both the website's certificate and the issuer's certificate.
You can find both certificates in `crts`.
For technical reasons, also the issuer's certificate is required for the next steps.

Running the following scripts will verify that `https://auth.felixlinker.de`'s root key is correctly committed.

```sh
$ ./logs.sh
$ ./check_setup.sh
2023/02/03 11:58:40 root key correctly committed to log:
        url:  https://oak.ct.letsencrypt.org/2023
        name: tz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJk=
2023/02/03 11:58:40 root key correctly committed to log:
        url:  https://ct.googleapis.com/logs/argon2023
        name: 6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=
```

The first script reads both certificates in `crts` and calculates hashes that are necessary to verify log inclusion, and stores all data in `logs.json`.
The second script reads that data and verifies the log inclusion, which is the root key commitment.
