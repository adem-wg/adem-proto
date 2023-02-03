# Token Generation

This directory provides an example how to generates tokens.
The provided scripts can generate a signed emblem and an endorsement and verify them.
The tokens will only be signed because organizational or endorsed emblems require root key commitments which are more involved for setup.

Running the scripts in the following order will give the respective, following output:

```sh
$ ./gen_emblem.sh
$ ./gen_endorsement.sh
$ ./check_trusted.sh
2023/02/03 11:34:49 Verified set of tokens. Results:
- Security levels:    SIGNED, SIGNED_TRUSTED
- Protected assets:   example.com
```

The scripts `gen_emblem.sh` and `gen_endorsement.sh` generate the emblem and endorsement respectively.
For that, they also generate fresh private keys.
The emblem's payload is defined in `emblem.json` and the endorsement's payload in `endorsement.json`.
Both scripts execute the same command (`emblemgen`).
The command generates endorsements instead of emblems when the `-pk` argument is provided.

The script `check_trusted.sh` verifies both tokens (as in `exm/vfy`).
Critically, verification in this instance must provide a trusted public key as input as otherwise, verification has no means to defend against adversary-provided verification keys.
