# Deployment materials

This directory retains public certificates and historical JWT/JWK fixtures from
the earlier deployment. They are not expected to validate under the current
COSE thumbprint and CWT specifications, and existing CT logs have not been
updated or reapproved.

The claim prototypes and generation scripts now produce CWTs in `cwt/`.
Re-running an organizational deployment requires the private keys, new binding
certificates for the COSE key IDs, and corresponding CT log information.
`records.sh` emits uppercase hex IHLE RDATA, not TXT records.

For development and verification without CT dependencies, use
[the local example](../local/README.md).
