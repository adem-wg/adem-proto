# Distribution over DNS

Use the reproducible [local example](../local/README.md) to generate CWTs,
serve IHLE records, and verify an ordinary A query's Additional records.
Run `sh check.sh` after starting that example's server.

Existing public TXT records and CT commitments use the previous JWT/JWK format.
They are not expected to validate under the current specifications.
