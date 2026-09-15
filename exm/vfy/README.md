# Verify local tokens

These scripts use the fresh local CWT example. Run `sh ../local/prepare.sh`
first, then `sh check.sh` or `sh check_trusted.sh`. The first returns `SIGNED-UNTRUSTED`; the latter returns `SIGNED-TRUSTED`
by supplying an explicitly trusted verification key from a local file.
