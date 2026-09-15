# Generate and verify tokens

From this directory run `sh gen_emblem.sh`, `sh gen_endorsement.sh`, then
`sh check_trusted.sh`. These generate fresh PEM keys, signed CWTs and public
COSE_Key records, and verify the chain offline. The result is `SIGNED-TRUSTED` because the authority key is explicitly trusted.

Claim prototypes are editable JSON: `ver` is the number `1` and `prp` is a
numeric bitmap from 1 to 31. Purpose 1 is protective use of the red cross,
red crescent, or red crystal. Endorsements authorize the purposes in their
bitmap. `emblemgen` converts these prototypes to signed CWTs.
