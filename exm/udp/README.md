# ADEM UDP Distribution

This directory provides example scripts to distribute and probe emblems via UDP.
The script `server.sh` generates keys for endorsement and emblem signing, signs an endorsement, and starts a server listening on port 6060 for incoming packets.
Whenever it receives a packet on that port, it sends the source address an emblem and the previously generated endorsement.

The script `probe.sh` sends that server a request and attempts to verify the received tokens, using the previously generated endorsement signing key as trusted public key.
This script listens on the privileged port 60, hence, requires root priviliges.
