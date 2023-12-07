# Emblem Server Docker

The `docker-compose.yml` and `Dockerfile` in this directory create two containers that work together to send emblems.
I next describe how the containers are intended to operate.
Unfortunately, the configuration doesn't work as intended yet.

The `syslog` container accepts syslog traffic on port 514, 601, and 6514 and writes logs into `/var/log/system.log`.
From the `syslog` container, all logs are shared as the volume `logs`.
The `emblemserver` container reads log files from the volume, more specifically from `system.log`.
Whenever it finds a related syslog event, it sends an emblem via port 6060.

The `emblemserver` generates a public/private key pair in the `Dockerfile`, and makes the public key accessible in the `keys` directory.
The `emblemserver` gets its configuration from the host, more specifically the `tokens` directory.

## Volumes

In summary, a quick list of how the volumes should be used:

- Container `emblemserver`...
  - ...writes to `./keys`
  - ...reads from `./tokens`
  - ...reads from shared volume `logs`
- Container `syslog`...
  - ...writes to shared volume `logs`
