#!/bin/sh
set -eu
cd "$(dirname "$0")"

scratch=$(mktemp -d)
server_pid=
trap 'if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi; rm -rf "$scratch"' EXIT

go build -o "$scratch/nameserver" ../../cmd/nameserver
"$scratch/nameserver" -conf Corefile > "$scratch/server.log" 2>&1 &
server_pid=$!

ready=false
for attempt in 1 2 3 4 5; do
  sleep 0.1
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$scratch/server.log"
    exit 1
  fi
  if [ "$(dig @127.0.0.1 -p 8053 www.example.org A +short +time=1 +tries=1)" = "192.0.2.1" ]; then
    ready=true
    break
  fi
done
if [ "$ready" != true ]; then
  cat "$scratch/server.log"
  exit 1
fi

# probe makes an A query and extracts the IHLE RRset from Additional.
go run ../../cmd/probe -server 127.0.0.1:8053 www.example.org > "$scratch/probed"
go run ../../cmd/records "$scratch/probed" > "$scratch/actual"
awk '$4 == "TYPE65297" { print $7 }' example.zone > "$scratch/expected"
cmp "$scratch/expected" "$scratch/actual"
printf 'Ordinary A answer and IHLE public key received successfully.\n'
