#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec go run ../../cmd/nameserver -name example.test -listen 127.0.0.1:8053 -records tmp/records.hex
