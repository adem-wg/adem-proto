#!/bin/sh
set -eu
cd "$(dirname "$0")/../local"
exec go run ../../cmd/emblemcheck -offline -tokens tmp/records.hex
