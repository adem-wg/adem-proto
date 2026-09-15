#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p tmp
sh records.sh > tmp/records.hex
go run ../../cmd/emblemcheck -tokens tmp/records.hex
