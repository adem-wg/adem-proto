#!/bin/sh
set -eu
cd "$(dirname "$0")/../local"
exec sh check.sh
