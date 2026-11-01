#!/usr/bin/env bash
# Prints the README's example: each command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${UNITWARDEN:-./bin/unitwarden}
echo "\$ unitwarden --root testdata/root"
"$bin" --root testdata/root | tr -d '\r'
echo
echo "\$ unitwarden --root testdata/root --effective uw-webapp.service"
"$bin" --root testdata/root --effective uw-webapp.service | tr -d '\r'
