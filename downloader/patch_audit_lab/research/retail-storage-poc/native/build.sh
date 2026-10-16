#!/bin/sh
# Existing pinned source only; no clone/download and no tracked source changes.
set -eu
src=$(realpath "$1");out=$(realpath "$2")
test "$(git -C "$src" rev-parse HEAD)" = 38a34665624b8775bb875274b36191b21c38d97b
test -z "$(git -C "$src" status --porcelain --untracked-files=no)"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
gcc -O2 -ffunction-sections -fdata-sections -c "$src/src/jenkins/lookup3.c" -o "$out/lookup3.o"
g++ -std=c++17 -O2 -DNDEBUG -ffunction-sections -fdata-sections -I"$src/src" -c "$here/blte_header_oracle.cpp" -o "$out/blte_header_oracle.o"
g++ -std=c++17 -O2 -DNDEBUG -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$src/src" "$here/storage_oracle.cpp" "$out/blte_header_oracle.o" "$out/lookup3.o" -lcrypto -lz -o "$out/storage_oracle"
