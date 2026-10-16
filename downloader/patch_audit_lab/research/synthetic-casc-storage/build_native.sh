#!/bin/sh
# Requires the caller's existing clone of the pinned public CascLib source.
set -eu
src=$(realpath "$1")
out=$(realpath "$2")
expected=38a34665624b8775bb875274b36191b21c38d97b
test "$(git -C "$src" rev-parse HEAD)" = "$expected"
# Refuse modified tracked source; no network or automatic clone.
test -z "$(git -C "$src" status --porcelain --untracked-files=no)"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
gcc -O2 -fPIC -shared "$src/src/jenkins/lookup3.c" -o "$out/liblookup3-reference.so"
gcc -O2 -ffunction-sections -fdata-sections -c "$src/src/jenkins/lookup3.c" -o "$out/lookup3.o"
g++ -std=c++17 -O2 -DNDEBUG -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$src/src" "$here/index_oracle.cpp" "$out/lookup3.o" -o "$out/index_oracle"
