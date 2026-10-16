#!/bin/sh
set -eu
src=$(realpath "$1");out=$(realpath "$2");here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Reuse pinned clean-source gate and objects; no downloads.
sh "$here/../../retail-storage-poc/native/build.sh" "$src" "$out"
g++ -std=c++17 -O2 -DNDEBUG -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$src/src" "$here/prefix_oracle.cpp" "$out/lookup3.o" -o "$out/prefix_oracle"
g++ -std=c++17 -O2 -DNDEBUG -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$src/src" "$here/real_object_oracle.cpp" "$out/blte_header_oracle.o" "$out/lookup3.o" -lcrypto -lz -o "$out/real_object_oracle"
