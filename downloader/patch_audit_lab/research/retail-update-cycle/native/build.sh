#!/bin/sh
set -eu
src=$(realpath "$1");out=$(realpath "$2");here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
sh "$here/../../archive-prefix-9824/native/build.sh" "$src" "$out"
g++ -std=c++17 -O2 -DNDEBUG -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$src/src" "$here/cycle_oracle.cpp" "$out/lookup3.o" -o "$out/cycle_oracle"
