#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${ZIG:=zig}"
"$ZIG" cc -target x86_64-windows-gnu -municode -Wl,--subsystem,windows -O2 -Wall -Wextra -Werror source/main.c -o WLab-Evidence.exe -luser32 -lgdi32 -lshell32 -ladvapi32 -lbcrypt -liphlpapi -lws2_32 -ltdh -lwinhttp
