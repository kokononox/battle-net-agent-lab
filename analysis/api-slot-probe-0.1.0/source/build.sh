#!/bin/sh
set -eu
cd "$(dirname "$0")"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-H=windowsgui -s -w -buildid=' -o ../WLab-APIProbe-0.1.0.exe .
