#!/bin/sh
set -eu

cd "$(dirname "$0")"
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
clang=$(xcrun --sdk iphoneos --find clang)
out=$(mktemp -d "${TMPDIR:-/tmp}/bale-flow.XXXXXX")
trap 'rm -rf "$out"' EXIT
mkdir -p Artifacts/iphoneos

cd FlowDriver
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 CC="$clang" \
  CGO_CFLAGS="-target arm64-apple-ios16.0 -isysroot $sdk" \
  CGO_LDFLAGS="-target arm64-apple-ios16.0 -isysroot $sdk" \
  go build -trimpath -buildmode=c-archive -o "$out/libflow_driver.a" ./cmd/iphone
mv "$out/libflow_driver.a" ../Artifacts/iphoneos/libflow_driver.a
