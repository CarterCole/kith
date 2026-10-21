#!/bin/sh
# Build kith for one target and archive it for a release.
#
#   packaging/archive.sh [target]
#
# The target is a Rust triple (default: this machine's) and has to be installed
# (rustup target add <target>). Writes dist/release/kith-<version>-<target>.tar.gz
# with the binary and the README. The version is the workspace's in Cargo.toml,
# which is what `kith --version` prints. A release needs one archive per target
# the formula names: see packaging/homebrew/formula.sh.
set -eu
cd "$(dirname "$0")/.."

target=${1:-$(rustc -vV | sed -n 's/^host: //p')}
version=$(cargo pkgid -p kith-cli | sed 's/.*[#@]//')
name=kith-$version-$target

cargo build --release --locked -p kith-cli --target "$target"
rm -rf "dist/release/$name"
mkdir -p "dist/release/$name"
cp "target/$target/release/kith" README.md "dist/release/$name/"
COPYFILE_DISABLE=1 tar -C dist/release -czf "dist/release/$name.tar.gz" "$name"
rm -r "dist/release/$name"
echo "dist/release/$name.tar.gz"
