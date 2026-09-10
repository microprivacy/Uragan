#!/usr/bin/env bash
# Build tornado_prover.wasm: upstream zkutil + two patched crates, compiled for
# wasm32-unknown-unknown with shared-memory threads.
#
# Patches (see patches/):
#   clap-v3 3.0.0-beta.1   one-line cfg: its wasm32 OsStr fallback was declared
#                          but only implemented for windows
#   bellman_ce 0.3.5       thread pool (src/multicore.rs) swapped for rayon, so
#                          the host can supply threads; no curve/field code touched
#
# Needs a nightly toolchain with rust-src and the wasm32-unknown-unknown target:
# std must be rebuilt with +atomics (-Z build-std). Users never run this -- the
# built .wasm is committed; this exists so anyone can reproduce it.
set -euo pipefail
cd "$(dirname "$0")"

fetch() { # name version sha256
  local dir="vendor/$1"
  [ -d "$dir" ] && return
  # Unpack and patch in a scratch dir, then move the finished tree into place,
  # so an interrupted run can never leave an unpatched crate at $dir that a
  # later run would mistake for done.
  local tmp
  tmp=$(mktemp -d vendor/.tmp.XXXXXX)
  curl -fsSL -A 'tornado-prover build.sh' "https://static.crates.io/crates/$1/$1-$2.crate" -o "$tmp/crate"
  echo "$3  $tmp/crate" | sha256sum -c --quiet
  mkdir "$tmp/src"
  tar -xzf "$tmp/crate" -C "$tmp/src" --strip-components=1
  patch -s -d "$tmp/src" -p1 < "patches/$1-$2-"*.patch
  mv "$tmp/src" "$dir"
  rm -rf "$tmp"
}
mkdir -p vendor
rm -rf vendor/.tmp.*   # debris from an interrupted run
fetch bellman_ce 0.3.5 a5ca1343d8690bb4d62e0665116bd4f109e33a642f86908ed107d226a402b0ef
fetch clap-v3 3.0.0-beta.1 bfac055d61c39ace5061621530f7f55651a261a4fba296ce1bad06d41a8de65e

# Memory limits are pinned so the host (src/prover.ts) can create a matching
# shared memory: 256 pages (16 MiB) initial, 32768 pages (2 GiB) max.
# Paths under $HOME are remapped so the binary neither leaks the builder's
# home directory nor varies with it.
export RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals \
  --remap-path-prefix=$HOME=/home \
  -C link-arg=--shared-memory -C link-arg=--import-memory \
  -C link-arg=--initial-memory=16777216 -C link-arg=--max-memory=2147483648 \
  -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size \
  -C link-arg=--export=__tls_align -C link-arg=--export=__stack_pointer"

cargo +nightly build --release --target wasm32-unknown-unknown -Z build-std=panic_abort,std
cp target/wasm32-unknown-unknown/release/tornado_prover.wasm .
rustc +nightly -vV | sed -n 's/^\(release\|commit-hash\): /  \1: /p'
sha256sum tornado_prover.wasm
