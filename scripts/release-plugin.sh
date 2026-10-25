#!/usr/bin/env bash
# Publishes the wasm scanner as a _k0t1k launcher plugin: a GitHub Release of
# this repo with plugin.json, plugin.json.sig and the wasm-bindgen files.
# Requires the wasm32-unknown-unknown target, a wasm-bindgen-cli matching
# Cargo.lock, openssl, gh (authenticated) and the plugin signing key.
set -euo pipefail

REPO="hhhhhffd/ratka_checker"
PLUGIN_ID="ratscan"
API_VERSION=1
MIN_LAUNCHER="0.1.0"
# Raw 32-byte Ed25519 public key (base64) embedded in the launcher.
PUBLIC_KEY_B64="b37Axim0D7VgDNWVIgvlnpdn2nVOMSLM/jIFbRFc/4k="
KEY="${K0T1K_PLUGIN_KEY:-$HOME/.config/k0t1k/plugin-signing-key.pem}"

die() { echo "release-plugin: $*" >&2; exit 1; }

cd "$(git rev-parse --show-toplevel)"

[ -r "$KEY" ] || die "signing key not readable: $KEY"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean"

upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)" \
    || die "current branch has no upstream"
git merge-base --is-ancestor HEAD "$upstream" \
    || die "HEAD is not pushed to $upstream"
head_sha="$(git rev-parse HEAD)"

# The ratscan-wasm crate version is the release version (the workspace defines none).
version="$(cargo metadata --locked --no-deps --format-version 1 \
    | jq -r '.packages[] | select(.name == "ratscan-wasm") | .version')"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "unexpected version: $version"
tag="v$version"

git rev-parse -q --verify "refs/tags/$tag" >/dev/null && die "local tag $tag already exists"
[ -z "$(git ls-remote --tags origin "refs/tags/$tag")" ] || die "remote tag $tag already exists"
if gh release view "$tag" --repo "$REPO" >/dev/null 2>&1; then
    die "release $tag already exists"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
out="$work/out"
mkdir "$out"

cargo build --locked -p ratscan-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --no-typescript --out-dir "$out" \
    "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/ratscan_wasm.wasm"
[ -z "$(git status --porcelain)" ] || die "build modified the working tree"

js_sha="$(sha256sum "$out/ratscan_wasm.js" | cut -d' ' -f1)"
wasm_sha="$(sha256sum "$out/ratscan_wasm_bg.wasm" | cut -d' ' -f1)"

# Written once; the signature covers these exact bytes.
cat > "$out/plugin.json" <<JSON
{
  "id": "$PLUGIN_ID",
  "version": "$version",
  "api": $API_VERSION,
  "minLauncher": "$MIN_LAUNCHER",
  "files": {
    "ratscan_wasm.js": "$js_sha",
    "ratscan_wasm_bg.wasm": "$wasm_sha"
  }
}
JSON

{ printf '_k0t1k-plugin\n'; cat "$out/plugin.json"; } > "$work/msg"
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$work/msg" | base64 -w0 > "$out/plugin.json.sig"

# Verify against the launcher's public key: SPKI DER = fixed Ed25519 prefix + raw key.
{ printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; printf '%s' "$PUBLIC_KEY_B64" | base64 -d; } > "$work/pub.der"
base64 -d "$out/plugin.json.sig" > "$work/sig.bin"
openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "$work/pub.der" \
    -in "$work/msg" -sigfile "$work/sig.bin" >/dev/null \
    || die "signature does not verify against the launcher public key (wrong signing key?)"

gh release create "$tag" \
    --repo "$REPO" \
    --target "$head_sha" \
    --title "RatScan plugin $tag" \
    --notes "RatScan launcher plugin $version (plugin API $API_VERSION, built from $head_sha)." \
    "$out/plugin.json" "$out/plugin.json.sig" \
    "$out/ratscan_wasm.js" "$out/ratscan_wasm_bg.wasm"

echo "released $tag"
