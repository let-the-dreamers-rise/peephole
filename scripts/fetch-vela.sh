#!/usr/bin/env bash
# Fetches the pinned Vela and vela-nova sources into third_party/ and adds
# peephole's one-file constructor shim to Vela's executor package.
# Vela is BUSL-1.1 ("internal evaluation and testing purposes"); peephole does
# not redistribute it, it downloads it here for local testing.
set -euo pipefail
cd "$(dirname "$0")/.."
VELA_COMMIT=335724c95ba7b58d64ec97bbb67d18640123278e   # v0.2.0, 2026-07-02
NOVA_COMMIT=${NOVA_COMMIT:-}
mkdir -p third_party
if [ ! -d third_party/vela ]; then
  git clone -q https://github.com/HorizenOfficial/vela third_party/vela
fi
git -C third_party/vela fetch -q --depth 1 origin "$VELA_COMMIT" 2>/dev/null || true
git -C third_party/vela checkout -q "$VELA_COMMIT"
cp shim/zz_peephole_export.go.tmpl third_party/vela/pkg/executor/zz_peephole_export.go
if [ ! -d third_party/vela-nova ]; then
  git clone -q https://github.com/HorizenOfficial/vela-nova third_party/vela-nova
fi
if [ -n "$NOVA_COMMIT" ]; then git -C third_party/vela-nova checkout -q "$NOVA_COMMIT"; fi
echo "vela @ $(git -C third_party/vela rev-parse --short HEAD), vela-nova @ $(git -C third_party/vela-nova rev-parse --short HEAD)"
