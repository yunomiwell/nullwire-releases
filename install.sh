#!/usr/bin/env bash
#
# NULLWIRE — Installer
# =====================
#
# Usage:
#   curl -sSL https://nullwire.xyz/install.sh | bash
#
# What this does:
#   1. Detects your platform (macOS/Linux, x86_64/arm64)
#   2. Downloads the matching nullwire-cli binary from GitHub Releases
#   3. Verifies the SHA256 checksum before doing anything with it
#   4. Installs to ~/.nullwire/bin/
#   5. Creates your identity + post-quantum prekey bundle
#   6. Starts the messenger server on http://127.0.0.1:4310
#   7. Opens your default browser
#
# Paranoid install (recommended for first-time users):
#   curl -sSL https://nullwire.xyz/install.sh -o install.sh
#   cat install.sh                           # read it
#   shasum -a 256 install.sh                 # compare to hash on nullwire.xyz
#   bash install.sh
#
# Uninstall:
#   ~/.nullwire/bin/nullwire-cli uninstall
#   # or manually:  rm -rf ~/.nullwire
#
# https://nullwire.xyz  |  https://github.com/yunomiwell/nullwire-releases

set -euo pipefail

# ─────────────────────────────────────────────────────────────────
# CONFIG — kept at top so it's easy to audit
# ─────────────────────────────────────────────────────────────────
readonly NULLWIRE_VERSION="${NULLWIRE_VERSION:-v0.1.3-rc5}"
readonly NULLWIRE_RELEASES_BASE="https://github.com/yunomiwell/nullwire-releases/releases/download"
readonly NULLWIRE_HOME="${NULLWIRE_HOME:-$HOME/.nullwire}"
readonly NULLWIRE_PORT="${NULLWIRE_PORT:-4310}"

# ─────────────────────────────────────────────────────────────────
# PILOT-PAYER (rc4 v5 split-payer)
# ─────────────────────────────────────────────────────────────────
#
# Solana program v5 (deployed 2026-04-28, slot 458720281) splits the
# rent-payer account from the identity-owner account in the user-handle
# register instruction.  Pre-v5 these were the same account, and a
# shared install-time keypair would let anyone with that key rotate
# every tester's bundle.  Post-v5 the embedded keypair below ONLY pays
# rent — the identity-owner is the user's local ed25519 signing key
# (stored in `state.json`, never leaves the device).
#
# Why we embed it:
#   - The Solana devnet faucet rate-limits hard.  Without a pre-funded
#     payer, every fresh `curl install.sh | bash` hits the faucet, fails,
#     and forces a manual `solana transfer` recovery — unworkable for a
#     100-tester pilot.
#   - With the embedded payer, register-self uses the existing balance
#     and the airdrop call is skipped.
#
# Compromise model:
#   - This keypair is PUBLIC by design (it's literally in this script,
#     served from a CDN).
#   - Worst case: someone drains the wallet → next install can't
#     register until we top up the wallet.  Cost: a few SOL of devnet
#     funds, no security impact.  Bundle uploads cannot be forged
#     because the upload-bundle Edge Function verifies the signature
#     against the on-chain owner_pubkey, which is the user's identity,
#     NOT this payer.
#   - Devnet only.  Mainnet (post-v1.0) will use a different model.
#
# Refresh: regenerate locally with
#   solana-keygen new -o phase0/devnet-pilot-payer.json --no-bip39-passphrase --force
#   solana transfer <new-pubkey> 5 --keypair phase0/devnet-deployer.json --url devnet
#   base64 -i phase0/devnet-pilot-payer.json | tr -d '\n'
# and replace the constant below.
readonly NULLWIRE_PILOT_PAYER_PUBKEY="He8V5kgZszVXtjtxcq8CLaQ9GUfAK4dXvwgxcQyxqazA"
readonly NULLWIRE_PILOT_PAYER_KEYPAIR_B64="WzIyMCwxMTgsMjUxLDI0NiwyNywyMzUsNzUsMjE2LDc4LDIxMywyNywxNzgsMTg2LDIxMCw3Niw3LDgxLDE5LDY3LDIxNSwxMTIsNDksMTU5LDg4LDcwLDk3LDE0Myw4MiwxMDQsMjE5LDYxLDEwNCwyNDcsNjEsMjQxLDExMywxMTIsNDksMTI4LDE1NSw3LDExMywyMDUsMjQzLDE2NSwyNDQsMTYsMTAxLDE5NSwyMDMsNzAsMjM3LDQ2LDU4LDIwMCwxNDQsMTY4LDE0MSwxMDMsMTE0LDIxMiwyMjAsMTIzLDE5OV0="

# ─────────────────────────────────────────────────────────────────
# COLORS — only if stdout is a terminal
# ─────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    readonly C_LIME='\033[38;5;191m'     # lime green
    readonly C_MAGENTA='\033[38;5;199m'  # magenta
    readonly C_DIM='\033[2m'
    readonly C_BOLD='\033[1m'
    readonly C_RESET='\033[0m'
else
    readonly C_LIME='' C_MAGENTA='' C_DIM='' C_BOLD='' C_RESET=''
fi

log()   { printf "${C_DIM}→${C_RESET} %s\n" "$*"; }
ok()    { printf "${C_LIME}✓${C_RESET} %s\n" "$*"; }
warn()  { printf "${C_MAGENTA}!${C_RESET} %s\n" "$*" >&2; }
fail()  { printf "${C_MAGENTA}✗${C_RESET} %s\n" "$*" >&2; exit 1; }

banner() {
    printf "\n"
    printf "${C_LIME}${C_BOLD}"
    cat <<'EOF'
  █   NULLWIRE
  █   post-quantum encrypted messenger
  █   https://nullwire.xyz
EOF
    printf "${C_RESET}\n"
}

# ─────────────────────────────────────────────────────────────────
# PLATFORM DETECTION
# ─────────────────────────────────────────────────────────────────
detect_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        darwin)  os="macos" ;;
        linux)   os="linux" ;;
        *)       fail "unsupported OS: $os (currently supports: macos, linux)" ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        arm64|aarch64) arch="arm64" ;;
        *)             fail "unsupported arch: $arch (currently supports: x86_64, arm64)" ;;
    esac

    # v0.1.0 ships 3 platforms only: macos-arm64, macos-x86_64, linux-x86_64.
    # Linux ARM64 is on the roadmap but not built yet — fail clearly instead of 404ing.
    if [ "$os" = "linux" ] && [ "$arch" = "arm64" ]; then
        fail "linux/arm64 is not yet built. v0.1.0 ships macos-arm64, macos-x86_64, linux-x86_64. follow https://nullwire.xyz/status for arm64-linux progress."
    fi

    echo "${os}-${arch}"
}

# ─────────────────────────────────────────────────────────────────
# DEPENDENCIES CHECK
# ─────────────────────────────────────────────────────────────────
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

check_deps() {
    require_cmd curl
    require_cmd shasum
    require_cmd uname

    # v0.1.3+: messenger is a single Rust binary with the UI bundled via
    # include_dir!. No Node.js, no separate UI tarball, no extraction step.
    # The binary either runs (and serves the UI it was compiled with) or
    # it doesn't — eliminating the v0.1.1 "missing src/" install bug class.
}

# ─────────────────────────────────────────────────────────────────
# DOWNLOAD + VERIFY
# ─────────────────────────────────────────────────────────────────
download() {
    local url="$1" dest="$2"
    log "fetching $(basename "$dest")..."
    if ! curl -sSL --fail "$url" -o "$dest"; then
        fail "download failed: $url"
    fi
}

verify_sha256() {
    local file="$1" expected_hash="$2"
    local actual_hash
    actual_hash="$(shasum -a 256 "$file" | awk '{print $1}')"
    if [ "$actual_hash" != "$expected_hash" ]; then
        fail "checksum mismatch for $(basename "$file")
    expected: $expected_hash
    actual:   $actual_hash
    This could indicate a corrupted download or a tampered binary.
    Do NOT run this file. Report at https://github.com/yunomiwell/nullwire-releases/issues"
    fi
    ok "verified $(basename "$file")"
}

# ─────────────────────────────────────────────────────────────────
# MAIN INSTALL FLOW
# ─────────────────────────────────────────────────────────────────
main() {
    banner

    log "checking dependencies..."
    check_deps

    local platform
    platform="$(detect_platform)"
    ok "detected platform: $platform"

    # Set up directory layout
    log "creating state directory at $NULLWIRE_HOME..."
    mkdir -p "$NULLWIRE_HOME"/{bin,state,ui}
    chmod 700 "$NULLWIRE_HOME"              # only current user can read
    chmod 700 "$NULLWIRE_HOME/state"        # extra protection for crypto material

    # ─────────────────────────────────────────────────────────────
    # rc4 v5 split-payer: stage the pilot rent-payer keypair
    # ─────────────────────────────────────────────────────────────
    #
    # Decode the embedded base64 keypair (see CONFIG block above) into
    # `<state-dir>/service-fee.json` ONLY if the file doesn't already
    # exist.  `nullwire-cli setup --auto-register` reuses this file and
    # skips the airdrop step (its `ensure_service_fee_wallet` short-
    # circuits when the wallet has any balance ≥ 0.01 SOL).
    #
    # Permissions: 0600 — same posture as state.json.  This is harmless
    # on devnet (the keypair is in this public script anyway) but
    # follows the convention so a future rotation to per-install
    # keypairs doesn't leave a 0644 file lying around.
    local fee_keypair_path="$NULLWIRE_HOME/state/service-fee.json"
    if [ ! -f "$fee_keypair_path" ]; then
        log "staging pilot rent-payer keypair (v5 payer-only, owner remains local)..."
        if printf '%s' "$NULLWIRE_PILOT_PAYER_KEYPAIR_B64" | base64 -d > "$fee_keypair_path" 2>/dev/null; then
            chmod 600 "$fee_keypair_path"
            ok "pilot rent-payer staged ($NULLWIRE_PILOT_PAYER_PUBKEY)"
        else
            warn "could not decode pilot rent-payer; falling back to per-install airdrop"
            rm -f "$fee_keypair_path"
        fi
    fi

    # Determine download URLs.  v0.1.3+: single binary per platform,
    # UI bundled via include_dir!. No more separate UI tarball.
    local base_url="${NULLWIRE_RELEASES_BASE}/${NULLWIRE_VERSION}"
    local cli_asset="nullwire-cli-${platform}"
    local checksums_url="${base_url}/checksums.sha256"

    # Fetch checksums manifest first — it's small, signed, and drives verification
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT

    download "$checksums_url" "$tmp_dir/checksums.sha256"

    # Extract expected hash for the CLI binary.
    local cli_hash
    cli_hash="$(grep " $cli_asset\$" "$tmp_dir/checksums.sha256" | awk '{print $1}')"

    if [ -z "$cli_hash" ]; then
        fail "could not find expected checksum entries for platform $platform
    This version of the installer may not match the release."
    fi

    # Download CLI binary (UI bundled inside).
    download "$base_url/$cli_asset" "$tmp_dir/$cli_asset"
    verify_sha256 "$tmp_dir/$cli_asset" "$cli_hash"

    # Install CLI
    log "installing nullwire-cli to $NULLWIRE_HOME/bin..."
    mv "$tmp_dir/$cli_asset" "$NULLWIRE_HOME/bin/nullwire-cli"
    chmod +x "$NULLWIRE_HOME/bin/nullwire-cli"
    # Defensive: strip macOS quarantine attribute if present (only matters
    # if the user obtained the binary via browser before piping; curl-fetched
    # files don't have it). Silent no-op on Linux + when xattr absent.
    if command -v xattr >/dev/null 2>&1; then
        xattr -d com.apple.quarantine "$NULLWIRE_HOME/bin/nullwire-cli" 2>/dev/null || true
    fi
    ok "installed nullwire-cli $NULLWIRE_VERSION"

    # Run initial setup (creates identity + prekey bundle)
    log "initializing your identity..."
    if [ -f "$NULLWIRE_HOME/state/identity.json" ]; then
        ok "existing identity found — skipping setup"
    else
        # `--ui-dir` is vestigial in v0.1.3+ (UI is bundled into the
        # binary via include_dir!) but `nullwire-cli setup` still
        # requires it.  Pass it for compat — the directory gets
        # created but stays empty.
        "$NULLWIRE_HOME/bin/nullwire-cli" setup \
            --state-dir "$NULLWIRE_HOME/state" \
            --ui-dir "$NULLWIRE_HOME/ui" \
            --home "$NULLWIRE_HOME"
        ok "identity created"
    fi

    # Start the messenger server (Rust, single binary, UI embedded).
    log "starting messenger on http://127.0.0.1:${NULLWIRE_PORT}..."
    "$NULLWIRE_HOME/bin/nullwire-cli" server \
        --home "$NULLWIRE_HOME" \
        --port "$NULLWIRE_PORT" \
        --bind 127.0.0.1 &
    local server_pid=$!

    # Wait briefly for server to be ready
    sleep 2
    if ! kill -0 "$server_pid" 2>/dev/null; then
        fail "server failed to start — see $NULLWIRE_HOME/install.log"
    fi

    # Open browser
    log "opening browser..."
    if command -v open >/dev/null 2>&1; then
        open "http://127.0.0.1:${NULLWIRE_PORT}"
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "http://127.0.0.1:${NULLWIRE_PORT}"
    else
        warn "could not auto-open browser — go to http://127.0.0.1:${NULLWIRE_PORT} manually"
    fi

    # Print bundle for sharing
    printf "\n"
    printf "${C_LIME}${C_BOLD}  NULLWIRE IS RUNNING${C_RESET}\n\n"
    printf "  UI:       ${C_LIME}http://127.0.0.1:${NULLWIRE_PORT}${C_RESET}\n"
    printf "  State:    ${C_DIM}${NULLWIRE_HOME}/state${C_RESET}\n"
    printf "  Uninstall: ${C_DIM}${NULLWIRE_HOME}/bin/nullwire-cli uninstall${C_RESET}\n\n"

    printf "${C_MAGENTA}${C_BOLD}  YOUR BUNDLE (share with contacts)${C_RESET}\n"
    printf "${C_DIM}  ────────────────────────────────────────${C_RESET}\n"
    "$NULLWIRE_HOME/bin/nullwire-cli" export-prekey-bundle \
        --state-dir "$NULLWIRE_HOME/state" 2>/dev/null | head -20
    printf "${C_DIM}  ────────────────────────────────────────${C_RESET}\n\n"

    printf "Press Ctrl+C to stop the server.\n\n"

    # Keep script alive until server dies
    wait "$server_pid"
}

main "$@"
