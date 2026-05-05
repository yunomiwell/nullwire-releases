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
readonly NULLWIRE_VERSION="${NULLWIRE_VERSION:-v0.1.3-rc14}"
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
    # rc6 audit T2-F1: balance-gated staging
    # ─────────────────────────────────────────────────────────────
    #
    # Decode the embedded base64 keypair (see CONFIG block above) into
    # `<state-dir>/service-fee.json` ONLY if the file doesn't already
    # exist.  `nullwire-cli setup --auto-register` reuses this file and
    # skips the airdrop step (its `ensure_service_fee_wallet` short-
    # circuits when the wallet has any balance ≥ 0.01 SOL).
    #
    # rc6 audit T2-F1 (HIGH): the embedded keypair is publicly drainable.
    # If a hostile actor hits the wallet with rapid `RegisterUserHandle`
    # calls, balance can hit zero in under a minute. We pre-flight the
    # balance over Solana JSON-RPC and fall through to the per-install
    # faucet path when the wallet is below `MIN_PILOT_PAYER_LAMPORTS`,
    # which avoids a confusing "registration failed" experience for the
    # tester (they get the airdrop path with a clear top-up notice).
    #
    # Permissions: 0600 — same posture as state.json.  This is harmless
    # on devnet (the keypair is in this public script anyway) but
    # follows the convention so a future rotation to per-install
    # keypairs doesn't leave a 0644 file lying around.

    # 0.5 SOL = 500_000_000 lamports.
    #
    # R7-02 (rc6 follow-up): raised from 0.1 SOL → 0.5 SOL because a
    # launch-day burst of >35 concurrent installs would all read a
    # stale-but-above-threshold balance, stage the keypair, then
    # collide on-chain when the wallet drained mid-burst — and the
    # CLI's per-pubkey airdrop fallback rate-limits at the faucet.
    # 0.5 SOL covers ~175 concurrent registrations of headroom, a
    # comfortable margin for the 100-tester pilot.
    local MIN_PILOT_PAYER_LAMPORTS=500000000
    local fee_keypair_path="$NULLWIRE_HOME/state/service-fee.json"

    # 5-second cap on the RPC; a slow Solana endpoint must not block
    # the install.  On any network/parse failure we fall through to
    # staging (fail-open) — the worst case is the user hits a drained
    # wallet and gets a register error, identical to today.
    pilot_payer_balance_lamports() {
        local resp
        resp="$(curl -sS -m 5 -X POST \
            -H 'Content-Type: application/json' \
            -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"${NULLWIRE_PILOT_PAYER_PUBKEY}\"]}" \
            https://api.devnet.solana.com 2>/dev/null)" || return 1
        # Extract "value":NUMBER from response — whitespace-tolerant
        # (R7-06 LOW, rc6 follow-up). The Solana RPC can return either
        # `"value":1234` or `"value": 1234` depending on the validator
        # node's serializer; strict `[0-9]` after `:` failed on the
        # latter. POSIX `[[:space:]]` is portable on macOS BSD grep
        # and GNU grep. Still no jq dependency — the response shape is
        # `..."value":NUMBER}...` in both spaced and unspaced cases.
        printf '%s' "$resp" \
            | grep -oE '"value"[[:space:]]*:[[:space:]]*[0-9]+' \
            | head -1 \
            | sed 's/.*[^0-9]\([0-9][0-9]*\)[^0-9]*/\1/'
    }

    # R7-03 (rc6 follow-up): always re-check balance, even if a
    # service-fee.json file already exists from a prior attempt.
    # A stale file from a failed install would otherwise short-circuit
    # this guard and quietly stage a possibly-drained shared payer.
    # If the balance is OK, we leave the existing file alone (no rewrite
    # needed); if it's low, we delete the stale file so the CLI's own
    # ensure_service_fee_wallet fallback path takes over with a fresh
    # per-install keypair.
    log "checking pilot rent-payer balance (devnet)..."
    local payer_balance
    payer_balance="$(pilot_payer_balance_lamports || true)"
    if [ -n "$payer_balance" ] && [ "$payer_balance" -lt "$MIN_PILOT_PAYER_LAMPORTS" ] 2>/dev/null; then
        warn "pilot rent-payer is low (${payer_balance} lamports < ${MIN_PILOT_PAYER_LAMPORTS}); falling back to per-install devnet airdrop."
        warn "if registration fails with rate-limit, retry in a few minutes — funds are being topped up."
        # Remove any stale staged keypair from a prior failed install so
        # the CLI's ensure_service_fee_wallet path generates a fresh
        # per-install keypair.
        if [ -f "$fee_keypair_path" ]; then
            rm -f "$fee_keypair_path"
            log "removed stale service-fee.json so CLI can generate per-install keypair"
        fi
    elif [ ! -f "$fee_keypair_path" ]; then
        log "staging pilot rent-payer keypair (v5 payer-only, owner remains local)..."
        if printf '%s' "$NULLWIRE_PILOT_PAYER_KEYPAIR_B64" | base64 -d > "$fee_keypair_path" 2>/dev/null; then
            chmod 600 "$fee_keypair_path"
            if [ -n "$payer_balance" ]; then
                ok "pilot rent-payer staged ($NULLWIRE_PILOT_PAYER_PUBKEY, balance: ${payer_balance} lamports)"
            else
                # X9 (R7-C MEDIUM): explicit fail-open messaging — the
                # 5s RPC probe missed (transient devnet slowness, TLS
                # hiccup, network blip). Surface a concrete recovery
                # path so the tester is not surprised if register fails.
                warn "pilot rent-payer staged ($NULLWIRE_PILOT_PAYER_PUBKEY) but balance unverified — devnet RPC unreachable in 5s probe."
                warn "  if 'nullwire-cli setup' fails with 'insufficient funds' or 'register failed',"
                warn "  retry in 1-2 minutes (devnet RPC may be transiently slow)."
                warn "  persistent failure: report at relay@nullwire.xyz with 'pilot rent-payer status' in the subject."
            fi
        else
            warn "could not decode pilot rent-payer; falling back to per-install airdrop"
            rm -f "$fee_keypair_path"
        fi
    else
        if [ -n "$payer_balance" ]; then
            ok "pilot rent-payer already staged ($NULLWIRE_PILOT_PAYER_PUBKEY, balance: ${payer_balance} lamports)"
        else
            # X9 (R7-C MEDIUM): same explicit messaging as the staging
            # path above — already-staged + unverified balance is the
            # higher-risk state because we can't tell if the file is
            # stale-from-a-failed-install or fine.
            warn "pilot rent-payer already staged but balance unverified — devnet RPC unreachable in 5s probe."
            warn "  if you see register errors below, the embedded keypair may be drained;"
            warn "  remove ~/.nullwire/state/service-fee.json and re-run install to retry."
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
    # X5 (R7-C HIGH, rc6 follow-up): conditional Gatekeeper strip.
    #
    # Today (Apple DTS case 102873775642 pending notarization unblock):
    # binaries ship ad-hoc signed; without the strip Gatekeeper would
    # refuse to launch and the install fails. Future (Apple unblocks):
    # binaries ship Developer ID + stapled notarization; an
    # unconditional strip would silently disable Gatekeeper EVEN when
    # the binary is properly notarized — defeats defense-in-depth.
    #
    # Probe via `spctl --assess`. If "Notarized" → skip strip + log so
    # the user knows notarization is active. Anything else (ad-hoc,
    # rejected, no spctl) → strip + log + reference the sha256 verify
    # above as the actual integrity root.
    if [ "$(uname)" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
        local _gk_assess=""
        if command -v spctl >/dev/null 2>&1; then
            _gk_assess="$(spctl --assess --type execute --verbose=4 \
                "$NULLWIRE_HOME/bin/nullwire-cli" 2>&1 || true)"
        fi
        if echo "$_gk_assess" | grep -q "source=Notarized Developer ID"; then
            ok "binary is notarized (Apple Developer ID + stapled ticket); leaving Gatekeeper enabled"
        else
            log "binary is ad-hoc signed (Apple DTS case 102873775642 pending); enabling Gatekeeper bypass."
            log "  integrity root for this install is the sha256 already verified above."
            xattr -d com.apple.quarantine "$NULLWIRE_HOME/bin/nullwire-cli" 2>/dev/null || true
        fi
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
        #
        # rc7+: NULLWIRE_HANDLE env var plumbed through to setup's
        # --handle flag. If unset, setup auto-generates @anon-XXXX
        # (current behavior). If set, setup registers that exact handle
        # — useful for cross-Mac testing or named-identity onboarding.
        #
        # Reserved handles (welcome, support, admin, martin, doxologic,
        # yunomi, yunomiwell, etc.) are blocked at the CLI register
        # layer. To register a reserved handle as the legitimate owner,
        # also set NULLWIRE_ALLOW_RESERVED_HANDLE=1.
        local handle_arg=""
        if [ -n "${NULLWIRE_HANDLE:-}" ]; then
            handle_arg="--handle ${NULLWIRE_HANDLE}"
            log "using custom handle from NULLWIRE_HANDLE: @${NULLWIRE_HANDLE}"
        fi
        # shellcheck disable=SC2086 # word-splitting is intentional for the optional flag
        "$NULLWIRE_HOME/bin/nullwire-cli" setup \
            --state-dir "$NULLWIRE_HOME/state" \
            --ui-dir "$NULLWIRE_HOME/ui" \
            --home "$NULLWIRE_HOME" \
            $handle_arg
        ok "identity created"
    fi

    # Start the messenger server (Rust, single binary, UI embedded).
    # rc13: NULLWIRE_PAIR_BROKER_URL injects window.__NULLWIRE_PAIR_BROKER__
    # into the embedded UI so the AddContact pair-code tab can reach the
    # cross-origin broker at pair.nullwire.xyz (auto-clears the spurious
    # "TESTING MODE — TURN RELAY NOT DEPLOYED" warning that rc12 shipped
    # because the legacy server.mjs's inject path never ported to Rust).
    # Tester can override at install time with NULLWIRE_PAIR_BROKER_URL=…
    # but the default points at our deployed live broker.
    log "starting messenger on http://127.0.0.1:${NULLWIRE_PORT}..."
    NULLWIRE_PAIR_BROKER_URL="${NULLWIRE_PAIR_BROKER_URL:-https://pair.nullwire.xyz}" \
    "$NULLWIRE_HOME/bin/nullwire-cli" server \
        --home "$NULLWIRE_HOME" \
        --port "$NULLWIRE_PORT" \
        --bind 127.0.0.1 &
    local server_pid=$!

    # Wait briefly for server to be ready
    sleep 2
    if ! kill -0 "$server_pid" 2>/dev/null; then
        fail "server failed to start — check the terminal output above for errors (port $NULLWIRE_PORT may already be in use)"
    fi

    # Send a kick-off "hi" to @welcome so the user sees a populated UI on first
    # load.  Without this the messenger shows "WAITING FOR NODE" with no thread
    # activity until the user manually types something — looks broken on first
    # impression.  Best-effort — failures are non-fatal (don't escalate into
    # install failure; the user can still send manually from the UI).
    log "kicking off welcome conversation..."
    if curl -fsSL -X POST "http://127.0.0.1:${NULLWIRE_PORT}/api/send" \
        -H "Content-Type: application/json" \
        -H "Origin: http://127.0.0.1:${NULLWIRE_PORT}" \
        -d "{\"threadId\":\"welcome\",\"text\":\"hi\"}" \
        >/dev/null 2>&1; then
        ok "welcome message sent — check the UI for the bot's reply (~10-30s mesh round-trip)"
    else
        warn "welcome kick-off failed — you can manually send a 'hi' from the UI"
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
