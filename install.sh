#!/usr/bin/env bash
#
# NULLWIRE — Installer
# =====================
#
# Usage:
#   curl -sSL https://nullwire.xyz/install.sh | bash
#
# Pick your own handle (e.g. @alice — note: env var goes AFTER the pipe):
#   curl -sSL https://nullwire.xyz/install.sh | NULLWIRE_HANDLE=alice bash
#
# Auto-add a contact at install time (so a fresh install lands ready to
# message its inviter — no copy-pasting bundles, no QR scan):
#   curl -sSL https://nullwire.xyz/install.sh | NULLWIRE_ADD=tas bash
#   # or, equivalently, the magic-link form:
#   curl -sSL https://nullwire.xyz/i/tas | bash
#   # or as a positional arg:
#   curl -sSL https://nullwire.xyz/install.sh | bash -s tas
#
# Auto-add MULTIPLE contacts (comma-separated, both env-var and magic-link):
#   curl -sSL https://nullwire.xyz/install.sh | NULLWIRE_ADD=tas,kuba,welcome bash
#   curl -sSL https://nullwire.xyz/i/tas,kuba,welcome | bash
#
# Magic-link with own-handle pre-set (path-segment form):
#   curl -sSL https://nullwire.xyz/i/tas/fogel | bash             # adds @tas, registers as @fogel
#   curl -sSL https://nullwire.xyz/i/tas,kuba/fogel | bash        # adds 2, registers as @fogel
#
# What this does:
#   1. Detects your platform (macOS/Linux, x86_64/arm64)
#   2. Downloads the matching nullwire-cli binary from GitHub Releases
#   3. Verifies the SHA256 against the offline-signed `releases.json`
#      when minisign is available, falling back to the GitHub-releases
#      `checksums.sha256` otherwise (a TLS-only trust root — see
#      "Full verification" below)
#   4. Installs to ~/.nullwire/bin/
#   5. Creates your identity + post-quantum prekey bundle
#   6. Starts the messenger server on http://127.0.0.1:4310
#   7. (optional) Auto-adds the NULLWIRE_ADD handle as a contact
#   8. Opens your default browser
#
# Paranoid install (recommended for first-time users):
#   curl -sSL https://nullwire.xyz/install.sh -o install.sh
#   cat install.sh                           # read it
#   shasum -a 256 install.sh                 # compare to hash on nullwire.xyz
#   bash install.sh
#
# Full verification (rc41+, recommended): install minisign first.
#   brew install minisign        (macOS)
#   apt install minisign         (Debian/Ubuntu)
#   pkg install minisign         (FreeBSD)
# install.sh auto-detects minisign and uses it to verify the signed
# manifest at https://nullwire.xyz/releases.json.minisig before
# downloading any binary.  Without minisign, install.sh falls back to
# a TLS+sha256-only path (rc40 era — still safe under TLS but loses
# the offline-signature guarantee against a compromised GitHub-releases
# account).
#
# To REQUIRE signature verification (refuse install if minisign is
# missing or the manifest does not verify):
#   curl -sSL https://nullwire.xyz/install.sh | NULLWIRE_REQUIRE_SIGNED_MANIFEST=1 bash
#
# Transport hardening (round-4 audit):
#   nullwire.xyz is on the public HSTS preload list (verified via
#   hstspreload.org/api/v2/status?domain=nullwire.xyz → status:
#   "preloaded", bulk: true).  This pins HTTPS for all browser-class
#   clients on first contact.  curl, however, does not consult the
#   preload list — so a first-fetch MITM on the very first run of
#   `curl install.sh | bash` on a brand-new system from a hostile
#   network is still possible.  See "Honest trust-model note" below
#   for the residual gap.  rc42+ work: add `includeSubDomains; preload`
#   directives to the live HSTS header (currently `max-age=31536000`
#   alone) for renewal hygiene.
#
# Honest trust-model note (F1 audit; refined round 2):
#   The signature pubkey is embedded IN this script (the
#   NULLWIRE_RELEASE_PUBKEY constant).  install.sh itself is fetched
#   over TLS from nullwire.xyz, which today is Cloudflare-fronted in
#   front of a Netlify-hosted origin.  If ANY link in that chain —
#   Cloudflare account, Netlify account, or the DNS for nullwire.xyz —
#   were compromised, an attacker could publish an install.sh with a
#   DIFFERENT pubkey baked in AND a manifest signed under that
#   attacker key, and the verification path inside this script would
#   pass cleanly.  The signed-manifest path closes the GitHub-releases
#   admin-account attack vector (which was the C2 P0); it does NOT
#   close the CDN-takeover vector.
#   For higher assurance, install minisign separately and verify the
#   install.sh file's own sha256 against the value published on the
#   public GitHub release page at
#   https://github.com/yunomiwell/nullwire-releases/releases — that
#   surface is operationally independent from Netlify + DNS.
#
# Uninstall:
#   ~/.nullwire/bin/nullwire-cli uninstall
#   # or manually:  rm -rf ~/.nullwire
#
# https://nullwire.xyz  |  https://github.com/yunomiwell/nullwire-releases

# Round-3 audit (HIGH): reject `source install.sh` / `. install.sh`.
# This script is a top-level installer, not a library.  Without this
# guard, sourcing has THREE bad effects:
#   (1) the caller's shell gets polluted with our helpers
#       (have_minisign, fetch_*, verify_*, parse_*, log/ok/warn/fail,
#       detect_platform, install_messenger, ...).
#   (2) our `trap '...' EXIT` registers in the caller's shell, so any
#       later exit triggers our cleanup against THEIR tmp_dirs.
#   (3) — critically — the side-effecting startup runs against the
#       caller's $HOME/.nullwire.  Round-3 testing confirmed sourcing
#       attempts a full install (downloads rc40, registers launchd
#       plist, restarts the daemon), with risk of overwriting an
#       existing identity if NULLWIRE_HOME wasn't already populated.
# The `(return 0 2>/dev/null)` idiom: `return` is only valid in a
# sourced context; in a subshell it succeeds iff we're being sourced.
# The redirect suppresses bash's "can only `return' from a function or
# sourced script" complaint when we're executed normally.
if (return 0 2>/dev/null); then
    printf '\033[38;5;199m✗\033[0m install.sh must be EXECUTED, not sourced.\n' >&2
    printf '  use:    bash install.sh\n' >&2
    printf '  not:    source install.sh   (or `. install.sh`)\n' >&2
    return 1
fi

set -euo pipefail

# ─────────────────────────────────────────────────────────────────
# CONFIG — kept at top so it's easy to audit
# ─────────────────────────────────────────────────────────────────
readonly NULLWIRE_VERSION="${NULLWIRE_VERSION:-v0.1.3-rc40}"
readonly NULLWIRE_RELEASES_BASE="${NULLWIRE_RELEASES_BASE:-https://github.com/yunomiwell/nullwire-releases/releases/download}"

# C2 (red-team rc37): the cold-install path used to trust the UNSIGNED
# `checksums.sha256` file shipped alongside the GitHub release.  An
# attacker with releases-admin access could swap both the manifest and
# the binary atomically and the install would verify cleanly.  rc41+
# consumes the SIGNED `releases.json` manifest from the canonical CDN
# instead and verifies it with this pubkey before extracting any sha256.
# Pubkey matches the offline minisign key whose `public.key` lives in
# the nullwire-core repo and whose value is baked into rc29+ binaries
# at build time via the NULLWIRE_RELEASE_PUBKEY env var.
readonly NULLWIRE_RELEASE_PUBKEY="${NULLWIRE_RELEASE_PUBKEY:-RWTyt2chT6zEFvcqNZ8A0LhwmwEqYdfFeLYN0Yj3h3LiVXOZJVFcAyM7}"
readonly NULLWIRE_MANIFEST_URL="${NULLWIRE_MANIFEST_URL:-https://nullwire.xyz/releases.json}"
readonly NULLWIRE_MANIFEST_SIG_URL="${NULLWIRE_MANIFEST_SIG_URL:-https://nullwire.xyz/releases.json.minisig}"

# F6 (audit): both manifest URLs MUST be https://.  An http:// override
# would let a network attacker swap the manifest in transit — defeats
# the whole point of the signed-manifest path.  Loopback http:// is
# permitted (http://127.0.0.1:* / http://localhost:*) because it can
# only be reached by the test driver running on the same host — an
# off-host attacker cannot redirect production install.sh to loopback.
_nw_assert_manifest_url_safe() {
    local var_name="$1" url="$2"
    case "$url" in
        https://*) return 0 ;;
        http://127.0.0.1:*|http://127.0.0.1/*|http://localhost:*|http://localhost/*) return 0 ;;
        *) echo "✗ $var_name must be https:// (or http://127.0.0.1/localhost for local tests). Got: $url" >&2; exit 1 ;;
    esac
}
_nw_assert_manifest_url_safe NULLWIRE_MANIFEST_URL "$NULLWIRE_MANIFEST_URL"
_nw_assert_manifest_url_safe NULLWIRE_MANIFEST_SIG_URL "$NULLWIRE_MANIFEST_SIG_URL"
unset -f _nw_assert_manifest_url_safe

# Paranoid mode: if set to 1, the install REFUSES to proceed when
# minisign is unavailable OR when manifest verification fails.  Default
# off so the public `curl install.sh | bash` path still works on systems
# without a minisign package (warns loudly instead).  Set to 1 for
# air-gap / production / supply-chain-conscious installs.
readonly NULLWIRE_REQUIRE_SIGNED_MANIFEST="${NULLWIRE_REQUIRE_SIGNED_MANIFEST:-0}"

# F5 audit: integration-test dry-run.  When set to 1, install.sh exits
# 0 immediately after the manifest-verification + cli_hash decision
# (BEFORE any binary download or filesystem mutation outside /tmp).
# Used by `nullwire_messenger/scripts/c2-tests/test-verify-manifest.sh`
# integration mode to exercise the real install.sh main() flow without
# actually installing anything.  No production user should ever set
# this.
#
# Round-2 audit threat model:
#   Attacker sets NULLWIRE_INSTALL_DRYRUN=1 in a victim's env so that
#   `curl install.sh | bash` exits 0 without ever installing the binary.
#   Impact: DENIAL OF SERVICE only — victim sees a successful-looking
#   install but `~/.nullwire/bin/nullwire-cli` is never created.  No
#   privilege escalation, no malicious code execution.
#   Pre-conditions: attacker must already have env-write access to the
#   victim's shell (compromised .bashrc, CI-secret injection, malicious
#   wrapper script).  Any party with env-write access can already cause
#   much worse damage than triggering an early exit — DRYRUN is bounded
#   by what they could otherwise do directly.
#   The Netlify edge function at /i/<handle> CANNOT set arbitrary env
#   vars on the receiving bash side — it only controls the positional
#   $1 (which install.sh treats as NULLWIRE_ADD).  So a magic-link URL
#   cannot weaponize DRYRUN.  Verdict: low-severity DoS only.
readonly NULLWIRE_INSTALL_DRYRUN="${NULLWIRE_INSTALL_DRYRUN:-0}"

# Round-4 — Sigstore Posture B prototype.
#
# NULLWIRE_REKOR_URL: optional URL to a `releases.json.rekor` receipt
# proving the manifest's signature was published to Sigstore's Rekor
# transparency log.  If set AND the receipt fetches AND a verifier
# tool (cosign or rekor-cli) is available, install.sh additionally
# verifies the receipt as defense-in-depth — making any silent
# signing-key compromise detectable via the public log.  Empty by
# default in rc41 (the receipt-publishing pipeline lands in rc42+).
#
# NULLWIRE_REKOR_VERIFY_CMD: test-only override.  If set, install.sh
# uses this command (passed the manifest path + receipt path as $1 +
# $2) for Rekor verification instead of cosign/rekor-cli.  Exits
# non-zero on tamper, zero on valid.  Used by the c2-tests prototype
# to exercise the wiring without contacting the live Rekor service.
readonly NULLWIRE_REKOR_URL="${NULLWIRE_REKOR_URL:-}"
readonly NULLWIRE_REKOR_VERIFY_CMD="${NULLWIRE_REKOR_VERIFY_CMD:-}"

readonly NULLWIRE_HOME="${NULLWIRE_HOME:-$HOME/.nullwire}"
readonly NULLWIRE_PORT="${NULLWIRE_PORT:-4310}"

# rc36: optional handle to auto-add as a contact after the daemon comes up.
# Accepts the env var OR a positional first arg ($1) so all three of these
# invocations work identically:
#   NULLWIRE_ADD=tas bash      (env var on the bash side of the pipe)
#   bash -s tas                (positional, e.g. via `... | bash -s tas`)
#   /i/<handle> magic-link     (Netlify edge function injects NULLWIRE_ADD)
# `${1:-}` is set-u-safe.  Empty string = skip auto-add (legacy behaviour).
readonly NULLWIRE_ADD="${NULLWIRE_ADD:-${1:-}}"

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
  █   verify: shasum -a 256 install.sh → expected on github.com/yunomiwell/nullwire-releases/releases/latest
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
    # F11 (audit): parse_sha256_from_manifest uses python3 to walk the
    # signed-manifest JSON.  Already de-facto required by the rc36
    # NULLWIRE_ADD handle-add flow further down, but make the
    # dependency explicit at startup so a missing python3 fails fast
    # with a clear error rather than mid-install.
    require_cmd python3

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
    # M3-2 (round-3 audit): standardized curl timeouts.
    #   --connect-timeout 10   — give up if TCP handshake hasn't finished in 10s
    #                            (defends slow-loris-style stall on dial)
    #   --max-time 60           — bound the whole transfer.  60s is wide
    #                            enough for a 50 MB binary on a 10 Mbps
    #                            link, narrow enough that a hostile server
    #                            slow-feeding bytes can't hang us forever.
    if ! curl -sSL --fail --connect-timeout 10 --max-time 60 "$url" -o "$dest"; then
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
# C2 — Signed manifest verification helpers (Phase 2)
# Phase 3 wires these into the cold-install flow.  No call sites
# from this script yet — these are pure helpers.
# ─────────────────────────────────────────────────────────────────
have_minisign() {
    # NULLWIRE_FORCE_NO_MINISIGN=1 forces this to return false even when
    # minisign IS on PATH.  Test-only knob used by the c2-tests
    # integration driver to exercise the no-minisign branches (G+H)
    # without uninstalling minisign from the test host.  Production
    # users have no reason to set this.
    if [ "${NULLWIRE_FORCE_NO_MINISIGN:-0}" = "1" ]; then
        return 1
    fi
    command -v minisign >/dev/null 2>&1
}

fetch_signed_manifest() {
    local manifest_out="$1" sig_out="$2"
    log "fetching signed manifest..."
    if ! curl -sSL --fail --connect-timeout 10 --max-time 30 "$NULLWIRE_MANIFEST_URL" -o "$manifest_out"; then
        # No manifest reachable at all — CDN outage, pre-release state,
        # genuine network failure.  Soft-fallback territory; caller
        # decides what that means under strict mode.
        return 1
    fi
    if ! curl -sSL --fail --connect-timeout 10 --max-time 30 "$NULLWIRE_MANIFEST_SIG_URL" -o "$sig_out"; then
        # F2 (audit): manifest IS reachable but signature is NOT.  This
        # is the downgrade-attack shape — an attacker who can rewrite
        # the CDN could serve a tampered manifest while removing the
        # signature, forcing the no-signed-path branch.  Distinct rc=2
        # so caller can hard-fail regardless of strict mode.
        return 2
    fi
    return 0
}

verify_signed_manifest() {
    local manifest="$1" sig="$2" pubkey="$3"
    if ! command -v minisign >/dev/null 2>&1; then
        return 1
    fi
    minisign -Vm "$manifest" -x "$sig" \
        -p <(printf 'untrusted comment: nullwire release\n%s\n' "$pubkey") \
        >/dev/null 2>&1
}

parse_sha256_from_manifest() {
    local manifest="$1" platform="$2"
    # Round-4: dual-parser for schema v1 (platforms[plat].sha256) and
    # schema v2 (platforms[plat].cli.sha256).  v1 is rc40-era output;
    # v2 introduces nested cli/tray sub-objects so the tray hash can be
    # signed alongside the cli hash (closes F8).  rc41+ install.sh
    # accepts BOTH and dispatches on schema_version.
    #
    # F3/F4/F10 (audit): strict hex validation via re.fullmatch
    # (length-only check let a non-hex string slip through previously),
    # plus TypeError in the except tuple to catch a non-string sha
    # (e.g. {"sha256": null} or {"sha256": 42}) — KeyError alone would
    # let those through to .lower() and surface as an unhelpful crash.
    python3 -c '
import json, re, sys
manifest_path = sys.argv[1]
platform = sys.argv[2]
try:
    with open(manifest_path) as f:
        data = json.load(f)
    schema_version = data.get("schema_version", 1)
    if schema_version == 1:
        sha = data["platforms"][platform]["sha256"]
    elif schema_version == 2:
        sha = data["platforms"][platform]["cli"]["sha256"]
    else:
        sys.stderr.write(f"unsupported schema_version: {schema_version}\n")
        sys.exit(1)
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        sys.stderr.write(f"invalid sha256 in manifest for {platform}\n")
        sys.exit(1)
    print(sha)
except (KeyError, TypeError, json.JSONDecodeError, FileNotFoundError) as e:
    sys.stderr.write(f"manifest parse error: {e}\n")
    sys.exit(1)
' "$manifest" "$platform"
}

# Round-4: parse top-level fields from a v2 manifest.  Safe no-ops
# against v1 manifests (return non-zero, caller treats as "absent").
parse_manifest_schema_version() {
    local manifest="$1"
    python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f).get("schema_version", 1))
except Exception:
    print(1)
' "$manifest"
}

parse_installer_sha256_from_manifest() {
    local manifest="$1"
    python3 -c '
import json, re, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    sha = data.get("installer_sha256")
    if sha is None:
        sys.exit(2)
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        sys.stderr.write("invalid installer_sha256 in manifest\n")
        sys.exit(1)
    print(sha)
except (json.JSONDecodeError, FileNotFoundError) as e:
    sys.stderr.write(f"manifest parse error: {e}\n")
    sys.exit(1)
' "$manifest"
}

# Round-4 — Sigstore Posture B prototype.
# Optional Rekor-transparency-log verification of the signed manifest.
# Returns 0 on "OK or n/a" (no receipt, no verifier tool, valid receipt),
# returns 1 on "receipt present but verification FAILED" (tamper signal).
# Production cosign/rekor-cli integration is rc42+ work — the prototype
# wires the call site so the test driver can prove the gating logic.
fetch_rekor_receipt() {
    local out_path="$1"
    if [ -z "$NULLWIRE_REKOR_URL" ]; then
        return 1  # not configured — caller treats as "no receipt"
    fi
    if ! curl -sSL --fail --connect-timeout 10 --max-time 30 \
            "$NULLWIRE_REKOR_URL" -o "$out_path" 2>/dev/null; then
        # Receipt not reachable.  In rc41 prototype we treat this as
        # non-fatal — the manifest signature is still the load-bearing
        # check.  rc42+: when Rekor receipts ship by default, a
        # configured-but-missing receipt should be promoted to a hard
        # fail (downgrade-attack shape, parallels F2).
        return 1
    fi
    return 0
}

verify_rekor_receipt() {
    local manifest="$1" receipt="$2"
    # Test-only override path: lets the c2-tests driver simulate
    # cosign/rekor-cli behavior without contacting the live service.
    if [ -n "$NULLWIRE_REKOR_VERIFY_CMD" ]; then
        $NULLWIRE_REKOR_VERIFY_CMD "$manifest" "$receipt"
        return $?
    fi
    # Production path (rc42+ work): try rekor-cli first, then cosign.
    if command -v rekor-cli >/dev/null 2>&1; then
        # Real impl will be `rekor-cli verify --uuid ... --rekor_server ...`
        # — for now we sanity-check the receipt is well-formed JSON with
        # an entry uuid present.  Replace with real verification in rc42+.
        python3 -c '
import json, sys, re
try:
    with open(sys.argv[1]) as f:
        r = json.load(f)
    uuid = r.get("rekor_entry_uuid")
    if not isinstance(uuid, str) or not re.fullmatch(r"[0-9a-fA-F]{16,}", uuid):
        sys.exit(1)
except Exception:
    sys.exit(1)
sys.exit(0)
' "$receipt" || return 1
        log "rekor-cli detected; receipt well-formed (real verification deferred to rc42+)"
        return 0
    fi
    if command -v cosign >/dev/null 2>&1; then
        log "cosign detected; rekor verification deferred to rc42+"
        return 0
    fi
    # Neither tool available — defense-in-depth unavailable but the
    # core manifest signature already gated us.
    log "no rekor-cli or cosign on PATH; transparency-log verification skipped"
    return 0
}

# Round-4: revoked_versions kill-switch.  Returns 0 if the candidate
# version is NOT in the revoked list (safe to install); returns 1 if
# revoked (caller must hard-fail).  Empty list / missing field / v1
# manifest → returns 0 (no revocations known).
check_version_not_revoked() {
    local manifest="$1" candidate="$2"
    python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    revoked = data.get("revoked_versions", [])
    if not isinstance(revoked, list):
        sys.stderr.write("revoked_versions must be a list\n")
        sys.exit(1)
    candidate = sys.argv[2]
    if candidate in revoked:
        sys.stderr.write(f"version {candidate} appears in revoked_versions\n")
        sys.exit(1)
    sys.exit(0)
except (json.JSONDecodeError, FileNotFoundError) as e:
    sys.stderr.write(f"manifest parse error: {e}\n")
    sys.exit(1)
' "$manifest" "$candidate"
}

# ─────────────────────────────────────────────────────────────────
# rc30: install a Desktop launcher icon.
#
# macOS  → ~/Desktop/NullWire.app  (proper .app bundle with .icns)
# Linux  → ~/Desktop/NullWire.desktop  (XDG entry pointing at icon-512.png)
#
# Best-effort.  Failures (no Desktop folder, network error fetching the
# icon, sips/iconutil missing on a stripped macOS) downgrade silently to
# a `warn` — the messenger still runs, the user can always reach it via
# the menubar tray icon (rc28) or by visiting http://127.0.0.1:4310.
#
# The .app bundle is intentionally tiny: a CFBundleExecutable shell
# script that just `open`s the loopback URL.  No code-signing required
# because the bundle ships no native binary, just a shell script — Gate-
# keeper does not assess script-only .app bundles the way it does
# Mach-O bundles.
# ─────────────────────────────────────────────────────────────────
install_desktop_icon() {
    local platform="$1"
    local desktop_dir="$HOME/Desktop"
    if [ ! -d "$desktop_dir" ]; then
        log "no Desktop folder — skipping desktop icon"
        return 0
    fi

    case "$platform" in
        macos-*)
            local app_path="$desktop_dir/NullWire.app"
            if [ -d "$app_path" ]; then
                log "desktop icon already exists at $app_path — refreshing"
                # rc37 fix: macOS TCC can deny Desktop deletes when the .app
                # has a `com.apple.macl` xattr (granted-application MAC tag)
                # and/or `com.apple.fileprovider.fpfs#P` (iCloud Drive Desktop
                # sync provenance).  Earlier rcs let `rm -rf` fail under
                # set -e and aborted the whole install at the desktop-icon
                # step, masking the fact that the binary install + daemon
                # restart had already succeeded.  Now: the rm is best-
                # effort, and if it fails we warn + skip the refresh,
                # leaving the existing .app in place.  The existing .app's
                # CFBundleExecutable shell script works fine for Chrome-
                # installed users; rc36+ multi-browser fallback is
                # cosmetic-only when Chrome is present.
                if ! rm -rf "$app_path" 2>/dev/null; then
                    warn "could not refresh desktop icon at $app_path"
                    warn "  macOS TCC is blocking the delete (likely com.apple.macl xattr or iCloud Drive Desktop sync)"
                    warn "  the existing .app continues to work — to refresh manually:"
                    warn "    drag $app_path to Trash via Finder, then re-run install.sh"
                    return 0
                fi
            fi
            # rc37 fix: even mkdir can fail under TCC if the parent
            # Desktop folder denies writes to bash.  Same posture as
            # the rm above — warn + skip, never abort the install.
            if ! mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources" 2>/dev/null; then
                warn "could not create $app_path (macOS TCC blocked Desktop write)"
                warn "  grant Terminal 'Files and Folders → Desktop' or 'Full Disk Access' in System Settings → Privacy & Security to enable the Desktop icon"
                return 0
            fi

            # Fetch the prebuilt .icns from the public CDN.  Best-effort:
            # if the fetch fails the .app still works (Finder shows a
            # generic app icon instead of the NullWire glyph).
            local icns_url="https://nullwire.xyz/NullWire.icns"
            if ! curl -sSL --fail --connect-timeout 10 --max-time 10 "$icns_url" \
                -o "$app_path/Contents/Resources/AppIcon.icns" 2>/dev/null; then
                warn "could not fetch desktop icon from $icns_url; .app will use generic Finder icon"
            fi

            # Strip leading "v" from the version (CFBundleShortVersionString
            # rejects non-numeric leading chars on some macOS versions).
            local short_version="${NULLWIRE_VERSION#v}"
            cat > "$app_path/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>NullWire</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIdentifier</key><string>xyz.nullwire.desktop-launcher</string>
    <key>CFBundleName</key><string>NullWire</string>
    <key>CFBundleDisplayName</key><string>NullWire</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${short_version}</string>
    <key>CFBundleVersion</key><string>${short_version}</string>
    <key>LSUIElement</key><false/>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
            cat > "$app_path/Contents/MacOS/NullWire" <<EOF
#!/bin/sh
# NullWire desktop launcher (rc32+).
# Opens the messenger in a chromeless phone-sized window via Chrome's
# --app mode (iPhone 17 Pro logical dimensions: 393×852, no tabs, no
# address bar — looks like a native phone app).  Falls back to the
# default browser if Chrome is unavailable.
#
# --user-data-dir is REQUIRED on macOS: without a dedicated profile,
# Chrome reuses the existing browser process and silently ignores the
# --window-size flag.  A NullWire-specific profile under
# \$NULLWIRE_HOME/chrome-profile keeps the messenger isolated from the
# user's normal Chrome (no shared cookies, no shared history) — that's
# actually the right posture: this is a separate app, not a tab in
# your regular browser.
#
# Daemon itself is managed by launchd; this is purely a UI shortcut.
URL="http://127.0.0.1:${NULLWIRE_PORT}"
PROFILE="$NULLWIRE_HOME/chrome-profile"
# rc36: walk priority list of Chromium-family browsers (all support
# the same --app/--user-data-dir/--window-size flags).  First binary
# that resolves to an executable file wins.  NULLWIRE_BROWSER env
# overrides for non-default install locations.  Profile dir name kept
# as "chrome-profile" for backward compat — Chromium profile data is
# engine-compatible across the family.
CANDIDATES="
\${NULLWIRE_BROWSER:-}
/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
/Applications/Brave Browser.app/Contents/MacOS/Brave Browser
/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge
/Applications/Arc.app/Contents/MacOS/Arc
/Applications/Vivaldi.app/Contents/MacOS/Vivaldi
/Applications/Chromium.app/Contents/MacOS/Chromium
/Applications/Opera.app/Contents/MacOS/Opera
"
BROWSER=""
OLDIFS="\$IFS"
IFS='
'
for c in \$CANDIDATES; do
    [ -z "\$c" ] && continue
    if [ -x "\$c" ]; then
        BROWSER="\$c"
        break
    fi
done
IFS="\$OLDIFS"
if [ -n "\$BROWSER" ]; then
    mkdir -p "\$PROFILE"
    "\$BROWSER" \\
        --user-data-dir="\$PROFILE" \\
        --app="\$URL" \\
        --window-size=393,852 \\
        --window-position=120,120 \\
        --no-first-run \\
        --no-default-browser-check \\
        >/dev/null 2>&1 &
    disown
else
    exec /usr/bin/open "\$URL"
fi
EOF
            chmod +x "$app_path/Contents/MacOS/NullWire"

            # Force Finder to refresh its icon cache for the new bundle.
            # Without this the .app sometimes shows the generic icon
            # until the next login.  `touch` updates mtime on the bundle
            # which is enough for Finder to re-read Info.plist + .icns.
            touch "$app_path"

            ok "desktop icon installed at ~/Desktop/NullWire.app"
            ;;
        linux-*)
            local icon_url="https://nullwire.xyz/icons/icon-512.png"
            local icon_path="$NULLWIRE_HOME/icons/NullWire.png"
            mkdir -p "$NULLWIRE_HOME/icons"
            if ! curl -sSL --fail --connect-timeout 10 --max-time 10 "$icon_url" -o "$icon_path" 2>/dev/null; then
                warn "could not fetch desktop icon — skipping"
                return 0
            fi
            local desktop_file="$desktop_dir/NullWire.desktop"
            cat > "$desktop_file" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=NullWire
GenericName=Post-quantum E2E messenger
Comment=Open the NullWire messenger in your browser
Exec=xdg-open http://127.0.0.1:${NULLWIRE_PORT}
Icon=${icon_path}
Categories=Network;InstantMessaging;
Terminal=false
EOF
            chmod +x "$desktop_file"
            ok "desktop icon installed at ~/Desktop/NullWire.desktop"
            ;;
        *)
            ;;
    esac
}

# ─────────────────────────────────────────────────────────────────
# rc36: auto-add a contact after install (NULLWIRE_ADD).
#
# Three-step dance against the local daemon's HTTP API:
#   1. Resolve the handle on chain via the CLI's read-only resolver
#      (`lookup-user-handle-solana`).  No state-lock conflict with the
#      running daemon — pure RPC + HTTPS fetch + sha256 verify.
#   2. POST /api/contacts to create the contact + thread (defaults
#      mirror the messenger UI's `makeEmptyContactForm` — gw-nbg
#      ingress + the canonical 5-hop mesh route).
#   3. POST /api/threads/<id>/import-peer-bundle with the resolved
#      bundle JSON (same path the AddContactModal's "lookup handle"
#      tab uses for v3/v4 bundles).
#
# Best-effort throughout: any failure (network, parse, conflict on
# already-existing contact) downgrades to a `warn` and the install
# completes normally — the user can always add the contact manually
# from the UI.  Never escalates to `fail` — auto-add is convenience,
# not a correctness gate.
#
# JSON manipulation needs python3 (universally available on macOS
# 11+ and every modern Linux distro).  If python3 is missing we
# warn + skip; on those edge-case systems the user can run the
# follow-up command we print at the end.
# ─────────────────────────────────────────────────────────────────
add_contact_from_chain() {
    local handle="$1"
    handle="${handle#@}"  # strip leading @ if present
    if [ -z "$handle" ]; then
        return 0
    fi

    # Validate the handle shape locally so we don't waste an RPC call
    # on a string that the server will 400 anyway.  Mirror the on-chain
    # register's regex: 1-32 chars, lowercase a-z0-9 + hyphens, must
    # start + end with alphanumeric.
    if ! echo "$handle" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$'; then
        warn "NULLWIRE_ADD value '$handle' is not a valid handle (lowercase a-z0-9 + hyphens, 1-32 chars) — skipping auto-add"
        return 0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 not found; skipping auto-add of @${handle}.  add manually:"
        warn "  open the NullWire messenger → Add Contact → Lookup handle → '$handle'"
        return 0
    fi

    log "looking up @${handle} on chain to auto-add as a contact..."

    # Step 1: resolve via the CLI (writes the bundle JSON to a file).
    local bundle_file
    bundle_file="$(mktemp -t nullwire-add-XXXXXX)" || {
        warn "could not create temp file for bundle — skipping auto-add"
        return 0
    }
    if ! "$NULLWIRE_HOME/bin/nullwire-cli" lookup-user-handle-solana \
        --handle "$handle" --out "$bundle_file" >/dev/null 2>&1; then
        warn "could not resolve @${handle} on chain — skipping auto-add (handle not registered? RPC down?). add manually from the UI."
        rm -f "$bundle_file"
        return 0
    fi

    # Step 2: extract the bundle JSON + build the create-contact body.
    # The CLI writes the on-chain record JSON containing the parsed
    # bundle nested under `bundle`.  We need:
    #   - the inner bundle as a JSON STRING (for the import endpoint's
    #     bundleJson field), and
    #   - a contact-create body with default route + gateway.
    # Print both as two newline-separated JSON objects from one
    # python3 invocation — single-pass parsing, no temp files.
    local two_payloads
    two_payloads="$(python3 - "$bundle_file" "$handle" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        record = json.load(f)
    handle = sys.argv[2]
    # The CLI lookup-user-handle-solana writes:
    #   { handle, ownerPubkeyBase58, version, bundle: {...}, ... }
    # Accept either nested-bundle shape or already-flat-bundle shape.
    bundle = record.get("bundle") if isinstance(record.get("bundle"), dict) else record
    if not isinstance(bundle, dict) or "version" not in bundle or "handle" not in bundle:
        sys.exit(2)
    contact_obj = {
        "handle": handle,
        "name": "",
        "recipientGateway": "nullwire-gw-nbg",
        "recipientMailbox": "",
        "route": "nullwire-gw-nbg nullwire-l2-us nullwire-l2-va nullwire-l3-sg nullwire-l1-hel"
    }
    print(json.dumps(contact_obj))
    print(json.dumps({"bundleJson": json.dumps(bundle)}))
except SystemExit:
    raise
except Exception:
    sys.exit(3)
PYEOF
)" || {
        warn "could not parse on-chain record for @${handle} — skipping auto-add. add manually from the UI."
        rm -f "$bundle_file"
        return 0
    }
    rm -f "$bundle_file"

    local contact_payload bundle_import_payload
    contact_payload="$(printf '%s\n' "$two_payloads" | sed -n '1p')"
    bundle_import_payload="$(printf '%s\n' "$two_payloads" | sed -n '2p')"

    if [ -z "$contact_payload" ] || [ -z "$bundle_import_payload" ]; then
        warn "auto-add: payload split failed — skipping. add @${handle} manually from the UI."
        return 0
    fi

    # Step 3a: create the contact.
    local create_resp
    create_resp="$(curl -fsS --connect-timeout 5 --max-time 10 -X POST \
        -H "Content-Type: application/json" \
        -H "Origin: http://127.0.0.1:${NULLWIRE_PORT}" \
        -d "$contact_payload" \
        "http://127.0.0.1:${NULLWIRE_PORT}/api/contacts" 2>/dev/null)" || {
        warn "could not create contact for @${handle} (might already exist) — open the UI to verify"
        return 0
    }

    # Step 3b: find the new contact's id in the bootstrap response.
    local contact_id
    contact_id="$(printf '%s' "$create_resp" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    target = sys.argv[1].lstrip("@").lower()
    contacts = data.get("contacts") or []
    for c in contacts:
        c_handle = (c.get("handle") or "").lstrip("@").lower()
        if c_handle == target:
            print(c.get("id", ""))
            break
except Exception:
    sys.exit(1)
' "$handle" 2>/dev/null)"

    if [ -z "$contact_id" ]; then
        warn "@${handle} contact created but could not locate its id for bundle import — open the UI to verify"
        return 0
    fi

    # Step 3c: import the bundle into the new thread.
    if curl -fsS --connect-timeout 5 --max-time 10 -X POST \
        -H "Content-Type: application/json" \
        -H "Origin: http://127.0.0.1:${NULLWIRE_PORT}" \
        -d "$bundle_import_payload" \
        "http://127.0.0.1:${NULLWIRE_PORT}/api/threads/${contact_id}/import-peer-bundle" \
        >/dev/null 2>&1; then
        ok "auto-added @${handle} as a contact (post-quantum bundle imported from chain)"
    else
        warn "@${handle} contact created but bundle import failed — open the UI's Add Contact menu and use Advanced → paste bundle"
    fi
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
        resp="$(curl -sS --connect-timeout 3 -m 5 -X POST \
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
    # F5 (audit): dry-run mode skips the devnet RPC probe — keeps the
    # c2-tests integration mode hermetic and fast (no off-host calls).
    if [ "$NULLWIRE_INSTALL_DRYRUN" = "1" ]; then
        log "dry-run: skipping pilot rent-payer balance check"
        local payer_balance=""
    else
        log "checking pilot rent-payer balance (devnet)..."
        local payer_balance
        payer_balance="$(pilot_payer_balance_lamports || true)"
    fi
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
    #
    # rc28: a SECOND binary `nullwire-tray-${platform}` is shipped alongside
    # the CLI. It is the menubar / system-tray helper (separate launchd
    # plist on macOS, separate systemd-user unit on Linux). Two binaries
    # because the daemon is headless and the tray needs an event loop +
    # GUI runtime — coupling them would force the daemon to inherit the
    # desktop session lifetime, which we do NOT want (the daemon has to
    # survive logout). We download + sha256-verify both.
    local base_url="${NULLWIRE_RELEASES_BASE}/${NULLWIRE_VERSION}"
    local cli_asset="nullwire-cli-${platform}"
    local tray_asset="nullwire-tray-${platform}"
    local checksums_url="${base_url}/checksums.sha256"

    # rc41 C2: prefer the offline-signed `releases.json` manifest as
    # the source of truth for the CLI binary sha256.  Fall back to the
    # unsigned `checksums.sha256` only if minisign is unavailable or
    # the manifest cannot be fetched.  HARD-FAIL if a manifest IS
    # fetched AND minisign IS present AND the signature does not verify
    # — that is an attack signal, not a transient.
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    # Bake the resolved path into the trap NOW (double-quoted) so the
    # cleanup runs even after this function returns and `tmp_dir`
    # falls out of `local` scope.  rc29 fix: a single-quoted trap
    # ('rm -rf "$tmp_dir"') deferred expansion to EXIT time, by which
    # point `tmp_dir` was unbound under `set -u`, producing the
    # "unbound variable" error users saw at the very end of install.
    trap "rm -rf '$tmp_dir'" EXIT

    local cli_hash=""
    local used_signed_manifest=0
    if have_minisign; then
        # F2 (audit): fetch_signed_manifest distinguishes
        #   0 = both fetched OK
        #   1 = neither (or just manifest) reachable — soft fallback eligible
        #   2 = manifest reachable but sig MISSING — downgrade attack, hard fail
        local fetch_rc=0
        fetch_signed_manifest "$tmp_dir/releases.json" "$tmp_dir/releases.json.minisig" || fetch_rc=$?
        case "$fetch_rc" in
            0)
                if verify_signed_manifest "$tmp_dir/releases.json" "$tmp_dir/releases.json.minisig" "$NULLWIRE_RELEASE_PUBKEY"; then
                    # Round-4 (Sigstore Posture B prototype): optional
                    # Rekor transparency-log verification.  Defense-in-
                    # depth on top of the minisign signature — if a
                    # signing-key compromise minted a manifest without a
                    # corresponding Rekor entry, this would catch it.
                    if fetch_rekor_receipt "$tmp_dir/releases.json.rekor"; then
                        if ! verify_rekor_receipt "$tmp_dir/releases.json" "$tmp_dir/releases.json.rekor"; then
                            fail "Rekor transparency-log verification FAILED.
    The signed manifest verified against the embedded pubkey, but the
    accompanying Rekor receipt at $NULLWIRE_REKOR_URL did not.
    This could indicate a stolen-offline-key attack where the attacker
    minted a manifest without publishing to the public transparency log.
    Refusing to install.  Report at https://github.com/yunomiwell/nullwire-releases/issues"
                        fi
                        ok "Rekor transparency-log receipt verified"
                    fi
                    # Round-4: revoked_versions kill-switch (schema v2+).
                    # If THIS version appears in the signed manifest's revoke
                    # list, refuse to install — even if everything else
                    # verifies.  Defends against the case where a backdoored
                    # rcXX shipped, was discovered post-publish, and was
                    # killed by adding it to the manifest.
                    if ! check_version_not_revoked "$tmp_dir/releases.json" "$NULLWIRE_VERSION" 2>/dev/null; then
                        fail "version $NULLWIRE_VERSION is REVOKED in the signed manifest.
    This release has been killed post-publish (likely because a security
    issue was discovered).  Refusing to install.
    Check https://nullwire.xyz/security for details, or upgrade to a
    newer version."
                    fi
                    cli_hash="$(parse_sha256_from_manifest "$tmp_dir/releases.json" "$platform" 2>/dev/null || true)"
                    if [ -n "$cli_hash" ]; then
                        local schema_v
                        schema_v="$(parse_manifest_schema_version "$tmp_dir/releases.json" 2>/dev/null || echo 1)"
                        ok "signed manifest verified (schema v${schema_v}) — using sha256 from manifest"
                        used_signed_manifest=1
                    else
                        fail "manifest verified but missing sha256 entry for platform $platform — installer/manifest version mismatch."
                    fi
                else
                    fail "manifest signature INVALID — refusing to install.
    The signed release manifest at $NULLWIRE_MANIFEST_URL did not verify
    against the embedded pubkey ($NULLWIRE_RELEASE_PUBKEY).
    Either the manifest was tampered with or the release key rotated.
    Do NOT proceed.  Report at https://github.com/yunomiwell/nullwire-releases/issues"
                fi
                ;;
            2)
                # F2 (audit): manifest fetched, signature missing.
                # ALWAYS hard-fail — irrespective of NULLWIRE_REQUIRE_SIGNED_MANIFEST.
                # A legitimate release publishes both files atomically;
                # serving manifest without its signature is the
                # downgrade-attack shape, never a transient.
                fail "DOWNGRADE ATTACK DETECTED: manifest available at $NULLWIRE_MANIFEST_URL
    but signature missing at $NULLWIRE_MANIFEST_SIG_URL.
    A legitimate release publishes both files atomically.  Refusing to install.
    Report at https://github.com/yunomiwell/nullwire-releases/issues"
                ;;
            *)
                # rc=1 (or anything else): neither file reachable.
                # Soft fallback unless strict mode is on.
                warn "could not fetch signed manifest from $NULLWIRE_MANIFEST_URL — falling back to TLS+sha256"
                ;;
        esac
    fi

    if [ "$used_signed_manifest" = "0" ]; then
        if [ "$NULLWIRE_REQUIRE_SIGNED_MANIFEST" = "1" ]; then
            if ! have_minisign; then
                fail "NULLWIRE_REQUIRE_SIGNED_MANIFEST=1 set but minisign not installed.
    Refusing to proceed.  Install minisign and re-run:
        brew install minisign        (macOS)
        apt install minisign         (Debian/Ubuntu)
        pkg install minisign         (FreeBSD)"
            else
                fail "NULLWIRE_REQUIRE_SIGNED_MANIFEST=1 set but signed manifest is unavailable.
    Check connectivity to $NULLWIRE_MANIFEST_URL and re-run."
            fi
        fi
        warn "⚠️  WARNING: signature verification OFF. Install minisign for full first-install verification. Falling back to TLS+sha256 only."
    fi

    # Always fetch checksums.sha256: signed-manifest path uses it only
    # for the OPTIONAL tray binary hash (manifest schema v1 does not
    # ship tray hashes).  Fallback path uses it for CLI hash too.
    download "$checksums_url" "$tmp_dir/checksums.sha256"

    if [ "$used_signed_manifest" = "0" ]; then
        cli_hash="$(grep " $cli_asset\$" "$tmp_dir/checksums.sha256" | awk '{print $1}')"
        if [ -z "$cli_hash" ]; then
            fail "could not find expected checksum entries for platform $platform
    This version of the installer may not match the release."
        fi
    fi

    # F5 (audit): integration-test dry-run.  Exit BEFORE downloading the
    # CLI binary, BEFORE touching $NULLWIRE_HOME, BEFORE launchd/systemd
    # setup.  All verification gates have already run by this point —
    # exit 0 means "would have installed", exit non-zero means an
    # earlier gate already aborted.  Used by the c2-tests integration
    # mode; production users have no reason to set this.
    if [ "$NULLWIRE_INSTALL_DRYRUN" = "1" ]; then
        ok "dry-run: verification gates passed (used_signed_manifest=$used_signed_manifest, cli_hash=$cli_hash)"
        exit 0
    fi

    # F8 (audit): tray binary is verified against the UNSIGNED
    # checksums.sha256, not the signed manifest.  Schema v1 manifest
    # carries CLI sha256 only.  Tray supply-chain hardening via schema
    # v2 manifest is rc42+ work — tray is optional + fail-soft + UI-only
    # surface, so the asymmetric trust model is acceptable for now.
    # See RC41_C2_AUDIT.md F8.
    #
    # rc28: extract the tray-binary hash if the release ships one. We treat
    # the tray as OPTIONAL: a release without a tray asset (older versions,
    # or a partial release rebuild) installs cleanly minus the menubar
    # icon.  The fail-soft model means a CDN propagation lag for the tray
    # asset doesn't break the messenger setup itself.
    local tray_hash
    tray_hash="$(grep " $tray_asset\$" "$tmp_dir/checksums.sha256" | awk '{print $1}' || true)"

    # Download CLI binary (UI bundled inside).
    download "$base_url/$cli_asset" "$tmp_dir/$cli_asset"
    verify_sha256 "$tmp_dir/$cli_asset" "$cli_hash"

    # Download tray binary if the release advertises one.  Best-effort:
    # log + continue on download/verify failure so a transient CDN issue
    # on the tray asset doesn't block the messenger install.
    if [ -n "$tray_hash" ]; then
        if curl -sSL --fail --connect-timeout 10 --max-time 60 "$base_url/$tray_asset" -o "$tmp_dir/$tray_asset" 2>/dev/null; then
            local actual_tray_hash
            actual_tray_hash="$(shasum -a 256 "$tmp_dir/$tray_asset" | awk '{print $1}')"
            if [ "$actual_tray_hash" = "$tray_hash" ]; then
                ok "verified $tray_asset"
            else
                warn "tray binary checksum mismatch — skipping menubar helper install."
                rm -f "$tmp_dir/$tray_asset"
            fi
        else
            warn "could not fetch $tray_asset — skipping menubar helper install."
        fi
    else
        log "this release does not ship a menubar helper (rc28+ feature); skipping tray install."
    fi

    # Install CLI
    log "installing nullwire-cli to $NULLWIRE_HOME/bin..."
    mv "$tmp_dir/$cli_asset" "$NULLWIRE_HOME/bin/nullwire-cli"
    chmod +x "$NULLWIRE_HOME/bin/nullwire-cli"

    # rc28: install tray binary too if we successfully downloaded + verified
    # it above.  `tray_present` gates the launchd / systemd setup later so
    # we only register the tray service when the binary is actually on disk.
    local tray_present=0
    if [ -f "$tmp_dir/$tray_asset" ]; then
        log "installing nullwire-tray to $NULLWIRE_HOME/bin..."
        mv "$tmp_dir/$tray_asset" "$NULLWIRE_HOME/bin/nullwire-tray"
        chmod +x "$NULLWIRE_HOME/bin/nullwire-tray"
        tray_present=1
    fi
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
            # rc28: same posture for the tray binary.  Skipped silently if
            # the tray asset wasn't shipped in this release (the file just
            # doesn't exist yet) — xattr -d treats missing-attr as success.
            if [ "$tray_present" = "1" ]; then
                xattr -d com.apple.quarantine "$NULLWIRE_HOME/bin/nullwire-tray" 2>/dev/null || true
            fi
        fi
    fi
    ok "installed nullwire-cli $NULLWIRE_VERSION"
    if [ "$tray_present" = "1" ]; then
        ok "installed nullwire-tray $NULLWIRE_VERSION"
    fi

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

    # rc25: install the messenger server as a real OS service so it
    # survives terminal close, auto-starts on login, and respawns on
    # crash.  Pre-rc25 the server was launched with `&` from install.sh,
    # which inherited the install shell's stdout — closing the terminal
    # killed the server (HUP signal propagation through the parent
    # shell).  Users were complaining about "messenger stops working
    # when I close terminal" + "have to re-run install every reboot."
    # Now: launchd agent on macOS, systemd --user unit on Linux.
    #
    # rc13 carried over: NULLWIRE_PAIR_BROKER_URL gets baked into the
    # service's environment so the AddContact pair-code tab reaches
    # the cross-origin broker at pair.nullwire.xyz.

    # First: kill any pre-rc25 manually-backgrounded server so the new
    # daemon doesn't fail with port-in-use.  Skips silently if none.
    pkill -TERM -f 'nullwire-cli server' 2>/dev/null || true
    # rc28: kill any previous tray-helper instance too so the new binary
    # can replace it cleanly.  launchctl bootout does this implicitly when
    # the plist is reloaded, but we belt-and-braces in case the user is
    # upgrading from a build that ran the tray manually outside launchd.
    pkill -TERM -f 'nullwire-tray' 2>/dev/null || true
    sleep 2

    local broker_url="${NULLWIRE_PAIR_BROKER_URL:-https://pair.nullwire.xyz}"
    # rc25 fix: re-derive `os` from $platform since detect_platform()'s
    # local var doesn't escape the function (we get only the
    # "macos-arm64" / "linux-x86_64" string back).
    local os="${platform%%-*}"

    case "$os" in
        macos)
            # ~/Library/LaunchAgents/xyz.nullwire.cli.plist
            local plist_dir="$HOME/Library/LaunchAgents"
            local plist_path="$plist_dir/xyz.nullwire.cli.plist"
            mkdir -p "$plist_dir"

            # Unload existing if present (idempotent for upgrades).
            launchctl bootout "gui/$(id -u)/xyz.nullwire.cli" 2>/dev/null || true
            launchctl unload "$plist_path" 2>/dev/null || true

            cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>xyz.nullwire.cli</string>
  <key>ProgramArguments</key>
  <array>
    <string>$NULLWIRE_HOME/bin/nullwire-cli</string>
    <string>server</string>
    <string>--home</string>
    <string>$NULLWIRE_HOME</string>
    <string>--port</string>
    <string>$NULLWIRE_PORT</string>
    <string>--bind</string>
    <string>127.0.0.1</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NULLWIRE_PAIR_BROKER_URL</key>
    <string>$broker_url</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>$NULLWIRE_HOME/server.log</string>
  <key>StandardErrorPath</key>
  <string>$NULLWIRE_HOME/server.err</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
EOF
            chmod 644 "$plist_path"
            log "starting messenger via launchd at http://127.0.0.1:${NULLWIRE_PORT}..."
            launchctl bootstrap "gui/$(id -u)" "$plist_path" 2>/dev/null \
                || launchctl load "$plist_path"

            # rc28: separate launchd plist for the menubar helper.
            #
            # Why a separate plist instead of merging into the daemon's:
            #   - The tray helper is a GUI process (NSStatusItem requires
            #     a Cocoa runtime + accessory activation policy). The
            #     daemon must NOT be a GUI process (it runs under
            #     ProcessType=Background, no AppKit, no Dock entry).
            #   - We want them to crash-isolate: a tray-icon library
            #     panic must not nuke the messenger; a daemon segfault
            #     must not kill the menubar.
            #   - launchd's KeepAlive applies per-Label, so each gets its
            #     own respawn policy.
            #
            # NULLWIRE_HOME is plumbed through as an env var so the tray
            # helper writes its "Pause Notifications" marker into the same
            # state dir the daemon reads from.
            if [ "$tray_present" = "1" ]; then
                local tray_plist_path="$plist_dir/xyz.nullwire.tray.plist"

                launchctl bootout "gui/$(id -u)/xyz.nullwire.tray" 2>/dev/null || true
                launchctl unload "$tray_plist_path" 2>/dev/null || true

                cat > "$tray_plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>xyz.nullwire.tray</string>
  <key>ProgramArguments</key>
  <array>
    <string>$NULLWIRE_HOME/bin/nullwire-tray</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NULLWIRE_HOME</key>
    <string>$NULLWIRE_HOME</string>
    <key>NULLWIRE_PORT</key>
    <string>$NULLWIRE_PORT</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <!-- rc30 fix: respect "Quit Tray Icon" menu click.  KeepAlive=true
       (the original) made launchd respawn the tray a few hundred ms
       after the user clicked Quit, so the icon kept reappearing and
       users had to click Quit twice (or more).  The dict form below
       narrows KeepAlive to "only relaunch on ABNORMAL exit": an
       intentional Quit returns 0 → launchd leaves it dead;
       a crash returns non-zero → launchd respawns within
       ThrottleInterval. -->
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>$NULLWIRE_HOME/tray.log</string>
  <key>StandardErrorPath</key>
  <string>$NULLWIRE_HOME/tray.err</string>
</dict>
</plist>
EOF
                chmod 644 "$tray_plist_path"
                log "starting tray helper via launchd..."
                launchctl bootstrap "gui/$(id -u)" "$tray_plist_path" 2>/dev/null \
                    || launchctl load "$tray_plist_path"
            fi
            ;;
        linux)
            # ~/.config/systemd/user/nullwire.service
            local unit_dir="$HOME/.config/systemd/user"
            local unit_path="$unit_dir/nullwire.service"
            mkdir -p "$unit_dir"

            # Stop existing if present (idempotent for upgrades).
            systemctl --user stop nullwire.service 2>/dev/null || true

            cat > "$unit_path" <<EOF
[Unit]
Description=NullWire messenger server
After=network.target

[Service]
ExecStart=$NULLWIRE_HOME/bin/nullwire-cli server --home $NULLWIRE_HOME --port $NULLWIRE_PORT --bind 127.0.0.1
Restart=on-failure
RestartSec=10
Environment=NULLWIRE_PAIR_BROKER_URL=$broker_url
StandardOutput=append:$NULLWIRE_HOME/server.log
StandardError=append:$NULLWIRE_HOME/server.err

[Install]
WantedBy=default.target
EOF
            chmod 644 "$unit_path"
            log "starting messenger via systemd at http://127.0.0.1:${NULLWIRE_PORT}..."
            systemctl --user daemon-reload
            systemctl --user enable --now nullwire.service

            # rc28: separate systemd-user unit for the menubar / system-tray
            # helper.  Same "two units, crash-isolated" rationale as the
            # macOS plist split above.  WantedBy=graphical-session.target
            # would be more correct (the tray needs an X11 / Wayland
            # display) but `default.target` matches the daemon's posture
            # and works on the systemd-user setups we ship to (Ubuntu,
            # Debian, Fedora). The tray gracefully no-ops if no display
            # is available — the tray-icon crate logs and exits.
            if [ "$tray_present" = "1" ]; then
                local tray_unit_path="$unit_dir/nullwire-tray.service"

                systemctl --user stop nullwire-tray.service 2>/dev/null || true

                cat > "$tray_unit_path" <<EOF
[Unit]
Description=NullWire menubar / system-tray helper
After=graphical-session.target nullwire.service

[Service]
ExecStart=$NULLWIRE_HOME/bin/nullwire-tray
Restart=on-failure
RestartSec=10
Environment=NULLWIRE_HOME=$NULLWIRE_HOME
Environment=NULLWIRE_PORT=$NULLWIRE_PORT
StandardOutput=append:$NULLWIRE_HOME/tray.log
StandardError=append:$NULLWIRE_HOME/tray.err

[Install]
WantedBy=default.target
EOF
                chmod 644 "$tray_unit_path"
                log "starting tray helper via systemd..."
                systemctl --user daemon-reload
                systemctl --user enable --now nullwire-tray.service
            fi
            # Note: for the server to survive logout, user must run:
            #   sudo loginctl enable-linger $USER
            # We do NOT auto-enable linger — too invasive for an installer
            # and most pilot testers stay logged in anyway.  Surface as an
            # opt-in tip below.
            ;;
        *)
            fail "service installation not supported on $os"
            ;;
    esac

    # Wait for the daemon to be reachable on its HTTP port (replaces the
    # rc24-and-earlier `kill -0 server_pid` check, which doesn't apply
    # to managed daemons whose PID is owned by launchd / systemd).
    local attempts=0
    while [ $attempts -lt 30 ]; do
        if curl -fsS -o /dev/null "http://127.0.0.1:${NULLWIRE_PORT}/api/health" 2>/dev/null; then
            ok "messenger server is up (managed by $os service)"
            break
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    if [ $attempts -ge 30 ]; then
        fail "server did not respond on http://127.0.0.1:${NULLWIRE_PORT} within 30s — check $NULLWIRE_HOME/server.err"
    fi

    # rc30: install a Desktop launcher icon (best-effort).  See the
    # function definition for platform-specific behaviour.  The
    # `platform` variable is set near the top of `main`.
    install_desktop_icon "$platform"

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

    # rc36: optional auto-add of one OR MANY inviter handles.
    # NULLWIRE_ADD accepts a comma-separated list:
    #   NULLWIRE_ADD=tas
    #   NULLWIRE_ADD=tas,kuba,welcome
    # Loop is sequential so partial failure (one handle unregistered)
    # leaves the others intact.  Each iteration is independently best-
    # effort — see `add_contact_from_chain` above.  Whitespace around
    # commas is tolerated (paste-from-Notes friendly).
    if [ -n "${NULLWIRE_ADD:-}" ]; then
        _NW_OLDIFS="$IFS"
        IFS=','
        for _nw_h in $NULLWIRE_ADD; do
            _nw_h="$(printf '%s' "$_nw_h" | tr -d '[:space:]')"
            if [ -n "$_nw_h" ]; then
                add_contact_from_chain "$_nw_h"
            fi
        done
        IFS="$_NW_OLDIFS"
        unset _NW_OLDIFS _nw_h
    fi

    # Open browser.
    #
    # rc34 + rc36 multi-browser: previously this used `open <url>` which
    # hands off to the default URL handler (your existing Chrome profile)
    # and opens a plain tab in your already-running browser — defeating
    # the whole point of the chromeless 393x852 phone-sized launcher we
    # just baked into ~/Desktop/NullWire.app.  On macOS we now walk a
    # priority list of Chromium-family browsers (all support the same
    # --app/--user-data-dir/--window-size flags) and invoke the first
    # installed one with the chromeless setup.  Brave, Edge, Arc,
    # Vivaldi, and Opera all qualify — a Brave-only user is no longer
    # forced to install Chrome.  NULLWIRE_BROWSER env overrides the
    # priority for non-default install locations.  Safari/Firefox-only
    # users fall through to `open` (regular browser tab); the messenger
    # UI is mobile-responsive at 393px so they can manually resize.
    log "opening browser..."
    URL="http://127.0.0.1:${NULLWIRE_PORT}"
    if [ "$(uname -s)" = "Darwin" ]; then
        PROFILE="${NULLWIRE_HOME}/chrome-profile"
        CANDIDATES="
${NULLWIRE_BROWSER:-}
/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
/Applications/Brave Browser.app/Contents/MacOS/Brave Browser
/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge
/Applications/Arc.app/Contents/MacOS/Arc
/Applications/Vivaldi.app/Contents/MacOS/Vivaldi
/Applications/Chromium.app/Contents/MacOS/Chromium
/Applications/Opera.app/Contents/MacOS/Opera
"
        BROWSER=""
        OLDIFS="$IFS"
        IFS='
'
        for c in $CANDIDATES; do
            [ -z "$c" ] && continue
            if [ -x "$c" ]; then
                BROWSER="$c"
                break
            fi
        done
        IFS="$OLDIFS"
        if [ -n "$BROWSER" ]; then
            mkdir -p "$PROFILE"
            "$BROWSER" \
                --user-data-dir="$PROFILE" \
                --app="$URL" \
                --window-size=393,852 \
                --window-position=120,120 \
                --no-first-run \
                --no-default-browser-check \
                >/dev/null 2>&1 &
            disown 2>/dev/null || true
        elif command -v open >/dev/null 2>&1; then
            open "$URL"
        else
            warn "could not auto-open browser — go to ${URL} manually"
        fi
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$URL"
    else
        warn "could not auto-open browser — go to ${URL} manually"
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

    # rc25: server is now a managed daemon (launchd / systemd-user), not a
    # backgrounded child of this script.  Don't `wait` for a PID we no
    # longer own — return immediately so the install shell exits cleanly.
    printf "the server is running as a managed daemon — close this terminal whenever you want, the messenger keeps running.\n"
    case "$os" in
        macos)
            printf "  control: ${C_DIM}launchctl unload ~/Library/LaunchAgents/xyz.nullwire.cli.plist${C_RESET} (stop)\n"
            printf "         : ${C_DIM}launchctl   load ~/Library/LaunchAgents/xyz.nullwire.cli.plist${C_RESET} (start)\n"
            printf "  logs   : ${C_DIM}${NULLWIRE_HOME}/server.log${C_RESET} + ${C_DIM}${NULLWIRE_HOME}/server.err${C_RESET}\n"
            if [ "$tray_present" = "1" ]; then
                printf "  tray   : ${C_DIM}launchctl unload ~/Library/LaunchAgents/xyz.nullwire.tray.plist${C_RESET} (hide menubar)\n"
                printf "         : ${C_DIM}~/.nullwire/bin/nullwire-tray${C_RESET} (run inline for debugging)\n"
            fi
            ;;
        linux)
            printf "  control: ${C_DIM}systemctl --user stop nullwire.service${C_RESET}\n"
            printf "         : ${C_DIM}systemctl --user start nullwire.service${C_RESET}\n"
            printf "  logs   : ${C_DIM}${NULLWIRE_HOME}/server.log${C_RESET} + ${C_DIM}${NULLWIRE_HOME}/server.err${C_RESET}\n"
            if [ "$tray_present" = "1" ]; then
                printf "  tray   : ${C_DIM}systemctl --user stop nullwire-tray.service${C_RESET} (hide tray)\n"
            fi
            printf "  tip (optional, for headless ops): ${C_DIM}sudo loginctl enable-linger \$USER${C_RESET} keeps the server running across user logout.\n"
            ;;
    esac
    printf "\n"
}

main "$@"
