# NullWire — Releases

This repo hosts **pre-built binaries** and the **install script** for NullWire.
Source code lives in a private repository.

**Current release:** `v0.1.3-rc3` (2026-04-27).  Three platforms.  **Single Rust binary
— no Node.js prereq, no separate UI tarball.**

**Live infrastructure:**
- 5-node Sphinx mixnet across DE / FI / US-W / US-E / SG since 2026-04-21.
- WebRTC pair broker + TURN at `pair.nullwire.xyz` / `turn.nullwire.xyz` since 2026-04-24.
- On-chain user-handle registry on Solana devnet since 2026-04-27 (`@yunomi`,
  `@welcome`, plus any user who runs `register-user-handle-solana`).
- Welcome bot live on the Helsinki node since 2026-04-27 — message
  `@welcome.nullwire` to verify the mesh is round-tripping.

First real cross-machine encrypted message round-trip through the live mesh:
2026-04-25.  First end-to-end run via the public install path
(`curl install.sh | bash` → on-chain handle resolution → bot reply): 2026-04-27.

## Install (one command)

```bash
curl -fsSL https://nullwire.xyz/install.sh | bash
```

This downloads the right binary for your platform, verifies its SHA256 checksum,
installs to `~/.nullwire/`, generates your post-quantum identity, and opens the
messenger in your browser.

## Paranoid install (recommended on first run)

Don't trust scripts you can't see. Download, read, verify, then run:

```bash
curl -fsSL https://nullwire.xyz/install.sh -o install.sh
cat install.sh                              # read it
shasum -a 256 install.sh                    # cross-check against the
                                            #   release notes for the tag
bash install.sh
```

The install-script SHA256 is published in each tagged GitHub Release alongside
the binaries.

## Supported platforms

| OS | Arch | Binary |
|----|------|--------|
| macOS | Apple Silicon (M1/M2/M3/M4) | `nullwire-cli-macos-arm64` |
| macOS | Intel | `nullwire-cli-macos-x86_64` |
| Linux | x86_64 | `nullwire-cli-linux-x86_64` |

Linux ARM64 and mobile (iOS / Android) are on the roadmap — not yet shipped.

## What gets installed

```
~/.nullwire/
├── bin/nullwire-cli        ← single Rust binary (~12MB) — UI bundled inside
├── state/                  ← your identity, contacts, messages, crypto keys (0700)
├── ui/                     ← vestigial in v0.1.3+ (UI is bundled into the binary;
│                            kept empty for compat with `nullwire-cli setup`)
├── config.json             ← auto-generated, points at the live Solana-derived gateway
└── install.log             ← what happened during install
```

The `state/` directory has permissions `0700` — only you can read it. **Back it up
encrypted** if you want recovery; losing it means losing your identity and message
history.

### What v0.1.3 ships over v0.1.0 / v0.1.2

- **Single binary.**  No Node prereq, no separate UI tarball.  The
  installer downloads one file, verifies its SHA-256, and runs it.
- **Solana-derived gateway.**  At first-run, the CLI queries the on-chain
  registry for live mesh nodes and writes their endpoint into your
  config.  No more localhost-mock defaults.
- **On-chain handle resolution.**  `nullwire-cli register-user-handle-solana
  --handle alice` claims `@alice.nullwire` on Solana devnet.  Anyone can
  then `lookup-user-handle-solana --handle alice` (or visit
  `https://nullwire.xyz/add/alice`) to fetch your verified prekey bundle.
- **Welcome bot.**  A pre-registered `@welcome` contact runs on the
  Helsinki mesh node and auto-replies to anyone who messages it through
  the live mixnet.  First-message demo for new users.
- **In-process protocol.**  The Round-5 architectural surface where the
  server spawned a `nullwire-cli` subprocess for each send/poll is
  eliminated; everything runs in the same Rust process under one Tokio
  Mutex.

## Uninstall

```bash
~/.nullwire/bin/nullwire-cli uninstall
```

Or just: `rm -rf ~/.nullwire`

## Security

- All binaries are SHA256-checksummed in `checksums.sha256` per release.
- **macOS binaries: ad-hoc signed (`codesign --sign -`).** Apple Developer ID
  notarization is currently blocked on Apple's side — a DTS (Developer Technical
  Support) ticket is open since ~2 weeks ago.  Until that resolves, Gatekeeper
  will block first launch:
  - **GUI:** right-click the binary → Open → confirm.
  - **Terminal:** `xattr -cr ~/.nullwire/bin/nullwire-cli`
  Full Developer ID + notarization will return in a follow-up release once Apple
  flips the team flag.  v0.2 adds **Sigstore + cosign + Rekor transparency log**
  as an Apple-independent verification path.
- Linux binaries are stripped but currently unsigned (Sigstore in v0.2).
- The install.sh script is reviewed-by-design — read it before running.
- Bundle CDN at `https://nullwire.xyz/handles/` serves only **public** prekey
  bundle material (identity / signed-prekey / ML-KEM public keys + Ed25519
  signatures).  No private keys touch the network.  On-chain `bundle_sha256`
  protects against tampering: the client refuses any bundle whose hash doesn't
  match the on-chain record, even if the CDN is compromised.

Found a security issue? Please report privately to **relay@nullwire.xyz**.
GPG key + warrant canary at <https://nullwire.xyz/warrant-canary>.

## Source code

Source lives in a private repo. The compiled binaries here are reproducible from
that source. Security researchers wanting source access for review: email
**relay@nullwire.xyz** with your background and we'll set up access.

## License

Binaries are distributed under the MIT License.
See [LICENSE](LICENSE) for details.

---

[nullwire.xyz](https://nullwire.xyz) · [@nllwrprtcl](https://twitter.com/nllwrprtcl)
