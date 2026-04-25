# NullWire — Releases

This repo hosts **pre-built binaries** and the **install script** for NullWire.
Source code lives in a private repository.

**Current release:** `v0.1.0` (2026-04-20). Three platforms.
**Live infrastructure:** 5-node Sphinx mixnet across DE / FI / US-W / US-E / SG since 2026-04-21.
First real cross-machine encrypted message round-trip through the live mesh: 2026-04-25.

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
├── bin/nullwire-cli        ← compiled Rust binary (~25MB)
├── state/                  ← your identity, contacts, messages, crypto keys
├── ui/                     ← the messenger web interface
├── config.json             ← auto-generated, no editing needed
└── install.log             ← what happened during install
```

The `state/` directory has permissions `0700` — only you can read it. **Back it up
encrypted** if you want recovery; losing it means losing your identity and message
history.

## Uninstall

```bash
~/.nullwire/bin/nullwire-cli uninstall
```

Or just: `rm -rf ~/.nullwire`

## Security

- All binaries are SHA256-checksummed in `checksums.sha256` per release.
- **macOS binaries: ad-hoc signed (`codesign --sign -`).** Apple Developer ID
  notarization is currently blocked on Apple's side — a DTS (Developer Technical
  Support) ticket is open. Until that resolves, Gatekeeper will block first launch:
  - **GUI:** right-click the binary → Open → confirm.
  - **Terminal:** `xattr -cr ~/.nullwire/bin/nullwire-cli`
  Full Developer ID + notarization will return in a follow-up release once Apple
  flips the team flag.
- Linux binaries are stripped but currently unsigned (Sigstore signing planned).
- The install.sh script is reviewed-by-design — read it before running.

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
