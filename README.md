# NullWire — Releases

This repo hosts **pre-built binaries** and the **install script** for NullWire.
Source code lives in a private repository.

## Install (one command)

```bash
curl -sSL https://nullwire.xyz/install.sh | bash
```

This downloads the right binary for your platform, verifies its SHA256 checksum,
installs to `~/.nullwire/`, generates your post-quantum identity, and opens the
messenger in your browser.

## Paranoid install (recommended on first run)

Don't trust scripts you can't see. Download, read, verify, then run:

```bash
curl -sSL https://nullwire.xyz/install.sh -o install.sh
cat install.sh                              # read it
shasum -a 256 install.sh                    # compare to hash below
bash install.sh
```

**install.sh expected hash (v0.1.0):** `<published with each release>`

## Supported platforms

| OS | Arch | Binary |
|----|------|--------|
| macOS | Apple Silicon (M1/M2/M3/M4) | `nullwire-cli-macos-arm64` |
| macOS | Intel | `nullwire-cli-macos-x86_64` |
| Linux | x86_64 | `nullwire-cli-linux-x86_64` |
| Linux | ARM64 | `nullwire-cli-linux-arm64` |

Mobile (iOS / Android) is on the roadmap — not yet shipped.

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

- All binaries are SHA256-checksummed in `checksums.sha256` per release
- macOS binaries are codesigned + notarized by Apple (starting with v0.1.0)
- Linux binaries are stripped but currently unsigned (Sigstore signing planned)
- The install.sh script is reviewed-by-design — read it before running

Found a security issue? Please report privately: https://nullwire.xyz/security

## Source code

Source lives in a private repo. The compiled binaries here are reproducible from
that source. If you're a security researcher and want access for review, contact:
[your email]

## License

Binaries are distributed under the MIT License.
See [LICENSE](LICENSE) for details.

---

[nullwire.xyz](https://nullwire.xyz) · [@nllwrprtcl](https://twitter.com/nllwrprtcl)
