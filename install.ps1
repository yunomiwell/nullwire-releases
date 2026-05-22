#Requires -Version 5.1
<#
  NULLWIRE - Windows Installer (PowerShell)
  ========================================

  Usage:
    irm https://nullwire.xyz/install.ps1 | iex

  Pick your own handle:
    $env:NULLWIRE_HANDLE = 'alice'; irm https://nullwire.xyz/install.ps1 | iex

  Auto-add a contact at install time (fresh install lands ready to message
  its inviter - no copy-pasting bundles, no QR scan):
    $env:NULLWIRE_ADD = 'tas'; irm https://nullwire.xyz/install.ps1 | iex
    # comma-separated for multiple:
    $env:NULLWIRE_ADD = 'tas,kuba'; irm https://nullwire.xyz/install.ps1 | iex

  What this does:
    1. Detects your platform (Windows x86_64)
    2. Downloads the matching nullwire-cli.exe from GitHub Releases
    3. Verifies the SHA256 against the offline-signed releases.json manifest
       when minisign is available, falling back to the GitHub-releases
       checksums.sha256 otherwise (a TLS-only trust root)
    4. Installs to %USERPROFILE%\.nullwire\bin\
    5. Creates your identity + post-quantum prekey bundle
    6. Runs the messenger server as a per-user Scheduled Task on
       http://127.0.0.1:4310 (auto-starts at logon)
    7. (optional) Auto-adds the NULLWIRE_ADD handle as a contact
    8. Opens your browser

  Paranoid install (recommended for first-time users):
    irm https://nullwire.xyz/install.ps1 -OutFile install.ps1
    Get-Content install.ps1                              # read it
    Get-FileHash -Algorithm SHA256 install.ps1           # compare to the
                                                         # hash on the
                                                         # GitHub release page
    .\install.ps1

  Full verification (recommended): install minisign first
  (winget install jedisct1.minisign  -or-  scoop install minisign).
  install.ps1 auto-detects minisign and uses it to verify the signed
  manifest at https://nullwire.xyz/releases.json.minisig before
  downloading any binary.  Without minisign, install.ps1 falls back to
  a TLS+sha256-only path - still safe under TLS but loses the offline-
  signature guarantee against a compromised GitHub-releases account.

  To REQUIRE signature verification (refuse install if minisign is
  missing or the manifest does not verify):
    $env:NULLWIRE_REQUIRE_SIGNED_MANIFEST = '1'
    irm https://nullwire.xyz/install.ps1 | iex

  Honest trust-model note:
    The signature pubkey is embedded IN this script (the
    $NullwireReleasePubkey constant).  install.ps1 itself is fetched
    over TLS from nullwire.xyz, which is Cloudflare-fronted in front of
    a Netlify origin.  If that chain (Cloudflare / Netlify / DNS) were
    compromised, an attacker could publish an install.ps1 with a
    DIFFERENT pubkey AND a manifest signed under that key, and this
    script's verification would pass.  The signed-manifest path closes
    the GitHub-releases admin-account attack vector; it does NOT close
    the CDN-takeover vector.  For higher assurance, verify this file's
    own SHA256 against the value published on the GitHub release page at
    https://github.com/yunomiwell/nullwire-releases/releases - that
    surface is operationally independent from Netlify + DNS.

  Uninstall:
    & "$env:USERPROFILE\.nullwire\bin\nullwire-cli.exe" uninstall
    Unregister-ScheduledTask -TaskName NullWire -Confirm:$false
    Remove-Item -Recurse -Force "$env:USERPROFILE\.nullwire"

  https://nullwire.xyz  |  https://github.com/yunomiwell/nullwire-releases
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

# ---------------------------------------------------------------------
# CONFIG - kept at top so it's easy to audit
# ---------------------------------------------------------------------

# NULLWIRE_VERSION MUST match the release tag that carries the
# nullwire-cli-windows-x86_64 asset.  Bumped in lockstep with install.sh
# at every release cut.  The Windows binary debuts in v0.1.3-rc51.
$NullwireVersion = if ($env:NULLWIRE_VERSION) { $env:NULLWIRE_VERSION } else { 'v0.1.3-rc51' }

$NullwireReleasesBase = if ($env:NULLWIRE_RELEASES_BASE) { $env:NULLWIRE_RELEASES_BASE } `
    else { 'https://github.com/yunomiwell/nullwire-releases/releases/download' }

# Pubkey matches the offline minisign key whose public.key lives in the
# nullwire-core repo and whose value is baked into rc29+ binaries at
# build time via the NULLWIRE_RELEASE_PUBKEY env var.
$NullwireReleasePubkey = if ($env:NULLWIRE_RELEASE_PUBKEY) { $env:NULLWIRE_RELEASE_PUBKEY } `
    else { 'RWTyt2chT6zEFvcqNZ8A0LhwmwEqYdfFeLYN0Yj3h3LiVXOZJVFcAyM7' }

$NullwireManifestUrl = if ($env:NULLWIRE_MANIFEST_URL) { $env:NULLWIRE_MANIFEST_URL } `
    else { 'https://nullwire.xyz/releases.json' }
$NullwireManifestSigUrl = if ($env:NULLWIRE_MANIFEST_SIG_URL) { $env:NULLWIRE_MANIFEST_SIG_URL } `
    else { 'https://nullwire.xyz/releases.json.minisig' }

$NullwireHome = if ($env:NULLWIRE_HOME) { $env:NULLWIRE_HOME } `
    else { Join-Path $env:USERPROFILE '.nullwire' }
$NullwirePort = if ($env:NULLWIRE_PORT) { $env:NULLWIRE_PORT } else { '4310' }

# Paranoid mode: refuse to proceed when minisign is unavailable OR when
# manifest verification fails.  Default off so the public one-liner path
# still works on systems without minisign (warns loudly instead).
$RequireSignedManifest = ($env:NULLWIRE_REQUIRE_SIGNED_MANIFEST -eq '1')

# Integration-test dry-run.  When '1', install.ps1 exits 0 immediately
# after the manifest-verification + cli_hash decision (BEFORE any binary
# download or filesystem mutation outside the temp dir).  No production
# user should set this.
$InstallDryRun = ($env:NULLWIRE_INSTALL_DRYRUN -eq '1')

$NullwireHandle = $env:NULLWIRE_HANDLE
$NullwireAdd    = $env:NULLWIRE_ADD
$BrokerUrl = if ($env:NULLWIRE_PAIR_BROKER_URL) { $env:NULLWIRE_PAIR_BROKER_URL } `
    else { 'https://pair.nullwire.xyz' }

# Scheduled Task name - the in-app updater's daemon-recycle path
# (nullwire-server/src/update.rs schedule_daemon_recycle) runs
# `schtasks /Run /TN NullWire`, so this name is load-bearing.  Do not
# change it without changing that Rust code in lockstep.
$TaskName = 'NullWire'

# Pilot rent-payer (devnet program v5 split-payer).  This keypair ONLY
# pays Solana rent for handle registration - the identity-owner is the
# user's local ed25519 key, never this.  Public by design (it is in this
# script).  Worst case if drained: next install can't register until the
# wallet is topped up.  Devnet only.  See install.sh for the full model.
$PilotPayerPubkey     = 'He8V5kgZszVXtjtxcq8CLaQ9GUfAK4dXvwgxcQyxqazA'
$PilotPayerKeypairB64 = 'WzIyMCwxMTgsMjUxLDI0NiwyNywyMzUsNzUsMjE2LDc4LDIxMywyNywxNzgsMTg2LDIxMCw3Niw3LDgxLDE5LDY3LDIxNSwxMTIsNDksMTU5LDg4LDcwLDk3LDE0Myw4MiwxMDQsMjE5LDYxLDEwNCwyNDcsNjEsMjQxLDExMywxMTIsNDksMTI4LDE1NSw3LDExMywyMDUsMjQzLDE2NSwyNDQsMTYsMTAxLDE5NSwyMDMsNzAsMjM3LDQ2LDU4LDIwMCwxNDQsMTY4LDE0MSwxMDMsMTE0LDIxMiwyMjAsMTIzLDE5OV0='
$MinPilotPayerLamports = 500000000

$BaseUrl  = "$NullwireReleasesBase/$NullwireVersion"
$Platform = 'windows-x86_64'
$CliAsset = "nullwire-cli-$Platform"
$UiUrl    = "http://127.0.0.1:$NullwirePort"

# ---------------------------------------------------------------------
# OUTPUT HELPERS
# ---------------------------------------------------------------------
function Info($m) { Write-Host "  -> $m" -ForegroundColor DarkGray }
function Ok($m)   { Write-Host "  + $m"  -ForegroundColor Green }
function Warn($m) { Write-Host "  ! $m"  -ForegroundColor Magenta }
function Fail($m) {
    Write-Host "  x $m" -ForegroundColor Magenta
    exit 1
}

function Banner {
    Write-Host ""
    Write-Host "  #  NULLWIRE" -ForegroundColor Green
    Write-Host "  #  post-quantum encrypted messenger" -ForegroundColor Green
    Write-Host "  #  https://nullwire.xyz" -ForegroundColor Green
    Write-Host "  #  verify: Get-FileHash install.ps1 -> expected on the GitHub release page" -ForegroundColor Green
    Write-Host ""
}

# Assert a manifest URL is https:// (loopback http is allowed for local
# tests only - an off-host attacker cannot redirect to loopback).
function Confirm-ManifestUrlSafe($name, $url) {
    if ($url -match '^https://') { return }
    if ($url -match '^http://(127\.0\.0\.1|localhost)([:/]|$)') { return }
    Fail "$name must be https:// (or http://127.0.0.1/localhost for local tests). Got: $url"
}

# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
Banner
Confirm-ManifestUrlSafe 'NULLWIRE_MANIFEST_URL' $NullwireManifestUrl
Confirm-ManifestUrlSafe 'NULLWIRE_MANIFEST_SIG_URL' $NullwireManifestSigUrl

# --- TLS: PowerShell 5.1 defaults to TLS 1.0; GitHub + Netlify need 1.2+
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# --- Platform detection -------------------------------------------------
Info 'checking platform...'
$arch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
if ($arch -ne 'AMD64') {
    Fail "unsupported architecture: $arch
    This installer ships an x86_64 (AMD64) Windows build only.
    On Windows on ARM, x64 emulation is untested - follow
    https://nullwire.xyz/status for native ARM64 progress."
}
Ok "detected platform: $Platform"

# --- Temp workspace -----------------------------------------------------
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("nullwire-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
try {

# --- Manifest verification ---------------------------------------------
$cliHash = ''
$usedSignedManifest = $false
$haveMinisign = [bool](Get-Command minisign -ErrorAction SilentlyContinue)

if ($haveMinisign) {
    Info 'fetching signed manifest...'
    $manifestPath = Join-Path $tmpDir 'releases.json'
    $sigPath      = Join-Path $tmpDir 'releases.json.minisig'

    $manifestFetched = $true
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Uri $NullwireManifestUrl -OutFile $manifestPath
    } catch { $manifestFetched = $false }

    if (-not $manifestFetched) {
        Warn "could not fetch signed manifest from $NullwireManifestUrl - falling back to TLS+sha256"
    } else {
        # Manifest IS reachable: the signature MUST be too.  A legitimate
        # release publishes both files atomically; manifest-without-sig
        # is the downgrade-attack shape - hard-fail regardless of mode.
        try {
            Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Uri $NullwireManifestSigUrl -OutFile $sigPath
        } catch {
            Fail "DOWNGRADE ATTACK DETECTED: manifest available at $NullwireManifestUrl
    but signature missing at $NullwireManifestSigUrl.
    A legitimate release publishes both files atomically. Refusing to install.
    Report at https://github.com/yunomiwell/nullwire-releases/issues"
        }

        # minisign -Vm needs the pubkey in a minisign-format file.
        $pubkeyFile = Join-Path $tmpDir 'release.pub'
        Set-Content -Path $pubkeyFile -Encoding ASCII -Value @(
            'untrusted comment: nullwire release'
            $NullwireReleasePubkey
        )

        & minisign -Vm $manifestPath -x $sigPath -p $pubkeyFile 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Fail "manifest signature INVALID - refusing to install.
    The signed release manifest at $NullwireManifestUrl did not verify
    against the embedded pubkey ($NullwireReleasePubkey).
    Either the manifest was tampered with or the release key rotated.
    Do NOT proceed. Report at https://github.com/yunomiwell/nullwire-releases/issues"
        }

        $manifest = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json

        # revoked_versions kill-switch: refuse a release killed post-publish.
        if ($manifest.revoked_versions -and ($NullwireVersion -in $manifest.revoked_versions)) {
            Fail "version $NullwireVersion is REVOKED in the signed manifest.
    This release has been killed post-publish (likely a security issue).
    Check https://nullwire.xyz/security or upgrade to a newer version."
        }

        $schema = if ($manifest.schema_version) { $manifest.schema_version } else { 1 }
        $platEntry = $manifest.platforms.'windows-x86_64'
        if ($platEntry) {
            if ($schema -ge 2) {
                if ($platEntry.cli) { $cliHash = [string]$platEntry.cli.sha256 }
            } else {
                $cliHash = [string]$platEntry.sha256
            }
        }
        if ($cliHash -match '^[0-9a-fA-F]{64}$') {
            Ok "signed manifest verified (schema v$schema) - using sha256 from manifest"
            $usedSignedManifest = $true
        } else {
            Fail "manifest verified but missing a valid sha256 entry for $Platform -
    installer/manifest version mismatch."
        }
    }
}

if (-not $usedSignedManifest) {
    if ($RequireSignedManifest) {
        if (-not $haveMinisign) {
            Fail "NULLWIRE_REQUIRE_SIGNED_MANIFEST=1 set but minisign is not installed.
    Install it and re-run:  winget install jedisct1.minisign"
        }
        Fail "NULLWIRE_REQUIRE_SIGNED_MANIFEST=1 set but the signed manifest is
    unavailable. Check connectivity to $NullwireManifestUrl and re-run."
    }
    Warn 'WARNING: signature verification OFF. Install minisign for full first-install verification. Falling back to TLS+sha256 only.'

    # TLS+sha256 fallback: trust the GitHub-release checksums.sha256.
    $checksumsPath = Join-Path $tmpDir 'checksums.sha256'
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Uri "$BaseUrl/checksums.sha256" -OutFile $checksumsPath
    } catch {
        Fail "could not fetch checksums.sha256 from $BaseUrl - cannot verify the
    download. Install minisign for the signed-manifest path, or check that
    release $NullwireVersion exists."
    }
    foreach ($line in Get-Content -Path $checksumsPath) {
        if ($line -match "^([0-9a-fA-F]{64})\s+\*?$([regex]::Escape($CliAsset))\s*$") {
            $cliHash = $Matches[1]
            break
        }
    }
    if ($cliHash -notmatch '^[0-9a-fA-F]{64}$') {
        Fail "could not find a checksum entry for $CliAsset in checksums.sha256 -
    this installer version may not match release $NullwireVersion."
    }
}

# --- Dry-run exit (verification gates have all run) --------------------
if ($InstallDryRun) {
    Ok "dry-run: verification gates passed (used_signed_manifest=$usedSignedManifest, cli_hash=$cliHash)"
    exit 0
}

# --- Download + verify the CLI binary ----------------------------------
$cliTmp = Join-Path $tmpDir $CliAsset
Info "fetching $CliAsset ..."
try {
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 120 -Uri "$BaseUrl/$CliAsset" -OutFile $cliTmp
} catch {
    Fail "download failed: $BaseUrl/$CliAsset"
}
$actualHash = (Get-FileHash -Algorithm SHA256 -Path $cliTmp).Hash.ToLower()
if ($actualHash -ne $cliHash.ToLower()) {
    Fail "checksum mismatch for $CliAsset
    expected: $($cliHash.ToLower())
    actual:   $actualHash
    This could indicate a corrupted download or a tampered binary.
    Do NOT run this file. Report at https://github.com/yunomiwell/nullwire-releases/issues"
}
Ok "verified $CliAsset"

# --- Directory layout (private to the current user) --------------------
$binDir   = Join-Path $NullwireHome 'bin'
$stateDir = Join-Path $NullwireHome 'state'
$uiDir    = Join-Path $NullwireHome 'ui'
Info "creating state directory at $NullwireHome ..."
foreach ($d in @($NullwireHome, $binDir, $stateDir, $uiDir)) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
# chmod-700 equivalent: strip inherited ACEs, grant only the current
# user.  Crypto material lives under state\ - lock the tree down.
foreach ($d in @($NullwireHome, $stateDir)) {
    & icacls $d /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" /T /Q 2>&1 | Out-Null
}

# --- Stage the pilot rent-payer keypair --------------------------------
# Balance-gated: if the shared payer is drained we delete any stale file
# so the CLI's own ensure_service_fee_wallet generates a per-install
# keypair.  Any RPC failure falls through to staging (fail-open).
$feeKeypairPath = Join-Path $stateDir 'service-fee.json'
$payerBalance = $null
try {
    $body = @{ jsonrpc = '2.0'; id = 1; method = 'getBalance'; params = @($PilotPayerPubkey) } | ConvertTo-Json -Compress
    $resp = Invoke-RestMethod -Method Post -Uri 'https://api.devnet.solana.com' `
        -ContentType 'application/json' -Body $body -TimeoutSec 5
    if ($resp.result -and ($null -ne $resp.result.value)) { $payerBalance = [long]$resp.result.value }
} catch { $payerBalance = $null }

if (($null -ne $payerBalance) -and ($payerBalance -lt $MinPilotPayerLamports)) {
    Warn "pilot rent-payer is low ($payerBalance lamports) - falling back to per-install devnet airdrop."
    if (Test-Path $feeKeypairPath) { Remove-Item -Force $feeKeypairPath }
} elseif (-not (Test-Path $feeKeypairPath)) {
    Info 'staging pilot rent-payer keypair (v5 payer-only, owner stays local)...'
    try {
        [IO.File]::WriteAllBytes($feeKeypairPath, [Convert]::FromBase64String($PilotPayerKeypairB64))
        & icacls $feeKeypairPath /inheritance:r /grant:r "$($env:USERNAME):F" /Q 2>&1 | Out-Null
        if ($null -ne $payerBalance) {
            Ok "pilot rent-payer staged ($PilotPayerPubkey, balance: $payerBalance lamports)"
        } else {
            Warn "pilot rent-payer staged ($PilotPayerPubkey) but balance unverified - devnet RPC unreachable."
            Warn "  if 'setup' fails with 'insufficient funds', retry in 1-2 minutes."
        }
    } catch {
        Warn 'could not decode pilot rent-payer; falling back to per-install airdrop'
        if (Test-Path $feeKeypairPath) { Remove-Item -Force $feeKeypairPath }
    }
}

# --- Install the binary -------------------------------------------------
$cliExe = Join-Path $binDir 'nullwire-cli.exe'
Info "installing nullwire-cli to $binDir ..."
# The daemon may be running from a previous install - stop it so the
# .exe is unlocked before we overwrite it.
try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop } catch { }
Get-Process -Name 'nullwire-cli' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Copy-Item -Path $cliTmp -Destination $cliExe -Force
Ok "installed nullwire-cli $NullwireVersion"

# --- Identity setup (creates identity + post-quantum prekey bundle) ----
if (Test-Path (Join-Path $stateDir 'identity.json')) {
    Ok 'existing identity found - skipping setup'
} else {
    Info 'initializing your identity...'
    $setupArgs = @('setup', '--state-dir', $stateDir, '--ui-dir', $uiDir, '--home', $NullwireHome)
    if ($NullwireHandle) {
        $setupArgs += @('--handle', $NullwireHandle)
        Info "using custom handle from NULLWIRE_HANDLE: @$NullwireHandle"
    }
    & $cliExe @setupArgs
    if ($LASTEXITCODE -ne 0) {
        Fail "identity setup failed (exit $LASTEXITCODE). See output above."
    }
    Ok 'identity created'
}

# --- Register the messenger as a per-user Scheduled Task ---------------
# S4U principal => the task runs as the user, non-interactively (no
# console window ever) and needs no stored password.  cmd /s /c does the
# stdout/stderr redirection that launchd/systemd do on macOS/Linux.
Info "registering the messenger as the '$TaskName' Scheduled Task..."
$serverLog = Join-Path $NullwireHome 'server.log'
$serverErr = Join-Path $NullwireHome 'server.err'
# Persist the broker URL the daemon (running as this user) will inherit.
[Environment]::SetEnvironmentVariable('NULLWIRE_PAIR_BROKER_URL', $BrokerUrl, 'User')

# /s /c " ... "  ->  cmd strips exactly the outermost quote pair and runs
# the rest verbatim, so the inner quoted paths survive intact.
$cmdLine = ('/s /c " "{0}" server --home "{1}" --port {2} --bind 127.0.0.1 >> "{3}" 2>> "{4}" "' `
    -f $cliExe, $NullwireHome, $NullwirePort, $serverLog, $serverErr)

try {
    $action    = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $cmdLine
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
        -LogonType S4U -RunLevel Limited
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force `
        -Description 'NullWire post-quantum messenger server' | Out-Null
} catch {
    Fail "could not register the '$TaskName' Scheduled Task: $($_.Exception.Message)"
}

Info "starting messenger at $UiUrl ..."
Start-ScheduledTask -TaskName $TaskName

# --- Wait for the daemon to answer on its HTTP port --------------------
$up = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri "$UiUrl/api/health" | Out-Null
        $up = $true
        break
    } catch { Start-Sleep -Seconds 1 }
}
if ($up) {
    Ok 'messenger server is up (managed by the NullWire Scheduled Task)'
} else {
    Fail "server did not respond on $UiUrl within 30s - check $serverErr"
}

# --- Kick off the welcome conversation (best-effort) -------------------
Info 'kicking off welcome conversation...'
try {
    Invoke-RestMethod -Method Post -Uri "$UiUrl/api/send" `
        -ContentType 'application/json' `
        -Headers @{ Origin = $UiUrl } `
        -Body (@{ threadId = 'welcome'; text = 'hi' } | ConvertTo-Json -Compress) `
        -TimeoutSec 10 | Out-Null
    Ok 'welcome message sent - check the UI for the reply (~10-30s mesh round-trip)'
} catch {
    Warn 'welcome kick-off failed - you can manually send a hi from the UI'
}

# --- Optional auto-add of inviter handle(s) ----------------------------
# Ported from install.sh add_contact_from_chain: resolve the handle on
# chain via the CLI, create the contact, import the peer bundle.
function Add-ContactFromChain($handle) {
    $handle = $handle.TrimStart('@')
    if (-not $handle) { return }
    if ($handle -notmatch '^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$') {
        Warn "NULLWIRE_ADD value '$handle' is not a valid handle - skipping auto-add"
        return
    }
    Info "looking up @$handle on chain to auto-add as a contact..."
    $bundleFile = Join-Path $tmpDir ("add-" + $handle + ".json")
    & $cliExe lookup-user-handle-solana --handle $handle --out $bundleFile 2>&1 | Out-Null
    if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $bundleFile))) {
        Warn "could not resolve @$handle on chain - skipping auto-add. Add it manually from the UI."
        return
    }
    try {
        $record = Get-Content -Raw -Path $bundleFile | ConvertFrom-Json
        $bundle = if ($record.PSObject.Properties.Name -contains 'bundle' -and $record.bundle) {
            $record.bundle
        } else { $record }
        if (-not ($bundle.PSObject.Properties.Name -contains 'version' -and
                  $bundle.PSObject.Properties.Name -contains 'handle')) {
            Warn "on-chain record for @$handle is not a valid bundle - skipping auto-add."
            return
        }
        $contactObj = @{
            handle           = $handle
            name             = ''
            recipientGateway = 'nullwire-gw-nbg'
            recipientMailbox = ''
            route            = 'nullwire-gw-nbg nullwire-l2-us nullwire-l2-va nullwire-l3-sg nullwire-l1-hel'
        }
        $createResp = Invoke-RestMethod -Method Post -Uri "$UiUrl/api/contacts" `
            -ContentType 'application/json' -Headers @{ Origin = $UiUrl } `
            -Body ($contactObj | ConvertTo-Json -Compress) -TimeoutSec 10
        $contactId = ''
        if ($createResp.contacts) {
            foreach ($c in $createResp.contacts) {
                if (($c.handle -as [string]).TrimStart('@').ToLower() -eq $handle.ToLower()) {
                    $contactId = [string]$c.id
                    break
                }
            }
        }
        if (-not $contactId) {
            Warn "@$handle contact created but could not locate its id for bundle import - open the UI to verify."
            return
        }
        $importBody = @{ bundleJson = ($bundle | ConvertTo-Json -Depth 20 -Compress) } | ConvertTo-Json -Compress
        Invoke-RestMethod -Method Post -Uri "$UiUrl/api/threads/$contactId/import-peer-bundle" `
            -ContentType 'application/json' -Headers @{ Origin = $UiUrl } `
            -Body $importBody -TimeoutSec 10 | Out-Null
        Ok "auto-added @$handle as a contact (post-quantum bundle imported from chain)"
    } catch {
        Warn "@$handle: auto-add failed ($($_.Exception.Message)) - open the UI's Add Contact menu and use Advanced -> paste bundle."
    }
}

if ($NullwireAdd) {
    $handles = $NullwireAdd -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($h in $handles) { Add-ContactFromChain $h }

    # Self-heal: if a contact's peer-bundle file is still missing after
    # the import POST, recover it via /refresh-bundle-from-chain.
    $authToken = ''
    $tokenPath = Join-Path $stateDir 'api-auth-token'
    if (Test-Path $tokenPath) { $authToken = (Get-Content -Raw -Path $tokenPath).Trim() }
    foreach ($h in $handles) {
        $hh = $h.TrimStart('@')
        if (-not $hh) { continue }
        if (Test-Path (Join-Path $stateDir "peer-bundles\$hh.json")) { continue }
        if (-not $authToken) {
            Warn "auto-add @${hh}: no api-auth-token; cannot heal. Open the UI -> contact menu -> Refresh bundle."
            continue
        }
        try {
            Invoke-RestMethod -Method Post -Uri "$UiUrl/api/contacts/$hh/refresh-bundle-from-chain" `
                -Headers @{ Origin = $UiUrl; 'X-Nullwire-Auth-Token' = $authToken } -TimeoutSec 15 | Out-Null
            Ok "auto-add @${hh}: bundle recovered via refresh-from-chain"
        } catch {
            Warn "auto-add @${hh}: refresh-from-chain failed. Open the UI's contact menu -> Refresh bundle."
        }
    }
}

# --- Open the browser ---------------------------------------------------
Info 'opening browser...'
$browserProfile = Join-Path $NullwireHome 'chrome-profile'
$browsers = @(
    $env:NULLWIRE_BROWSER
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe"
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { $_ -and (Test-Path $_) }

if ($browsers.Count -gt 0) {
    New-Item -ItemType Directory -Path $browserProfile -Force | Out-Null
    Start-Process -FilePath $browsers[0] -ArgumentList @(
        "--user-data-dir=$browserProfile"
        "--app=$UiUrl"
        '--window-size=393,852'
        '--no-first-run'
        '--no-default-browser-check'
    )
} else {
    try { Start-Process $UiUrl } catch { Warn "could not auto-open browser - go to $UiUrl manually" }
}

# --- Final summary ------------------------------------------------------
Write-Host ""
Write-Host "  NULLWIRE IS RUNNING" -ForegroundColor Green
Write-Host ""
Write-Host "  UI:        $UiUrl"
Write-Host "  State:     $stateDir"
Write-Host "  Logs:      $serverLog  +  $serverErr"
Write-Host "  Control:   Stop-ScheduledTask  -TaskName $TaskName"
Write-Host "             Start-ScheduledTask -TaskName $TaskName"
Write-Host "  Uninstall: & `"$cliExe`" uninstall"
Write-Host ""
Write-Host "  YOUR BUNDLE (share with contacts)" -ForegroundColor Magenta
Write-Host "  ----------------------------------------"
try { & $cliExe export-prekey-bundle --state-dir $stateDir 2>$null | Select-Object -First 20 } catch { }
Write-Host "  ----------------------------------------"
Write-Host ""
Write-Host "  The server runs as the '$TaskName' Scheduled Task - close this window"
Write-Host "  whenever you want, the messenger keeps running and restarts at logon."
Write-Host ""

} finally {
    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue }
}
