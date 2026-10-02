#
# Purpose:
#   (id_whitelist_add/remove, whitelist_add/remove; implicit self.save())
#   which overwrote the REAL client config (%APPDATA%\kirin_desk\default.toml)
#   on every gate wave (physical evidence: device-temp+24h residue, encrypted
#   empty token, 32 id-derivation write-back lines over two days). This script
#   wraps any command that may touch config as a last-line canary: it takes the
#   sha256 of the real client config (when present) BEFORE and AFTER the command
#   and exits 1 on any mismatch. Root fixes are the KIRIN_DATA_DIR sandbox
#   (self-test entry), Config::save_override (unit tests) and the save_to
#   destructive-write backup (F3) — the sentinel proves in the gate log that
#   the real file is untouched.
#
# Usage (Git Bash — preferred in this repo):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/config_pollution_sentinel.ps1 -Command "cargo test -p kirin-desk-utils --jobs 4"
#
# Usage (PowerShell prompt):
#   .\scripts\config_pollution_sentinel.ps1 -Command "cargo build --release --jobs 4"
#
# Behavior:
#   1. before: sha256 of %APPDATA%\kirin_desk\default.toml ("ABSENT" if missing);
#   2. run the command via cmd /c (its exit code is captured);
#   3. after:  sha256 again;
#      - equal (or both ABSENT)  -> exit with the command's own exit code;
#      - mismatch                -> report before/after hashes and exit 1
#                                   (pollution verdict takes precedence over
#                                    the command's exit code, even if the
#                                    command itself exited 0).
#
# Optional -ConfigPath overrides the protected file (default: the real client
# config %APPDATA%\kirin_desk\default.toml).
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Command line to execute")]
    [string]$Command,
    [string]$ConfigPath
)

$ErrorActionPreference = "Stop"

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $env:APPDATA "kirin_desk\default.toml"
}

function Get-ConfigSha256 {
    if (Test-Path -LiteralPath $ConfigPath) {
        (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
    } else {
        "ABSENT"
    }
}

Write-Host "[sentinel] protected config : $ConfigPath"
$before = Get-ConfigSha256
Write-Host "[sentinel] sha256 before    : $before"
Write-Host "[sentinel] running command  : $Command"

# cmd /c keeps the whole command line intact (quotes included) and surfaces
# the child's exit code in $LASTEXITCODE.
& cmd /c $Command
$exitCode = $LASTEXITCODE
Write-Host "[sentinel] command exit     : $exitCode"

$after = Get-ConfigSha256
Write-Host "[sentinel] sha256 after     : $after"

if ($before -ne $after) {
    Write-Error "[sentinel] CONFIG POLLUTION DETECTED: real client config changed by the command."
    Write-Error "[sentinel]   before: $before"
    Write-Error "[sentinel]   after : $after"
    Write-Error "[sentinel]   path  : $ConfigPath"
    exit 1
}

Write-Host "[sentinel] OK: real client config unchanged."
exit $exitCode
