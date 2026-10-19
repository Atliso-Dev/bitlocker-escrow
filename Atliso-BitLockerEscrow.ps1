<#PSScriptInfo
.VERSION 1.0.1
.GUID 42717945-3a08-4fb2-8608-57b20814ca86
.AUTHOR Atliso
.COMPANYNAME Atliso
.COPYRIGHT (c) 2026 Atliso. MIT License.
.TAGS Intune BitLocker EntraID Escrow RecoveryKey Remediation
.LICENSEURI https://github.com/Atliso-Dev/bitlocker-escrow/blob/main/LICENSE
.PROJECTURI https://atliso.com/blog/bitlocker-recovery-key-escrow-fix
.REQUIREDMODULES 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES Gallery metadata added. Script logic unchanged from v1.0.0.
#>

<#
.SYNOPSIS
    Atliso-BitLockerEscrow.ps1 - Audit and force BitLocker recovery-key escrow to Entra ID.

.DESCRIPTION
    BitLocker can report as encrypted while its recovery password never made it to
    Entra ID (Azure AD), leaving the device unrecoverable. This script confirms whether
    a successful escrow was logged recently, and if not, forces the backup for every
    RecoveryPassword protector on the target volumes.

    Detection signal: event ID 845 in the
    Microsoft-Windows-BitLocker-API/Management channel is written when a key is
    successfully backed up to Entra ID. If one exists inside -MaxAgeDays, the volume
    is treated as escrowed and nothing is re-sent.

    Runs audit-only by default (-WhatIf $true). Set -WhatIf $false to actually call
    BackupToAAD-BitLockerKeyProtector.

    Intune usage: deploy as a Remediation. Use the detection half (exit 1 when nothing
    is confirmed) as the detection script, and this script with -WhatIf $false as the
    remediation script. Run as SYSTEM, 64-bit.

.NOTES
    MIT licensed. Free to use and modify.
    Reconstructed from the published Atliso article spec - lab-test before fleet rollout.
    Tested target: Windows 10/11, BitLocker enabled, PowerShell 5.1+.
#>

[CmdletBinding()]
param(
    # Drive letters to check. The OS volume by default; add data volumes if you encrypt them.
    [string[]]$VolumesToCheck = @("C:"),

    # A confirmed backup event inside this window counts as "escrowed", so an
    # already-escrowed key is not re-sent on every run.
    [int]$MaxAgeDays = 7,

    # $true reports only. $false actually calls BackupToAAD-BitLockerKeyProtector.
    [bool]$WhatIf = $true,

    # Timestamped run log.
    [string]$LogPath = (Join-Path $env:LOCALAPPDATA "Atliso\BitLockerEscrow.log")
)

# ── Logging ───────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    try {
        $dir = Split-Path -Parent $LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -ErrorAction Stop
    } catch { }
    Write-Output $line
}

# ── Preconditions ───────────────────────────────────────────────────────────────
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    Write-Log "BitLocker cmdlets not available on this device. Nothing to do." "WARN"
    exit 0
}

Write-Log "Run start. Volumes=$($VolumesToCheck -join ',') MaxAgeDays=$MaxAgeDays WhatIf=$WhatIf"

# ── Detection: was a successful escrow logged inside the window? ─────────────────
# Get-WinEvent throws instead of returning empty when the channel has no matching
# events, so wrap it. Any error means nothing was confirmed.
$cutoff = (Get-Date).AddDays(-$MaxAgeDays)
try {
    $confirmed = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-BitLocker-API/Management'
        Id        = 845
        StartTime = $cutoff
    } -ErrorAction Stop
} catch {
    $confirmed = $null
}

if ($confirmed) {
    Write-Log "Escrow already confirmed by event 845 within $MaxAgeDays day(s). Nothing to do."
    exit 0   # compliant - a successful escrow logged inside the window
}

Write-Log "No confirmed escrow (event 845) in the last $MaxAgeDays day(s)." "WARN"

# In audit-only mode we stop here and report non-compliant, which is exactly the
# shape an Intune detection script wants.
if ($WhatIf) {
    Write-Log "WhatIf is on - reporting only, no escrow attempted. Re-run with -WhatIf `$false to force it."
    exit 1
}

# ── Remediation: force the backup for every RecoveryPassword protector ───────────
$attempted = 0
$failures  = 0

foreach ($mount in $VolumesToCheck) {
    try {
        $vol = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop
    } catch {
        Write-Log "Could not read BitLocker volume $mount : $($_.Exception.Message)" "WARN"
        continue
    }

    $recoveryKeys = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }

    if (-not $recoveryKeys) {
        Write-Log "No RecoveryPassword protector on $mount - add one before this can escrow anything." "WARN"
        continue
    }

    if ($recoveryKeys.Count -gt 1) {
        Write-Log "$($recoveryKeys.Count) RecoveryPassword protectors found on $mount. Escrowing all. Consider removing stale ones with Remove-BitLockerKeyProtector once you confirm which is current." "WARN"
    }

    foreach ($kp in $recoveryKeys) {
        try {
            BackupToAAD-BitLockerKeyProtector -MountPoint $mount -KeyProtectorId $kp.KeyProtectorId -ErrorAction Stop
            $attempted++
            Write-Log "Escrow attempted: $mount protector $($kp.KeyProtectorId)"
        } catch {
            $failures++
            Write-Log "Escrow FAILED: $mount protector $($kp.KeyProtectorId) : $($_.Exception.Message)" "ERROR"
        }
    }
}

Write-Log "Run end. Escrow attempts=$attempted failures=$failures"

# Non-zero exit if any backup call failed, so Intune surfaces the remediation error.
if ($failures -gt 0) { exit 1 }
exit 0
