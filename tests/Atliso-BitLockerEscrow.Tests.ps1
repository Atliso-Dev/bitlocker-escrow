# Pester 5+. BitLocker and the event log are mocked, so these run anywhere, no encrypted drive needed:
#   Invoke-Pester ./tests

BeforeAll {
  $script:Script = Join-Path $PSScriptRoot '..\Atliso-BitLockerEscrow.ps1'

  # Stand-ins so the mocks have something to replace on machines without the BitLocker module.
  if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { function global:Get-BitLockerVolume { param($MountPoint) } }
  if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) { function global:Get-WinEvent { param($FilterHashtable, $ListLog) } }
  if (-not (Get-Command BackupToAAD-BitLockerKeyProtector -ErrorAction SilentlyContinue)) { function global:BackupToAAD-BitLockerKeyProtector { param($MountPoint, $KeyProtectorId) } }

  function script:Volume([string[]]$Types) {
    [pscustomobject]@{ MountPoint = 'C:'; KeyProtector = @($Types | ForEach-Object { [pscustomobject]@{ KeyProtectorType = $_; KeyProtectorId = "{$([guid]::NewGuid())}" } }) }
  }

  function script:Invoke-Escrow([hashtable]$Params = @{}) {
    $p = @{ LogPath = (Join-Path $TestDrive 'escrow.log') } + $Params
    $out = & $script:Script @p | Out-String
    [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $out }
  }
}

Describe 'Atliso-BitLockerEscrow' {

  Context 'Atliso Pro contract' {
    It 'has exactly one [bool]$WhatIf parameter that Pro can flip for the detection and remediation copies' {
      $src = Get-Content $script:Script -Raw
      ([regex]::Matches($src, '(\[bool\]\$WhatIf\s*=\s*)\$(true|false)', 'IgnoreCase')).Count | Should -Be 1
      $src | Should -Match '\[bool\]\$WhatIf\s*=\s*\$true'
    }
  }

  It 'escrow confirmed by event 845 inside the window: exit 0, nothing sent' {
    Mock Get-WinEvent { [pscustomobject]@{ Id = 845 } }
    Mock BackupToAAD-BitLockerKeyProtector { }
    $r = Invoke-Escrow @{ WhatIf = $false }
    $r.Exit | Should -Be 0
    $r.Output | Should -Match 'Escrow already confirmed'
    Should -Invoke BackupToAAD-BitLockerKeyProtector -Times 0
  }

  It 'no event 845 (Get-WinEvent throws on no match): WhatIf reports non-compliant, exit 1, nothing sent' {
    Mock Get-WinEvent { throw 'No events were found that match the specified selection criteria.' }
    Mock BackupToAAD-BitLockerKeyProtector { }
    $r = Invoke-Escrow
    $r.Exit | Should -Be 1
    $r.Output | Should -Match 'No confirmed escrow'
    Should -Invoke BackupToAAD-BitLockerKeyProtector -Times 0
  }

  It 'remediation escrows every RecoveryPassword protector and only those' {
    Mock Get-WinEvent { throw 'No events were found' }
    Mock Get-BitLockerVolume { Volume @('Tpm', 'RecoveryPassword', 'RecoveryPassword') }
    Mock BackupToAAD-BitLockerKeyProtector { }
    $r = Invoke-Escrow @{ WhatIf = $false }
    $r.Exit | Should -Be 0
    Should -Invoke BackupToAAD-BitLockerKeyProtector -Times 2 -Exactly
    $r.Output | Should -Match '2 RecoveryPassword protectors found'
  }

  It 'a failed backup call exits 1 so Intune shows the remediation error' {
    Mock Get-WinEvent { throw 'No events were found' }
    Mock Get-BitLockerVolume { Volume @('Tpm', 'RecoveryPassword') }
    Mock BackupToAAD-BitLockerKeyProtector { throw 'The device is not joined to Azure AD.' }
    $r = Invoke-Escrow @{ WhatIf = $false }
    $r.Exit | Should -Be 1
    $r.Output | Should -Match 'Escrow FAILED'
  }

  It 'no RecoveryPassword protector: warns, sends nothing' {
    Mock Get-WinEvent { throw 'No events were found' }
    Mock Get-BitLockerVolume { Volume @('Tpm') }
    Mock BackupToAAD-BitLockerKeyProtector { }
    $r = Invoke-Escrow @{ WhatIf = $false }
    $r.Output | Should -Match 'No RecoveryPassword protector on C:'
    Should -Invoke BackupToAAD-BitLockerKeyProtector -Times 0
  }

  It 'an unreadable volume is skipped, the others still run' {
    Mock Get-WinEvent { throw 'No events were found' }
    Mock Get-BitLockerVolume { throw 'not a BitLocker volume' } -ParameterFilter { $MountPoint -eq 'D:' }
    Mock Get-BitLockerVolume { Volume @('RecoveryPassword') } -ParameterFilter { $MountPoint -eq 'C:' }
    Mock BackupToAAD-BitLockerKeyProtector { }
    $r = Invoke-Escrow @{ WhatIf = $false; VolumesToCheck = @('D:', 'C:') }
    $r.Output | Should -Match 'Could not read BitLocker volume D:'
    Should -Invoke BackupToAAD-BitLockerKeyProtector -Times 1 -Exactly
  }

  It 'looks for event 845 in the BitLocker-API Management channel inside MaxAgeDays' {
    Mock Get-WinEvent { [pscustomobject]@{ Id = 845 } }
    Invoke-Escrow @{ MaxAgeDays = 3 } | Out-Null
    Should -Invoke Get-WinEvent -ParameterFilter {
      $FilterHashtable.LogName -eq 'Microsoft-Windows-BitLocker-API/Management' -and $FilterHashtable.Id -eq 845 -and
      $FilterHashtable.StartTime -gt (Get-Date).AddDays(-3).AddMinutes(-5) -and $FilterHashtable.StartTime -lt (Get-Date).AddDays(-3).AddMinutes(5)
    }
  }
}
