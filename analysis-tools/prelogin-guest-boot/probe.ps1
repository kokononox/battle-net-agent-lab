$ErrorActionPreference = 'Stop'
$root = 'C:\LabOwnedGuest'
New-Item -ItemType Directory -Path $root -Force | Out-Null
# Copy only this project's synthetic control, never Battle.net data.
if ($PSScriptRoot -ne $root) {
 Copy-Item (Join-Path $PSScriptRoot 'probe.ps1') (Join-Path $root 'probe.ps1') -Force
 Copy-Item (Join-Path $PSScriptRoot 'config.json') (Join-Path $root 'config.json') -Force
}
$config = Get-Content (Join-Path $root 'config.json') -Raw | ConvertFrom-Json
function Emit($payload) {
 $port = [System.IO.Ports.SerialPort]::new('COM1',115200,[System.IO.Ports.Parity]::None,8,[System.IO.Ports.StopBits]::One)
 $port.Open()
 try { 1..3 | ForEach-Object { $port.WriteLine('LABGUEST:' + ($payload | ConvertTo-Json -Compress)); Start-Sleep -Seconds 1 } }
 finally { $port.Close() }
}
$statePath = Join-Path $root 'state.dpapi'
$reg = 'HKCU:\Software\BattleNetAgentLab\OwnedGuestControl'
$phase = 'first'
try {
 Add-Type -AssemblyName System.Security
 $os = Get-CimInstance Win32_OperatingSystem
 $boot = $os.LastBootUpTime.ToUniversalTime()
 $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $full = (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT')) -and ([int]$os.BuildNumber -eq 26100) -and ([int]$os.ProductType -eq 3)
 if (-not $full) { throw 'not_full_windows' }
 if (-not (Test-Path $statePath)) {
  $marker = [guid]::NewGuid().ToString('D')
  New-Item $reg -Force | Out-Null
  New-ItemProperty $reg -Name 'Marker' -Value $marker -PropertyType String -Force | Out-Null
  $state = @{marker=$marker; boot=$boot.ToString('o'); captured=[DateTime]::UtcNow.ToString('o'); sid=$sid; profile=$env:USERPROFILE}
  $bytes = [Text.Encoding]::UTF8.GetBytes(($state | ConvertTo-Json -Compress))
  $enc = [Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
  [IO.File]::WriteAllBytes($statePath,$enc)
  # User-specific RunOnce executes in the same profile after an actual guest reboot.
  New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'LabOwnedReboot' -PropertyType String -Value 'powershell.exe -NoProfile -File C:\LabOwnedGuest\probe.ps1' -Force | Out-Null
  Emit @{schema='owned-guest-signal-1';challenge=$config.challenge;phase='first';full_windows=$full;baseline_saved=$true;boot_changed=$false;same_profile=$false;dpapi_ok=$false;marker_equal=$false;error=$false}
  Start-Sleep -Seconds 3
  Restart-Computer -Force
 } else {
  $phase = 'second'
  $enc = [IO.File]::ReadAllBytes($statePath)
  $bytes = [Security.Cryptography.ProtectedData]::Unprotect($enc,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
  $s = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
  $changed = ($boot -gt [DateTime]::Parse($s.boot).ToUniversalTime()) -and ($boot -gt [DateTime]::Parse($s.captured).ToUniversalTime())
  $same = ($sid -ceq $s.sid) -and ($env:USERPROFILE -ceq $s.profile)
  $value = (Get-ItemProperty $reg -Name Marker).Marker
  Emit @{schema='owned-guest-signal-1';challenge=$config.challenge;phase='second';full_windows=$full;baseline_saved=$true;boot_changed=$changed;same_profile=$same;dpapi_ok=$true;marker_equal=($value -ceq $s.marker);error=$false}
  shutdown.exe /s /t 15 | Out-Null
 }
} catch {
 # Do not emit exception text, registry values, SID, profile, or dumps.
 Emit @{schema='owned-guest-signal-1';challenge=$config.challenge;phase=$phase;full_windows=$false;baseline_saved=$false;boot_changed=$false;same_profile=$false;dpapi_ok=$false;marker_equal=$false;error=$true}
 shutdown.exe /s /t 15 | Out-Null
}
