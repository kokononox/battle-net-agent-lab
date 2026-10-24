param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'matrix.ps1')
. (Join-Path $PSScriptRoot 'https-tools.ps1')
$root=Split-Path $PSScriptRoot -Parent
$base=(SafePath (Join-Path $root 'private-state/control126-jobs'))+[IO.Path]::DirectorySeparatorChar
$req=SafePath $Request;$out=SafePath $Output;$job=[IO.Path]::GetDirectoryName($req)
if(-not $req.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or -not $out.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or $job -cne [IO.Path]::GetDirectoryName($out) -or (Get-Item -LiteralPath $req).Length -gt 8192){throw 'control_request_scope_or_size'}
$q=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($req))
if($q.schema -cne 'unifiedfw-control126-request-1' -or $q.programs -isnot [array] -or $q.programs.Count -ne 2){throw 'control_request_schema'}
$endpoint=HValidateEndpoint $q.https_url $q.address
for($i=0;$i -lt 2;$i++){
 $p=$q.programs[$i];$expected=SafePath (Join-Path $root @('runtime/python.exe','runtime/pythonw.exe')[$i])
 if($p.role -cne @('A','B')[$i] -or -not [string]::Equals($p.path,$expected,[StringComparison]::OrdinalIgnoreCase) -or $p.sha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash.ToLowerInvariant() -cne $p.sha256){throw 'control_runtime_binding'}
}
$matrixQ=[pscustomobject]@{schema='unifiedfw-coexistence-request-1';transport='https_php';https_url=$q.https_url;address=$q.address;port=443;programs=$q.programs}
$elevated=$null
try{$identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{$principal=New-Object Security.Principal.WindowsPrincipal($identity);$elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}}catch{$elevated=$null}
$script:report=[ordered]@{controller_is_elevated=$elevated;elevation_requested=$false;schema='unifiedfw-control126-result-1';started_utc=[datetime]::UtcNow.ToString('o');completed=$false;rows=@();errors=@();planned_attempts=126;firewall_mutation_attempted=$false;vpn_or_route_changes_attempted=$false;protection_verified=$false;controller_pid=$PID;reference_process='single_long_lived_Windows_PowerShell_controller';reference_version=[string]$PSVersionTable.PSVersion;minimum_gap_ms=4000;tcp_timeout_seconds=3;child_deadline_seconds=12;automatic_retries=0;all_attempts_expected_allowed=$true;actual_apply_or_restore_performed=$false;live_policy_or_route_queried=$false;endpoint=$endpoint;programs=$q.programs}
function SaveControlRow($Row){
 Add-Member -InputObject $Row -NotePropertyName phase -NotePropertyValue $script:phase
 Add-Member -InputObject $Row -NotePropertyName control_segment -NotePropertyValue $script:segment
 Add-Member -InputObject $Row -NotePropertyName controller_pid -NotePropertyValue $PID
 $script:report.rows+=,$Row
 TSave $out $script:report
 $status='FAIL';if($Row.probe_valid -eq $true -and $Row.connected -eq $true -and $Row.tls_verified -eq $true -and $Row.handshake_ok -eq $true -and $Row.http_status -eq 200){$status='OK'}
 Write-Host ($script:report.rows.Count.ToString()+'/126 '+$script:phase+' '+$script:segment+' '+$Row.role+' '+$status+' '+$Row.error)
}
try{
 TSave $out $script:report
 foreach($script:phase in @('baseline','wl_allows','wl_denies','wl_allows_bl_A','wl_allows_bl_B','wl_allows_bl_both','wl_denies_bl_A')){
  foreach($script:segment in @('during_control','after_restore_control')){
   $null=TMatrix $matrixQ $job $root
  }
 }
 $script:report.completed=$true
}catch{$script:report.errors+=,$_.Exception.Message}
finally{$script:report.ended_utc=[datetime]::UtcNow.ToString('o');TSave $out $script:report}
if(-not $script:report.completed){exit 1}
