# Pure identity-based discovery. A baseline excludes older process instances; it never suspends or blocks them.
function Test-NewProcessBirth([string]$Ticks,[long]$Cutoff){
 $value=0L;return ([long]::TryParse($Ticks,[ref]$value) -and $Cutoff -gt 0 -and $value -gt $Cutoff)
}
function Register-NewProcess([long]$ProcessId,[string]$Ticks,[string]$Path,[string]$Utc,[string]$Source){
 if($ProcessId -le 0 -or $ProcessId -gt 4294967295 -or -not (Test-NewProcessBirth $Ticks $script:baselineCutoff)){return $null}
 if(-not $Path -or $Path.Length -gt 32767 -or $Path -notmatch '^[a-zA-Z]:\\' -or [IO.Path]::GetExtension($Path) -ine '.exe'){return $null}
 $at=[DateTime]::Parse($Utc).ToUniversalTime();if([long]$Ticks -gt $at.Ticks){return $null}
 $key=$ProcessId.ToString()+'|'+$Ticks
 if($script:newProcesses.ContainsKey($key)){
  $row=$script:newProcesses[$key];if($row.program_path -ine $Path){$script:baselineTruncated=$true;return $null}
  if($at -lt [DateTime]::Parse($row.first_seen_utc).ToUniversalTime()){$row.first_seen_utc=$Utc}
  return $row
 }
 if($script:newProcesses.Count -ge 2000){$script:baselineTruncated=$true;return $null}
 $pathKey=$Path.ToLowerInvariant()
 if(-not $script:autoPrograms.ContainsKey($pathKey)){
  if($script:autoPrograms.Count -ge 512){$script:baselineTruncated=$true;return $null}
  $script:autoPrograms[$pathKey]=[pscustomobject]@{id=[guid]::NewGuid().ToString('N').Substring(0,24);path=$Path;registered_for_firewall=$false;hash_verified=$false}
 }
 $p=$script:autoPrograms[$pathKey]
 $row=[ordered]@{record_id=[guid]::NewGuid().ToString('N');program_id=[string]$p.id;program_path=[string]$p.path;pid=$ProcessId;process_start_ticks=$Ticks;first_seen_utc=$Utc;last_seen_utc=$Utc;presence='unknown';source=$Source;registered_for_firewall=$false;hash_verified=$false}
 $script:newProcesses[$key]=$row;return $row
}
function Add-NewProcessSnapshot($Rows,[string]$Utc,[bool]$Succeeded){
 $seen=@{};$accepted=@()
 if($Succeeded){foreach($p in $Rows){$r=Register-NewProcess ([long]$p.pid) ([string]$p.ticks) ([string]$p.path) $Utc 'process_sample';if($null -ne $r){$key=[string]$p.pid+'|'+[string]$p.ticks;$seen[$key]=$true;$r.last_seen_utc=$Utc;$accepted+=,$p}}}
 foreach($key in @($script:newProcesses.Keys)){$r=$script:newProcesses[$key];$r.presence=if(-not $Succeeded){'unknown'}elseif($seen.ContainsKey($key)){'present'}else{'not_in_latest_snapshot'}}
 return ,$accepted
}
