$ErrorActionPreference='Stop';$stage='observe_setup'
try {
 $j=Get-Content -LiteralPath $env:WOW_BL_REQUEST -Raw -Encoding UTF8|ConvertFrom-Json
 if($j.seconds -notin @(60,120,300) -or [IO.Path]::GetFileName($j.program) -ine 'Wow.exe' -or !(Test-Path -LiteralPath $j.program -PathType Leaf)){throw 'invalid_observe_plan'}
 if((Get-FileHash -LiteralPath $j.program -Algorithm SHA256).Hash -ine $j.program_sha256){throw 'program_changed'}
 [void](Get-Command Get-NetTCPConnection -ErrorAction Stop)
 $flows=@{};$errors=0;$start=[DateTime]::UtcNow;$clock=[Diagnostics.Stopwatch]::StartNew()
 [IO.File]::WriteAllText($j.ready_path,'ready');$stage='observe_sample'
 while($clock.Elapsed.TotalSeconds -lt [int]$j.seconds){
  if(Test-Path -LiteralPath $j.stop_path){break}
  if(!(Get-Process -Id $j.parent_pid -ErrorAction SilentlyContinue)){break}
  $owned=@{}
  foreach($proc in @(Get-Process -Name Wow -ErrorAction SilentlyContinue)){
   try{if($proc.Path -ieq $j.program){$owned[[int]$proc.Id]=$proc.StartTime.ToUniversalTime().Ticks}}catch{$errors++}
  }
  if($owned.Count -gt 0){
   try{
    foreach($c in @(Get-NetTCPConnection -ErrorAction Stop)){
     if(!$owned.ContainsKey([int]$c.OwningProcess)){continue}
     try{$live=Get-Process -Id $c.OwningProcess -ErrorAction Stop;if($live.Path -ine $j.program -or $live.StartTime.ToUniversalTime().Ticks -ne $owned[[int]$c.OwningProcess]){continue}}catch{continue}
     $ip=[string]$c.RemoteAddress;$port=[int]$c.RemotePort
     if($port -le 0 -or $ip -in @('0.0.0.0','::','::1','127.0.0.1')){continue}
     $key=$ip+'/'+[string]$port
     if(!$flows.ContainsKey($key) -and $flows.Count -lt 2000){$flows[$key]=[ordered]@{ip=$ip;port=$port;samples=0;fresh_process_seen=$false}}
     if($flows.ContainsKey($key)){$flows[$key].samples++;if($live.StartTime.ToUniversalTime() -ge $start){$flows[$key].fresh_process_seen=$true}}
    }
   }catch{$errors++}
  }
  Start-Sleep -Milliseconds 1000
 }
 @{ok=$true;seconds=[math]::Round($clock.Elapsed.TotalSeconds,1);query_errors=$errors;endpoints=@($flows.Values)}|ConvertTo-Json -Depth 6 -Compress
}catch{@{ok=$false;stage=$stage}|ConvertTo-Json -Compress;exit 3}
