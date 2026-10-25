$ErrorActionPreference='Stop'
function Read-Context([string]$Path){
 $full=[IO.Path]::GetFullPath($Path);$prefix=(Join-Path $env:ProgramData 'BNetIntegratedG12')+'\'
 if(-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -ne 'config.json'){throw 'context_scope_refused'}
 $value=Get-Content -Raw $full | ConvertFrom-Json
 if($value.root -ne (Split-Path $full) -or $value.watchdog_name -notmatch '^BNetLabG12_[0-9a-f]{32}_recovery$' -or $value.service_name -notmatch '^BNetLabG12_[0-9a-f]{32}_svc$' -or $value.task_name -notmatch '^BNetLabG12_[0-9a-f]{32}_task$'){throw 'context_identity_refused'}
 return $value
}
function Save-Private([string]$Path,$Value){
 $text=$Value | ConvertTo-Json -Depth 12 -Compress;$temp=$Path+'.tmp';[IO.File]::WriteAllText($temp,$text,[Text.UTF8Encoding]::new($false))
 if(Test-Path $Path){$prior=$Path+'.prior';if(Test-Path $prior){[IO.File]::Delete($prior)};[IO.File]::Replace($temp,$Path,$prior)}else{[IO.File]::Move($temp,$Path)}
}
function Enter-Lease($Context){
 $mutex=[Threading.Mutex]::new($false,$Context.mutex_name)
 try{try{$held=$mutex.WaitOne(120000)}catch [Threading.AbandonedMutexException]{$held=$true};if(-not $held){throw 'lease_wait_timeout'};return $mutex}catch{$mutex.Dispose();throw}
}
function Invoke-Gate($Context,[string]$Action){
 $ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
 $text=& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $Context.root 'FirewallGate.ps1') -Action $Action -Work $Context.root -ProxyExe $Context.proxy_exe -Config (Join-Path $Context.root 'proxy.json') 2>$null
 if($LASTEXITCODE -ne 0){throw ('gate_'+$Action.ToLowerInvariant()+'_failed')}
 $joined=$text -join "`n";if($joined.Length -gt 16384){throw 'gate_protocol_limit'};return ($joined | ConvertFrom-Json)
}
function Record-Process($Process,[string]$Path){$null=$Process.Handle;Save-Private $Path @{pid=$Process.Id;created=$Process.StartTime.ToFileTimeUtc();image=$Process.MainModule.FileName}}
function Open-Verified($Identity){
 $p=Get-Process -Id $Identity.pid -ErrorAction SilentlyContinue;if(-not $p){return $null}
 $null=$p.Handle;if($p.StartTime.ToFileTimeUtc() -ne [long]$Identity.created){$p.Dispose();return $null}
 if(-not [string]::Equals($p.MainModule.FileName,$Identity.image,[StringComparison]::OrdinalIgnoreCase)){$p.Dispose();throw 'process_identity_changed'};return $p
}
function Wait-File([string]$Path,[int]$Seconds){$w=[Diagnostics.Stopwatch]::StartNew();while(-not (Test-Path $Path) -and $w.Elapsed.TotalSeconds -lt $Seconds){Start-Sleep -Milliseconds 100};if(-not (Test-Path $Path)){throw 'receipt_timeout'}}
function Invoke-Canary($Context,[string]$Mode){
 $text=& $Context.exe $Mode (Join-Path $Context.root 'config.json') $Context.token
 if($LASTEXITCODE -ne 0){throw 'canary_process_failed'};$v=$text | ConvertFrom-Json
 if($null -eq $v.connected -or $null -eq $v.http200){throw 'canary_protocol_failed'};return $v
}
function Hash-Bytes([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($sha.ComputeHash($Bytes))}finally{$sha.Dispose()}}

function Error-Shape($Record){
 $type=$Record.Exception.GetType().Name;$id=[string]$Record.FullyQualifiedErrorId
 if($id -notmatch '^[A-Za-z0-9_,.+-]{1,140}$'){$id='unclassified'}
 $name=[IO.Path]::GetFileName($Record.InvocationInfo.ScriptName)
 if($name -notin @('Common.ps1','Supervisor.ps1','Recover.ps1','Driver.ps1','FirewallGate.ps1')){$name='unavailable'}
 return @{type=$type;id=$id;line=$Record.InvocationInfo.ScriptLineNumber;source=$name}
}
