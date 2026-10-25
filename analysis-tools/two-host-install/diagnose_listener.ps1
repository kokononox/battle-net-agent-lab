$ErrorActionPreference='Stop'
$approval='lab: approved two-host listener diagnosis G4 20261025'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:BNET_TWO_HOSTS -ne $approval -or $env:GITHUB_RUN_ATTEMPT -ne '1') { throw 'fresh_hosted_approval_required' }
$r=[ordered]@{schema='bnet-two-hosts-listener-g4-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;installer_launched=$false;policy_changed=$false;services_changed=$false;listeners=@();service_states=@();excluded_ranges=@();probe_errors=@()}
try {
 foreach($c in @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -in @(80,443)})) {
  $kind='other'; $p=Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
  if($c.OwningProcess -eq 4){$kind='system_http_sys_candidate'}elseif($p.ProcessName -in @('w3wp','iisexpress','httpd','nginx','svchost')){$kind=$p.ProcessName}
  $r.listeners+=@{port=$c.LocalPort;address_family= $(if($c.LocalAddress.Contains(':')){'ipv6'}else{'ipv4'});loopback=($c.LocalAddress -in @('127.0.0.1','::1'));owner_kind=$kind}
 }
}catch{$r.probe_errors+='listener_query_failed'}
foreach($n in @('W3SVC','WAS','WinRM','HTTP','MsDepSvc','WMSVC')){
 $s=Get-Service -Name $n -ErrorAction SilentlyContinue
 $r.service_states+=@{name=$n;state=$(if($s){[string]$s.Status}else{'absent'})}
}
foreach($family in @('ipv4','ipv6')){
 try{
  $lines=& "$env:SystemRoot\System32\netsh.exe" interface $family show excludedportrange protocol=tcp 2>$null
  if($LASTEXITCODE -ne 0){throw 'netsh_failed'}
  foreach($line in $lines){if($line -match '^\s*(\d+)\s+(\d+)(?:\s+\*)?\s*$'){
   $a=[int]$Matches[1];$b=[int]$Matches[2]
   foreach($port in @(80,443)){if($a -le $port -and $port -le $b){$r.excluded_ranges+=@{family=$family;port=$port;start=$a;end=$b}}}
  }}
 }catch{$r.probe_errors+='excluded_range_query_failed_'+$family}
}
New-Item -ItemType Directory -Path output -Force | Out-Null
$r | ConvertTo-Json -Depth 6 | Set-Content output/two-hosts-listener-g4.json -Encoding utf8
Write-Output 'Read-only listener diagnosis complete. No installer or network policy changes.'
