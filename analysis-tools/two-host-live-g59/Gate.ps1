param([ValidateSet('Prepare','Apply','Verify','Restore')][string]$Action,[string]$Root)
$ErrorActionPreference='Stop'
if($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:BNET_G59 -ne 'approved-live-startup-two-hosts-g59'){throw 'fresh_hosted_required'}
$expected=Join-Path $env:RUNNER_TEMP 'g59-private'
if([IO.Path]::GetFullPath($Root) -ne [IO.Path]::GetFullPath($expected)){throw 'root_rejected'}
$group='BNetLiveG59';$backup=Join-Path $Root 'before.PRIVATE.wfw';$cfg=Join-Path $Root 'config.json';$armed=Join-Path $Root 'armed'
function Targets { @(Get-Process -Name 'Agent','Battle.net','Battle.net Launcher','Battle.net-Setup' -ErrorAction SilentlyContinue) }
function Verify {
 $p=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
 if($p.Count -ne 3 -or @($p|Where-Object{$_.Enabled -ne 'True' -or $_.DefaultOutboundAction -ne 'Block' -or $_.DefaultInboundAction -ne 'Block' -or @($_.DisabledInterfaceAliases|Where-Object{$_ -and $_ -ne 'NotConfigured'}).Count}).Count){throw 'profiles_unverified'}
 $c=Get-Content -LiteralPath $cfg -Raw|ConvertFrom-Json
 $a=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow)
 if($a.Count -ne (@($c.management).Count+1)){throw 'unexpected_allow_count'}
 foreach($r in $a){
  if($r.Group -ne $group -or $r.Direction -ne 'Outbound'){throw 'foreign_allow'}
  $program=[string](($r|Get-NetFirewallApplicationFilter).Program)
  if($r.DisplayName -eq 'G59 two destination IPs'){
   if($program -ne 'Any'){throw 'destination_program_mismatch'}
   $actual=@(($r|Get-NetFirewallAddressFilter).RemoteAddress|Sort-Object)
   if(($actual -join ',') -ne ((@($c.ips)|Sort-Object)-join ',')){throw 'destination_ips_mismatch'}
  }elseif($program -notin @($c.management)){throw 'management_mismatch'}
  if(($r|Get-NetFirewallSecurityFilter).OverrideBlockRules -eq $true){throw 'authenticated_bypass'}
 }
}
if($Action -eq 'Prepare'){
 if((Targets).Count){throw 'preexisting_target_process'}
 if((Get-Service mpssvc).Status -ne 'Running'){throw 'firewall_not_running'}
 $management=@(Get-Process -Name 'Runner.Listener','Runner.Worker'|ForEach-Object{$_.Path}|Sort-Object -Unique)
 if($management.Count -lt 1 -or $management.Count -gt 4 -or @($management|Where-Object{$_ -notmatch '(?i)\\bin\\Runner\.(Listener|Worker)\.exe$'}).Count){throw 'CI_identity_rejected'}
 $ips=@()
 foreach($h in @('level3.blizzard.com','us.version.battle.net')){
  $answers=@([Net.Dns]::GetHostAddresses($h)|ForEach-Object{$_.ToString()})
  if(-not $answers.Count){throw 'target_resolution_empty'}
  $ips+=$answers
 }
 $ips=@($ips|Sort-Object -Unique);if($ips.Count -gt 64){throw 'target_IP_limit'}
 # Pin and verify the official bootstrap before any execution.
 Add-Type -AssemblyName System.Net.Http
 $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseProxy=$false;$handler.UseCookies=$false
 $client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds(40);$client.MaxResponseContentBufferSize=8MB
 try{
  $response=$client.GetAsync('https://downloader.battle.net/download/installer/win/1.0.68/Battle.net-Setup.exe').GetAwaiter().GetResult()
  if([int]$response.StatusCode -ne 200){throw 'bootstrap_download_failed'}
  $bytes=$response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();if($bytes.Length -ne 4700880){throw 'bootstrap_size_mismatch'}
  $setup=Join-Path $Root 'Battle.net-Setup.exe';[IO.File]::WriteAllBytes($setup,$bytes)
  if((Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'){throw 'bootstrap_hash_mismatch'}
  $sig=Get-AuthenticodeSignature -LiteralPath $setup
  if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Blizzard Entertainment'){throw 'bootstrap_signature_rejected'}
 }finally{$client.Dispose();$handler.Dispose()}
 @{ips=$ips;management=$management;bootstrap_sha256='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6';signature_valid=$true}|ConvertTo-Json|Set-Content -LiteralPath $cfg -Encoding UTF8
 $null=& "$env:SystemRoot\System32\netsh.exe" advfirewall export $backup
 if($LASTEXITCODE -ne 0 -or -not(Test-Path $backup)){throw 'backup_failed'}
}elseif($Action -eq 'Apply'){
 $c=Get-Content -LiteralPath $cfg -Raw|ConvertFrom-Json
 if(-not(Test-Path $backup)){throw 'backup_missing'}
 Set-Content -LiteralPath $armed -Value 'armed_before_mutation'
 Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Action Allow|Disable-NetFirewallRule
 foreach($program in @($c.management)){$null=New-NetFirewallRule -DisplayName ('G59 management '+[IO.Path]::GetFileName($program)) -Group $group -Direction Outbound -Action Allow -Program $program -Profile Any}
 $null=New-NetFirewallRule -DisplayName 'G59 two destination IPs' -Group $group -Direction Outbound -Action Allow -Program Any -RemoteAddress @($c.ips) -Profile Any
 Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block -DefaultInboundAction Block -AllowLocalFirewallRules True -DisabledInterfaceAliases @()
 Verify
}elseif($Action -eq 'Verify'){Verify}
else{
 if(Test-Path $armed){
  $extra=Join-Path $Root 'late-processes.PRIVATE.json'
  if(Test-Path $extra){
   foreach($e in @(Get-Content -LiteralPath $extra -Raw|ConvertFrom-Json)){
    $p=Get-Process -Id ([int]$e.pid) -ErrorAction SilentlyContinue
    if($p){
     if($p.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [long]$e.birth -or $p.Path -ne $e.image_path){throw 'late_process_identity_changed_no_restore'}
     Stop-Process -Id $p.Id -Force
    }
   }
  }
  # Never release the network policy while known target processes/services remain.
  $services=@(Get-CimInstance Win32_Service|Where-Object{$_.PathName -match '(?i)Battle\.net|Blizzard'})
  foreach($s in $services){if($s.State -ne 'Stopped'){Stop-Service -Name $s.Name -Force -ErrorAction Stop}}
  foreach($p in (Targets)){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
  Start-Sleep -Seconds 2
  if((Targets).Count){throw 'target_still_active_no_restore'}
  if(@(Get-CimInstance Win32_Service|Where-Object{$_.PathName -match '(?i)Battle\.net|Blizzard' -and $_.State -ne 'Stopped'}).Count){throw 'target_service_active_no_restore'}
  $null=& "$env:SystemRoot\System32\netsh.exe" advfirewall import $backup
  if($LASTEXITCODE -ne 0){throw 'restore_failed'}
  Remove-Item -LiteralPath $armed
 }
}
