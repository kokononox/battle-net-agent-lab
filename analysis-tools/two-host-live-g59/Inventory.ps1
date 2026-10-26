param([string]$Root,[string]$Known)
$ErrorActionPreference='Stop'
if($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:BNET_G59 -ne 'approved-live-startup-two-hosts-g59'){throw 'fresh_hosted_required'}
if([IO.Path]::GetFullPath($Root) -ne [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP 'g59-private'))){throw 'root_rejected'}
$ids=@($Known.Split(',')|Where-Object{$_ -match '^\d+$'}|ForEach-Object{[int]$_})
$all=@(Get-CimInstance Win32_Process|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath)
$rows=@()
foreach($p in $all){
 $path=[string]$p.ExecutablePath
 if($p.ProcessId -in $ids -or $p.ParentProcessId -in $ids -or $p.Name -in @('Agent.exe','Battle.net.exe','Battle.net Launcher.exe','Battle.net-Setup.exe') -or $path -match '(?i)\\(Battle\.net|Blizzard Entertainment)\\'){
  $verified=$false;$status='not_checked';$hash=$null
  if($path -and (Test-Path -LiteralPath $path)){
   $f=Get-Item -LiteralPath $path
   if($f.Length -lt 128MB){
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $s=Get-AuthenticodeSignature -LiteralPath $path;$status=[string]$s.Status
    $verified=$s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Blizzard Entertainment'
   }
  }
  $rows+=@{pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId;image_path=$path;name=[string]$p.Name;sha256=$hash;signature_status=$status;blizzard_verified=[bool]$verified;already_observed=($p.ProcessId -in $ids)}
 }
}
$c=Get-Content -LiteralPath (Join-Path $Root 'config.json') -Raw|ConvertFrom-Json
$connections=@(Get-NetTCPConnection -ErrorAction SilentlyContinue|Where-Object{$_.RemoteAddress -in @($c.ips)}|Select-Object OwningProcess,State,RemotePort)
# Full executable paths stay private and are stripped before publication.
@{processes=@($rows|Select-Object -First 32);target_IP_TCP=@($connections|Select-Object -First 128);candidate_limit_hit=($rows.Count -gt 32)}|ConvertTo-Json -Depth 8 -Compress|Set-Content -LiteralPath (Join-Path $Root 'inventory.PRIVATE.json') -Encoding UTF8
