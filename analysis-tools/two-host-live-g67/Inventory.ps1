param([string]$Root,[string]$Known)
$ErrorActionPreference='Stop'
if($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:BNET_G67 -ne 'approved-live-startup-two-hosts-g67'){throw 'fresh_hosted_required'}
if([IO.Path]::GetFullPath($Root) -ne [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP 'g67-private'))){throw 'root_rejected'}
$ids=@($Known.Split(',')|Where-Object{$_ -match '^\d+$'}|ForEach-Object{[int]$_})
$c=Get-Content -LiteralPath (Join-Path $Root 'config.json') -Raw|ConvertFrom-Json
$connections=@(Get-NetTCPConnection -ErrorAction SilentlyContinue|Where-Object{$_.RemoteAddress -in @($c.ips)}|Select-Object OwningProcess,@{n='State';e={switch([int]$_.State){1{'Closed'}2{'Listen'}3{'SynSent'}4{'SynReceived'}5{'Established'}6{'FinWait1'}7{'FinWait2'}8{'CloseWait'}9{'Closing'}10{'LastAck'}11{'TimeWait'}12{'DeleteTcb'}100{'Bound'}default{'other'}}}},RemotePort)
$owners=@($connections|Where-Object{$_.OwningProcess -ne 0}|ForEach-Object{[int]$_.OwningProcess}|Sort-Object -Unique)
$all=@(Get-CimInstance Win32_Process|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath)
$rows=@()
foreach($p in $all){
 $path=[string]$p.ExecutablePath
 if($p.ProcessId -in $owners -or $p.ProcessId -in $ids -or $p.ParentProcessId -in $ids -or $p.Name -in @('Agent.exe','Battle.net.exe','Battle.net Launcher.exe','Battle.net-Setup.exe') -or $path -match '(?i)\\(Battle\.net|Blizzard Entertainment)\\'){
  $verified=$false;$status='not_checked';$hash=$null;$publisher='not_verified'
  if($path -and (Test-Path -LiteralPath $path)){
   $f=Get-Item -LiteralPath $path
   if($f.Length -lt 128MB){
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $s=Get-AuthenticodeSignature -LiteralPath $path;$status=[string]$s.Status
    $verified=$s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Blizzard Entertainment'
    if($verified){$publisher='Blizzard'}elseif($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Microsoft Corporation|Microsoft Windows'){$publisher='Microsoft'}elseif($s.Status -eq 'Valid'){$publisher='other_valid_signer'}
   }
  }
  $rows+=@{pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId;image_path=$path;name=[string]$p.Name;sha256=$hash;signature_status=$status;publisher_class=$publisher;target_TCP_owner=($p.ProcessId -in $owners);blizzard_verified=[bool]$verified;already_observed=($p.ProcessId -in $ids)}
 }
}
# Full executable paths stay private and are stripped before publication.
@{processes=@($rows|Select-Object -First 32);target_IP_TCP=@($connections|Select-Object -First 128);candidate_limit_hit=($rows.Count -gt 32);TCP_limit_hit=($connections.Count -gt 128)}|ConvertTo-Json -Depth 8 -Compress|Set-Content -LiteralPath (Join-Path $Root 'inventory.PRIVATE.json') -Encoding UTF8
