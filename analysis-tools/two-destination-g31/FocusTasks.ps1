# Read-only observations. No task is started, changed, disabled, or trusted by these functions.
$script:FocusIds=@{
 '6137a887b08bde613f10c2469a266d09ae1a4771d17512f64acba2c4d4d1e883'='RefreshCache'
 '21475573fddc2e641b67691a5d4d3096ea5135278dae645a8fd4a2e0bc4c613a'='PrintJobCleanupTask'
 '2b11947a6c63d26c27256985033a4d1d7e97e56883cf36ed29a8beb6f79a4559'='Registration'
 '4023f1322db1c44e9afe47a715033f592132e209dd8511b71be83c290ae8c7a2'='SvcRestartTask'
}
function Focus-Hash([string]$Text){return (Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant()}
function Get-FocusTasks($Context,[string]$Phase,[int]$Elapsed,[switch]$Deep){
 $r=@{schema='focus_task_snapshot_private_v1';phase=$Phase;elapsed_seconds=$Elapsed;captured_utc=[DateTime]::UtcNow.ToString('o');system_identity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');lookup_complete=$false;deep=[bool]$Deep;tasks=@{};target_processes_observed=0;query_errors=0}
 $scheduler=$null
 try{
  $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
  foreach($t in @(Get-ScheduledTask)){
   $key=[string]$t.TaskPath+[string]$t.TaskName;$id=Focus-Hash $key;if(-not $script:FocusIds.ContainsKey($id)){continue}
   $row=@{identifier=$script:FocusIds[$id];identity_sha256=$id;capture_complete=$false;permissions_read=$false;binding_checked=$false}
   $captureStage='task_xml'
   try{
    $xml=[string](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath);if($xml.Length -gt 65536){throw 'focus_xml_bound'};$doc=[xml]$xml
    $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    $row.xml=$xml;$row.xml_sha256=Focus-Hash $xml
    foreach($section in @('Actions','Principals','Settings','Triggers')){$node=$doc.SelectSingleNode('/t:Task/t:'+$section,$ns);$row[$section.ToLowerInvariant()+'_sha256']=Focus-Hash $(if($node){$node.OuterXml}else{'absent'})}
    $captureStage='task_permissions'
    $folderPath=([string]$t.TaskPath).TrimEnd([char]'\');if(-not $folderPath){$folderPath='\'}
    $folder=$scheduler.GetFolder($folderPath);$registered=$folder.GetTask([string]$t.TaskName)
    try{$row.scheduler_enabled=[bool]$registered.Definition.Settings.Enabled;$sddl=[string]$registered.GetSecurityDescriptor(7);$row.permissions_sha256=Focus-Hash $sddl;$row.permissions_read=$true}finally{if($registered){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($registered)};if($folder){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($folder)}}
    $captureStage='task_binding'
    if($Deep){
     $com=@($doc.SelectNodes('/t:Task/t:Actions/t:ComHandler',$ns));$exec=@($doc.SelectNodes('/t:Task/t:Actions/t:Exec',$ns))
     if($com.Count -eq 1 -and $exec.Count -eq 0){$row.binding=Get-SvcBinding $xml;$row.binding_checked=$true}
     elseif($exec.Count -eq 1 -and $com.Count -eq 0){
      $command=[string]$exec[0].Command;$path=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($command).Trim('"'));$prefix=$env:SystemRoot+'\System32\'
      if(-not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'focus_exec_outside_system32'}
      $f=Get-Item -LiteralPath $path;if($f.Length -gt 33554432){throw 'focus_image_bound'};$d=$f;while($null -ne $d){if(($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'focus_reparse'};if($d -is [IO.FileInfo]){$d=$d.Directory}else{$d=$d.Parent}}
      $stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$h=[Security.Cryptography.SHA256]::Create();try{$digest=[BitConverter]::ToString($h.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose();$stream.Dispose()}
      $row.binding=@{capture_complete=$true;file_sha256=$digest;binding_hash=(Focus-Hash $path);image_path=$path};$row.binding_checked=$true
     }
    }
    if($Deep -and $Phase -eq 'baseline' -and $row.binding.capture_complete){
     $captureStage='baseline_signature_before_gate'
     $imagePath=[string]$row.binding.image_path;$sig=Get-AuthenticodeSignature -LiteralPath $imagePath
     $recheck=(Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash.ToLowerInvariant()
     $row.baseline_signature=@{checked_before_gate=$true;hash_stable=($recheck -eq $row.binding.file_sha256);valid_microsoft=([string]$sig.Status -eq 'Valid' -and $null -ne $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)');revocation_policy_independently_audited=$false}
    }
    $row.capture_complete=$true
   }catch{$row.error_code='focus_task_capture_incomplete';$row.failure_stage=$captureStage;$row.failure_hresult=('{0:x8}' -f ($_.Exception.HResult -band 0xffffffffL));$r.query_errors++}
   $r.tasks[$id]=$row
  }
  $r.lookup_complete=$true
  $r.target_processes_observed=@(Get-Process -Name 'Battle.net-Setup','Agent','Battle.net','BlizzardError' -ErrorAction SilentlyContinue).Count
 }catch{$r.query_errors++}
 finally{if($scheduler){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($scheduler)}}
 return $r
}
