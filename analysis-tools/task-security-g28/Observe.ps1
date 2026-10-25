param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
function Hash-Bytes([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($h.ComputeHash($Bytes))}finally{$h.Dispose()}}
function Digest([string]$Text){return (Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant()}
. (Join-Path $PSScriptRoot 'TaskTrust.ps1')
$ids=@{
 '6137a887b08bde613f10c2469a266d09ae1a4771d17512f64acba2c4d4d1e883'='RefreshCache'
 '21475573fddc2e641b67691a5d4d3096ea5135278dae645a8fd4a2e0bc4c613a'='PrintJobCleanupTask'
 '2b11947a6c63d26c27256985033a4d1d7e97e56883cf36ed29a8beb6f79a4559'='Registration'
 '4023f1322db1c44e9afe47a715033f592132e209dd8511b71be83c290ae8c7a2'='SvcRestartTask'
}
function Failure($Record,[string]$Stage){
 $ex=$Record.Exception;$type=$ex.GetType().Name;if($type -notmatch '^[A-Za-z0-9_]{1,100}$'){$type='OtherException'}
 $code=[string]$Record.FullyQualifiedErrorId;if($code -notmatch '^[A-Za-z0-9_,.:-]{1,150}$'){$code='unclassified'}
 return @{stage=$Stage;exception_type=$type;hresult=('{0:x8}' -f ($ex.HResult -band 0xffffffffL));error_id=$code}
}
function Get-Permissions($Scheduler,[string]$FolderPath,[string]$TaskName){
 $stage='get_folder';$folder=$null;$registered=$null
 try{
  $folder=$Scheduler.GetFolder($FolderPath);$stage='get_task';$registered=$folder.GetTask($TaskName)
  $stage='get_security_descriptor';$sddl=[string]$registered.GetSecurityDescriptor(7)
  $stage='parse_security_descriptor';$descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($sddl)
  if($null -eq $descriptor.Owner -or $null -eq $descriptor.Group -or $null -eq $descriptor.DiscretionaryAcl){throw 'security_descriptor_incomplete'}
  return @{complete=$true;descriptor_sha256=(Digest $sddl);owner_sha256=(Digest $descriptor.Owner.Value);group_sha256=(Digest $descriptor.Group.Value);dacl_sha256=(Digest ($descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::Access)));ace_count=$descriptor.DiscretionaryAcl.Count;descriptor_parsed=$true;sacl_requested=$false}
 }catch{return @{complete=$false;failure=(Failure $_ $stage)}}
 finally{foreach($o in @($registered,$folder)){if($null -ne $o -and [Runtime.InteropServices.Marshal]::IsComObject($o)){try{$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($o)}catch{}}}}
}
function File-Evidence([string]$Path){
 $stage='image_path'
 try{
  if(-not [IO.Path]::IsPathRooted($Path)){throw 'absolute_system_path_required'}
  $p=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path).Trim('"'));$prefix=$env:SystemRoot+'\System32\'
  if(-not $p.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'system32_required'}
  $f=Get-Item -LiteralPath $p;$d=$f
  while($null -ne $d){if(($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'reparse_refused'};if($d -is [IO.FileInfo]){$d=$d.Directory}else{$d=$d.Parent}}
  if($f.Length -gt 33554432){throw 'image_size_bound'}
  $stage='image_hash';$before=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
  $stage='authenticode';$sig=Get-AuthenticodeSignature -LiteralPath $p
  $stage='image_recheck';$after=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
  if($before -ne $after){throw 'image_changed_during_signature_check'}
  $cert=$sig.SignerCertificate;$status=[string]$sig.Status
  if($status -notin @('Valid','NotSigned','HashMismatch','NotTrusted','NotSupportedFileFormat','Incompatible','UnknownError')){$status='Other'}
  $microsoft=($null -ne $cert -and $cert.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)')
  return @{complete=$true;file_sha256=$before;file_bytes=$f.Length;image_name=$f.Name;signature_status=$status;signature_valid_microsoft=($status -eq 'Valid' -and $microsoft);signer_certificate_sha256=$(if($cert){(Hash-Bytes $cert.RawData).Replace('-','').ToLowerInvariant()}else{$null});hash_stable_across_signature_check=$true;signature_api='GetAuthenticodeSignature';network_isolated=$false;revocation_policy_independently_audited=$false}
 }catch{return @{complete=$false;failure=(Failure $_ $stage)}}
}
$r=@{schema='task_security_g28_v1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;system_identity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');installer_executed=$false;firewall_changed=$false;target_tasks_modified=$false;automatic_exemptions_added=$false;mutation_actor_proven=$false;signature_checks_outside_isolation=$true;samples=@()}
if(-not $r.system_identity){throw 'system_identity_required'}
$scheduler=$null
try{
 $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
 for($sampleIndex=0;$sampleIndex -lt 2;$sampleIndex++){
  $sample=@{captured_utc=[DateTime]::UtcNow.ToString('o');tasks=@()}
  foreach($t in @(Get-ScheduledTask)){
   $id=Digest ([string]$t.TaskPath+[string]$t.TaskName);if(-not $ids.ContainsKey($id)){continue}
   $row=@{identifier=$ids[$id];identity_sha256=$id;xml_complete=$false;binding_complete=$false}
   $stage='export_xml'
   try{
    $xml=[string](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath);if($xml.Length -gt 65536){throw 'xml_size_bound'}
    $doc=[xml]$xml;$ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    $row.xml_sha256=Digest $xml;$row.xml_complete=$true
    foreach($section in @('Actions','Principals','Settings','Triggers')){$node=$doc.SelectSingleNode('/t:Task/t:'+$section,$ns);$row[$section.ToLowerInvariant()+'_sha256']=Digest $(if($node){$node.OuterXml}else{'absent'})}
    # Diagnose the original folder argument without changing the registered task.
    $row.original_folder_permissions=Get-Permissions $scheduler ([string]$t.TaskPath) ([string]$t.TaskName)
    $normalized=([string]$t.TaskPath).TrimEnd([char]'\');if(-not $normalized){$normalized='\'}
    $row.folder_argument_changed=($normalized -ne [string]$t.TaskPath)
    $row.normalized_folder_permissions=Get-Permissions $scheduler $normalized ([string]$t.TaskName)
    # Independent exact full-path lookup: no supplied folder argument.
    $root=$null;$registered=$null
    try{$root=$scheduler.GetFolder('\');$registered=$root.GetTask([string]$t.TaskPath+[string]$t.TaskName);$row.full_path_lookup_xml_equal=((Digest ([string]$registered.Xml)) -eq $row.xml_sha256)}catch{$row.full_path_lookup_failure=Failure $_ 'full_path_lookup'}finally{foreach($o in @($registered,$root)){if($null -ne $o -and [Runtime.InteropServices.Marshal]::IsComObject($o)){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($o)}}}
    $stage='action_shape';$com=@($doc.SelectNodes('/t:Task/t:Actions/t:ComHandler',$ns));$exec=@($doc.SelectNodes('/t:Task/t:Actions/t:Exec',$ns))
    if($com.Count -eq 1 -and $exec.Count -eq 0){
     $binding=Get-SvcBinding $xml;$row.action_kind='com_handler';$row.binding_complete=$binding.capture_complete
     if($binding.capture_complete){$row.binding_sha256=Digest ([string]$binding.binding_hash);$row.image=File-Evidence $binding.image_path}else{$row.binding_failure=@{stage=$binding.failure_stage;code=$binding.error_code}}
    }elseif($exec.Count -eq 1 -and $com.Count -eq 0){
     $row.action_kind='exec';$path=[Environment]::ExpandEnvironmentVariables(([string]$exec[0].Command).Trim('"'));$row.image=File-Evidence $path;$row.binding_complete=$row.image.complete
     $row.binding_sha256=Digest ([string]$exec[0].OuterXml)
    }else{$row.action_kind='unsupported';$row.binding_failure=@{code='single_action_required'}}
   }catch{$row.failure=Failure $_ $stage}
   $sample.tasks+=@($row)
  }
  foreach($id in $ids.Keys){if(@($sample.tasks | Where-Object {$_.identity_sha256 -eq $id}).Count -ne 1){$sample.tasks+=@(@{identifier=$ids[$id];identity_sha256=$id;missing_or_duplicated=$true})}}
  $r.samples+=@($sample)
  if($sampleIndex -eq 0){Start-Sleep -Seconds 15}
 }
}finally{if($scheduler){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($scheduler)}}
$r | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $Output -Encoding UTF8
