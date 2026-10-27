# Concrete filesystem adapter using unchanged protected storage helpers.
# Must run inside the PRIVATE Ufw.SessionJournal module scope. No firewall setter.
function Get-UfwUnifiedStorageJson($Data){return ConvertTo-Json -InputObject $Data -Depth 64 -Compress}
function Get-UfwUnifiedStorageRoot {return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFW-IntegratedSessions-01'}
function New-UfwUnifiedStorage([string]$SessionId='') {
 if($SessionId -cne '' -and $SessionId -cnotmatch '^[a-f0-9]{32}$'){throw 'ufw_unified_storage_id'}
 $root=Get-UfwUnifiedStorageRoot
 if([IO.Directory]::Exists($root)){Assert-UfwJournalAcl $root $true}else{New-UfwPrivateJournalDirectory $root}
 $id=$SessionId;if($id -ceq ''){$id=[guid]::NewGuid().ToString('N')};$dir=Join-Path $root ('session-'+$id);New-UfwPrivateJournalDirectory $dir
 $lock=Open-UfwPrivateJournalFile (Join-Path $dir 'operation.lock') ([IO.FileMode]::CreateNew)
 return [pscustomobject]@{id=$id;dir=$dir;sequence=0;head=('0'*64);lock=$lock;total_bytes=[long]0}
}
function Read-UfwUnifiedStorage($Handle){
 Assert-UfwJournalAcl $Handle.dir $true
 $files=@(Get-ChildItem -LiteralPath $Handle.dir -Force)
 foreach($file in $files){if($file.PSIsContainer -or ($file.Name -cne 'operation.lock' -and $file.Name -cnotmatch '^[0-9]{8}\.json$')){throw 'ufw_unified_storage_unexpected_file'}}
 $entries=@($files|Where-Object{$_.Name -cne 'operation.lock'}|Sort-Object Name);if($entries.Count -gt 4096){throw 'ufw_unified_storage_sequence_cap'}
 $prev='0'*64;$seq=0;$total=[long]0;$records=@();$closed=$false
 foreach($file in $entries){
  if($closed){throw 'ufw_unified_storage_tail_after_close'}
  $seq++;if($file.Name -cne ($seq.ToString('00000000')+'.json')){throw 'ufw_unified_storage_gap'}
  Assert-UfwJournalAcl $file.FullName $false
  $f=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{if($f.Length -lt 2 -or $f.Length -gt 67108864){throw 'ufw_unified_storage_record_size'};$total+=$f.Length;if($total -gt 268435456){throw 'ufw_unified_storage_total_size'};$reader=New-Object IO.StreamReader($f,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}}finally{$f.Dispose()}
  $en=ConvertFrom-Json $text
  if((@($en.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'payload,previous_hash,sequence,sha256' -or $en.payload -isnot [string] -or ($en.sequence -isnot [int32] -and $en.sequence -isnot [int64]) -or $en.sequence -ne $seq -or $en.previous_hash -cne $prev -or $en.sha256 -isnot [string] -or $en.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'ufw_unified_storage_envelope'}
  $hash=Get-UfwJournalHash ($seq.ToString()+'|'+$prev+'|'+$en.payload)
  if($hash -cne $en.sha256){throw 'ufw_unified_storage_checksum'}
  $data=ConvertFrom-Json $en.payload
  if((@($data.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'data,kind,schema,session_id' -or $data.schema -cne 'ufw-unified-checkpoint-01' -or $data.session_id -cne $Handle.id -or $data.kind -cnotin @('baseline','intent','result','restore_intent','restore_result','restored')){throw 'ufw_unified_storage_payload'}
  if(($seq -eq 1) -ne ($data.kind -ceq 'baseline')){throw 'ufw_unified_storage_baseline_order'}
  $closed=$data.kind -ceq 'restored';$records+=,$data;$prev=$hash
 }
 return [pscustomobject]@{sequence=$seq;head=$prev;records=$records;total_bytes=$total;readback_verified=$true}
}
function Write-UfwUnifiedStorage($Handle,[string]$Kind,$Data){
 if($null -eq $Handle.lock -or -not $Handle.lock.CanWrite){throw 'ufw_unified_storage_lock_missing'}
 if($Kind -cnotin @('baseline','intent','result','restore_intent','restore_result','restored')){throw 'ufw_unified_storage_kind'}
 $back=Read-UfwUnifiedStorage $Handle
 if($back.sequence -ne $Handle.sequence -or $back.head -cne $Handle.head){throw 'ufw_unified_storage_stale_head'}
 $seq=$Handle.sequence+1;if($seq -gt 4096){throw 'ufw_unified_storage_sequence_cap'}
 if(($seq -eq 1) -ne ($Kind -ceq 'baseline')){throw 'ufw_unified_storage_baseline_order'}
 if($seq -gt 1 -and $back.records[-1].kind -ceq 'restored'){throw 'ufw_unified_storage_closed'}
 $payload=Get-UfwUnifiedStorageJson ([pscustomobject]@{schema='ufw-unified-checkpoint-01';session_id=$Handle.id;kind=$Kind;data=$Data})
 $hash=Get-UfwJournalHash ($seq.ToString()+'|'+$Handle.head+'|'+$payload)
 $en=Get-UfwUnifiedStorageJson ([pscustomobject]@{sequence=$seq;previous_hash=$Handle.head;payload=$payload;sha256=$hash});$bytes=[Text.Encoding]::UTF8.GetBytes($en)
 if($bytes.Length -gt 67108864 -or $back.total_bytes+$bytes.Length -gt 268435456){throw 'ufw_unified_storage_record_size'}
 $file=Open-UfwPrivateJournalFile (Join-Path $Handle.dir ($seq.ToString('00000000')+'.json')) ([IO.FileMode]::CreateNew)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 $check=Read-UfwUnifiedStorage $Handle
 if($check.sequence -ne $seq -or $check.head -cne $hash){throw 'ufw_unified_storage_readback'}
 $Handle.sequence=$seq;$Handle.head=$hash;$Handle.total_bytes=$check.total_bytes
 return [pscustomobject]@{head=$hash;readback_verified=$true;sequence=$seq}
}
function Close-UfwUnifiedStorage($Handle){if($null -ne $Handle -and $null -ne $Handle.lock){$Handle.lock.Dispose();$Handle.lock=$null}}
