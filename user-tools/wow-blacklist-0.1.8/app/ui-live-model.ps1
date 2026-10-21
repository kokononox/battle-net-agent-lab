# Pure labels/signals: a pulse means a TCP table sample, never packet/request activity.
function Live-DestinationLabel([string]$status){switch($status){'previously_seen'{return 'قدیمی؛ قبلاً رصدشده'}'first_in_local_history'{return 'تازه در سابقهٔ محلی'}default{return 'سابقه نامطمئن'}}}
function Live-ProcessLabel($row){if($row.fresh_process_seen){return 'تازه پس از شروع ضبط'};return 'قدیمی / شروع نامشخص'}
function Live-PulseKind($before,$after){
 if(!$before){return 'discovery'}
 if(!$after.seen_in_latest_sample){return 'absent'}
 if(!$before.seen_in_latest_sample){return 'reappeared'}
 if([int]$after.samples -gt [int]$before.samples){return 'sample'}
 return 'none'
}
function Live-ReadSnapshot([string]$path,[string]$ident){
 $stream=$null
 try{
  $stream=New-Object IO.FileStream($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  if($stream.Length -gt 16777216){throw 'live_snapshot_too_large'}
  $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8);try{$raw=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
  if($raw.schema -ne 'wow-live-observation-1' -or $raw.capture_id -cne $ident -or @($raw.endpoints).Count -gt 2000){throw 'invalid_live_snapshot'}
  return $raw
 }finally{if($stream){$stream.Dispose()}}
}

function Live-EvidenceLabel($event){
 if($event.kind -eq 'wfp_connection_block'){return 'منع اتصال ثبت‌شده؛ WFP'}
 switch($event.hosts_mapping){
 'local_sink_mapping'{return 'DNS ثبت‌شده؛ نگاشت محلی hosts؛ اثر تأییدنشده'}
 'mixed_mapping'{return 'DNS ثبت‌شده؛ نگاشت hosts متناقض'}
 'other_mapping'{return 'DNS ثبت‌شده؛ نگاشت دیگر hosts'}
 'hosts_unavailable'{return 'DNS ثبت‌شده؛ hosts نامعلوم'}
 default{return 'DNS ثبت‌شده؛ منع/اجازه اثبات نشده'}
 }
}
function Live-StreamLabel($stream){
 switch($stream.status){'readable_logging_coverage_unverified'{return 'لاگ خواندنی؛ کامل‌بودن ثبت تضمین نیست'}'read_failed'{return 'خطای خواندن؛ شواهد نامطمئن'}default{return 'شواهد در دسترس نیست / ثبت فعال نیست'}}
}
function Live-RuleLabel($row,$snapshot){
 if(!$snapshot -or !$snapshot.available){return 'Block شروع نامطمئن'}
 foreach($entry in @($snapshot.entries)){if($entry.protocol -eq 'TCP' -and [int]$entry.port -eq [int]$row.port -and (Ui-Contains $entry ([string]$row.ip))){return 'منطبق با Block شروع؛ افت نامعلوم'}}
 return 'Block همین نصب تأیید نشد'
}
