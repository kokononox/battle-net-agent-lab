param([string]$Config)
$ErrorActionPreference='Stop'
$c=Get-Content -Raw $Config | ConvertFrom-Json
$r=@{schema='application_error_events_v1';scope='vm_time_window_known_target_names_not_exact_process_attribution';query_complete=$false;events=@();limited=$false}
try{
 $since=[datetime]::Parse($c.observation_start_utc).ToLocalTime()
 $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000,1001;StartTime=$since} -MaxEvents 65 -ErrorAction Stop)
 $r.limited=$events.Count -gt 64
 foreach($event in @($events | Select-Object -First 64)){
  $xml=[xml]$event.ToXml();$foundNames=@();$codes=@()
  foreach($node in @($xml.Event.EventData.Data)){
   $text=[string]$node.'#text'
   foreach($name in @('Battle.net.exe','Battle.net Launcher.exe','Agent.exe','Battle.net-Setup.exe')){if($text -match ('(?i)(^|[\\/\s])'+[regex]::Escape($name)+'($|[\s])')){$foundNames+=$name}}
   if([string]$node.Name -match '(?i)^(ExceptionCode|ExceptionStatus)$' -and $text -match '^(?i)(0x)?([a-f0-9]{8})$'){$codes+=('0x'+$Matches[2].ToLowerInvariant())}
  }
  if($foundNames.Count -gt 0){$r.events+=@{event_id=$event.Id;target_names=@($foundNames | Sort-Object -Unique);exception_codes=@($codes | Sort-Object -Unique)}}
 }
 $r.query_complete=$true
}catch{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$r.query_complete=$true}else{$r.error_code='application_event_query_failed'}}
Save-Private (Join-Path $c.root 'application-events.json') $r
