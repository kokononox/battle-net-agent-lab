# Event-derived proposals only. Process lineage is an observation, never an execution grant.
Set-StrictMode -Version 2.0
function Get-UfwRuntimeAuditSpec {
 return ,@([pscustomobject]@{id='0cce9226-69ae-11d9-bed3-505054503030';required=3},[pscustomobject]@{id='0cce922b-69ae-11d9-bed3-505054503030';required=1},[pscustomobject]@{id='0cce922c-69ae-11d9-bed3-505054503030';required=1})
}
function Get-UfwRuntimeAuditPlan($Query){
 $out=@();foreach($s in (Get-UfwRuntimeAuditSpec)){
  $v=& $Query $s.id;if(($v -isnot [int] -and $v -isnot [uint32]) -or $v -lt 0 -or $v -gt 3){throw 'ufw_runtime_audit_mask'}
  $out+=,[pscustomobject][ordered]@{id=$s.id;before=[int]$v;during=([int]$v -bor $s.required)}
 };return ,$out
}
function Assert-UfwRuntimeAuditPlan($Plan){
 $spec=Get-UfwRuntimeAuditSpec
 if($Plan -isnot [array] -or $Plan.Count -ne 3){throw 'ufw_runtime_journal_shape'}
 for($i=0;$i -lt 3;$i++){
  $p=$Plan[$i];if($null -eq $p -or (@($p.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'before,during,id' -or $p.id -isnot [string] -or $p.id -cne $spec[$i].id -or ($p.before -isnot [int] -and $p.before -isnot [long]) -or $p.before -lt 0 -or $p.before -gt 3 -or ($p.during -isnot [int] -and $p.during -isnot [long]) -or $p.during -ne ($p.before -bor $spec[$i].required)){throw 'ufw_runtime_journal_shape'}
 }
}
function Restore-UfwRuntimeAuditPlan($Plan,$Query,$Set){
 Assert-UfwRuntimeAuditPlan $Plan
 # Validate every current value before the first restoration write; do not overwrite unrelated drift.
 $current=@();foreach($p in $Plan){$v=& $Query $p.id;if($v -cnotin @($p.before,$p.during)){throw 'ufw_runtime_audit_drift_recovery_required'};$current+=,[int]$v}
 for($i=0;$i -lt 3;$i++){
  $p=$Plan[$i];$fresh=& $Query $p.id;if($fresh -ne $current[$i]){throw 'ufw_runtime_audit_drift_recovery_required'}
  if($fresh -ne $p.before){& $Set $p.id $p.before}
  if((& $Query $p.id) -ne $p.before){throw 'ufw_runtime_audit_restore_unverified'}
 }
 foreach($p in $Plan){if((& $Query $p.id) -ne $p.before){throw 'ufw_runtime_audit_restore_unverified'}}
 return $true
}
function ConvertTo-UfwRuntimePid([string]$Value){
 $n=[long]0
 if($Value -cmatch '^0x[0-9a-fA-F]{1,8}$'){$n=[Convert]::ToInt64($Value.Substring(2),16)}
 elseif($Value -cmatch '^[0-9]{1,10}$'){$n=[long]$Value}else{throw 'ufw_runtime_event_pid'}
 if($n -lt 1 -or $n -gt [int]::MaxValue){throw 'ufw_runtime_event_pid'};return [int]$n
}
function ConvertTo-UfwRuntimePath([string]$Path,$Map){
 if($Path.StartsWith('\??\',[StringComparison]::OrdinalIgnoreCase)){$Path=$Path.Substring(4)}
 elseif($Path.StartsWith('\\?\',[StringComparison]::OrdinalIgnoreCase)){$Path=$Path.Substring(4)}
 if($Path.StartsWith('\Device\',[StringComparison]::OrdinalIgnoreCase)){
  $matches=@($Map|Where-Object{$Path.StartsWith($_.device+'\',[StringComparison]::OrdinalIgnoreCase)})
  if($matches.Count -ne 1){throw 'ufw_runtime_event_path_unmapped'}
  $Path=$matches[0].drive+$Path.Substring($matches[0].device.Length)
 }
 if($Path.Length -gt 32760 -or $Path -cnotmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path.IndexOfAny([char[]]'/*?%"<>|') -ge 0){throw 'ufw_runtime_event_path'}
 foreach($c in $Path.ToCharArray()){if([int]$c -lt 32){throw 'ufw_runtime_event_path'}}
 foreach($part in $Path.Substring(3).Split('\')){if($part -ceq '' -or $part -cin @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'ufw_runtime_event_path'}}
 return $Path.Substring(0,1).ToUpperInvariant()+$Path.Substring(1)
}
function ConvertFrom-UfwRuntimeXml([string]$Text,$Map){
 if([Text.Encoding]::UTF8.GetByteCount($Text) -gt 262144){throw 'ufw_runtime_event_size'}
 $settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
 $string=New-Object IO.StringReader($Text);$reader=[Xml.XmlReader]::Create($string,$settings)
 try{$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader)}finally{$reader.Dispose();$string.Dispose()}
 $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
 $system=$doc.SelectSingleNode('/e:Event/e:System',$ns)
 if($null -eq $system -or $system.SelectSingleNode('e:Provider',$ns).GetAttribute('Guid').ToLowerInvariant() -cne '{54849625-5478-4994-a5ba-3e3b0328c30d}' -or [string]$system.SelectSingleNode('e:Channel',$ns).InnerText -cne 'Security'){throw 'ufw_runtime_event_provider'}
 $id=[int]$system.SelectSingleNode('e:EventID',$ns).InnerText;$record=[long]$system.SelectSingleNode('e:EventRecordID',$ns).InnerText
 $time=[datetime]::Parse($system.SelectSingleNode('e:TimeCreated',$ns).GetAttribute('SystemTime'),[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
 if($record -le 0 -or $id -cnotin @(4688,4689,5156,5157,1101,1102,1104,4719)){throw 'ufw_runtime_event_kind'}
 $r=[pscustomobject][ordered]@{id=$id;record=$record;time=$time;pid=0;path='';parent_pid=0;parent_path='';actor='';direction='';address='';port=0;protocol=0}
 if($id -cin @(1101,1102,1104,4719)){return $r}
 $fields=@{};foreach($n in $doc.SelectNodes('/e:Event/e:EventData/e:Data',$ns)){$name=$n.GetAttribute('Name');if($fields.ContainsKey($name)){throw 'ufw_runtime_duplicate_event_field'};$fields[$name]=[string]$n.InnerText}
 if($id -eq 4688){
  foreach($k in @('NewProcessId','NewProcessName','ProcessId','SubjectUserSid')){if(-not $fields.ContainsKey($k)){throw 'ufw_runtime_event_fields'}}
  $r.pid=ConvertTo-UfwRuntimePid $fields.NewProcessId;$r.path=ConvertTo-UfwRuntimePath $fields.NewProcessName $Map
  try{$r.parent_pid=ConvertTo-UfwRuntimePid $fields.ProcessId}catch{$r.parent_pid=0}
  if($fields.ContainsKey('ParentProcessName') -and -not [string]::IsNullOrWhiteSpace($fields.ParentProcessName)){try{$r.parent_path=ConvertTo-UfwRuntimePath $fields.ParentProcessName $Map}catch{$r.parent_path=''}}
  $r.actor=$fields.SubjectUserSid
  if($fields.ContainsKey('TargetUserSid') -and $fields.TargetUserSid -cmatch '^S-1-' -and $fields.TargetUserSid -cne 'S-1-0-0'){$r.actor=$fields.TargetUserSid}
 }elseif($id -eq 4689){
  foreach($k in @('ProcessId','ProcessName')){if(-not $fields.ContainsKey($k)){throw 'ufw_runtime_event_fields'}}
  $r.pid=ConvertTo-UfwRuntimePid $fields.ProcessId;$r.path=ConvertTo-UfwRuntimePath $fields.ProcessName $Map
 }else{
  foreach($k in @('ProcessID','Application','Direction','DestAddress','DestPort','Protocol')){if(-not $fields.ContainsKey($k)){throw 'ufw_runtime_event_fields'}}
  $r.pid=ConvertTo-UfwRuntimePid $fields.ProcessID;$r.path=ConvertTo-UfwRuntimePath $fields.Application $Map
  $r.direction=$fields.Direction;$r.address=$fields.DestAddress
  if($fields.DestPort -cnotmatch '^\d{1,5}$' -or $fields.Protocol -cnotmatch '^\d{1,3}$'){throw 'ufw_runtime_event_fields'}
  $r.port=[int]$fields.DestPort;$r.protocol=[int]$fields.Protocol
 }
 return $r
}
function Get-UfwRuntimeEndpoint([string]$Address,[int]$Port,[int]$Protocol){
 if($Port -lt 1 -or $Port -gt 65535 -or $Protocol -cnotin @(6,17)){return $null}
 $ip=$null;if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip)){throw 'ufw_runtime_event_ip'}
 if($ip.IsIPv4MappedToIPv6){$ip=$ip.MapToIPv4()};$v4=$ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork;$bytes=$ip.GetAddressBytes()
 if([Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any) -or ($v4 -and ($bytes[0] -eq 0 -or $bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254))) -or (-not $v4 -and ($ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.ScopeId -ne 0))){return $null}
 return [pscustomobject]@{address=$ip.ToString();port=$Port;protocol=$(if($Protocol -eq 6){'TCP'}else{'UDP'})}
}
function Get-UfwRuntimeProposals($Events,$Programs,[string]$Actor,[datetime]$Begin,[datetime]$End){
 if($Events -isnot [array] -or $Events.Count -gt 50000 -or $End -lt $Begin){throw 'ufw_runtime_event_window'}
 $active=@{};$instances=@();$endpoints=@{};$last=[long]0;$roots=0;$children=0;$blocked=0;$permitted=0;$unmatched=0;$excluded=0;$warnings=0
 foreach($e in @($Events|Sort-Object record)){
  if($e.record -le $last){throw 'ufw_runtime_duplicate_record'};$last=$e.record
  if($e.time -lt $Begin -or $e.time -gt $End){continue}
  if($e.id -eq -1){$warnings++;continue}
  if($e.id -eq 0){$active=@{};$warnings++;continue}
  if($e.id -cin @(1101,1102,1104,4719)){$warnings++;if($e.id -cin @(1101,1102,1104)){$active=@{}};continue}
  if($e.id -eq 4688){
   $root='';$kind='unrelated';$parent=''
   foreach($p in $Programs){if([string]::Equals($e.path,$p.path,[StringComparison]::OrdinalIgnoreCase) -and $e.actor -ceq $Actor){$root=$p.program_id;$kind='selected_root';break}}
   if($kind -ceq 'unrelated' -and $active.ContainsKey($e.parent_pid)){
    $a=$active[$e.parent_pid]
    if($a.root -cne '' -and $e.time -ge $a.started -and $e.parent_path -cne '' -and [string]::Equals($e.parent_path,$a.path,[StringComparison]::OrdinalIgnoreCase)){$root=$a.root;$kind='unreviewed_descendant';$parent=$a.instance_id}
   }
   $instance=[pscustomobject][ordered]@{instance_id=('instance'+($instances.Count+1).ToString('D5'));path=$e.path;root=$root;kind=$kind;parent_instance=$parent;started=$e.time;start_record=$e.record}
   # Every observed start replaces the PID slot, including unrelated process reuse.
   $active[$e.pid]=$instance
   if($root -cne ''){if($instances.Count -ge 1024){throw 'ufw_runtime_process_limit'};$instances+=,$instance;if($kind -ceq 'selected_root'){$roots++}else{$children++}}
  }elseif($e.id -eq 4689){
   if($active.ContainsKey($e.pid)){$a=$active[$e.pid];if($e.time -ge $a.started -and [string]::Equals($e.path,$a.path,[StringComparison]::OrdinalIgnoreCase)){$active.Remove($e.pid)}}
  }elseif($e.id -cin @(5156,5157)){
   if(-not $active.ContainsKey($e.pid)){$unmatched++;continue};$a=$active[$e.pid]
   if($a.root -ceq '' -or $e.time -lt $a.started -or $e.record -le $a.start_record -or -not [string]::Equals($e.path,$a.path,[StringComparison]::OrdinalIgnoreCase)){$unmatched++;continue}
   if($e.direction -cne '%%14593'){$excluded++;continue}
   $ep=Get-UfwRuntimeEndpoint $e.address $e.port $e.protocol;if($null -eq $ep){$excluded++;continue}
   $key=$a.instance_id+'|'+$ep.address+'|'+$ep.port+'|'+$ep.protocol
   if(-not $endpoints.ContainsKey($key)){
    if($endpoints.Count -ge 512){throw 'ufw_runtime_endpoint_limit'}
    $endpoints[$key]=[pscustomobject][ordered]@{instance_id=$a.instance_id;root_program_id=$a.root;program_kind=$a.kind;address=$ep.address;port=$ep.port;protocol=$ep.protocol;direction='outbound';blocked_events=0;permitted_events=0;approval='not_reviewed'}
   }
   if($e.id -eq 5157){$endpoints[$key].blocked_events++;$blocked++}else{$endpoints[$key].permitted_events++;$permitted++}
  }
 }
 # Unrelated processes and PID slots never become persisted program lists.
 return [pscustomobject]@{root_start_events=$roots;descendant_start_events=$children;blocked_events=$blocked;permitted_events=$permitted;unattributed_network_events=$unmatched;excluded_network_events=$excluded;integrity_warning_events=$warnings;programs=$instances;endpoints=@($endpoints.Values|Sort-Object instance_id,address,port,protocol);destinations_approved=$false;complete_coverage=$false;ready_for_apply=$false}
}
