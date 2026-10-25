# Global registration snapshot + observed named Job members, not a kernel process-creation barrier.
function Get-RegistrationSnapshot {
 $services=@{};$tasks=@{};$serviceCommands=@{};$taskImages=@{};$taskXml=@{}
 foreach($s in @(Get-CimInstance Win32_Service)){
  $value=ConvertTo-Json -Compress -InputObject @([string]$s.PathName,[string]$s.StartMode,[string]$s.StartName)
  $serviceCommands[[string]$s.Name]=[string]$s.PathName
  $services[[string]$s.Name]=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($value))
 }
 foreach($t in @(Get-ScheduledTask)){
  $key=[string]$t.TaskPath+[string]$t.TaskName
  $xml=[string](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath)
  $taskImages[$key]=@($t.Actions | ForEach-Object {[string]$_.Execute})
  $taskXml[$key]=$xml;$tasks[$key]=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($xml))
 }
 return @{services=$services;tasks=$tasks;service_commands=$serviceCommands;task_images=$taskImages;task_xml=$taskXml}
}
function Registration-Changes($Context){
 $before=Get-Content -Raw (Join-Path $Context.root 'registrations-before.json') | ConvertFrom-Json;$after=Get-RegistrationSnapshot;Save-Private (Join-Path $Context.root 'registrations-after.json') $after;$changed=0
 foreach($kind in @('services','tasks')){
  $prior=@{};foreach($entry in $before.$kind.PSObject.Properties){$prior[$entry.Name]=[string]$entry.Value}
  foreach($key in $after[$kind].Keys){if(-not $prior.ContainsKey($key) -or $prior[$key] -ne $after[$kind][$key]){$changed++}}
  foreach($key in $prior.Keys){if(-not $after[$kind].ContainsKey($key)){$changed++}}
 };return $changed
}
