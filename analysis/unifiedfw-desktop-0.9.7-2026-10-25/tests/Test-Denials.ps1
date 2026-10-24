param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
. (Join-Path $Root 'app/denial-model.ps1')
. (Join-Path $Root 'app/baseline-model.ps1')
. (Join-Path $Root 'app/baseline-wfp.ps1')
$p=[pscustomobject]@{id=('a'*24);path='C:\Apps\Game.exe'}
$e=[pscustomobject]@{record_id=('b'*32);event_record_id=101;kind='wfp_connection_block';program_id=$p.id;program_path=$p.path;pid=123;ip='8.8.8.8';port=443;protocol='TCP';observed_utc='2026-10-24T12:00:00Z'}
Check (@(Get-DenialGroups @()).Count -eq 0) 'empty-not-attempt'
$g=@(Get-DenialGroups @($e));Check ($g.Count -eq 1 -and $g[0].samples -eq 1 -and $g[0].rule_state -ceq 'wfp_denial_event') 'denial-row'
Check ($g[0].program_path -ceq $p.path -and $g[0].remote_port -eq 443) 'context-transfer-fields-preserved'
$copy=$e.PSObject.Copy();$copy.record_id='c'*32
$g=@(Get-DenialGroups @($e,$copy));Check ($g[0].samples -eq 1) 'Security-record-id-deduplicated'
$copy.event_record_id=102;$copy.observed_utc='2026-10-24T12:00:02Z'
$g=@(Get-DenialGroups @($copy,$e));Check ($g.Count -eq 1 -and $g[0].samples -eq 2) 'same-destination-grouped'
Check ($g[0].record_id -ceq $e.record_id -and $g[0].first_seen_utc -ceq $e.observed_utc -and $g[0].last_seen_utc -ceq $copy.observed_utc) 'order-independent-times-and-key'
Check ((Get-DenialPulse $null $g[0]) -ceq 'wfp') 'new-record-red-pulse'
Check ((Get-DenialPulse ([pscustomobject]@{samples=1}) $g[0]) -ceq 'wfp') 'additional-attempt-pulse'
Check ((Get-DenialPulse ([pscustomobject]@{samples=2}) $g[0]) -ceq 'none') 'repaint-not-new-attempt'
Check ((Get-EvidencePulseColor 'wfp') -ceq '#F4A6A6') 'red-background-not-blue'
Check ((Get-EvidencePulseColor 'dns') -ceq '#B9DAF5') 'DNS-unchanged'
Check (Test-MonitorRowVisible $g[0] $true) 'only-present-keeps-WFP'
Check (-not (Test-MonitorRowVisible ([pscustomobject]@{presence='absent'}) $true)) 'only-present-still-filters-absent-TCP'
Check (Test-MonitorRowVisible ([pscustomobject]@{presence='present'}) $true) 'present-TCP-visible'
Check (Test-MonitorRowVisible ([pscustomobject]@{presence='absent'}) $false) 'filter-off'
$copy.ip='1.1.1.1';Check (@(Get-DenialGroups @($e,$copy)).Count -eq 2) 'destinations-distinct'
$copy.ip=$e.ip;$copy.protocol='UDP';Check (@(Get-DenialGroups @($e,$copy)).Count -eq 2) 'protocols-distinct'
$copy.protocol=$e.protocol;$copy.pid=124;Check (@(Get-DenialGroups @($e,$copy)).Count -eq 2) 'PIDs-distinct'
$copy.pid=$e.pid;$copy|Add-Member NoteProperty process_start_ticks '1';Check (@(Get-DenialGroups @($e,$copy)).Count -eq 2) 'births-distinct'
$copy.kind='dns_query';Check (@(Get-DenialGroups @($copy)).Count -eq 0) 'DNS-not-denial'
# Exercise actual pulse-render function with fake row controls, no WinForms invocation.
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-evidence.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in @('Apply-PulseCell','State-Color')){
 $f=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true)
 Invoke-Expression $f.Extent.Text
}
$ink=[Drawing.Color]::Black;$base=State-Color 'wfp_denial_event'
$row=[pscustomobject]@{Cells=@{pulse=[pscustomobject]@{Value='';Tag=$null;Style=[pscustomobject]@{BackColor=[Drawing.Color]::Empty;ForeColor=[Drawing.Color]::Black}}};DefaultCellStyle=[pscustomobject]@{BackColor=$base;SelectionBackColor=$base}}
Apply-PulseCell $row 'wfp' $true
Check ($row.DefaultCellStyle.BackColor.R -eq 244 -and $row.DefaultCellStyle.BackColor.G -eq 166) 'actual-row-background-red'
Check ($row.Cells.pulse.Tag.base -eq $base -and $row.Cells.pulse.Value -ceq '● منع') 'pulse-restores-semantic-base'
$row.DefaultCellStyle.BackColor=$base;Apply-PulseCell $row 'wfp' $false;Check ($row.DefaultCellStyle.BackColor -eq $base -and $row.Cells.pulse.Value -ceq '—') 'history-no-animation'
# WFP baseline identity uses CURRENT path and birth; exited/reused/old PID cannot be guessed.
$script:baselineCutoff=[DateTime]::Parse('2026-10-24T11:59:00Z').ToUniversalTime().Ticks
$script:autoPrograms=@{};$script:newProcesses=@{};$script:baselineTruncated=$false
$script:proc=[pscustomobject]@{Id=123;Path=$p.path;StartTime=[DateTime]::Parse('2026-10-24T11:59:30Z').ToUniversalTime()};$script:exited=$false
function Get-Process {param($Id,$ErrorAction)if($script:exited){throw 'exited'};return $script:proc}
$time=[DateTime]::Parse('2026-10-24T12:00:00Z').ToUniversalTime()
$x=Resolve-BaselineWfp 123 $p.path $time;Check ($null -ne $x -and $x.program.path -ceq $p.path) 'new-process-denied-before-TCP-still-discovered'
Check ($script:newProcesses.Count -eq 1 -and -not $x.program.registered_for_firewall) 'no-auto-registration'
Check ($null -eq (Resolve-BaselineWfp 123 'C:\Other\Game.exe' $time)) 'mismatched-application-rejected'
$script:proc.StartTime=$time.AddSeconds(1);Check ($null -eq (Resolve-BaselineWfp 123 $p.path $time)) 'PID-reused-after-event-rejected'
$script:proc.StartTime=$time.AddMinutes(-2);Check ($null -eq (Resolve-BaselineWfp 123 $p.path $time)) 'pre-baseline-rejected'
$script:exited=$true;Check ($null -eq (Resolve-BaselineWfp 123 $p.path $time)) 'exited-no-identity-no-guess'
Check ($null -eq (Resolve-BaselineWfp 0 $p.path $time)) 'invalid-PID'

# Full log reader in baseline mode, fake Security channel and fake live process identity.
$script:exited=$false;$script:proc.StartTime=$time.AddSeconds(-30)
function Get-WfpDevicePath([string]$Path){if($Path -ieq $p.path){return '\Device\HarddiskVolume1\Apps\Game.exe'};return ''}
Check ($null -ne (Resolve-BaselineWfp 123 '\Device\HarddiskVolume1\Apps\Game.exe' $time)) 'NT-device-path-to-live-DOS-identity'
$start=$time.AddSeconds(-10)
$j=[pscustomobject]@{observation_mode='new_processes';event_programs=@();hosts_baseline=[pscustomobject]@{available=$false;truncated=$false;entries=@()};dns_etw_requested=$false}
$script:fakeLogEvent=[pscustomobject]@{RecordId=200;ProviderName='Microsoft-Windows-Security-Auditing';TimeCreated=$time}
$script:fakeLogEvent|Add-Member ScriptMethod ToXml {return '<Event><EventData><Data Name="Application">\Device\HarddiskVolume1\Apps\Game.exe</Data><Data Name="ProcessID">123</Data><Data Name="Direction">%%14593</Data><Data Name="Protocol">6</Data><Data Name="DestAddress">8.8.8.8</Data><Data Name="DestPort">443</Data><Data Name="FilterRTID">42</Data></EventData></Event>'}
function Get-WinEvent {param($ListLog,$FilterHashtable,$MaxEvents,$ErrorAction)if($ListLog){return [pscustomobject]@{IsEnabled=$true}};return $script:fakeLogEvent}
. (Join-Path $Root 'app/live-events.ps1')
Update-EventEvidence $true
$ev=Event-Evidence
Check ($ev.events.Count -eq 1 -and $ev.events[0].kind -ceq 'wfp_connection_block') 'baseline-full-5157-reader'
Check ($ev.events[0].process_start_ticks -ceq $script:proc.StartTime.Ticks.ToString()) 'birth-carried-through-reader'
Check (-not $ev.persistent_logging_configuration_changed -and -not $ev.configuration_changed) 'reader-never-changes-audit-policy'
Check ($ev.streams.dns.status -ceq 'not_collected') 'baseline-Sysmon-not-guessed'
Update-EventEvidence $true;Check ((Event-Evidence).events.Count -eq 1) 'reader-repeat-deduplicates'
$script:fakeLogEvent.RecordId=201;$script:exited=$true;Update-EventEvidence $true
Check ((Event-Evidence).events.Count -eq 1) 'reader-exited-PID-not-attributed'
$result=@{suite='denial-evidence';passed=$true;assertions=$script:checks;Windows_events_executed=$false;Windows_GUI_executed=$false;environment='PowerShell 7 Linux; grouping, actual pulse function with fake row controls, live-identity reader mocks'}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/denial-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
