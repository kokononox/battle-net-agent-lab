param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$b,[string]$n){if(-not $b){throw ('test_failed: '+$n)};$script:checks++}
. (Join-Path $Root 'app/live-evidence-model.ps1')
. (Join-Path $Root 'app/live-model.ps1')
. (Join-Path $Root 'app/denial-model.ps1')
. (Join-Path $Root 'app/activity-model.ps1')
. (Join-Path $Root 'app/activity-display-model.ps1')
. (Join-Path $Root 'app/row-update-model.ps1')
$t=$null;$errors=$null
foreach($spec in @(@('ui-evidence.ps1',@('Apply-PulseCell','State-Color','Render-Domains','Expire-LivePulses')),@('ui-baseline.ps1',@('Render-NewProcesses')))){
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root ('app/'+$spec[0])),[ref]$t,[ref]$errors)
 foreach($name in $spec[1]){$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true);. ([scriptblock]::Create($node.Extent.Text))}
}
Add-Type -TypeDefinition @'
using System;using System.Collections;using System.Collections.Generic;
public class DisplayStyle {public object BackColor;public object SelectionBackColor;public object SelectionForeColor;public object ForeColor;}
public class DisplayCell {public object Value;public object Tag;public string ToolTipText;public DisplayStyle Style=new DisplayStyle();}
public class DisplayRow {public object Tag;public bool Selected;public Dictionary<string,DisplayCell> Cells=new Dictionary<string,DisplayCell>();public DisplayStyle DefaultCellStyle=new DisplayStyle();public DisplayRow(){foreach(string n in new[]{"pulse","domain","ips","program","rule","count","status","hosts","time","source","name","activity","denied","lastDenied","lastTarget","reason","pid","birth","path","presence","first","last","trust"})Cells[n]=new DisplayCell();}}
public class DisplayRows:IEnumerable {private List<DisplayRow> rows=new List<DisplayRow>();public int Count{get{return rows.Count;}}public DisplayRow this[int i]{get{return rows[i];}}public int Add(){rows.Add(new DisplayRow());return rows.Count-1;}public void RemoveAt(int i){rows.RemoveAt(i);}public IEnumerator GetEnumerator(){return rows.GetEnumerator();}}
public class DisplayGrid {public DisplayRows Rows=new DisplayRows();public int FirstDisplayedScrollingRowIndex=-1;public void SuspendLayout(){}public void ResumeLayout(){}}
'@
$ink=[Drawing.Color]::Black;$flash=[pscustomobject]@{Checked=$true};$liveFilter=[pscustomobject]@{Text=''};$script:liveFinal=$false;$onlyPresent=[pscustomobject]@{Checked=$false};$processActivityFilter=[pscustomobject]@{SelectedIndex=0};$popupActivityFilter=[pscustomobject]@{SelectedIndex=0};$script:processMainSeen=@{};$script:processPopupSeen=@{}
$p=[pscustomobject]@{record_id='p1';program_id='app';program_path='C:\Apps\Game.exe';pid=100;process_start_ticks='100';presence='present';first_seen_utc='2026-10-25T00:00:00Z';last_seen_utc='2026-10-25T00:00:03Z'}
$d=[pscustomobject]@{record_id='d1';kind='dns_query';program_id='app';program_path=$p.program_path;pid=100;process_start_ticks='100';domain='a.example';query_results='8.8.8.8';observed_utc='2026-10-25T00:00:01Z';dns_status='0';dns_phase='query_completed';hosts_mapping='not_listed';hosts_addresses=@();source='DNSClient_ETW'}
$d2=$d.PSObject.Copy();$d2.record_id='d2';$d2.domain='A.EXAMPLE.';$d2.observed_utc='2026-10-25T00:00:02Z'
$w=[pscustomobject]@{record_id='w';kind='wfp_connection_block';event_record_id=7;program_id='app';program_path=$p.program_path;pid=100;process_start_ticks='100';ip='8.8.8.8';port=443;protocol='TCP';filter_id='42';observed_utc='2026-10-25T00:00:03Z'}
function Frame($Events,$Processes=@($p)){return [pscustomobject]@{schema='unified-new-process-monitor-1';processes=@($Processes);endpoints=@();event_evidence=[pscustomobject]@{events=@($Events)}}}
$f=Frame @($d,$d2,$d2,$w)
$x=@(Get-DomainDisplayRows $f)
Check ($x.Count -eq 1 -and $x[0].events_count -eq 2) 'same-domain-case-trailing-dot-updates-one-row'
Check ($x[0].denied_count -eq 1 -and $x[0].activity_state -ceq 'denied') 'actual-related-WFP-labelled'
Check ($x[0].activity_label.Contains('نه اثبات منع خود DNS')) 'not-claiming-query-block-proof'
Check ($x[0].observed_utc -ceq $d2.observed_utc) 'last-time-updated'
$bad=$w.PSObject.Copy();$bad.process_start_ticks='99';$x=@(Get-DomainDisplayRows (Frame @($d,$bad)))
Check ($x[0].denied_count -eq 0) 'PID-reuse-not-correlated'
$bad=$w.PSObject.Copy();$bad.observed_utc='2026-10-25T00:00:00Z';$x=@(Get-DomainDisplayRows (Frame @($d,$bad)))
Check ($x[0].denied_count -eq 0) 'older-denial-not-correlated-to-new-answer'
$bad=$w.PSObject.Copy();$bad.ip='1.1.1.1';$x=@(Get-DomainDisplayRows (Frame @($d,$bad)))
Check ($x[0].denied_count -eq 0) 'unrelated-IP-not-correlated'
$fail=$d.PSObject.Copy();$fail.dns_status='9003';$fail.query_results='';$x=@(Get-DomainDisplayRows (Frame @($fail)))
Check ($x[0].activity_state -ceq 'dns_error' -and $x[0].denied_count -eq 0) 'DNS-error-not-firewall-denial'
$pending=$d.PSObject.Copy();$pending.dns_phase='query_called';$pending.dns_status='0';$pending.query_results='';$x=@(Get-DomainDisplayRows (Frame @($pending)))
Check ($x[0].activity_state -ceq 'pending' -and $x[0].denied_count -eq 0) 'query-start-zero-code-not-success-proof'
$other=$d2.PSObject.Copy();$other.program_path='C:\Other\Game.exe';$other.program_id='other';$x=@(Get-DomainDisplayRows (Frame @($d,$other,$w)))
Check ($x.Count -eq 2) 'same-filename-other-exe-separated'
$processGrid=New-Object DisplayGrid;$domain=New-Object DisplayGrid;$seen=@{}
Render-Domains $domain (Frame @($d)) $seen $true $true
Check ($domain.Rows.Count -eq 1) 'first-DNS-row-added'
$row=$domain.Rows[0];$until=$row.Cells['pulse'].Tag.until;$blue=$row.DefaultCellStyle.BackColor
Render-Domains $domain (Frame @($d)) $seen $true $true
Check ([object]::ReferenceEquals($row,$domain.Rows[0])) 'same-DNS-row-object-updated'
Check ($row.Cells['pulse'].Tag.until -eq $until -and $row.DefaultCellStyle.BackColor -eq $blue) 'blue-pulse-survives-refresh-without-restart'
Render-Domains $domain (Frame @($d,$d2,$w)) $seen $true $true
Check ($domain.Rows.Count -eq 1 -and $row.Cells['count'].Value -ceq '2 / 1') 'repeat-count-and-denial-updated-in-place'
Check ($row.Cells['pulse'].Value -ceq '● منع') 'new-WFP-red-whole-row'
Check ($row.DefaultCellStyle.BackColor.ToArgb() -eq $row.DefaultCellStyle.SelectionBackColor.ToArgb()) 'selection-keeps-visible-pulse'
$before=$row.Cells['pulse'].Tag.until;Render-Domains $domain (Frame @($d,$d2,$w)) $seen $true $true
Check ($row.Cells['pulse'].Tag.until -eq $before) 'red-pulse-not-reset-by-unchanged-frame'
# One EXE stays on its own display row across PID births; raw instances remain attached.
$p2=$p.PSObject.Copy();$p2.record_id='p2';$p2.pid=200;$p2.process_start_ticks='200';$p2.last_seen_utc='2026-10-25T00:00:04Z'
$x=@(Get-ProcessDisplayRows (Frame @($d,$w) @($p,$p2,$p2)))
Check ($x.Count -eq 1 -and $x[0].instance_count -eq 2) 'repeated-process-one-display-row-two-identities'
Check ($x[0].activity.denied -eq 1 -and $x[0].instances.Count -eq 2) 'raw-identities-retained-no-double-count'
Render-NewProcesses $processGrid (Frame @($d) @($p));$pr=$processGrid.Rows[0]
Render-NewProcesses $processGrid (Frame @($d,$w) @($p,$p2))
Check ($processGrid.Rows.Count -eq 1 -and [object]::ReferenceEquals($pr,$processGrid.Rows[0])) 'same-process-row-object-preserved'
Check ($pr.Cells['denied'].Value -eq 1 -and $pr.Tag.instance_count -eq 2) 'process-row-counters-updated'
$otherP=$p2.PSObject.Copy();$otherP.program_path='C:\Other\Game.exe';$otherP.program_id='other'
Check (@(Get-ProcessDisplayRows (Frame @() @($p,$otherP))).Count -eq 2) 'different-full-path-never-merged'
$liveFilter.Text='no-match';Render-Domains $domain (Frame @($d,$d2,$w)) $seen $true $true
Check ($domain.Rows.Count -eq 0 -and $seen.Count -eq 1) 'filter-removes-display-not-seen-evidence'
$liveFilter.Text='';Render-Domains $domain (Frame @($d,$d2,$w)) $seen $true $true
Check ($null -eq $domain.Rows[0].Cells['pulse'].Tag) 'filter-return-does-not-fake-new-event'
$result=@{suite='grouped-DNS-process-and-persistent-row-pulses';passed=$true;assertions=$script:checks;production_renderers_executed_with_fake_grid=$true;Windows_GUI_executed=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/grouped-display-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
