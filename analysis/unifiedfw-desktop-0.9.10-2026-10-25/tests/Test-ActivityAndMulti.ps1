param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
. (Join-Path $Root 'app/live-evidence-model.ps1')
. (Join-Path $Root 'app/activity-model.ps1')
. (Join-Path $Root 'app/denial-model.ps1')
$tokens=$null;$errors=$null
function Load-Functions([string]$File,$Names){
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $File),[ref]$tokens,[ref]$errors)
 foreach($name in $Names){$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true);if($null -eq $f){throw ('missing_function: '+$name)};. ([scriptblock]::Create($f.Extent.Text))}
}
# Dot-source loader so extracted definitions live in this script scope.
. Load-Functions 'app/ui-context.ps1' @('Observed-PrefillOptions','Get-ObservedChoices','Merge-WhitelistDraft','Prefill-Observed')
. Load-Functions 'app/ui-evidence.ps1' @('Apply-PulseCell','State-Color','Expire-LivePulses')
$p=[pscustomobject]@{record_id='p';program_id='id';program_path='C:\Apps\Game.exe';pid=123;process_start_ticks='100';presence='present'}
$tcp=[pscustomobject]@{record_id='tcp';program_id='id';program_path=$p.program_path;pid=123;process_start_ticks='100';remote_ip='8.8.8.8';remote_port=443;protocol='TCP';samples=2}
$d=[pscustomobject]@{record_id='dns1';kind='dns_query';program_id='id';program_path=$p.program_path;pid=123;process_start_ticks='100';domain='a.example';query_results='8.8.8.8;1.1.1.1';observed_utc='2026-10-25T00:00:00Z'}
$w=[pscustomobject]@{record_id='w1';kind='wfp_connection_block';event_record_id=12;program_id='id';program_path=$p.program_path;pid=123;process_start_ticks='100';ip='8.8.8.8';port=443;protocol='TCP';filter_id='42';observed_utc='2026-10-25T00:00:01Z'}
$f=[pscustomobject]@{endpoints=@($tcp);event_evidence=[pscustomobject]@{events=@($d,$w)}}
$a=Get-RowActivity $f $p
Check ($a.denied -eq 1 -and $a.dns -eq 1 -and $a.tcp -eq 2) 'process-all-three-sources'
Check ($a.last_target -ceq '8.8.8.8:443 / TCP' -and $a.last_denied -ceq $w.observed_utc) 'last-denial-destination-time'
Check ($a.reason.Contains('42') -and $a.reason.Contains('مشخص نیست')) 'evidence-reason-not-claimed-rule-owner'
Check ((Get-ActivityPulse $null $a) -ceq 'wfp') 'red-over-blue-same-frame'
Check ((Get-ActivityPulse $a $a) -ceq 'none') 'same-frame-no-invented-attempt'
$i=New-ActivityIndex $f;$b=Get-RowActivity $f $p $false $i
Check (($a|ConvertTo-Json -Compress) -ceq ($b|ConvertTo-Json -Compress)) 'index-equals-independent-scan'
$a=Get-RowActivity $f $tcp $true;$b=Get-RowActivity $f $tcp $true $i
Check ($a.denied -eq 1 -and $a.dns -eq 1) 'IP-row-DNS-and-denial'
Check (($a|ConvertTo-Json -Compress) -ceq ($b|ConvertTo-Json -Compress)) 'indexed-IP-agrees'
$other=$tcp.PSObject.Copy();$other.remote_ip='9.9.9.9';$a=Get-RowActivity $f $other $true $i
Check ($a.denied -eq 0 -and $a.dns -eq 0) 'no-DNS-or-WFP-to-unrelated-IP'
$other.remote_ip=$tcp.remote_ip;$other.remote_port=80;$a=Get-RowActivity $f $other $true $i
Check ($a.denied -eq 0 -and $a.dns -eq 1) 'deny-port-exact-DNS-not-transport-proof'
$old=$w.PSObject.Copy();$old.process_start_ticks='99';$dup=$w.PSObject.Copy();$dup.record_id='duplicate'
$f.event_evidence.events=@($old,$w,$dup);$a=Get-RowActivity $f $p
Check ($a.denied -eq 1) 'reused-PID-old-birth-and-duplicate-excluded'
$old=$w.PSObject.Copy();$old.program_path='C:\Other\Game.exe';$f.event_evidence.events=@($old)
Check ((Get-RowActivity $f $p).denied -eq 0) 'full-path-exact-not-filename'
$f.event_evidence.events=@($d);$a=Get-RowActivity $f $p
Check ((Get-ActivityPulse $null $a) -ceq 'dns' -and $a.denied -eq 0) 'DNS-blue-not-red'
$f.event_evidence.events=@();$a=Get-RowActivity $f $p
Check ($a.reason.Contains('نه اثبات') -and $a.denied -eq 0) 'no-evidence-not-allowed'
Check ((Get-ActivityPulse $null $a) -ceq 'sample') 'TCP-blue-not-delivery'
Check (Test-ProcessActivityVisible ([pscustomobject]@{denied=1}) 1 $true 'not_in_latest_snapshot') 'blocked-process-visible-with-only-present'
Check (-not (Test-ProcessActivityVisible ([pscustomobject]@{denied=0}) 1 $false 'present')) 'denial-filter-excludes-no-evidence'
Check (-not (Test-ProcessActivityVisible ([pscustomobject]@{denied=1}) 2 $false 'present')) 'non-denial-filter-excludes-denial'
$f.event_evidence.events=@($d,$w);$script:liveFrame=$f
$x=@(Get-ObservedChoices @([pscustomobject]@{Tag=$p},[pscustomobject]@{Tag=$p}) 'process')
Check ($x.Count -eq 2) 'multiple-processes-deduplicate-domain-and-IP'
$d2=$d.PSObject.Copy();$d2.domain='b.example';$d2.record_id='dns2';$f.event_evidence.events=@($d,$d2,$w)
$x=@(Get-ObservedChoices @([pscustomobject]@{Tag=$p}) 'process')
Check ($x.Count -eq 3 -and @($x|Where-Object{$_.type -ceq 'domain'}).Count -eq 2) 'one-process-multiple-domains'
$base="existing.example`r`n8.8.8.8";$merged=Merge-WhitelistDraft $base $x
Check ($merged.StartsWith($base+"`r`n") -and @($merged -split '\r?\n').Count -eq 4) 'append-not-overwrite-and-dedup'
Check ((Merge-WhitelistDraft $merged $x) -ceq $merged) 'repeat-transfer-idempotent'
Check ((Merge-WhitelistDraft 'A.EXAMPLE' @([pscustomobject]@{value='a.example'})) -ceq 'A.EXAMPLE') 'case-insensitive-domain-dedup'
$bad=$false;try{$null=Merge-WhitelistDraft $base @([pscustomobject]@{value="bad`nvalue"})}catch{$bad=$true};Check $bad 'newline-injection-refused'
$many=@(1..1025|ForEach-Object{[pscustomobject]@{value=('a'+$_+'.example')}});$bad=$false;try{$null=Merge-WhitelistDraft '' $many}catch{$bad=$true};Check $bad 'bounded-merge-no-silent-partial'
# End-to-end transfer function with non-GUI controls; dialog mocked to choose all candidates.
$script:state='unchanged';$script:job=[pscustomobject]@{action='baseline_record'}
function Select-WhitelistChoices($Options,$Owner){return ,@($Options)}
$grid=[pscustomobject]@{SelectedRows=@([pscustomobject]@{Tag=$p})};$grid|Add-Member ScriptMethod FindForm {return $null}
$whitelist=[pscustomobject]@{Text=$base};$whitelist|Add-Member ScriptMethod Focus {}
$form=[pscustomobject]@{};$form|Add-Member ScriptMethod BringToFront {}
$tabs=[pscustomobject]@{SelectedTab=$null};$policyTab='policy';$status=[pscustomobject]@{Text=''}
Prefill-Observed $grid 'process' 'whitelist'
Check ($whitelist.Text -ceq $merged -and $tabs.SelectedTab -ceq 'policy') 'multi-transfer-actual-handler-appends'
Check ($script:state -ceq 'unchanged' -and $script:job.action -ceq 'baseline_record') 'no-save-no-stop-no-apply'
# Actual full-row pulse / expiry functions using fake row/grid, including process grids.
$ink=[Drawing.Color]::Black;$baseColor=State-Color 'wfp_denial_event'
$row=[pscustomobject]@{Cells=@{pulse=[pscustomobject]@{Value='';Tag=$null;Style=[pscustomobject]@{BackColor=[Drawing.Color]::Empty;ForeColor=$ink}}};DefaultCellStyle=[pscustomobject]@{BackColor=$baseColor;SelectionBackColor=$baseColor}}
Apply-PulseCell $row 'dns' $true
Check ($row.DefaultCellStyle.BackColor.ToArgb() -eq [Drawing.ColorTranslator]::FromHtml('#FBE6B7').ToArgb()) 'DNS-full-row-amber-not-connection'
$row.DefaultCellStyle.BackColor=$baseColor;$row.DefaultCellStyle.SelectionBackColor=$baseColor
Apply-PulseCell $row 'wfp' $true
Check ($row.DefaultCellStyle.BackColor.ToArgb() -eq [Drawing.ColorTranslator]::FromHtml('#F4A6A6').ToArgb()) 'denial-full-row-red'
$row.Cells.pulse.Tag.until=[DateTime]::UtcNow.AddSeconds(-1)
$liveGrid=[pscustomobject]@{Rows=@()};$popupGrid=$liveGrid;$domainMain=$liveGrid;$domainPopup=$liveGrid;$processGrid=[pscustomobject]@{Rows=@($row)};$popupProcessGrid=$liveGrid;$flash=[pscustomobject]@{Checked=$true}
Expire-LivePulses
Check ($row.DefaultCellStyle.BackColor -eq $baseColor -and $null -eq $row.Cells.pulse.Tag) 'process-pulse-expires-restores-base'
$src=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-context.ps1'))
Check ($src.Contains('if(-not $sender.Rows[$e.RowIndex].Selected)') -and $src.Contains('SelectedRows.Count -eq 0')) 'right-click-retains-multi-selection'
Check ($src.Contains('CheckedListBox') -and $src.Contains('انتخاب همه')) 'multi-picker-with-select-all'
$layout=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-layout.ps1'));$baseline=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-baseline.ps1'))
Check ($layout.Contains('Add-ToolControl $monitorTools $processActivityFilter') -and -not $baseline.Contains('Add-ToolControl $monitorTools')) 'attach-tools-only-after-panels-created'
$r=@{suite='baseline-activity-and-multi-transfer';passed=$true;assertions=$script:checks;Windows_GUI_executed=$false;Windows_events_executed=$false;environment='PowerShell 7.4.6 Linux, actual functions with mock controls'}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/activity-multi-tests.json'),(ConvertTo-Json $r));$r|ConvertTo-Json -Compress
