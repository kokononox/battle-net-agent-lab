# UI-only evidence presentation. Row-background pulse restores the exact semantic base color.
. (Join-Path $PSScriptRoot 'live-evidence-model.ps1')
. (Join-Path $PSScriptRoot 'denial-model.ps1')
. (Join-Path $PSScriptRoot 'activity-display-model.ps1')
. (Join-Path $PSScriptRoot 'row-update-model.ps1')
$script:domainMainSeen=@{};$script:domainPopupSeen=@{};$script:ptrJob=$null;$script:ptrCache=@{}
function New-EvidenceTabs($Parent,[int]$Row,$IpGrid){
 $t=New-Object Windows.Forms.TabControl;$t.Dock='Fill'
 $a=New-Object Windows.Forms.TabPage;$a.Text='IP / نمونهٔ TCP و منع WFP';$a.BackColor=[Drawing.Color]::White;$a.Controls.Add($IpGrid);[void]$t.TabPages.Add($a)
 $b=New-Object Windows.Forms.TabPage;$b.Text='دامنه / رویدادهای DNS';$b.BackColor=[Drawing.Color]::White;[void]$t.TabPages.Add($b)
 $Parent.Controls.Add($t,0,$Row);return $t
}
$mainLiveTabs=New-EvidenceTabs $m 2 $liveGrid;$popupLiveTabs=New-EvidenceTabs $pv 2 $popupGrid
function Configure-IPGrid($Grid){
 foreach($c in @(@('pulse','پالس'),@('rule','وضعیت / مبنای رنگ'),@('dns','دامنهٔ DNS مرتبط — نه اثبات نام سوکت'),@('ptr','نام PTR — نه دامنهٔ درخواست'),@('source','منبع'))){
  $col=New-Object Windows.Forms.DataGridViewTextBoxColumn;$col.Name=$c[0];$col.HeaderText=$c[1];$col.ReadOnly=$true;$col.SortMode='NotSortable';[void]$Grid.Columns.Add($col)
 }
 $Grid.Columns['pulse'].DisplayIndex=0;$Grid.Columns['program'].DisplayIndex=1;$Grid.Columns['destination'].DisplayIndex=2;$Grid.Columns['rule'].DisplayIndex=3;$Grid.Columns['dns'].DisplayIndex=4;$Grid.Columns['ptr'].DisplayIndex=5;$Grid.Columns['source'].DisplayIndex=6
 $Grid.AutoSizeColumnsMode='None';foreach($c in $Grid.Columns){$c.Width=160};$Grid.Columns['pulse'].Width=85;$Grid.Columns['program'].Width=170;$Grid.Columns['destination'].Width=180;$Grid.Columns['rule'].Width=260;$Grid.Columns['dns'].Width=240;$Grid.Columns['ptr'].Width=240;$Grid.Columns['samples'].Width=105;$Grid.Columns['samples'].HeaderText='نمونه / تعداد منع';$Grid.Columns['first'].Width=210;$Grid.Columns['last'].Width=210
 $Grid.Columns['pulse'].Visible=$false
 $Grid.AccessibleName='Sampled TCP and logged WFP IP evidence; rule colors from timestamped owned snapshot, not allow/block packet certification'
}
Configure-IPGrid $liveGrid;Configure-IPGrid $popupGrid
function New-DomainGrid {
 $v=Grid @(@('pulse','پالس DNS'),@('domain','دامنهٔ درخواست DNS'),@('ips','IP در پاسخ ثبت‌شده'),@('program','برنامه / PID'),@('rule','وضعیت منع / مبنا'),@('count','رویداد / منع مرتبط'),@('status','آخرین نتیجهٔ DNS'),@('hosts','hosts در شروع رصد؛ نه اثبات منع'),@('time','زمان رویداد UTC'),@('source','منبع / انتساب'))
 $v.ReadOnly=$true;$v.RightToLeft='No';$v.AutoSizeColumnsMode='None';$v.AutoSizeRowsMode='None';$v.RowTemplate.Height=34
 foreach($c in $v.Columns){$c.Width=180};$v.Columns['pulse'].Visible=$false;$v.Columns['pulse'].Width=90;$v.Columns['domain'].Width=240;$v.Columns['rule'].Width=330;$v.Columns['count'].Width=120;$v.Columns['status'].Width=160;$v.Columns['domain'].DisplayIndex=1;$v.Columns['rule'].DisplayIndex=2;$v.Columns['count'].DisplayIndex=3;$v.Columns['status'].DisplayIndex=4;$v.Columns['ips'].DisplayIndex=5;$v.Columns['program'].DisplayIndex=6;$v.Columns['ips'].Width=280;$v.Columns['time'].Width=220;$v.Columns['source'].Width=280;$v.Columns['hosts'].Width=260
 $v.AccessibleName='DNS-Client live ETW and existing Sysmon query events for selected exact executable paths; PTR is not a query event';return $v
}
$domainMain=New-DomainGrid;$domainPopup=New-DomainGrid
$domainMainPanel=Stack $mainLiveTabs.TabPages[1] 2;$domainPopupPanel=Stack $popupLiveTabs.TabPages[1] 2
$domainMainHint=Label 'برای DNS زنده، گزینهٔ DNS مستقل را روشن کنید و رصد را با Administrator شروع کنید.';$domainPopupHint=Label $domainMainHint.Text
$domainMainPanel.Controls.Add($domainMainHint,0,0);$domainMainPanel.Controls.Add($domainMain,0,1);$domainPopupPanel.Controls.Add($domainPopupHint,0,0);$domainPopupPanel.Controls.Add($domainPopup,0,1)
function Dns-StatusHint($Frame){
 if($Frame.event_evidence.PSObject.Properties.Name -notcontains 'dns_trace'){return 'این سابقه DNS زندهٔ مستقل ندارد؛ فقط رویدادهای قبلی Sysmon نمایش داده می‌شوند.'}
 $d=$Frame.event_evidence.dns_trace
 switch([string]$d.status){
  'start_failed'{return ('DNS زنده شروع نشد: '+$d.error_code+'؛ اگر Administrator لازم است، Start.cmd را با Run as administrator باز کنید و رصد تازه بگیرید.')}
  'running_realtime_coverage_unverified'{return ('DNS زنده فعال | رویداد منتخب: '+$d.selected_events+' | درخواست و پایان درخواست دو رویدادند. پس از شروع رصد برنامه را باز/فعال کنید؛ DNS کش‌شده، DoH داخلی و EXE کمکی پوشش قطعی ندارند.')}
  'not_requested'{return 'DNS مستقل خاموش است؛ اگر Sysmon هم داده ندهد جدول خالی می‌ماند. گزینهٔ DNS زنده مستقل را فعال و رصد تازه را با Administrator شروع کنید.'}
  'stopped'{return ('DNS ثبت‌شده / پایان رصد | رویداد منتخب: '+$d.selected_events+'؛ خالی‌بودن اثبات نبودن DNS نیست.')}
  default{return ('وضعیت DNS زنده: '+$d.status+' / '+$d.error_code+' | پاکسازی لازم: '+$d.cleanup_required)}
 }
}

$evidenceLegend=$pv.GetControlFromPosition(0,3);$evidenceLegend.Text='رنگ ثابت: قرمز = رویداد واقعی منع WFP؛ نارنجی = Block در snapshot یا نامعلوم؛ سبز = بدون Block مطابقِ این ابزار در snapshot (نه تضمین آزادبودن)؛ نارنجی = نامعلوم / نگاشت hosts. پالس تمام پس‌زمینهٔ ردیف: آبی = فعالیت TCP/DNS مشاهده‌شده، نه رسیدن درخواست به مقصد؛ قرمز = رویداد جدید منع اتصال در لاگ ویندوز؛ تعداد، رویداد یکتاست نه بسته. منع الزاماً از قاعدهٔ این ابزار نیست. TCP فقط نمونه، DNS فقط رویداد درخواست DNS؛ هیچ‌کدام شمارش ارسال یا HTTP نیست.'
$evidenceLegend.Font=New-Object Drawing.Font('Tahoma',9);$evidenceLegend.ForeColor=[Drawing.ColorTranslator]::FromHtml('#57677C')
$ptrPick=Button 'PTR برای IPهای انتخابی';$ptrAll=Button 'PTR حداکثر ۱۰۰ IP';$ptrStop=Button 'توقف PTR';$ptrForce=New-Object Windows.Forms.CheckBox;$ptrForce.AutoSize=$true;$ptrForce.Text='PTR تازه، بدون کش'
foreach($c in @($ptrPick,$ptrAll,$ptrStop,$ptrForce)){$mb.Controls.Add($c)}
$popupPtrPick=Button 'PTR انتخاب IP';$popupPtrAll=Button 'PTR حداکثر ۱۰۰ IP';$popupPtrStop=Button 'توقف PTR';$popupPtrForce=New-Object Windows.Forms.CheckBox;$popupPtrForce.Text='PTR تازه، بدون کش';$popupPtrForce.AutoSize=$true
foreach($c in @($popupPtrPick,$popupPtrAll,$popupPtrStop,$popupPtrForce)){$popupOptions.Controls.Add($c)}
$popupPtrForce.Add_CheckedChanged({if($ptrForce.Checked -ne $popupPtrForce.Checked){$ptrForce.Checked=$popupPtrForce.Checked}})
$ptrForce.Add_CheckedChanged({if($popupPtrForce.Checked -ne $ptrForce.Checked){$popupPtrForce.Checked=$ptrForce.Checked}})
$ptrMainStatus=Label 'PTR اختیاری است؛ از DNS سیستم فقط نام معکوس IP خوانده می‌شود.';$mb.Controls.Add($ptrMainStatus)
$ptrPopupStatus=Label 'PTR اختیاری است؛ نام معکوس IP، نه دامنهٔ درخواست.';$popupOptions.Controls.Add($ptrPopupStatus)
function Set-PtrStatus([string]$Text){$ptrMainStatus.Text=$Text;$ptrPopupStatus.Text=$Text;$popupPtrPick.AccessibleDescription=$Text}
function Set-EvidenceControls {
 $can=($null -eq $script:ptrJob -and ($null -eq $script:job -or $script:job.action -in @('monitor_record','baseline_record')))
 foreach($v in @($ptrPick,$ptrAll,$ptrForce,$popupPtrPick,$popupPtrAll,$popupPtrForce)){$v.Enabled=$can};foreach($v in @($ptrStop,$popupPtrStop)){$v.Enabled=($null -ne $script:ptrJob)}
 if($null -ne $script:ptrJob){$apply.Enabled=$false;$restore.Enabled=$false}
}
function State-Color([string]$State){
 switch($State){
  'verified_owned_block_snapshot'{return [Drawing.ColorTranslator]::FromHtml('#FFF1DC')}
  'wfp_denial_event'{return [Drawing.ColorTranslator]::FromHtml('#FCE9E7')}
  'no_matching_owned_block_snapshot'{return [Drawing.ColorTranslator]::FromHtml('#E8F1EC')}
  default{return [Drawing.ColorTranslator]::FromHtml('#FFF1DC')}
 }
}
function Apply-PulseCell($Row,[string]$Kind,[bool]$Enabled){
 $Row.Cells['pulse'].Value='—';$Row.Cells['pulse'].Style.BackColor=[Drawing.Color]::Empty
 if(-not $Enabled -or $Kind -ceq 'none'){return}
 $text=switch($Kind){'dns'{'● DNS'};'wfp'{'● منع'};'discovery'{'● تازه'};'reappeared'{'● بازگشت'};default{'● نمونه'}}
 $Row.Cells['pulse'].Value=$text;$base=$Row.DefaultCellStyle.BackColor;$selection=$Row.DefaultCellStyle.SelectionBackColor
 $color=[Drawing.ColorTranslator]::FromHtml((Get-EvidencePulseColor $Kind))
 $Row.Cells['pulse'].Tag=@{until=[DateTime]::UtcNow.AddMilliseconds($(if($Kind -ceq 'wfp'){1800}else{1400}));base=$base;selection=$selection}
 $Row.DefaultCellStyle.BackColor=$color;$Row.DefaultCellStyle.SelectionBackColor=$color;$Row.Cells['pulse'].Style.ForeColor=$ink
}
function Monitor-IPRows($Frame){
 $rows=New-Object Collections.Generic.List[object]
 foreach($r in @($Frame.endpoints)){$rows.Add($r)}
 if($Frame.PSObject.Properties.Name -contains 'event_evidence'){
  foreach($row in @(Get-DenialGroups $Frame.event_evidence.events)){$rows.Add($row)}
 };return ,@($rows.ToArray())
}
function Ptr-Text([string]$IP){
 if(-not $script:ptrCache.ContainsKey($IP)){return 'بررسی نشده'}
 $p=$script:ptrCache[$IP];$age=([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge [double]$p.expires_utc)
 $text=if($p.status -ceq 'found'){@($p.names) -join ', '}else{[string]$p.status}
 return $text+$(if($age){' [کش قدیمی]'}elseif($p.cached){' [کش]'}else{''})
}
function Render-LiveGrid($Grid,$Frame,[hashtable]$Seen,[bool]$Pulse,[bool]$Follow,[bool]$Filtered){
 $selected=@{};foreach($r in $Grid.SelectedRows){if($null -ne $r.Tag){$selected[[string]$r.Tag.record_id]=$true}}
 $scroll=$Grid.FirstDisplayedScrollingRowIndex;$Grid.SuspendLayout();$all=Monitor-IPRows $Frame
 try{
  $Grid.Rows.Clear();$count=0
  foreach($r in @($all|Sort-Object @{Expression='last_seen_utc';Descending=$true},@{Expression='record_id';Descending=$false})){
   if($Filtered -and -not (Test-MonitorRowVisible $r $onlyPresent.Checked)){continue}
   $destination=([string]$r.remote_ip)+':'+[string]$r.remote_port+' / '+[string]$r.protocol
   $names=if($r.PSObject.Properties.Name -contains 'dns_names'){@($r.dns_names) -join ', '}else{''}
   if($Filtered -and $liveFilter.Text.Trim() -and ($destination+' '+$r.program_path+' '+$r.pid+' '+$names+' '+(Ptr-Text $r.remote_ip)).IndexOf($liveFilter.Text.Trim(),[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
   $count++;if($count -gt 2000){continue}
   $event=($r.PSObject.Properties.Name -contains 'kind' -and $r.kind -ceq 'wfp_connection_block')
   $presence=if($event){'تلاش منع‌شدهٔ ثبت‌شده'}else{switch([string]$r.presence){'present'{'حاضر در نمونه'};'absent'{'در نمونه نبود'};default{'نامعلوم'}}}
   $state=if($r.PSObject.Properties.Name -contains 'rule_state'){[string]$r.rule_state}else{'unknown'}
   $activity=$null
   if($event){$pulseKind=Get-DenialPulse $Seen[[string]$r.record_id] $r}else{
    $activity=Get-RowActivity $Frame $r $true (Get-FrameActivityIndex $Frame)
    $old=$Seen[[string]$r.record_id];$oldActivity=if($null -ne $old -and $old.PSObject.Properties.Name -contains 'activity'){$old.activity}else{$null}
    $pulseKind=Get-ActivityPulse $oldActivity $activity
    if($pulseKind -cnotin @('wfp','dns')){$pulseKind=Get-LivePulse $old $r}
    if($activity.denied -gt 0){$state='wfp_denial_event'}
   }
   $i=$Grid.Rows.Add(([IO.Path]::GetFileName([string]$r.program_path)+' / '+$r.pid),$destination,$presence,$(if($event){([string]$r.samples)+' منع'}else{$r.samples}),(($r.states.PSObject.Properties|ForEach-Object{$_.Name+':'+$_.Value}) -join ', '),$r.first_seen_utc,$r.last_seen_utc)
   $row=$Grid.Rows[$i];$row.Tag=$r;$row.Cells['program'].ToolTipText=$r.program_path+' | process_start_ticks='+$r.process_start_ticks
   $row.Cells['rule'].Value=if($event -and $r.PSObject.Properties.Name -contains 'denial_reason'){$r.denial_reason}elseif($null -ne $activity -and $activity.denied -gt 0){$activity.reason}else{Monitor-RuleLabel $state};$row.Cells['dns'].Value=$(if($names){$names}else{'نام DNS مرتبط ثبت نشده'});$row.Cells['ptr'].Value=Ptr-Text $r.remote_ip;$row.Cells['source'].Value=$(if($event){'Security 5157'}else{'TCP sample'})
   $row.Cells['dns'].ToolTipText='پالس آبی یعنی رویداد DNS مرتبط یا نمونهٔ TCP؛ نه تأیید تحویل درخواست. DNS با همان مسیر و PID و IP در پاسخ، از تولد فرایند تا آخرین نمونه؛ اثبات دامنهٔ همین سوکت نیست.'
   $row.Cells['rule'].ToolTipText=$(if($event){'منع اتصال خروجی ثبت‌شده در Security 5157؛ شمارش رویدادهای یکتای همین ثبت محدود است، نه بسته/HTTP. عامل منع الزاماً قاعدهٔ این ابزار نیست. زمان رویداد UTC را ببینید؛ تحویل لاگ ممکن است تأخیر داشته باشد.'}else{'وضعیت در snapshot زمان‌دار همین ابزار است، نه وضعیت تمام قواعد ویندوز یا تضمین افت بسته.'})
   $base=State-Color $state;$row.DefaultCellStyle.BackColor=$base;$row.DefaultCellStyle.SelectionBackColor=$base;$row.DefaultCellStyle.SelectionForeColor=$ink
   $row.DefaultCellStyle.SelectionBackColor=[Drawing.Color]::FromArgb([Math]::Max(0,$base.R-18),[Math]::Max(0,$base.G-18),[Math]::Max(0,$base.B-18))
   Apply-PulseCell $row $pulseKind $Pulse
  }
  $Grid.ClearSelection();foreach($r in $Grid.Rows){if($selected.ContainsKey([string]$r.Tag.record_id)){$r.Selected=$true}}
  if($Grid.Rows.Count -gt 0){if($Follow){$Grid.FirstDisplayedScrollingRowIndex=0}elseif($scroll -ge 0){$Grid.FirstDisplayedScrollingRowIndex=[Math]::Min($scroll,$Grid.Rows.Count-1)}}
 }finally{$Grid.ResumeLayout()}
 $Seen.Clear();foreach($r in $all){$Seen[[string]$r.record_id]=[pscustomobject]@{presence=$r.presence;samples=$r.samples;activity=$(if($r.PSObject.Properties.Name -contains 'kind' -and $r.kind -ceq 'wfp_connection_block'){$null}else{Get-RowActivity $Frame $r $true (Get-FrameActivityIndex $Frame)})}}
}
function Render-Domains($Grid,$Frame,[hashtable]$Seen,[bool]$Pulse,[bool]$Filtered){
 $scroll=$Grid.FirstDisplayedScrollingRowIndex;$visible=@{};$next=@{};$rowsByKey=@{};foreach($existing in $Grid.Rows){if($null -ne $existing.Tag){$rowsByKey[[string]$existing.Tag.record_id]=$existing}}
 $Grid.SuspendLayout();try{
  foreach($e in @(Get-DomainDisplayRows $Frame|Sort-Object observed_utc -Descending)){
   $key=[string]$e.record_id;$next[$key]=$e.snapshot;$ips=Get-MonitorResultIPs ([string]$e.query_results)
   if($Filtered -and $liveFilter.Text.Trim() -and ($e.domain+' '+($ips -join ', ')+' '+$e.program_path+' '+$e.display_pids).IndexOf($liveFilter.Text.Trim(),[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
   $visible[$key]=$true;$row=Get-OrAddDisplayRow $Grid $key $rowsByKey;$row.Tag=$e
   $values=@{domain=$e.domain;ips=($ips -join ', ');program=([IO.Path]::GetFileName([string]$e.program_path)+' / PID '+$e.display_pids);rule=$e.activity_label;count=([string]$e.events_count+' / '+[string]$e.denied_count);status=('DNS: '+$e.dns_status+$(if($e.PSObject.Properties.Name -contains 'dns_phase'){' / '+$e.dns_phase}else{''}));hosts=([string]$e.hosts_mapping+' '+(@($e.hosts_addresses) -join ', '));time=$e.observed_utc;source=$(if($e.PSObject.Properties.Name -contains 'source' -and $e.source -ceq 'DNSClient_ETW'){'DNS-Client ETW / مسیر و PID زنده'}else{'Sysmon 22 / مسیر دقیق در لاگ'})}
   foreach($name in $values.Keys){$row.Cells[$name].Value=$values[$name]}
   $row.Cells['program'].ToolTipText=$e.program_path;$row.Cells['ips'].ToolTipText=[string]$e.query_results
   $row.Cells['hosts'].ToolTipText='snapshot شروع رصد؛ وضعیت اکنون یا اثبات منع نیست.'
   $row.Cells['rule'].ToolTipText='قرمز: Security 5157 با همان مسیر، PID و تولد فرایند، روی IP پاسخ DNS و بعد از آن. ارتباط IP است؛ دامنهٔ دقیق سوکت یا علت شکست خود پرس‌وجو را ثابت نمی‌کند. آخرین منع UTC: '+$e.last_denied
   $row.Cells['count'].ToolTipText='تعداد رویدادهای یکتای نگه‌داری‌شده، نه تعداد بسته یا درخواست؛ query_called و query_completed رویدادهای جدا هستند.'
   $state=if($e.activity_state -ceq 'denied'){'wfp_denial_event'}elseif($e.activity_state -in @('dns_error','hosts_mapping')){'unknown'}else{'dns_neutral'}
   $base=if($state -ceq 'dns_neutral'){[Drawing.ColorTranslator]::FromHtml('#EDF3FA')}else{State-Color $state}
   $row.DefaultCellStyle.SelectionForeColor=$ink;Set-ActivityRowStyle $row $base (Get-ActivityPulse $Seen[$key] $e.snapshot) $Pulse
  }
  Remove-OldDisplayRows $Grid $visible
  if($Grid.Rows.Count -gt 0 -and $scroll -ge 0){$Grid.FirstDisplayedScrollingRowIndex=[Math]::Min($scroll,$Grid.Rows.Count-1)}
  $Seen.Clear();foreach($key in $next.Keys){$Seen[$key]=$next[$key]}
 }finally{$Grid.ResumeLayout()}
}
# Override frame rendering so both main view and popup keep separate IP/domain tabs.
function Render-Popup {
 if($null -eq $script:liveFrame -or -not $livePopup.Visible){return}
 $popupStatus.Text=Live-StatusText $script:liveFrame
 if($pause.Checked -and -not $script:liveFinal){$popupStatus.Text+=' | مکث نمایش؛ ثبت ادامه دارد.';return}
 Render-LiveGrid $popupGrid $script:liveFrame $script:popupSeen ($flash.Checked -and -not $script:liveFinal) $follow.Checked $false
 Render-Domains $domainPopup $script:liveFrame $script:domainPopupSeen ($flash.Checked -and -not $script:liveFinal) $false
 Render-NewProcesses $popupProcessGrid $script:liveFrame
}
function Accept-LiveFrame($Frame){
 Render-NewProcesses $processGrid $Frame
 $script:liveFrame=$Frame;$script:liveRevision=[int]$Frame.revision;$liveStatus.Text=Live-StatusText $Frame;$domainMainHint.Text=Dns-StatusHint $Frame;$domainPopupHint.Text=$domainMainHint.Text
 if(Get-Command Set-DenialHealth -ErrorAction SilentlyContinue){Set-DenialHealth $Frame}
 Render-LiveGrid $liveGrid $Frame $script:liveSeen ($flash.Checked -and -not $script:liveFinal) $false $true
 Render-Domains $domainMain $Frame $script:domainMainSeen ($flash.Checked -and -not $script:liveFinal) $true
 Render-Popup
 $processTab.Text='فرایندهای تازه ('+$processGrid.Rows.Count+')';$popupProcessTab.Text='فرایندهای تازه ('+$popupProcessGrid.Rows.Count+')'
 if($Frame.schema -ceq 'unified-new-process-monitor-1'){$status.Text='خط مبنا آماده؛ '+@($Frame.processes).Count+' فرایند تازه | '+$(if($Frame.status -ceq 'finished'){'ثبت پایان یافت'}else{'اکنون برنامهٔ هدف را اجرا کنید'})}
 $mainLiveTabs.TabPages[1].Text='دامنه / DNS ('+$domainMain.Rows.Count+')';$popupLiveTabs.TabPages[1].Text='دامنه / DNS ('+$domainPopup.Rows.Count+')'
}
function Expire-LivePulses {
 foreach($grid in @($liveGrid,$popupGrid,$domainMain,$domainPopup,$processGrid,$popupProcessGrid)){
  foreach($row in $grid.Rows){$pulse=$row.Cells['pulse'].Tag;if($null -ne $pulse -and ([DateTime]::UtcNow -ge $pulse.until -or -not $flash.Checked)){$row.DefaultCellStyle.BackColor=$pulse.base;$row.DefaultCellStyle.SelectionBackColor=$pulse.selection;$row.Cells['pulse'].Style.BackColor=[Drawing.Color]::Empty;$row.Cells['pulse'].Value='—';$row.Cells['pulse'].Tag=$null}}
 }
}
function Refresh-PtrCells {
 foreach($grid in @($liveGrid,$popupGrid)){foreach($row in $grid.Rows){$row.Cells['ptr'].Value=Ptr-Text $row.Tag.remote_ip}}
}
function Begin-Ptr([bool]$All){
 if($null -ne $script:ptrJob){throw 'PTR در حال انجام است.'}
 if($null -ne $script:job -and $script:job.action -notin @('monitor_record','baseline_record')){throw 'تا پایان عملیات دیگر صبر کنید.'}
 if($null -eq $script:liveFrame){throw 'ابتدا رصد را شروع یا سابقه را باز کنید.'}
 $ips=@();if($All){$ips=@((Monitor-IPRows $script:liveFrame)|ForEach-Object{$_.remote_ip}|Sort-Object -Unique|Select-Object -First 100)}else{
  $g=if($livePopup.ContainsFocus){$popupGrid}else{$liveGrid};$ips=@($g.SelectedRows|ForEach-Object{$_.Tag.remote_ip}|Sort-Object -Unique)
 }
 if($ips.Count -lt 1 -or $ips.Count -gt 100){throw '۱ تا ۱۰۰ IP عمومی انتخاب کنید. PTR فقط برای IP است، نه نام دامنه.'}
 if([Windows.Forms.MessageBox]::Show('PTR یک پرس‌وجوی اختیاری DNS سیستم است؛ نام معکوس IP، نه دامنهٔ قطعی درخواست برنامه. برای IPهای انتخاب‌شده انجام شود؟','PTR / نام معکوس','YesNo','Question') -ne 'Yes'){return}
 $id=[guid]::NewGuid().ToString('N');$folder=Join-Path $root ('private-state/jobs/'+$id);$null=New-Item -ItemType Directory -Path $folder -Force
 $request=Join-Path $folder 'request.json';$response=Join-Path $folder 'response.json'
 [IO.File]::WriteAllText($request,(ConvertTo-Json -InputObject @{action='monitor_ptr';payload=@{ips=$ips;force=[bool]$ptrForce.Checked}} -Depth 8),(New-Object Text.UTF8Encoding($false)))
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=Join-Path $root 'runtime/python.exe';$info.Arguments='-I "'+(Join-Path $PSScriptRoot 'desktop_cli.py')+'" --request "'+$request+'" --response "'+$response+'"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $proc=New-Object Diagnostics.Process;$proc.StartInfo=$info;[void]$proc.Start();$script:ptrJob=@{folder=$folder;response=$response;process=$proc};Set-PtrStatus 'PTR در حال اجرا؛ رصد مستقل ادامه دارد.';Set-EvidenceControls
}
function Stop-Ptr {
 if($null -ne $script:ptrJob){[IO.File]::WriteAllText((Join-Path $script:ptrJob.folder 'stop.txt'),'stop');Set-PtrStatus 'توقف PTR درخواست شد؛ نتیجه‌های تکمیل‌شده حفظ می‌شوند.'}
}
function Update-Ptr {
 if($null -eq $script:ptrJob){return}
 $j=$script:ptrJob
 if(-not $j.process.HasExited){
  try{$path=Join-Path $j.folder 'progress.json';if([IO.File]::Exists($path)){$p=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path));Set-PtrStatus ('PTR: '+$p.done+' / '+$p.total)}}catch{};return
 }
 try{
  if(-not [IO.File]::Exists($j.response)){throw 'PTR بدون پاسخ پایان یافت؛ جزئیات در پوشهٔ job است.'}
  $r=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($j.response));if(-not $r.ok){throw [string]$r.error}
  foreach($p in $r.ptr.entries){$script:ptrCache[[string]$p.ip]=$p}
  Set-PtrStatus ('PTR: '+$r.ptr.completed+' / '+$r.ptr.requested+' | توقف: '+$r.ptr.cancelled+' | نام معکوس، نه دامنهٔ درخواست');Refresh-PtrCells
 }catch{Set-PtrStatus ('خطای PTR: '+$_.Exception.Message)}finally{$j.process.Dispose();$script:ptrJob=$null;Set-EvidenceControls;if($null -eq $script:job){SetBusy $false}}
 if($script:closing -and $null -eq $script:job){$form.Close()}
}
$ptrPick.Add_Click({TryOp {Begin-Ptr $false}});$ptrAll.Add_Click({TryOp {Begin-Ptr $true}});$ptrStop.Add_Click({TryOp {Stop-Ptr}})
$liveFilter.Add_TextChanged({if($null -ne $script:liveFrame){Render-Domains $domainMain $script:liveFrame $script:domainMainSeen $false $true}})

$popupPtrPick.Add_Click({TryOp {Begin-Ptr $false}});$popupPtrAll.Add_Click({TryOp {Begin-Ptr $true}});$popupPtrStop.Add_Click({TryOp {Stop-Ptr}})

$dnsCleanup=Button 'پاکسازی نشست DNS باقی‌مانده';$mb.Controls.Add($dnsCleanup)
$dnsCleanup.Add_Click({TryOp {
 if($null -ne $script:job -or $null -ne $script:ptrJob){throw 'ابتدا ثبت و عملیات جاری را متوقف کنید.'}
 if([Windows.Forms.MessageBox]::Show('فقط نشست‌های ETW ثبت‌شدهٔ همین تنظیمات که فرایند جمع‌آوری آن‌ها پایان یافته بررسی و متوقف می‌شوند؛ هیچ trace دیگری، audit، فایروال یا hosts تغییر نمی‌کند. Administrator لازم است. ادامه؟','پاکسازی DNS','YesNo','Question') -eq 'Yes'){BeginOp 'monitor_dns_cleanup' @{consent=$true}}
}})
