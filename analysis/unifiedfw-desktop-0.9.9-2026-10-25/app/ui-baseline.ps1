# Automatic discovery is observation-only; no registration, native apply, suspension or network quarantine.
. (Join-Path $PSScriptRoot 'activity-model.ps1')
$script:processMainSeen=@{};$script:processPopupSeen=@{}
$script:historyMode='selected'
$baselineStart=Button 'خط مبنا ← رصد فرایندهای تازه';$baselineHistory=Button 'سوابق فرایندهای تازه'
$pb.Controls.Add($baselineStart);$mb.Controls.Add($baselineHistory)
$monitorStop=Button 'توقف ثبت جاری';$mb.Controls.Add($monitorStop);$monitorStop.Enabled=$false;$monitorStop.Add_Click({TryOp {Request-MonitorStop}})
$processTab=New-Object Windows.Forms.TabPage;$processTab.Text='فرایندهای تازه';$processTab.BackColor=[Drawing.Color]::White;[void]$mainLiveTabs.TabPages.Add($processTab)
$popupProcessTab=New-Object Windows.Forms.TabPage;$popupProcessTab.Text='فرایندهای تازه';$popupProcessTab.BackColor=[Drawing.Color]::White;[void]$popupLiveTabs.TabPages.Add($popupProcessTab)
function New-ProcessGrid {
 $v=Grid @(@('pulse','فعالیت'),@('name','نام EXE'),@('activity','وضعیت ارتباط'),@('denied','تعداد منع ثبت‌شده'),@('lastDenied','آخرین منع UTC'),@('lastTarget','آخرین مقصد منع‌شده'),@('reason','دلیل / شواهد انسداد'),@('pid','PIDهای دیده‌شده'),@('birth','تعداد نمونه‌های هویتی'),@('path','مسیر دقیق EXE'),@('presence','آخرین مشاهده'),@('first','اولین مشاهده UTC'),@('last','آخرین مشاهده UTC'),@('trust','هویت فایل'))
 $v.ReadOnly=$true;$v.RightToLeft='No';$v.AutoSizeRowsMode='None';$v.RowTemplate.Height=34;$v.AutoSizeColumnsMode='None'
 foreach($c in $v.Columns){$c.Width=180};$v.Columns['pulse'].Visible=$false;$v.Columns['activity'].Width=260;$v.Columns['reason'].Width=480;$v.Columns['lastTarget'].Width=240;$v.Columns['pid'].Width=75;$v.Columns['path'].Width=340;$v.Columns['name'].Width=190;$v.Columns['trust'].Width=250
 return $v
}
$processGrid=New-ProcessGrid;$popupProcessGrid=New-ProcessGrid;$processTab.Controls.Add($processGrid);$popupProcessTab.Controls.Add($popupProcessGrid)
$processActivityFilter=New-Object Windows.Forms.ComboBox;$processActivityFilter.DropDownStyle='DropDownList';$processActivityFilter.Width=250
[void]$processActivityFilter.Items.Add('همهٔ فرایندهای تازه');[void]$processActivityFilter.Items.Add('دارای تلاش منع‌شدهٔ ثبت‌شده');[void]$processActivityFilter.Items.Add('بدون شواهد منع — نه تضمین آزادی');$processActivityFilter.SelectedIndex=0

$popupActivityFilter=New-Object Windows.Forms.ComboBox;$popupActivityFilter.DropDownStyle='DropDownList';$popupActivityFilter.Width=250
foreach($text in $processActivityFilter.Items){[void]$popupActivityFilter.Items.Add($text)};$popupActivityFilter.SelectedIndex=0
function Render-NewProcesses($Grid,$Frame){
 $seen=if($Grid -eq $processGrid){$script:processMainSeen}else{$script:processPopupSeen};$next=@{};$visible=@{}
 $filterIndex=if($Grid -eq $processGrid){$processActivityFilter.SelectedIndex}else{$popupActivityFilter.SelectedIndex}
 $scroll=$Grid.FirstDisplayedScrollingRowIndex;$rowsByKey=@{};foreach($existing in $Grid.Rows){if($null -ne $existing.Tag){$rowsByKey[[string]$existing.Tag.record_id]=$existing}};$Grid.SuspendLayout();try{
  foreach($r in @(Get-ProcessDisplayRows $Frame|Sort-Object first_seen_utc -Descending)){
   $activity=$r.activity;$key=[string]$r.record_id;$next[$key]=$activity
   if($liveFilter.Text.Trim() -and ($r.program_path+' '+$r.display_pids).IndexOf($liveFilter.Text.Trim(),[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
   if(-not (Test-ProcessActivityVisible $activity $filterIndex $onlyPresent.Checked ([string]$r.presence))){continue}
   $visible[$key]=$true;$row=Get-OrAddDisplayRow $Grid $key $rowsByKey;$row.Tag=$r
   $presence=switch([string]$r.presence){'present'{'حداقل یک نمونه حاضر'};'not_in_latest_snapshot'{'در نمونه نبود؛ نه اثبات خروج'};default{'نامعلوم / فقط رویداد'}}
   $stateText=if($activity.denied -gt 0){'حداقل یک تلاش منع‌شده؛ نه مسدودی کل EXE'}else{'شواهد منع ثبت نشده / وضعیت نامعلوم'}
   $values=@{name=[IO.Path]::GetFileName($r.program_path);activity=$stateText;denied=$activity.denied;lastDenied=$activity.last_denied;lastTarget=$activity.last_target;reason=$activity.reason;pid=$r.display_pids;birth=([string]$r.instance_count+' نمونهٔ هویتی');path=$r.program_path;presence=$presence;first=$r.first_seen_utc;last=$r.last_seen_utc;trust='هویت زمان رصد: هش تأیید نشد / ثبت خودکار نشد'}
   foreach($name in $values.Keys){$row.Cells[$name].Value=$values[$name]}
   $row.Cells['path'].ToolTipText=$r.program_path;$row.Cells['reason'].ToolTipText=$activity.reason
   $row.Cells['birth'].ToolTipText=(@($r.instances|ForEach-Object{'PID '+$_.pid+' / ticks '+$_.process_start_ticks}) -join '; ')
   $color=State-Color $(if($activity.denied -gt 0){'wfp_denial_event'}else{'unknown'});$row.DefaultCellStyle.SelectionForeColor=$ink
   Set-ActivityRowStyle $row $color (Get-ActivityPulse $seen[$key] $activity) ($flash.Checked -and -not $script:liveFinal)
  }
  Remove-OldDisplayRows $Grid $visible
  if($Grid.Rows.Count -gt 0 -and $scroll -ge 0){$Grid.FirstDisplayedScrollingRowIndex=[Math]::Min($scroll,$Grid.Rows.Count-1)}
 }finally{$Grid.ResumeLayout()}
 $seen.Clear();foreach($key in $next.Keys){$seen[$key]=$next[$key]}
}
$baselineStart.Add_Click({TryOp {
 if($null -ne $script:job -or $null -ne $script:ptrJob){throw 'ابتدا عملیات یا ثبت جاری را تمام کنید.'}
 if($dnsTrace.Checked -and [Windows.Forms.MessageBox]::Show('حالت خط مبنا، فرایندهای قدیمی را فقط از رصد کنار می‌گذارد؛ چیزی متوقف یا مسدود نمی‌شود. DNS مستقل به Administrator و نشست موقت ETW نیاز دارد و فقط رویداد فرایندهایی را نگه می‌دارد که بعد از خط مبنا متولد شده‌اند. شروع؟','خط مبنا و DNS موقت','YesNo','Question') -ne 'Yes'){return}
 $script:processMainSeen=@{};$script:processPopupSeen=@{}
 $script:liveFrame=$null;$script:liveRevision=-1;$script:liveSeen=@{};$script:popupSeen=@{};$script:domainMainSeen=@{};$script:domainPopupSeen=@{};$script:liveCapture=$null;$script:liveFinal=$false
 foreach($g in @($liveGrid,$popupGrid,$domainMain,$domainPopup,$processGrid,$popupProcessGrid)){$g.Rows.Clear()}
 $liveStatus.Text='در حال ساخت خط مبنا؛ بازی را بعد از پیام آماده اجرا کنید.';$popupStatus.Text=$liveStatus.Text
 BeginOp 'baseline_record' @{seconds=@(30,60,120,300,0)[$duration.SelectedIndex];dns_etw_consent=[bool]$dnsTrace.Checked}
 $tabs.SelectedTab=$monitorTab;$mainLiveTabs.SelectedTab=$processTab;$popupLiveTabs.SelectedTab=$popupProcessTab
 if(-not $livePopup.Visible){$livePopup.Show($form)}
}})
$baselineHistory.Add_Click({TryOp {BeginOp 'baseline_history' @{}}})
$liveFilter.Add_TextChanged({if($null -ne $script:liveFrame){Render-NewProcesses $processGrid $script:liveFrame;if(-not $pause.Checked -or $script:liveFinal){Render-NewProcesses $popupProcessGrid $script:liveFrame}}})
$onlyPresent.Add_CheckedChanged({if($null -ne $script:liveFrame){Render-NewProcesses $processGrid $script:liveFrame;if(-not $pause.Checked -or $script:liveFinal){Render-NewProcesses $popupProcessGrid $script:liveFrame}}})

$processActivityFilter.Add_SelectedIndexChanged({if($null -ne $script:liveFrame){Render-NewProcesses $processGrid $script:liveFrame}})
$popupActivityFilter.Add_SelectedIndexChanged({if($null -ne $script:liveFrame -and (-not $pause.Checked -or $script:liveFinal)){Render-NewProcesses $popupProcessGrid $script:liveFrame}})
