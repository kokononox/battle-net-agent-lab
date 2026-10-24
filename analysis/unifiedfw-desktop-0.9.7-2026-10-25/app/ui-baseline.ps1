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
 $v=Grid @(@('pulse','فعالیت'),@('name','نام EXE'),@('activity','وضعیت ارتباط'),@('denied','تعداد منع ثبت‌شده'),@('lastDenied','آخرین منع UTC'),@('lastTarget','آخرین مقصد منع‌شده'),@('reason','دلیل / شواهد انسداد'),@('pid','PID'),@('birth','تولد فرایند / ticks'),@('path','مسیر دقیق EXE'),@('presence','آخرین مشاهده'),@('first','اولین مشاهده UTC'),@('last','آخرین مشاهده UTC'),@('trust','هویت فایل'))
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
 $seen=if($Grid -eq $processGrid){$script:processMainSeen}else{$script:processPopupSeen};$next=@{}
 $filterIndex=if($Grid -eq $processGrid){$processActivityFilter.SelectedIndex}else{$popupActivityFilter.SelectedIndex}
 $chosen=@{};foreach($r in $Grid.SelectedRows){if($null -ne $r.Tag){$chosen[[string]$r.Tag.record_id]=$true}};$scroll=$Grid.FirstDisplayedScrollingRowIndex
 $Grid.SuspendLayout();try{
  $Grid.Rows.Clear();if($Frame.schema -cne 'unified-new-process-monitor-1'){return}
  foreach($r in @($Frame.processes|Sort-Object first_seen_utc -Descending)){
   $activity=Get-RowActivity $Frame $r $false (Get-FrameActivityIndex $Frame);$next[[string]$r.record_id]=$activity
   if($liveFilter.Text.Trim() -and ($r.program_path+' '+$r.pid).IndexOf($liveFilter.Text.Trim(),[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
   if(-not (Test-ProcessActivityVisible $activity $filterIndex $onlyPresent.Checked ([string]$r.presence))){continue}
   $presence=switch([string]$r.presence){'present'{'حاضر در نمونه'};'not_in_latest_snapshot'{'در نمونه نبود؛ نه اثبات خروج'};default{'نامعلوم / فقط رویداد'}}
   $stateText=if($activity.denied -gt 0){'حداقل یک تلاش منع‌شده؛ نه مسدودی کل فرایند'}else{'شواهد منع ثبت نشده / وضعیت نامعلوم'}
   $i=$Grid.Rows.Add('—',[IO.Path]::GetFileName($r.program_path),$stateText,$activity.denied,$activity.last_denied,$activity.last_target,$activity.reason,$r.pid,$r.process_start_ticks,$r.program_path,$presence,$r.first_seen_utc,$r.last_seen_utc,'هویت زمان رصد: هش تأیید نشد / ثبت خودکار نشد')
   $row=$Grid.Rows[$i];$row.Tag=$r;$row.Cells['path'].ToolTipText=$r.program_path;$row.Cells['reason'].ToolTipText=$activity.reason
   $color=State-Color $(if($activity.denied -gt 0){'wfp_denial_event'}else{'unknown'});$row.DefaultCellStyle.BackColor=$color;$row.DefaultCellStyle.SelectionBackColor=$color;$row.DefaultCellStyle.SelectionForeColor=$ink
   Apply-PulseCell $row (Get-ActivityPulse $seen[[string]$r.record_id] $activity) ($flash.Checked -and -not $script:liveFinal)
  }
  $Grid.ClearSelection();foreach($r in $Grid.Rows){if($chosen.ContainsKey([string]$r.Tag.record_id)){$r.Selected=$true}}
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
