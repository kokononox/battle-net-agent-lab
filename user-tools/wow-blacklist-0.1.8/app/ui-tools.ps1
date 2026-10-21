# User-directed edits only. The background recorder never writes hosts or rules.
$script:recordingStopping=$false;$script:ptrJob=$null;$script:hostsReport=$null
function Write-UiDiagnostic([string]$area,$errorRecord){
 try{$path=Join-Path $private 'ui-diagnostics.log';if((Test-Path $path) -and (Get-Item $path).Length -gt 1048576){[IO.File]::Move($path,$path+'.'+[Guid]::NewGuid().ToString('N')+'.old')};[IO.File]::AppendAllText($path,([DateTime]::UtcNow.ToString('o')+' | '+$area+' | '+$errorRecord.Exception.GetType().Name+' | line '+$errorRecord.InvocationInfo.ScriptLineNumber+[Environment]::NewLine))}catch{}
}
function Pick-Stages($current,$remembered){
 $d=New-Object Windows.Forms.Form;$d.Text='مرحله‌های مشاهده — چندانتخابی';$d.ClientSize=New-Object Drawing.Size(560,448);$d.StartPosition='CenterScreen';$d.Font=New-Object Drawing.Font('Tahoma',10);$d.TopMost=$true;$d.FormBorderStyle='FixedDialog';$d.MaximizeBox=$false;$d.MinimizeBox=$false
 $p=New-Object Windows.Forms.TableLayoutPanel;$p.Dock='Fill';$p.Padding=New-Object Windows.Forms.Padding(16);$p.ColumnCount=1;$p.RowCount=3
 [void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,100)));[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)));[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,56)))
 $hint=Label ('این انتخاب فقط برای همین ضبط است. چند مرحله را می‌توانی تیک بزنی؛ هیچ انتخابی = نامشخص. سابقهٔ ضبط‌های دیگر: '+(Stage-Text $remembered)+' — سابقه به‌تنهایی حضور در این مرحله از ضبط فعلی را ثابت نمی‌کند.');$p.Controls.Add($hint,0,0)
 $list=New-Object Windows.Forms.TableLayoutPanel;$list.Dock='Fill';$list.ColumnCount=1;$list.RowCount=5;$codes=@('launch','login','dashboard','in_game','multi_stage');$choices=@{}
 $index=0;foreach($code in $codes){[void]$list.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,44)));$choice=New-Object Windows.Forms.CheckBox;$choice.Dock='Fill';$choice.Margin=New-Object Windows.Forms.Padding(0);$choice.Text=$script:stageLabels[$code];$choice.RightToLeft='Yes';$choice.Checked=($code -in @(Stage-Codes $current));$choices[$code]=$choice;$list.Controls.Add($choice,0,$index);$index++};$p.Controls.Add($list,0,1)
 $actions=Flow;$ok=Button 'ثبت انتخاب‌ها';$cancel=Button 'انصراف';$ok.DialogResult='OK';$cancel.DialogResult='Cancel';$actions.Controls.AddRange(@($ok,$cancel));$p.Controls.Add($actions,0,2);$d.Controls.Add($p);$d.AcceptButton=$ok;$d.CancelButton=$cancel
 try{if($d.ShowDialog() -eq 'OK'){return [pscustomobject]@{Stages=@($codes|Where-Object {$choices[$_].Checked})}};return $null}finally{$d.Dispose()}
}
function Edit-MainStages($rows){
 if(!$rows.Count -or $script:job){return};$r=$rows[0].Tag;$key=Observation-Key $r
 $answer=Pick-Stages $script:stageEdits[$key] $r.context.history_stages
 if($null -ne $answer){foreach($row in $rows){Set-RecordStages (Observation-Key $row.Tag) $answer.Stages};Show-ObservedRows}
}
function Live-Identity($row){if($row.kind -eq 'dns_query'){return 'dns|'+([string]$row.domain).ToLowerInvariant()};$protocol=if($row.protocol){[string]$row.protocol}else{'TCP'};return ([string]$row.ip).ToLowerInvariant()+'|'+[string]$row.port+'|'+$protocol}
function Live-RememberedStages($row){
 if($row.context){return @(Stage-Codes $row.context.history_stages)}
 if($script:liveLastSnapshot.stage_baseline){$prop=$script:liveLastSnapshot.stage_baseline.PSObject.Properties[(Live-Identity $row)];if($prop){return @(Stage-Codes $prop.Value)}}
 return @()
}
function Live-StageText($row){
 $key=[string]$row.record_id;$codes=if($script:liveStages.ContainsKey($key)){$script:liveStages[$key]}else{Row-CurrentStages $row}
 $text='این ضبط: '+(Stage-Text $codes);$session=@(Session-Stages $row);if(!$row.phase_context -and $row.kind -in @('dns_query','wfp_connection_block') -and (Get-Command Live-EventSessionStages -ErrorAction SilentlyContinue)){$session=@(Live-EventSessionStages $row)};if($session.Count){$text+=' | هنگام رصد: '+(Stage-Text $session)};$old=@(Live-RememberedStages $row);if($old.Count){$text+=' | سابقه: '+(Stage-Text $old)};return $text
}
function Edit-LiveStages($gridRow){
 if(!$gridRow.Tag -or ($script:job -and $script:job.Action -ne 'observe') -or (!$script:liveRunning -and $script:captureId -ne $script:liveCaptureId)){return}
 $key=[string]$gridRow.Tag.record_id;$current=if($script:liveStages.ContainsKey($key)){$script:liveStages[$key]}else{Row-CurrentStages $gridRow.Tag}
 $answer=Pick-Stages $current (Live-RememberedStages $gridRow.Tag)
 if($null -eq $answer){return}
 $script:liveStages[$key]=@($answer.Stages);$gridRow.Cells['stage'].Value=Live-StageText $gridRow.Tag
 if($script:liveRunning){$script:liveJournalDirty=$true;Save-LiveLabels}else{Set-RecordStages $key $answer.Stages;Show-ObservedRows}
}
function Request-RecordingStop {
 if($script:ptrJob){Stop-LivePtr};if(!$script:job -or $script:job.Action -notin @('observe','lookup')){return}
 try{
  # Flush pending labels/deletions before the collector's final journal recovery.
  if($script:job.Action -eq 'observe'){Commit-ObservationEdits;Save-LiveLabels;if($script:sessionPhaseDirty){[void](Publish-StageTimeline $script:sessionTransitions)}}
  [IO.File]::WriteAllText($script:job.Stop,'stop');$stop.Enabled=$false
  if($script:job.Action -eq 'observe'){$script:recordingStopping=$true;Set-LiveBusy;if($script:liveSummary){$script:liveSummary.Text='توقف درخواست شده؛ منتظر پایان خواندن رویدادها، ذخیره و انتقال به پنجره اصلی بمان.'}}
  $status.Text='درخواست توقف ثبت شد؛ تا دریافت نتیجهٔ نهایی منتظر بمان.'
 }catch{Write-UiDiagnostic 'stop_request' $_;$status.Text='درخواست توقف نوشته نشد؛ دوباره تلاش کن. ضبط را پایان‌یافته فرض نکن.'}
}
function Accept-CaptureReport($report,[bool]$historical){
 # Assign canonical data first; popup failures must never prevent main-model ingestion.
 $script:observed=@($report.endpoints);$script:observationSnapshot=$report.block_snapshot
 Set-CaptureContext $report $historical
 $script:historyNeedsRefresh=$true;$script:observedChecks=@{};$script:resetObservedChecks=$true;$script:observationTruncated=$report.truncated
 # A completed capture opens unfiltered; otherwise old-process records appeared to vanish.
 $onlyFresh.Checked=$false;$hideCovered.Checked=$false;Show-ObservedRows
}
function Confirm-RecordDelete([int]$count){return [Windows.Forms.MessageBox]::Show(('حذف '+$count+' رکورد از فهرست و خروجی‌های بعدی؟ فایل خام برای بازیابی محلی حفظ می‌شود. بلک‌لیست، hosts و ZIPهای قبلی تغییر نمی‌کنند.'),'حذف رکورد','YesNo','Warning') -eq 'Yes'}
function Delete-MainRecords {
 if($script:job -or !$script:captureId -or !(Can-SwitchCapture)){return};$grid=Active-TcpGrid;if(!$grid -or $grid -eq $black){return}
 $ids=@($grid.Rows|Where-Object {$_.Selected -or $_.Cells['choose'].Value -eq $true}|ForEach-Object {$_.Tag.record_id})
 if($ids.Count -and (Confirm-RecordDelete $ids.Count)){BeginOp 'delete_records' @{capture_id=$script:captureId;record_ids=$ids;deletion_consent=$true}}
}
function Delete-LiveRecords {
 if($script:recordingStopping){$script:liveSummary.Text='توقف در حال نهایی‌سازی است؛ حذف را پس از انتقال انجام بده.';return}
 if($script:job -and $script:job.Action -ne 'observe'){return}
 if(!$script:liveRunning -and $script:captureId -ne $script:liveCaptureId){return}
 $g=if($script:liveTabs.SelectedIndex -eq 1){$script:liveEvidenceGrid}else{$script:liveGrid};$ids=@($g.SelectedRows|ForEach-Object {$_.Tag.record_id})
 if(!$ids.Count -or !(Confirm-RecordDelete $ids.Count)){return}
 if(!$script:liveRunning){if(!(Can-SwitchCapture)){return};BeginOp 'delete_records' @{capture_id=$script:liveCaptureId;record_ids=$ids;deletion_consent=$true};return}
 foreach($id in $ids){$script:liveDeleted[[string]$id]=$true;$script:liveStages.Remove([string]$id);foreach($map in @($script:liveRows,$script:liveEventRows)){if($map.ContainsKey([string]$id)){$row=$map[[string]$id];$row.DataGridView.Rows.Remove($row);$map.Remove([string]$id)}}}
 $script:liveJournalDirty=$true;Save-LiveLabels
}
function Delete-SelectedCaptures {
 if($script:job -or !(Can-SwitchCapture)){return};$ids=@($historyGrid.SelectedRows|ForEach-Object {$_.Tag.capture_id});if(!$ids.Count){return}
 if([Windows.Forms.MessageBox]::Show(('انتقال '+$ids.Count+' ضبط و برچسب‌های آن‌ها به سطل محلی private-state/deleted-captures؟ از تاریخچه و خروجی بعدی حذف می‌شوند؛ ZIPهای قبلی و قواعد تغییر نمی‌کنند.'),'حذف ضبط‌های انتخابی','YesNo','Warning') -eq 'Yes'){BeginOp 'delete_captures' @{capture_ids=$ids;deletion_consent=$true}}
}
function Clear-DeletedCapture($history){
 if(!$script:captureId){return};if($script:captureId -notin @($history.entries|ForEach-Object {$_.capture_id})){
  $script:captureId='';$script:observed=@();$script:stageEdits=@{};$script:annotationsDirty=$false;Show-ObservedRows;Update-AnnotationIndicator
  if(!$script:liveRunning){$script:liveCaptureId='';$script:liveLastSnapshot=$null;$script:liveRows=@{};$script:liveEventRows=@{};if($script:liveForm){$script:liveGrid.Rows.Clear();$script:liveEvidenceGrid.Rows.Clear();$script:liveSummary.Text='ضبط حذف شد؛ در سطل محلی نگه داشته شده است.'}}
 }
}
# Hosts changes require an optimistic SHA match AND an explicit system-wide confirmation.
function Edit-HostsMapping([bool]$existing=$false){
 if(!$script:hostsReport){$status.Text='ابتدا hosts را بخوان.';return};$domain='';$addresses='0.0.0.0'
 if($existing){if($hostsGrid.SelectedRows.Count -ne 1){$status.Text='برای ویرایش، دقیقاً یک دامنه را انتخاب کن.';return};$entry=$hostsGrid.SelectedRows[0].Tag;$domain=$entry.domain;$addresses=@($entry.addresses) -join ', '}
 $d=New-Object Windows.Forms.Form;$d.Text='نگاشت hosts — تغییر سراسری';$d.ClientSize=New-Object Drawing.Size(600,340);$d.StartPosition='CenterScreen';$d.Font=New-Object Drawing.Font('Tahoma',10);$d.TopMost=$true
 $p=New-Object Windows.Forms.TableLayoutPanel;$p.Dock='Fill';$p.Padding=New-Object Windows.Forms.Padding(16);$p.ColumnCount=1;$p.RowCount=6
 foreach($h in @(56,28,40,28,40,72)){[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$h)))}
 $p.Controls.Add((Label 'فقط دامنه و IP؛ بدون https یا مسیر. برای IPv4 و IPv6 می‌توان چند IP با ویرگول وارد کرد. این تنظیم برای تمام برنامه‌های سیستم است.'),0,0)
 $p.Controls.Add((Label 'دامنه'),0,1);$name=New-Object Windows.Forms.TextBox;$name.Dock='Fill';$name.Text=$domain;$name.ReadOnly=$existing;$p.Controls.Add($name,0,2)
 $p.Controls.Add((Label 'IPها؛ مثال: 0.0.0.0, ::'),0,3);$ips=New-Object Windows.Forms.TextBox;$ips.Dock='Fill';$ips.Text=$addresses;$p.Controls.Add($ips,0,4)
 $actions=Flow;$ok=Button 'بررسی و اعمال';$cancel=Button 'انصراف';$ok.DialogResult='OK';$cancel.DialogResult='Cancel';$actions.Controls.AddRange(@($ok,$cancel));$p.Controls.Add($actions,0,5);$d.Controls.Add($p);$d.CancelButton=$cancel
 try{if($d.ShowDialog() -eq 'OK'){Apply-HostsChanges @(@{action='upsert';domain=$name.Text.Trim();addresses=@($ips.Text -split '[,;\s]+'|Where-Object {$_})})}}finally{$d.Dispose()}
}
function Apply-HostsChanges($changes){
 if(!$script:hostsReport -or $script:hostsReport.truncated){$status.Text='ابتدا hosts را کامل و بدون سقف نمایش بخوان.';return}
 $summary=@($changes|ForEach-Object {$_.action+' '+$_.domain+' -> '+(@($_.addresses) -join ', ')}) -join [Environment]::NewLine
 if([Windows.Forms.MessageBox]::Show(('این تغییر سراسری hosts است، نه فقط بازی. قبل از نوشتن پشتیبان گرفته می‌شود. نگاشت فعلی همین دامنه‌ها جایگزین/حذف می‌شود؛ aliasهای دیگر حفظ می‌شوند. نتیجهٔ مسدودسازی تضمین نیست.'+[Environment]::NewLine+$summary),'تأیید اعمال hosts','YesNo','Warning') -eq 'Yes'){BeginOp 'hosts_apply' @{expected_sha256=$script:hostsReport.sha256;changes=@($changes);hosts_edit_consent=$true}}
}
$hostsAdd=Button 'افزودن دامنه';$hostsEdit=Button 'ویرایش انتخاب';$hostsDelete=Button 'حذف انتخاب‌ها';$hostsTop.Controls.AddRange(@($hostsAdd,$hostsEdit,$hostsDelete))
$hostsAdd.Add_Click({Edit-HostsMapping $false});$hostsEdit.Add_Click({Edit-HostsMapping $true});$hostsDelete.Add_Click({$changes=@($hostsGrid.SelectedRows|ForEach-Object {@{action='remove';domain=$_.Tag.domain}});if($changes.Count){Apply-HostsChanges $changes}})
$recordDelete=Button 'حذف رکوردهای انتخابی';$obsFilters.Controls.Add($recordDelete);$recordDelete.Add_Click({Delete-MainRecords})
$historyDelete=Button 'حذف ضبط‌های انتخابی';$historyButtons.Controls.Add($historyDelete);$historyDelete.Add_Click({Delete-SelectedCaptures})
# Independent, bounded explicit PTR worker: never occupies or replaces the recorder job slot.
function Start-LivePtr([bool]$all){
 if($script:ptrJob -or ($script:job -and $script:job.Action -ne 'observe')){$script:liveSummary.Text='عملیات یا PTR دیگری در جریان است؛ پس از پایان دوباره بزن.';return}
 $grid=if($script:liveTabs.SelectedIndex -eq 1){$script:liveEvidenceGrid}else{$script:liveGrid}
 $rows=if($all){@($grid.Rows)}else{@($grid.SelectedRows)}
 $items=@($rows|Where-Object {$_.Tag -and $_.Tag.ip}|ForEach-Object {[pscustomobject]@{ip=$_.Tag.ip;port=$_.Tag.port;protocol='TCP'}}|Group-Object ip|ForEach-Object {$_.Group[0]})
 if($all){$items=@($items|Where-Object {!$script:ptr.ContainsKey([string]$_.ip) -or [double]$script:ptr[[string]$_.ip].expires_utc -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()})}
 $items=@($items|Select-Object -First 100)
 if(!$items.Count){$script:liveSummary.Text='IP انتخاب نشده یا همهٔ IPهای این تب کش معتبر PTR دارند؛ برای IPهای بیشتر، انتخاب تازه کن.';return}
 $id=[Guid]::NewGuid().ToString('N');$request=Join-Path $private ('job-'+$id+'.request.json');$result=Join-Path $private ('job-'+$id+'.result.json')
 [IO.File]::WriteAllText($request,(@{action='lookup';payload=@{text=(Ui-Text $items);force=$false}}|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
 $psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=Join-Path $root 'runtime\python.exe';$psi.Arguments='-I "'+(Join-Path $root 'app\backend.py')+'" "'+$request+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=$root
 try{$process=[Diagnostics.Process]::Start($psi);$script:ptrJob=@{Process=$process;Result=$result;Stop=(Join-Path $private ('job-'+$id+'.stop'))};$ptrTimer.Start();if(!$script:job){$stop.Enabled=$true};$script:liveSummary.Text='استعلام PTR در پس‌زمینه؛ حداکثر ۱۰۰ IP این نوبت. ضبط ادامه دارد؛ PTR دامنهٔ قطعی درخواست نیست.'}catch{Write-UiDiagnostic 'ptr_start' $_;$script:liveSummary.Text='اجرای PTR شروع نشد؛ ضبط مستقل ادامه دارد.'}
}
$ptrTimer=New-Object Windows.Forms.Timer;$ptrTimer.Interval=350
$ptrTimer.Add_Tick({
 if(!$script:ptrJob){$ptrTimer.Stop();return};$j=$script:ptrJob;if(!$j.Process.HasExited){return}
 $ptrTimer.Stop();$script:ptrJob=$null
 try{$r=[IO.File]::ReadAllText($j.Result)|ConvertFrom-Json;if(!$r.ok){throw 'ptr_result_failed'};ReadNames $r.lookup.entries;if($script:liveSummary){$script:liveSummary.Text='PTR تکمیل شد؛ '+$r.lookup.completed+' از '+$r.lookup.requested+' IP. نام معکوس، دامنهٔ واقعی را ثابت نمی‌کند.'}}catch{Write-UiDiagnostic 'ptr_result' $_;if($script:liveSummary){$script:liveSummary.Text='نتیجه PTR خوانده نشد؛ ضبط و داده‌های قبلی حفظ شده‌اند.'}}finally{$j.Process.Dispose();if(!$script:job){$stop.Enabled=$false};Flush-PendingFinalization}
})

function Finalize-LiveEdits($report){
 $keys=@($report.endpoints)+@($report.event_evidence.events)|ForEach-Object {$_.record_id}
 $pending=@($script:liveDeleted.Keys|Where-Object {$_ -in $keys})
 if(!$pending.Count -and !$script:annotationsDirty){return $false}
 $script:pendingFinalization=@{capture_id=$script:captureId;record_ids=$pending;entries=$script:stageEdits;deletion_consent=$true}
 if($script:ptrJob){[IO.File]::WriteAllText($script:ptrJob.Stop,'stop');$status.Text='ضبط منتقل شد؛ پس از پایان PTR، آخرین حذف‌ها و برچسب‌ها ذخیره می‌شوند.'}else{Flush-PendingFinalization}
 return $true
}
function Flush-PendingFinalization {
 if(!$script:pendingFinalization -or $script:job -or $script:ptrJob){return}
 $pending=$script:pendingFinalization;$script:pendingFinalization=$null
 if($pending.record_ids.Count){BeginOp 'delete_records' $pending}else{BeginOp 'annotate_observation' @{capture_id=$pending.capture_id;entries=$pending.entries}}
}

function Stop-LivePtr {
 if(!$script:ptrJob){return}
 try{[IO.File]::WriteAllText($script:ptrJob.Stop,'stop');if($script:liveSummary){$script:liveSummary.Text='توقف PTR درخواست شد؛ استعلام‌های در حال اجرا حداکثر مهلت خود را تمام می‌کنند و نتایج تکمیل‌شده می‌مانند.'}}catch{Write-UiDiagnostic 'ptr_stop' $_}
}
