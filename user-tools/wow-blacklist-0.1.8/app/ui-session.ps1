# One session-stage selector; advanced display options stay in one menu.
$script:sessionTransitions=@();$script:sessionStage='unknown';$script:sessionPhaseDirty=$false;$script:changingStage=$false;$script:liveFrameError=$false;$script:liveRenderError=$false;$script:liveLastArrival=[DateTime]::MinValue
$script:sessionCodes=@('unknown','launch','login','dashboard','in_game')
function Publish-StageTimeline($entries){
 if(!$script:liveJob){return $false}
 try{
  $path=$script:liveJob.Phases;$tmp=$path+'.tmp'
  $value=@{schema='wow-stage-journal-1';capture_id=$script:liveCaptureId;transitions=@($entries)}
  [IO.File]::WriteAllText($tmp,($value|ConvertTo-Json -Depth 7),(New-Object Text.UTF8Encoding($false)))
  if([IO.File]::Exists($path)){[IO.File]::Replace($tmp,$path,[NullString]::Value)}else{[IO.File]::Move($tmp,$path)}
  $script:sessionPhaseDirty=$false;return $true
 }catch{$script:sessionPhaseDirty=$true;Write-UiDiagnostic 'stage_journal' $_;return $false}
}
function Start-SessionStages {
 $script:sessionStage='unknown';$script:sessionTransitions=@([pscustomobject]@{sequence=1;stage='unknown';selected_utc=[DateTime]::UtcNow.ToString('o')})
 $script:liveFrameError=$false;$script:liveRenderError=$false;$script:liveLastArrival=[DateTime]::MinValue
 if($script:sessionSelector){$script:changingStage=$true;try{$script:sessionSelector.SelectedIndex=0}finally{$script:changingStage=$false}}
 [void](Publish-StageTimeline $script:sessionTransitions)
}
function Select-SessionStage([string]$code){
 if($script:changingStage -or !$script:liveRunning -or $script:recordingStopping -or $code -notin $script:sessionCodes -or $code -eq $script:sessionStage){return}
 $old=$script:sessionStage;$now=[DateTime]::UtcNow
 $valid=($script:sessionTransitions.Count -lt 500)
 if($script:sessionTransitions.Count -and $now -lt ([DateTimeOffset]::Parse([string]$script:sessionTransitions[-1].selected_utc)).UtcDateTime){$valid=$false}
 $candidate=@($script:sessionTransitions)+@([pscustomobject]@{sequence=($script:sessionTransitions.Count+1);stage=$code;selected_utc=$now.ToString('o')})
 if($valid -and (Publish-StageTimeline $candidate)){$script:sessionTransitions=$candidate;$script:sessionStage=$code}
 else{
  $script:changingStage=$true;try{$script:sessionSelector.SelectedIndex=[Array]::IndexOf($script:sessionCodes,$old)}finally{$script:changingStage=$false}
  $status.Text='مرحلهٔ تازه ذخیره نشد؛ انتخاب قبلی حفظ شد. سقف ۵۰۰ تغییر، ساعت سیستم یا نوشتن فایل را بررسی کن.'
 }
 Update-RecorderHealth
}
function New-SessionSelector {
 $bar=New-Object Windows.Forms.FlowLayoutPanel;$bar.Dock='Fill';$bar.FlowDirection='RightToLeft';$bar.WrapContents=$false;$bar.AutoScroll=$true
 $caption=New-Object Windows.Forms.Label;$caption.Text='مرحلهٔ فعلی (انتخاب تو):';$caption.AutoSize=$true;$caption.Margin=New-Object Windows.Forms.Padding(8,12,8,0)
 $script:sessionSelector=New-Object Windows.Forms.ComboBox;$script:sessionSelector.DropDownStyle='DropDownList';$script:sessionSelector.Width=190;$script:sessionSelector.Font=New-Object Drawing.Font('Tahoma',12);$script:sessionSelector.Margin=New-Object Windows.Forms.Padding(8,6,8,0)
 foreach($code in $script:sessionCodes){[void]$script:sessionSelector.Items.Add($script:stageLabels[$code])}
 $script:sessionSelector.SelectedIndex=[Array]::IndexOf($script:sessionCodes,$script:sessionStage)
 $script:sessionSelector.Enabled=($script:liveRunning -and !$script:recordingStopping)
 $script:sessionSelector.Add_SelectedIndexChanged({if($script:sessionSelector.SelectedIndex -ge 0){Select-SessionStage $script:sessionCodes[$script:sessionSelector.SelectedIndex]}})
 $hint=New-Object Windows.Forms.Label;$hint.Text='فقط نمونه‌ها و رویدادهای همان زمان برچسب می‌گیرند.';$hint.AutoSize=$true;$hint.Margin=New-Object Windows.Forms.Padding(8,12,8,0)
 $bar.Controls.AddRange(@($caption,$script:sessionSelector,$hint));return $bar
}
function Recorder-HealthText {
 if(!$script:liveRunning){return $(if($script:liveFailed){'ضبط تأیید نشد؛ نمایش قبلی را نتیجهٔ نهایی فرض نکن.'}elseif($script:liveLastSnapshot){'ضبط پایان یافت؛ نتیجهٔ ذخیره‌شده نمایش داده می‌شود.'}else{'آمادهٔ شروع رصد؛ مرحله با انتخاب تو مشخص می‌شود.'})}
 if($script:recordingStopping){return 'در حال پایان‌دادن: منتظر ذخیره و تأیید بمان؛ این وضعیت اتصال زنده نیست.'}
 $snapshot=$script:liveLastSnapshot
 if(!$snapshot){return 'در حال آماده‌سازی؛ منتظر اولین فریم معتبر رصد بمان.'}
 $age=if($script:liveLastArrival -eq [DateTime]::MinValue){999}else{[Math]::Max(0,([DateTime]::UtcNow-$script:liveLastArrival).TotalSeconds)}
 $parts=@($(if($age -gt 4){'هشدار: رصد/انتشار بیش از ۴ ثانیه به‌روز نشده'}elseif(!$snapshot.sampled_utc){'آماده؛ منتظر اولین نوبت رصد'}else{'رصد فعال؛ فریم تازه'}),('مرحله: '+$script:stageLabels[$script:sessionStage]),('TCP '+@($snapshot.endpoints).Count),('DNS '+@($snapshot.event_evidence.events|Where-Object {$_.kind -eq 'dns_query'}).Count),('منع WFP '+@($snapshot.event_evidence.events|Where-Object {$_.kind -eq 'wfp_connection_block'}).Count))
 if($snapshot.sampled_utc){$parts+=('آخرین نوبت رصد UTC: '+(Utc-Text $snapshot.sampled_utc))}
 if($script:livePause -and $script:livePause.Checked){$parts+='نمایش مکث است؛ دریافت/ضبط ادامه دارد'}
 if($script:liveFrameError){$parts+='خطای خواندن فریم؛ داده قبلی حفظ شد'}
 if($script:liveRenderError){$parts+='خطای نمایش؛ تاریخچهٔ ذخیره‌شده را بررسی کن'}
 if($script:sessionPhaseDirty -or $script:liveJournalDirty){$parts+='هشدار ذخیرهٔ انتخاب‌ها؛ انتخاب تازه را ذخیره‌شده فرض نکن'}
 if($snapshot.query_errors){$parts+=('خطای نمونه‌برداری: '+$snapshot.query_errors)}
 if($snapshot.live_write_errors){$parts+=('خطای انتشار: '+$snapshot.live_write_errors)}
 if($snapshot.phase_recording.read_errors){$parts+=('خطای خواندن مرحله: '+$snapshot.phase_recording.read_errors)}
 if(!$snapshot.history_baseline.complete){$parts+='سابقه ناقص؛ تازه/قدیمی بودن همیشه قطعی نیست'}
 if($snapshot.truncated -or $snapshot.event_evidence.truncated){$parts+='ضبط/شواهد ناقص؛ سقف یا ازدحام'}
 $parts+=('DNS: '+(Live-StreamLabel $snapshot.event_evidence.streams.dns));$parts+=('WFP: '+(Live-StreamLabel $snapshot.event_evidence.streams.wfp))
 $selected=@($snapshot.phase_recording.transitions)
 if($script:sessionTransitions.Count -gt $selected.Count){$parts+='مرحلهٔ تازه در انتظار دریافت ضبط‌کننده'}
 return $parts -join ' | '
}
function Live-EventSessionStages($row){
 # Live event delivery can lag. Associate its original timestamp, never arrival time.
 $snapshot=$script:liveLastSnapshot;$recording=$snapshot.phase_recording
 if(!$snapshot -or !$recording -or $recording.read_errors -or $recording.status -in @('invalid','not_recorded')){return @()}
 try{
  $when=[DateTimeOffset]::Parse((Utc-Text $row.observed_utc));$lo=[DateTimeOffset]::Parse((Utc-Text $snapshot.capture_started_utc));$hi=[DateTimeOffset]::Parse((Utc-Text $snapshot.published_utc))
  if($when -lt $lo -or $when -gt $hi){return @()}
  $code='unknown';$previous=[DateTimeOffset]::MinValue;$sequence=0
  foreach($entry in @($recording.transitions)){
   $sequence++;$at=[DateTimeOffset]::Parse((Utc-Text $entry.selected_utc))
   if($entry.sequence -ne $sequence -or $entry.stage -notin @('unknown','launch','login','dashboard','in_game') -or $at -lt $previous){return @()}
   if($at -le $when){$code=[string]$entry.stage};$previous=$at
  }
  return @(Stage-Codes $code)
 }catch{return @()}
}
function Update-RecorderHealth {
 $text=Recorder-HealthText
 if($script:liveSummary){$script:liveSummary.Text=$text;$warning=($text -match 'هشدار|خطا|ناقص|تأیید نشد');$script:liveSummary.BackColor=$(if($warning){[Drawing.Color]::FromArgb(251,235,222)}else{[Drawing.Color]::FromArgb(249,248,247)})}
 if($script:job -and $script:job.Action -eq 'observe'){$status.Text=$text}
}
function Start-CaptureComparison {
 if(!(Can-SwitchCapture)){return}
 $ids=@($historyGrid.SelectedRows|ForEach-Object {$_.Tag.capture_id})
 if($ids.Count -ne 2){$status.Text='برای مقایسه، دقیقاً دو ضبط را با Ctrl انتخاب کن.';return}
 BeginOp 'compare_captures' @{capture_ids=$ids}
}
function Show-CaptureComparison($report,[string]$text){
 $d=New-Object Windows.Forms.Form;$d.Text='مقایسهٔ دو ضبط — تفاوت مشاهدات، نه اثبات بلاک';$d.ClientSize=New-Object Drawing.Size(900,640);$d.MinimumSize=New-Object Drawing.Size(700,480);$d.StartPosition='CenterScreen';$d.Font=New-Object Drawing.Font('Tahoma',10)
 if($script:liveForm){$d.TopMost=$script:liveForm.TopMost}
 $panel=New-Object Windows.Forms.TableLayoutPanel;$panel.Dock='Fill';$panel.Padding=New-Object Windows.Forms.Padding(12);$panel.ColumnCount=1;$panel.RowCount=2
 [void]$panel.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)));[void]$panel.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,56)))
 $body=New-Object Windows.Forms.TextBox;$body.Dock='Fill';$body.Multiline=$true;$body.ReadOnly=$true;$body.ScrollBars='Both';$body.WordWrap=$false;$body.RightToLeft='No';$body.Font=New-Object Drawing.Font('Tahoma',10);$body.Text=$text;$body.Select(0,0);$panel.Controls.Add($body,0,0)
 $actions=Flow;$saveReport=Button 'ذخیرهٔ گزارش';$closeReport=Button 'بستن';$closeReport.DialogResult='OK';$actions.Controls.AddRange(@($closeReport,$saveReport));$panel.Controls.Add($actions,0,1)
 # Bind values in the modal dialog's scope; no file path from the backend is executed.
 $saveReport.Add_Click({$target=New-Object Windows.Forms.SaveFileDialog;$target.Filter='Text report (*.txt)|*.txt';$target.FileName='WoW-Comparison-'+[DateTime]::Now.ToString('yyyyMMdd-HHmmss')+'.txt';$target.OverwritePrompt=$true;try{if($target.ShowDialog() -eq 'OK'){[IO.File]::WriteAllText($target.FileName,$body.Text,(New-Object Text.UTF8Encoding($true)))}}catch{[void][Windows.Forms.MessageBox]::Show('ذخیرهٔ گزارش انجام نشد؛ مسیر و دسترسی را بررسی کن.')}finally{$target.Dispose()}})
 $d.Controls.Add($panel);$d.CancelButton=$closeReport;try{[void]$d.ShowDialog($form)}finally{$d.Dispose()}
}
