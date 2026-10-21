. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-live-model.ps1'))))
$script:liveForm=$null;$script:liveCaptureId='';$script:liveJob=$null;$script:liveStages=@{};$script:liveRows=@{};$script:liveEventRows=@{};$script:livePulses=@{};$script:liveRevision=0;$script:liveRendering=$false;$script:liveRunning=$false;$script:liveLastRead=[DateTime]::MinValue;$script:liveJournalDirty=$false;$script:liveSummary=$null;$script:liveLastSnapshot=$null;$script:liveDeleted=@{}
function New-LiveWindow {
 if($script:liveForm){return}
 $script:liveForm=New-Object Windows.Forms.Form;$w=$script:liveForm;$w.Text='مانیتور زندهٔ مقصدهای Wow — نمونه‌برداری TCP';$w.ClientSize=New-Object Drawing.Size(1180,740);$w.MinimumSize=New-Object Drawing.Size(900,660);$w.StartPosition='CenterScreen';$w.TopMost=$true;$w.Font=New-Object Drawing.Font('Tahoma',10);$w.BackColor=[Drawing.Color]::White;$w.AutoScaleMode='Dpi'
 $panel=New-Object Windows.Forms.TableLayoutPanel;$panel.Dock='Fill';$panel.Padding=New-Object Windows.Forms.Padding(12);$panel.ColumnCount=1;$panel.RowCount=6
 foreach($h in @(48,112,96,-1,64,56)){$style=if($h -eq -1){New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)}else{New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$h)};[void]$panel.RowStyles.Add($style)};$w.Controls.Add($panel)
 $panel.Controls.Add((New-SessionSelector),0,0)
 $toolbar=Flow;$toolbar.WrapContents=$true
 $script:liveTop=New-Object Windows.Forms.ToolStripMenuItem;$script:liveTop.Text='همیشه روی پنجره‌ها';$script:liveTop.Checked=$true;$script:liveTop.AutoSize=$true;$script:liveTop.Margin=New-Object Windows.Forms.Padding(8,16,8,0)
 $script:liveFlash=New-Object Windows.Forms.ToolStripMenuItem;$script:liveFlash.Text='پالس رنگی نمونهٔ TCP';$script:liveFlash.Checked=$true;$script:liveFlash.AutoSize=$true;$script:liveFlash.Margin=New-Object Windows.Forms.Padding(8,16,8,0)
 $script:liveFollow=New-Object Windows.Forms.ToolStripMenuItem;$script:liveFollow.Text='دنبال‌کردن ردیف تازه';$script:liveFollow.Checked=$true;$script:liveFollow.AutoSize=$true;$script:liveFollow.Margin=New-Object Windows.Forms.Padding(8,16,8,0)
 $script:livePause=New-Object Windows.Forms.ToolStripMenuItem;$script:livePause.Text='مکث نمایش (ضبط ادامه دارد)';$script:livePause.AutoSize=$true;$script:livePause.Margin=New-Object Windows.Forms.Padding(8,16,8,0)
 $script:liveStop=Button 'توقف ضبط';$liveStop=$script:liveStop;$liveSave=Button 'ذخیرهٔ برچسب‌ها';$liveHide=Button 'پنهان‌کردن';$livePtr=Button 'PTR انتخاب‌ها';$liveDelete=Button 'حذف انتخاب‌ها';$liveOptions=Button 'گزینه‌های نمایش'
 $options=New-Object Windows.Forms.ContextMenuStrip
 foreach($item in @($script:liveTop,$script:liveFlash,$script:liveFollow,$script:livePause)){$item.CheckOnClick=$true;$item.Margin=New-Object Windows.Forms.Padding(0);[void]$options.Items.Add($item)}
 [void]$options.Items.Add((New-Object Windows.Forms.ToolStripSeparator));$livePtrAll=New-Object Windows.Forms.ToolStripMenuItem;$livePtrAll.Text='PTR تا ۱۰۰ IP بدون کش معتبر';$livePtrStop=New-Object Windows.Forms.ToolStripMenuItem;$livePtrStop.Text='توقف PTR';[void]$options.Items.Add($livePtrAll);[void]$options.Items.Add($livePtrStop)
 $liveOptions.ContextMenuStrip=$options;$liveOptions.Add_Click({param($sender,$e) $sender.ContextMenuStrip.Show($sender,(New-Object Drawing.Point(0,$sender.Height)))})
 $livePtr.Add_Click({Start-LivePtr $false});$livePtrAll.Add_Click({Start-LivePtr $true});$livePtrStop.Add_Click({Stop-LivePtr});$liveDelete.Add_Click({Delete-LiveRecords});$toolbar.Controls.AddRange(@($liveStop,$liveSave,$liveDelete,$livePtr,$liveOptions,$liveHide));$panel.Controls.Add($toolbar,0,1)

 $script:liveSummary=Label 'منتظر شروع رصد؛ این پنجره اتصال واقعی یا ارسال درخواست را اثبات نمی‌کند.';$script:liveSummary.Font=New-Object Drawing.Font('Tahoma',9);$panel.Controls.Add($script:liveSummary,0,2)
 $script:liveGrid=Grid;$g=$script:liveGrid;$g.ReadOnly=$false;$g.EditMode='EditOnEnter';$g.AutoSizeColumnsMode='None';$g.AccessibleName='Live TCP recorder: destination local history, process age, sample pulses and manual stage'
 Column $g 'number' '#' 8;Column $g 'ip' 'IP' 20;Column $g 'port' 'Port' 8;Column $g 'history' 'مقصد تازه / قدیمی' 24
 $c=New-Object Windows.Forms.DataGridViewButtonColumn;$c.Name='stage';$c.HeaderText='مرحله‌ها؛ کلیک برای انتخاب';$c.FlatStyle='Flat';[void]$g.Columns.Add($c)
 Column $g 'hostname' 'نام PTR — نه دامنهٔ قطعی' 24;Column $g 'ptrstate' 'وضعیت PTR' 18
 Column $g 'blockspec' 'قانون در شروع ضبط؛ نه افت واقعی' 24
 Column $g 'signal' 'وضعیت آخرین نمونه' 20;Column $g 'states' 'حالت‌های TCP دیده‌شده' 20;Column $g 'first' 'اولین مشاهده UTC' 15;Column $g 'last' 'آخرین مشاهده UTC' 15;Column $g 'process' 'فرایند تازه / قدیمی' 20;Column $g 'pid' 'PID' 8;Column $g 'samples' 'دفعات مشاهده' 10
 foreach($col in $g.Columns){$col.ReadOnly=($col.Name -ne 'stage');$col.SortMode='NotSortable';$col.Width=160};$g.Columns['stage'].Width=360;$g.Columns['hostname'].Width=300;$g.Columns['number'].Width=48;$g.Columns['ip'].Width=180;$g.Columns['ip'].DefaultCellStyle.Font=New-Object Drawing.Font('Consolas',10);$g.Columns['port'].Width=66;$g.Columns['pid'].Width=68;$g.Columns['history'].Width=200;$g.Columns['first'].Width=210;$g.Columns['last'].Width=210;$g.Columns['samples'].Width=100;$g.Columns['blockspec'].Width=260
 $script:liveTabs=New-Object Windows.Forms.TabControl;$script:liveTabs.Dock='Fill';$tcpPage=New-Object Windows.Forms.TabPage;$tcpPage.Text='نمونه‌های TCP';$tcpPage.Controls.Add($g)
 $evidencePage=New-Object Windows.Forms.TabPage;$evidencePage.Text='شواهد DNS و منع اتصال';$script:liveEvidenceGrid=Grid;$eg=$script:liveEvidenceGrid;$eg.ReadOnly=$false;$eg.EditMode='EditOnEnter';$eg.AutoSizeColumnsMode='None'
 Column $eg 'when' 'زمان رویداد UTC' 18;Column $eg 'target' 'دامنه / IP و پورت' 25;Column $eg 'verdict' 'نوع شواهد؛ نه حدس' 30
 $ec=New-Object Windows.Forms.DataGridViewButtonColumn;$ec.Name='stage';$ec.HeaderText='مرحله‌ها؛ کلیک برای انتخاب';$ec.FlatStyle='Flat';[void]$eg.Columns.Add($ec)
 Column $eg 'hostname' 'نام PTR — فقط برای IP' 24;Column $eg 'ptrstate' 'وضعیت PTR' 18;Column $eg 'pid' 'PID' 8;Column $eg 'source' 'منبع' 12;Column $eg 'info' 'جزئیات DNS / hosts / WFP' 25
 foreach($col in $eg.Columns){$col.ReadOnly=($col.Name -ne 'stage');$col.SortMode='NotSortable';$col.Width=160};$eg.Columns['stage'].Width=360;$eg.Columns['when'].Width=230;$eg.Columns['target'].Width=280;$eg.Columns['verdict'].Width=360;$eg.Columns['pid'].Width=70;$eg.Columns['info'].Width=330
 $evidencePage.Controls.Add($eg);[void]$script:liveTabs.TabPages.Add($tcpPage);[void]$script:liveTabs.TabPages.Add($evidencePage);$panel.Controls.Add($script:liveTabs,0,3)
 $script:liveDetail=New-Object Windows.Forms.TextBox;$script:liveDetail.Dock='Fill';$script:liveDetail.Multiline=$true;$script:liveDetail.ReadOnly=$true;$script:liveDetail.ScrollBars='Vertical';$script:liveDetail.RightToLeft='No';$panel.Controls.Add($script:liveDetail,0,4)
 $legend=Label 'تب شواهد: قرمز=رویداد منع WFP؛ نارنجی=نگاشت hosts، نه اثبات منع. آبی: ردیف تازهٔ این ضبط؛ سبز: مشاهدهٔ دوباره در نمونهٔ TCP؛ خاکستری: در آخرین نمونه دیده نشد. رنگ یا شمارش نمونه، اثبات ارسال درخواست/بسته یا قطع اتصال نیست.';$legend.Font=New-Object Drawing.Font('Tahoma',9);$panel.Controls.Add($legend,0,5)
 $script:livePause.Add_CheckedChanged({if(!$script:livePause.Checked -and $script:liveLastSnapshot){Render-LiveSnapshot $script:liveLastSnapshot}})
 $script:liveTop.Add_CheckedChanged({$script:liveForm.TopMost=$script:liveTop.Checked})
 $liveHide.Add_Click({$script:liveForm.Hide()})
 $w.Add_FormClosing({param($sender,$e) $e.Cancel=$true;$sender.Hide()})
 $liveStop.Add_Click({Request-RecordingStop})
 $liveSave.Add_Click({Save-LiveLabels; if(!$script:liveRunning -and $script:captureId -eq $script:liveCaptureId){if(!$script:job){Save-CaptureAnnotations}else{$script:liveSummary.Text='عملیات دیگری در جریان است؛ برچسب‌ها نگه داشته شدند. پس از پایان دوباره ذخیره کن.'}}})
 foreach($editableGrid in @($g,$eg)){
 $editableGrid.Add_CurrentCellDirtyStateChanged({param($sender,$e) if($sender.IsCurrentCellDirty){[void]$sender.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit)}})
 $editableGrid.Add_CellContentClick({param($sender,$e) if($e.RowIndex -ge 0 -and $e.ColumnIndex -eq $sender.Columns['stage'].Index){Edit-LiveStages $sender.Rows[$e.RowIndex]}})
 $editableGrid.Add_DataError({param($sender,$e) $e.ThrowException=$false;$e.Cancel=$true})
 }
 $g.Add_SelectionChanged({if($script:liveGrid.SelectedRows.Count -and $script:liveGrid.SelectedRows[0].Tag){$r=$script:liveGrid.SelectedRows[0].Tag;$script:liveDetail.Text='TCP '+$r.ip+':'+$r.port+' | PID: '+$r.pid+' | شروع فرایند UTC: '+(Utc-Text $r.process_started_utc)+[Environment]::NewLine+'اولین مشاهده UTC: '+(Utc-Text $r.first_seen_utc)+' | آخرین مشاهده UTC: '+(Utc-Text $r.last_seen_utc)+[Environment]::NewLine+'این ردیف تاریخچهٔ نمونه‌هاست؛ درخواست HTTP، payload، شمارش بسته و افت فایروال اندازه‌گیری نمی‌شوند.'}})
}
function Open-LiveWindow {New-LiveWindow;if(!$script:liveForm.Visible){$script:liveForm.Show()};if($script:liveLastSnapshot){Render-LiveSnapshot $script:liveLastSnapshot};Set-LiveBusy}
function Set-LiveBusy {if(!$script:liveForm){return};$script:liveStop.Enabled=($script:liveRunning -and !$script:recordingStopping);if($script:sessionSelector){$script:sessionSelector.Enabled=($script:liveRunning -and !$script:recordingStopping)};$differentCapture=(!$script:liveRunning -and $script:captureId -and $script:captureId -ne $script:liveCaptureId);foreach($grid in @($script:liveGrid,$script:liveEvidenceGrid)){$grid.ReadOnly=($differentCapture -or ($script:job -and $script:job.Action -ne 'observe'));foreach($c in $grid.Columns){$c.ReadOnly=($c.Name -ne 'stage')}}}
function Start-LiveCapture($job){
 if($script:liveForm){[void]$script:liveGrid.EndEdit();$script:liveGrid.Rows.Clear();[void]$script:liveEvidenceGrid.EndEdit();$script:liveEvidenceGrid.Rows.Clear()}
 $script:recordingStopping=$false;$script:liveDeleted=@{};$script:liveCaptureId=$job.Id;$script:liveJob=$job;$script:liveStages=@{};$script:liveRows=@{};$script:liveEventRows=@{};$script:livePulses=@{};$script:liveRevision=0;$script:liveLastRead=[DateTime]::MinValue;$script:liveRunning=$true;$script:liveLastSnapshot=$null;$script:liveJournalDirty=$false
 $script:liveFailed=$false;Start-SessionStages
 if($script:liveForm){$script:livePause.Checked=$false;$script:liveSummary.Text='در حال آماده‌سازی سابقه و رصد؛ منتظر پیام آمادگی بمان.'}
 if($liveEnabled.Checked){Open-LiveWindow}
}
function Save-LiveLabels {
 if(!$script:liveJob){return}
 try{
  $path=$script:liveJob.LiveLabels;$tmp=$path+'.tmp';$data=@{schema='wow-live-labels-1';capture_id=$script:liveCaptureId;entries=$script:liveStages;deleted_record_ids=@($script:liveDeleted.Keys)}
  [IO.File]::WriteAllText($tmp,($data|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)));if([IO.File]::Exists($path)){[IO.File]::Replace($tmp,$path,[NullString]::Value)}else{[IO.File]::Move($tmp,$path)};$script:liveJournalDirty=$false
 }catch{$script:liveJournalDirty=$true;if($script:liveSummary){$script:liveSummary.Text='ذخیرهٔ زندهٔ برچسب ناموفق بود؛ انتخاب‌ها در حافظه‌اند. دوباره ذخیره کن و پنجره را نبند.'}}
}
function Live-StatesText($row){return @($row.state_samples.PSObject.Properties|ForEach-Object {$_.Name+' ('+$_.Value+')'}) -join ', '}
function Render-LiveSnapshot($snapshot){
 if(!$script:liveForm -or $script:livePause.Checked){return}
 $script:liveRendering=$true;$added=$false
 try{
  foreach($e in @($snapshot.endpoints)){
   $key=[string]$e.record_id;if($key -cnotmatch '^[a-f0-9]{32}$' -or $script:liveDeleted.ContainsKey($key)){continue}
   $before=$null
   if($script:liveRows.ContainsKey($key)){$r=$script:liveRows[$key];$before=$r.Tag}else{$i=$script:liveGrid.Rows.Add();$r=$script:liveGrid.Rows[$i];$script:liveRows[$key]=$r;$added=$true}
   $kind=Live-PulseKind $before $e
   if($kind -in @('discovery','sample','reappeared')){$script:livePulses[$key]=@{Kind=$kind;Until=[DateTime]::UtcNow.AddMilliseconds($(if($kind -eq 'discovery'){1800}else{650}))}}
   $r.Tag=$e;$values=@{hostname=(PtrName $e);ptrstate=(PtrState $e);number=$e.discovery_sequence;ip=$e.ip;port=[int]$e.port;history=(Live-DestinationLabel $e.destination_history);stage=(Live-StageText $e);blockspec=(Live-RuleLabel $e $snapshot.block_snapshot_start);signal=$(if($e.seen_in_latest_sample){'در آخرین نمونه دیده شد'}else{'در آخرین نمونه دیده نشد'});states=(Live-StatesText $e);first=(Utc-Text $e.first_seen_utc);last=(Utc-Text $e.last_seen_utc);process=(Live-ProcessLabel $e);pid=$e.pid;samples=$e.samples}
   foreach($name in $values.Keys){if($name -ne 'stage' -or !$r.Cells['stage'].IsInEditMode){if($r.Cells[$name].Value -ne $values[$name]){$r.Cells[$name].Value=$values[$name];if($name -eq 'stage'){$r.Cells[$name].ToolTipText=[string]$values[$name]}}}}
  }
  Render-LiveEvidence $snapshot.event_evidence
  $new=@($snapshot.endpoints|Where-Object {$_.destination_history -eq 'first_in_local_history'}).Count;$old=@($snapshot.endpoints|Where-Object {$_.destination_history -eq 'previously_seen'}).Count;$uncertain=@($snapshot.endpoints|Where-Object {$_.destination_history -eq 'history_uncertain'}).Count
  $script:liveSummary.Text=$(if($script:recordingStopping){'توقف درخواست شده؛ منتظر ذخیره و تأیید'}elseif($script:liveRunning){'ضبط زنده'}else{'ضبط پایان‌یافته؛ وضعیت‌ها مربوط به آخرین نمونه‌اند'})+' | '+[math]::Round($snapshot.seconds,1)+' ثانیه | کل '+@($snapshot.endpoints).Count+' | مقصد تازه '+$new+'، قدیمی '+$old+'، نامطمئن '+$uncertain+' | خطای خواندن '+$snapshot.query_errors
  $script:liveSummary.Text+=' | DNS: '+(Live-StreamLabel $snapshot.event_evidence.streams.dns)+' | Block: '+(Live-StreamLabel $snapshot.event_evidence.streams.wfp)
  if($snapshot.event_evidence.truncated){$script:liveSummary.Text+=' | شواهد رویداد ناقص؛ سقف/ازدحام'}
  if(!$snapshot.history_baseline.complete){$script:liveSummary.Text+=' | سابقه ناقص؛ ندیدن در سابقه به معنی تازه‌بودن نیست'}
  if($snapshot.truncated){$script:liveSummary.Text+=' | سقف ۲۰۰۰ رکورد؛ ضبط ناقص'}
  if($snapshot.live_write_errors){$script:liveSummary.Text+=' | خطای انتشار زنده: '+$snapshot.live_write_errors}
  if($script:liveJournalDirty){$script:liveSummary.Text+=' | هشدار: برچسب‌های ذخیره‌نشده'}
  if($added -and $script:liveFollow.Checked -and !$script:liveGrid.IsCurrentCellInEditMode -and $script:liveGrid.Rows.Count){$script:liveGrid.FirstDisplayedScrollingRowIndex=$script:liveGrid.Rows.Count-1}
 }finally{$script:liveRendering=$false}
 Paint-LivePulses;Update-RecorderHealth
}
function Paint-LivePulses {
 if(!$script:liveForm -or !$script:liveForm.Visible -or $script:livePause.Checked){return}
 $now=[DateTime]::UtcNow
 foreach($key in $script:liveRows.Keys){
  $row=$script:liveRows[$key];$color=if($row.Tag.seen_in_latest_sample){[Drawing.Color]::White}else{[Drawing.Color]::FromArgb(240,239,237)}
  if($script:liveFlash.Checked -and $script:liveRunning -and $script:livePulses.ContainsKey($key) -and $script:livePulses[$key].Until -gt $now){$color=if($script:livePulses[$key].Kind -eq 'discovery'){[Drawing.Color]::FromArgb(229,242,252)}else{[Drawing.Color]::FromArgb(232,241,236)}}
  if($row.DefaultCellStyle.BackColor.ToArgb() -ne $color.ToArgb()){$row.DefaultCellStyle.BackColor=$color;$row.DefaultCellStyle.ForeColor=[Drawing.Color]::FromArgb(44,44,43);$row.DefaultCellStyle.SelectionBackColor=[Drawing.Color]::FromArgb([Math]::Max(0,$color.R-20),[Math]::Max(0,$color.G-12),[Math]::Max(0,$color.B-5));$row.DefaultCellStyle.SelectionForeColor=[Drawing.Color]::FromArgb(44,44,43)}
 }
}
function Poll-LiveCapture($job){
 try{
  if(Test-Path -LiteralPath $job.Live){$stamp=[IO.File]::GetLastWriteTimeUtc($job.Live);if($stamp -ne $script:liveLastRead){$snapshot=Live-ReadSnapshot $job.Live $job.Id;if([int]$snapshot.revision -gt $script:liveRevision){$script:liveLastSnapshot=$snapshot;if($snapshot.finished){$script:recordingStopping=$true;$stop.Enabled=$false;Set-LiveBusy};$script:liveRevision=[int]$snapshot.revision;$script:liveLastRead=$stamp;$script:liveLastArrival=[DateTime]::UtcNow;$script:liveFrameError=$false;try{Render-LiveSnapshot $snapshot;$script:liveRenderError=$false}catch{$script:liveRenderError=$true;Write-UiDiagnostic 'live_render' $_}}}}
 }catch{$script:liveFrameError=$true;if($script:liveSummary){$script:liveSummary.Text='فریم زنده خوانده نشد؛ دادهٔ قبلی حفظ شد و دوباره تلاش می‌شود. ضبط مستقل ادامه دارد.'}}
 if($script:liveRunning -and $script:liveLastSnapshot -and ([DateTime]::UtcNow-$script:liveLastRead).TotalSeconds -gt 4 -and $script:liveSummary){$script:liveSummary.Text='هشدار: فریم زنده بیش از ۴ ثانیه به‌روز نشده؛ نمایش قبلی را وضعیت فعلی فرض نکن. رصد یا انتشار ممکن است در انتظار/خطا باشد.'}
 Paint-LivePulses;Update-RecorderHealth
}
function Finish-LiveCapture($report){
 $script:liveRunning=$false;$script:recordingStopping=$false
 # Labels changed after the collector's final journal read are retained for one final save.
 foreach($e in @($report.endpoints)+@($report.event_evidence.events)){$key=[string]$e.record_id;if($script:liveStages.ContainsKey($key)){
  $codes=@(Stage-Codes $script:liveStages[$key]);if(($codes -join '|') -ne (@(Stage-Codes $script:stageEdits[$key]) -join '|')){$script:stageEdits[$key]=$codes;$script:annotationsDirty=$true}
 }}
 Update-AnnotationIndicator
 # Use the verified final capture, NOT a potentially stale / paused live frame.
 $script:liveLastSnapshot=[pscustomobject]@{phase_recording=$report.phase_recording;endpoints=$report.endpoints;event_evidence=$report.event_evidence;block_snapshot_start=$report.block_snapshot_start;history_baseline=$report.history_baseline;seconds=$report.seconds;query_errors=$report.query_errors;truncated=$report.truncated}
 if($script:liveForm){$script:liveGrid.Rows.Clear();$script:liveEvidenceGrid.Rows.Clear();$script:liveRows=@{};$script:liveEventRows=@{};$script:livePause.Checked=$false;Render-LiveSnapshot $script:liveLastSnapshot}
 Set-LiveBusy
}
function Fail-LiveCapture {$script:liveFailed=$true;$script:liveRunning=$false;$script:recordingStopping=$false;Set-LiveBusy;if($script:liveSummary){$script:liveSummary.Text='رصد کامل ذخیره/تأیید نشد؛ این نمایش زنده را ضبط موفق فرض نکن. برچسب‌های موقت در private-state نگه داشته شده‌اند.'}}
function Sync-LiveStageFromMain([string]$key,$codes){
 if($script:liveRunning -or $script:captureId -ne $script:liveCaptureId){return}
 $script:liveStages[$key]=@(Stage-Codes $codes);$script:liveRendering=$true;try{foreach($map in @($script:liveRows,$script:liveEventRows)){if($map.ContainsKey($key)){$map[$key].Cells['stage'].Value=Live-StageText $map[$key].Tag}}}finally{$script:liveRendering=$false}
}

function Render-LiveEvidence($evidence){
 $eventAdded=$false
 foreach($e in @($evidence.events)){
  $key=[string]$e.record_id;if($key -cnotmatch '^[a-f0-9]{32}$' -or $script:liveDeleted.ContainsKey($key)){continue}
  if($script:liveEventRows.ContainsKey($key)){$row=$script:liveEventRows[$key]}else{$i=$script:liveEvidenceGrid.Rows.Add();$row=$script:liveEvidenceGrid.Rows[$i];$script:liveEventRows[$key]=$row;$eventAdded=$true}
  $row.Tag=$e;$isBlock=($e.kind -eq 'wfp_connection_block')
  $target=if($isBlock){[string]$e.ip+':'+[string]$e.port+' '+[string]$e.protocol}else{[string]$e.domain}
  $info=if($isBlock){'Security 5157 | filter: '+[string]$e.filter_id+' | مالک قانون تعیین نشده'}else{'DNS status: '+[string]$e.dns_status+' | hosts: '+(@($e.hosts_addresses) -join ', ')+' | '+[string]$e.query_results}
  $values=@{hostname=$(if($isBlock){PtrName $e}else{''});ptrstate=$(if($isBlock){PtrState $e}else{'نام DNS در خود رویداد است؛ PTR نیست'});when=(Utc-Text $e.observed_utc);target=$target;verdict=(Live-EvidenceLabel $e);stage=(Live-StageText $e);pid=$e.pid;source=$(if($isBlock){'Security 5157'}else{'Sysmon 22'});info=$info}
  foreach($name in $values.Keys){if($name -ne 'stage' -or !$row.Cells['stage'].IsInEditMode){if($row.Cells[$name].Value -ne $values[$name]){$row.Cells[$name].Value=$values[$name];if($name -eq 'stage'){$row.Cells[$name].ToolTipText=[string]$values[$name]}}}}
  $color=if($isBlock){[Drawing.Color]::FromArgb(252,233,231)}elseif($e.hosts_mapping -in @('local_sink_mapping','mixed_mapping')){[Drawing.Color]::FromArgb(251,235,222)}else{[Drawing.Color]::White}
  $row.DefaultCellStyle.BackColor=$color;$row.DefaultCellStyle.SelectionBackColor=$(if($isBlock){[Drawing.Color]::FromArgb(246,205,202)}else{[Drawing.Color]::FromArgb(229,242,252)});$row.DefaultCellStyle.SelectionForeColor=[Drawing.Color]::FromArgb(44,44,43)
 }
 $script:liveTabs.TabPages[1].Text='DNS / منع اتصال ('+$script:liveEventRows.Count+')'
 if($eventAdded -and $script:liveFollow.Checked -and !$script:liveEvidenceGrid.IsCurrentCellInEditMode -and $script:liveEvidenceGrid.Rows.Count){$script:liveEvidenceGrid.FirstDisplayedScrollingRowIndex=$script:liveEvidenceGrid.Rows.Count-1}
}
function Load-LiveHistory($report){
 $script:liveFailed=$false;$script:recordingStopping=$false;$script:sessionStage='unknown'
 if($script:sessionSelector){$script:changingStage=$true;try{$script:sessionSelector.SelectedIndex=0}finally{$script:changingStage=$false}}
 $script:liveDeleted=@{};$script:liveRunning=$false;$script:liveJob=$null;$script:liveCaptureId=[string]$report.capture_id;$script:liveStages=@{};$script:liveRows=@{};$script:liveEventRows=@{};$script:livePulses=@{}
 foreach($row in @($report.endpoints)+@($report.event_evidence.events)){if($row.context){$script:liveStages[[string]$row.record_id]=@(Row-CurrentStages $row)}}
 if($script:liveForm){$script:liveGrid.Rows.Clear();$script:liveEvidenceGrid.Rows.Clear();$script:livePause.Checked=$false}
 $script:liveLastSnapshot=[pscustomobject]@{phase_recording=$report.phase_recording;endpoints=$report.endpoints;event_evidence=$report.event_evidence;block_snapshot_start=$report.block_snapshot_start;history_baseline=$report.history_baseline;seconds=$report.seconds;query_errors=$report.query_errors;truncated=$report.truncated;live_write_errors=0}
 if($script:liveForm){Render-LiveSnapshot $script:liveLastSnapshot}
 Set-LiveBusy
}
