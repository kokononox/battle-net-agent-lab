$script:stageLabels=@{unknown='نامشخص';launch='لانچ برنامه';login='ورود';dashboard='داشبورد';in_game='محیط بازی';multi_stage='چند مرحله (قدیمی، بدون جزئیات)'}
function Stage-Code([string]$label){foreach($key in $script:stageLabels.Keys){if($script:stageLabels[$key] -eq $label){return $key}};return 'unknown'}
function Stage-Codes($value){return @($value|Where-Object {$_ -and $_ -ne 'unknown' -and $script:stageLabels.ContainsKey([string]$_)}|Select-Object -Unique)}
function Stage-Text($codes){$labels=@(Stage-Codes $codes|ForEach-Object {$script:stageLabels[[string]$_]});if(!$labels.Count){return 'نامشخص'};return $labels -join '، '}
function Row-CurrentStages($row){if($row.context -and $null -ne $row.context.stages){return @(Stage-Codes $row.context.stages)};if($row.context){return @(Stage-Codes $row.context.stage)};return @()}
function Session-Stages($row){
 if($row.phase_context){return @(Stage-Codes $row.phase_context.stages)}
 if($row.phase_hits -is [Collections.IDictionary]){return @(Stage-Codes @($row.phase_hits.Keys))}
 if($row.phase_hits){return @(Stage-Codes @($row.phase_hits.PSObject.Properties|ForEach-Object {$_.Name}))}
 return @()
}
function Stage-For($row){
 $key=Observation-Key $row;$codes=if($script:stageEdits.ContainsKey($key)){$script:stageEdits[$key]}else{Row-CurrentStages $row}
 $label='این ضبط: '+(Stage-Text $codes)
 $session=@(Session-Stages $row);if($session.Count){$label+=' | هنگام رصد: '+(Stage-Text $session)}
 if($row.context.history_stages){$label+=' | سابقه: '+(Stage-Text $row.context.history_stages)}
 return $label
}
function Update-AnnotationIndicator {$saveAnnotations.Text='ذخیرهٔ برچسب‌ها'+$(if($script:annotationsDirty){' *'}else{''})}
function Commit-ObservationEdits {foreach($grid in @($found,$covered,$script:liveGrid,$script:liveEvidenceGrid)){if(!$grid){continue};if($grid.IsCurrentCellDirty){[void]$grid.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit)};[void]$grid.EndEdit()}}
function Set-RecordStages([string]$key,$codes){
 $script:stageEdits[$key]=@(Stage-Codes $codes);$script:annotationsDirty=$true
 Sync-LiveStageFromMain $key $script:stageEdits[$key]
 Update-AnnotationIndicator
}
function Set-CaptureContext($report,[bool]$historical) {
 $script:captureId=[string]$report.capture_id;$script:stageEdits=@{};$script:annotationsDirty=$false;$script:observationHistorical=$historical
 foreach($row in @($report.endpoints)+@($report.event_evidence.events)){if(!$row -or !$row.record_id){continue};$script:stageEdits[(Observation-Key $row)]=@(Row-CurrentStages $row)}
 Update-AnnotationIndicator
}
function Can-SwitchCapture {
 Commit-ObservationEdits
 if($script:annotationsDirty){$status.Text='برچسب‌های این ضبط ذخیره نشده‌اند؛ ابتدا «ذخیرهٔ برچسب‌ها» یا خروجی تحلیلی همین ضبط را بزن.';return $false};return $true
}
function Save-CaptureAnnotations {
 Commit-ObservationEdits
 if(!$script:captureId){$status.Text='ابتدا رصد بگیر یا یک ضبط قبلی را باز کن.';return}
 BeginOp 'annotate_observation' @{capture_id=$script:captureId;entries=$script:stageEdits}
}
function Utc-Text($value){if($value -is [DateTimeOffset]){return $value.UtcDateTime.ToString('o')};if($value -is [DateTime]){return $value.ToUniversalTime().ToString('o')};return [string]$value}
function Observation-PayloadRows {
 return @($script:observed|ForEach-Object {@{ip=$_.ip;port=[int]$_.port;pid=[int]$_.pid;process_started_utc=(Utc-Text $_.process_started_utc);fresh_process_seen=[bool]$_.fresh_process_seen;samples=[int]$_.samples;state_samples=$_.state_samples;first_seen_utc=(Utc-Text $_.first_seen_utc);last_seen_utc=(Utc-Text $_.last_seen_utc);record_id=[string]$_.record_id;destination_history=[string]$_.destination_history;discovery_sequence=$_.discovery_sequence;phase_hits=$_.phase_hits}})
}
function Show-CaptureHistory($report) {
 $historyGrid.Rows.Clear()
 foreach($entry in @($report.entries)){
  $when=Utc-Text $entry.started_utc
  if(!$when -and $entry.recorded_utc_epoch){$when=([DateTimeOffset]::FromUnixTimeSeconds([long]$entry.recorded_utc_epoch)).UtcDateTime.ToString('o')}
  $i=$historyGrid.Rows.Add($when,$entry.capture_id.Substring(0,8),[int]$entry.records,[int]$entry.annotated_records,$entry.program_sha256.Substring(0,12),$(if($entry.truncated){'بله'}else{'خیر'}),$(if($entry.annotation_state -eq 'available'){'قابل‌خواندن'}else{'برچسب نامعتبر / در دسترس نیست'}));$historyGrid.Rows[$i].Tag=$entry
 }
 $historySummary.Text='ضبط‌های قابل‌خواندن: '+$historyGrid.Rows.Count+' | فایل نامعتبر: '+$report.invalid_files+' | انتخاب چند ضبط با Ctrl/Shift؛ خروجی حداکثر ۵۰ ضبط و ۲۰٬۰۰۰ رکورد. همهٔ ردیف‌های هر ضبط وارد خروجی می‌شوند، نه فقط موارد نمایان.'
 if($report.truncated){$historySummary.Text+=' | فقط '+$report.limit+' فایل اخیر از '+$report.total_files+' فایل بررسی شدند'}
 $script:historyNeedsRefresh=$false
}
function Open-SelectedCapture {
 if(!(Can-SwitchCapture)){return}
 if($historyGrid.SelectedRows.Count -ne 1){$status.Text='برای بازکردن، دقیقاً یک ضبط را انتخاب کن.';return}
 BeginOp 'load_observation' @{capture_id=$historyGrid.SelectedRows[0].Tag.capture_id}
}
function Start-AnalysisExport([bool]$fromHistory=$false) {
 Commit-ObservationEdits
 $ids=if($fromHistory -or $tabs.SelectedTab -eq $historyTab){@($historyGrid.SelectedRows|ForEach-Object {$_.Tag.capture_id})}elseif($script:captureId){@($script:captureId)}else{@()}
 if(!$ids.Count){$tabs.SelectedTab=$historyTab;$status.Text='برای خروجی تحلیلی، ضبط‌های دلخواه را در تاریخچه انتخاب کن؛ یا ابتدا یک رصد بگیر.';return}
 if($ids.Count -gt 50){$status.Text='هر خروجی حداکثر ۵۰ ضبط؛ تعداد کمتری را انتخاب کن.';return}
 if($script:annotationsDirty -and $script:captureId -notin $ids){$status.Text='برچسب‌های ضبط بازشده ذخیره نشده‌اند؛ ابتدا ذخیره کن یا آن ضبط را هم برای خروجی انتخاب کن.';return}
 $d=New-Object Windows.Forms.SaveFileDialog;$d.Filter='Analysis bundle (*.zip)|*.zip';$d.FileName='WoW-Analysis-'+[DateTime]::Now.ToString('yyyyMMdd-HHmmss')+'.zip';$d.OverwritePrompt=$true
 try{if($d.ShowDialog() -eq 'OK'){
  $p=@{capture_ids=$ids;program=$program.Text;draft_text=(Ui-Text (Entries));draft_dirty=$script:dirty}
  if($script:annotationsDirty){$p.annotations=@{capture_id=$script:captureId;entries=$script:stageEdits}}
  BeginOp 'export_analysis' $p $false $d.FileName
 }}finally{$d.Dispose()}
}
function Complete-AnalysisExport($result,$job) {
 if($result.filename -cnotmatch '^WoW-Analysis-[a-f0-9]{32}\.zip$'){throw 'invalid_export_filename'}
 $source=Join-Path (Join-Path $root 'output') $result.filename
 if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ine $result.sha256){throw 'export_hash_mismatch'}
 if([IO.Path]::GetFullPath($source) -ine [IO.Path]::GetFullPath($job.ExportTarget)){[IO.File]::Copy($source,$job.ExportTarget,$true)}
 if($result.saved_annotation_capture_id -eq $script:captureId){$script:annotationsDirty=$false;Update-AnnotationIndicator;$script:historyNeedsRefresh=$true}
 $status.Text='خروجی تحلیلی ZIP ذخیره شد: '+$result.capture_count+' ضبط و '+$result.record_count+' رکورد؛ آپلود خودکار انجام نشده.'+$(if(!$result.active_blacklist_available){' خواندن بلک‌لیست فعال تأیید نشد؛ در گزارش نامعتبر مشخص شده است.'}else{''})
}
