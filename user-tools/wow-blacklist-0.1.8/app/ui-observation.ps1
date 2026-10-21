function Active-TcpGrid {
 if($tabs.SelectedTab -eq $blackTab){return $black}
 if($tabs.SelectedTab -eq $obsTab){return $found}
 if($tabs.SelectedTab -eq $coveredTab){return $covered}
 return $null
}
function Observation-Key($e){if($e.record_id){return [string]$e.record_id};return [string]$e.pid+'|'+[string]$e.process_started_utc+'|'+(Ui-Key $e)}
function Observation-States($e){return @($e.state_samples.PSObject.Properties|ForEach-Object {$_.Name+' ('+[string]$_.Value+')'}) -join ', '}
function Observation-Coverage($e){if($e.covered_by_verified_block){return 'تطابق با Block در زمان بررسی'};if($e.block_classification -eq 'unverified'){return 'بررسی نامطمئن؛ پنهان نمی‌شود'};return 'Block منطبق در این نصب تأیید نشد'}
function Remember-ObservedChecks {
 if($script:renderingObserved){return}
 foreach($grid in @($found,$covered)){foreach($row in $grid.Rows){if($row.Tag){$script:observedChecks[(Observation-Key $row.Tag)]=($row.Cells['choose'].Value -eq $true)}}}
}
function Sync-ObservedCheck($source,[int]$index) {
 if($script:renderingObserved -or $script:syncingObservedChecks -or $index -lt 0){return}
 $row=$source.Rows[$index];if(!$row.Tag){return};$key=Observation-Key $row.Tag;$value=($row.Cells['choose'].Value -eq $true);$script:observedChecks[$key]=$value
 $script:syncingObservedChecks=$true
 try{foreach($grid in @($found,$covered)){foreach($other in $grid.Rows){if($other.Tag -and (Observation-Key $other.Tag) -eq $key -and $other.Cells['choose'].Value -ne $value){$other.Cells['choose'].Value=$value}}}}finally{$script:syncingObservedChecks=$false}
}
function Observed-Detail($e) {
 $matches=@($e.block_matches|ForEach-Object {Ui-Text @($_)}) -join ', '
 return (Ui-Text @($e))+' | PID: '+$e.pid+' | process started UTC: '+$e.process_started_utc+[Environment]::NewLine+'مرحلهٔ مشاهده (دستی): '+(Stage-For $e)+' | '+(Live-DestinationLabel $e.destination_history)+[Environment]::NewLine+'TCP samples: '+(Observation-States $e)+' | first UTC: '+$e.first_seen_utc+' | last UTC: '+$e.last_seen_utc+[Environment]::NewLine+(Observation-Coverage $e)+' | snapshot UTC: '+$e.block_checked_utc+' | '+$matches+[Environment]::NewLine+'Established یعنی این حالت در یک نمونه دیده شده، نه تضمین اتصال فعلی/ارسال داده. SynSent یعنی انتظار اتصال، نه اثبات ارسال یا افت بسته. تطابق Block اثبات افت بسته نیست.'+[Environment]::NewLine+(PtrDetail $e)
}
function Add-ObservedRow($grid,$e) {
 $i=$grid.Rows.Add();$row=$grid.Rows[$i];$row.Tag=$e;$key=Observation-Key $e
 $values=@{choose=($script:observedChecks.ContainsKey($key) -and $script:observedChecks[$key]);ip=$e.ip;port=[int]$e.port;protocol='TCP';hostname=(PtrName $e);ptrstate=(PtrState $e);samples=[int]$e.samples;fresh=$(if($e.fresh_process_seen){'تازه'}else{'قبلی / نامشخص'});tcpstate=(Observation-States $e);pid=[int]$e.pid;coverage=(Observation-Coverage $e);stage=(Stage-For $e);history=(Live-DestinationLabel $e.destination_history)}
 foreach($name in $values.Keys){$row.Cells[$name].Value=$values[$name]}
 $row.Cells['stage'].ToolTipText=Stage-For $e;$row.Cells['hostname'].ToolTipText=PtrName $e;$row.Cells['tcpstate'].ToolTipText=Observation-States $e
}
function Show-ObservedRows {
 if(!$script:resetObservedChecks){Remember-ObservedChecks};$script:resetObservedChecks=$false;$script:renderingObserved=$true
 try{
  $found.Rows.Clear();$covered.Rows.Clear()
  $partition=Ui-ObservationPartition $script:observed $onlyFresh.Checked $hideCovered.Checked
  foreach($e in @($partition.main)){Add-ObservedRow $found $e};foreach($e in @($partition.covered)){Add-ObservedRow $covered $e}
  $oldHidden=$partition.old_hidden;$matchCount=$partition.match_count
  $obsTab.Text='رصد اصلی ('+$found.Rows.Count+')';$coveredTab.Text='زیر پوشش Block ('+$covered.Rows.Count+')'
  $check=if($script:observationSnapshot -and $script:observationSnapshot.available){'UTC: '+$script:observationSnapshot.checked_utc}else{'بررسی Block نامعتبر/قدیمی؛ مقصدی بر این اساس پنهان نمی‌شود'}
  $obsSummary.Text='کل رکوردها: '+$script:observed.Count+' | فرایند قبلی پنهان: '+$oldHidden+' | تطابق Block: '+$matchCount+' | '+$check
  if($script:observationSnapshot -and $script:observationSnapshot.unverified_owned_count){$obsSummary.Text+=' | قواعد نامطمئن کنارگذاشته‌شده: '+$script:observationSnapshot.unverified_owned_count}
  if($script:observationProgram -and $script:observationProgram -ine $program.Text){$obsSummary.Text+=' | رصد مربوط به مسیر قبلی است؛ برای مسیر جدید ضبط کن'}
  if($script:observationHistorical){$obsSummary.Text+=' | ضبط ذخیره‌شده؛ وضعیت Block مربوط به زمان ضبط است'}
  if($script:observationTruncated){$obsSummary.Text+=' | هشدار: سقف ۲۰۰۰ رکورد؛ ضبط ناقص است'}
 }finally{$script:renderingObserved=$false}
}
function Invalidate-ObservationClassification {
 if(!$script:observed.Count){return}
 foreach($e in $script:observed){$e.covered_by_verified_block=$false;$e.block_classification='unverified';$e.block_matches=@();$e.block_checked_utc=''}
 $script:observationSnapshot=$null;Show-ObservedRows
}
function Hosts-Label([string]$kind){switch($kind){'local_sink_mapping'{'نگاشت محلی؛ روش رایج مسدودسازی'};'mixed_mapping'{'نگاشت محلی و غیرمحلی؛ نیاز به بررسی'};'system_local'{'نام محلی سیستم؛ مسدودسازی فرض نشود'};default{'نگاشت / تغییرمسیر دیگر'}}}
function Show-Hosts($report) {
 $script:hostsReport=$report
 $hostsGrid.Rows.Clear()
 foreach($e in @($report.entries)){$i=$hostsGrid.Rows.Add($e.domain,(@($e.addresses) -join ', '),(Hosts-Label $e.mapping_kind),(@($e.lines) -join ', '));$hostsGrid.Rows[$i].Tag=$e}
 $hostsSummary.Text='خوانده‌شده از hosts استاندارد ویندوز | دامنه‌ها: '+$hostsGrid.Rows.Count+' | نگاشت محلی رایج: '+$report.local_sink_domains+' | چندنگاشت: '+$report.mixed_domains+' | موارد نامعتبر: '+$report.invalid_items+' | فقط تنظیمات؛ تلاش بازی یا قطع واقعی تأیید نشده است.'
 if($report.truncated){$hostsSummary.Text+=' | نمایش ناقص: سقف '+$report.domain_limit+' دامنه'}
}
