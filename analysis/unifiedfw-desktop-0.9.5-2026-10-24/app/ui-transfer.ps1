# Explicit EXE registration is separate from IP/domain prefill. No implicit rule or endpoint creation.
$script:pendingProcessTransfer=$null
function Get-ObservedProgramPaths($Rows,$KnownPrograms){
 $known=@{};foreach($p in @($KnownPrograms)){$known[([string]$p.path).ToLowerInvariant()]=$true}
 $seen=@{};$paths=New-Object Collections.Generic.List[string]
 foreach($r in @($Rows)){
  if($null -eq $r.Tag -or $r.Tag.PSObject.Properties.Name -notcontains 'program_path'){throw 'ردیف انتخابی مسیر EXE ندارد.'}
  $path=[string]$r.Tag.program_path
  if(-not $path -or $path -notmatch '^[a-zA-Z]:\\' -or [IO.Path]::GetExtension($path) -ine '.exe'){throw 'مسیر EXE انتخابی معتبر نیست؛ چیزی ثبت نشد.'}
  $key=$path.ToLowerInvariant();if($known.ContainsKey($key) -or $seen.ContainsKey($key)){continue}
  $seen[$key]=$true;$paths.Add($path)
 }
 if($paths.Count -gt 32 -or @($KnownPrograms).Count+$paths.Count -gt 32){throw 'حداکثر ۳۲ مسیر برنامه در تنظیمات پشتیبانی می‌شود؛ تعداد کمتری انتخاب کنید.'}
 return $paths.ToArray()
}
function Set-ProcessTransferControls {
 $can=($null -ne $script:state -and $null -eq $script:pendingProcessTransfer -and -not $script:closing -and ($null -eq $script:job -or $script:job.action -in @('monitor_record','baseline_record')))
 foreach($button in @($transferPrograms,$popupTransferPrograms)){$button.Enabled=$can}
}
function Show-TransferredPrograms {
 # A prior search must not hide the newly registered rows. Checkboxes and native policy are unchanged.
 $filter.Text='';$tabs.SelectedTab=$programTab;$livePopup.Hide();$form.BringToFront()
 $status.Text='فرایندهای منتخب در برنامه‌ها ثبت شدند؛ فقط فایل فعلی دیسک بررسی و هش‌گیری شد. هیچ مقصد/قاعده‌ای اضافه یا Apply نشده است. برای عملیات بعدی EXEها را خودتان تیک بزنید.'
}
function Start-ProcessTransfer($Plan){
 if($script:closing){return}
 BeginOp 'register' @{paths=@($Plan.paths);generation=[int]$Plan.generation}
 $script:job.process_transfer=$true
}
function Transfer-ObservedPrograms($Grid){
 if($script:closing -or $null -ne $script:pendingProcessTransfer){throw 'انتقال یا بستن برنامه در حال انجام است؛ منتظر بمانید.'}
 if($null -ne $script:ptrJob){throw 'ابتدا PTR را پایان دهید یا متوقف کنید.'}
 if($null -ne $script:job -and $script:job.action -notin @('monitor_record','baseline_record')){throw 'ابتدا عملیات جاری را تمام کنید.'}
 if($Grid.SelectedRows.Count -eq 0){throw 'یک یا چند ردیف فرایند/مقصد را انتخاب کنید؛ Ctrl و Shift برای انتخاب چند ردیف هستند.'}
 $paths=@(Get-ObservedProgramPaths @($Grid.SelectedRows) @($script:state.config.programs))
 if($paths.Count -eq 0){$tabs.SelectedTab=$programTab;$filter.Text='';$livePopup.Hide();$form.BringToFront();$status.Text='این مسیرها قبلاً در برنامه‌ها ثبت شده‌اند؛ هش یا تنظیمات قبلی بازنویسی نشد.';return}
 $running=($null -ne $script:job)
 $explanation='فقط مسیرهای زیر به بخش برنامه‌ها افزوده می‌شوند. فایل فعلی هر مسیر روی دیسک با روش ثبت موجود بررسی و SHA256 گرفته می‌شود؛ هویت فایل در حافظه یا زمان رصد تأیید نمی‌شود. مسیرهای ثبت‌شده بازنویسی نمی‌شوند. هیچ IP، دامنه، بلک‌لیست، وایت‌لیست، hosts یا قاعده‌ای اضافه/Apply نمی‌شود.'+"`r`n`r`n"+($paths -join "`r`n")
 if($running){$explanation+="`r`n`r`nبا تأیید، ابتدا همین ثبت رصد به‌صورت عادی پایان می‌یابد و سپس انتقال انجام می‌شود؛ خود بازی/فرایندها متوقف نمی‌شوند. رصد خودکار دوباره شروع نمی‌شود."}
 if([Windows.Forms.MessageBox]::Show($explanation,'تأیید انتقال و ثبت EXE در برنامه‌ها','YesNo','Question') -ne 'Yes'){return}
 $plan=@{paths=@($paths);generation=(Generation)}
 if($running){
  $plan.recording_folder=[string]$script:job.folder;$script:pendingProcessTransfer=$plan
  try{Request-MonitorStop;$status.Text='توقف عادی رصد برای انتقال فرایندها درخواست شد؛ تا پایان ثبت صبر کنید. هنوز EXE ثبت نشده است.'}catch{$script:pendingProcessTransfer=$null;throw}
  Set-ProcessTransferControls
 }else{Start-ProcessTransfer $plan}
}
function Complete-PendingProcessTransfer($FinishedJob,[bool]$Succeeded){
 if($null -eq $script:pendingProcessTransfer){return $false}
 if([string]$script:pendingProcessTransfer.recording_folder -cne [string]$FinishedJob.folder){return $false}
 $plan=$script:pendingProcessTransfer;$script:pendingProcessTransfer=$null
 if($script:closing -or -not $Succeeded){$status.Text='انتقال EXE انجام نشد؛ ثبت رصد ناموفق بود یا برنامه در حال بسته‌شدن است. تنظیم برنامه‌ها از این انتقال تغییر نکرد.';Set-ProcessTransferControls;return $true}
 Start-ProcessTransfer $plan;return $true
}
$transferPrograms=Button 'انتقال فرایندهای منتخب به برنامه‌ها'
$popupTransferPrograms=Button 'انتقال فرایندهای منتخب به برنامه‌ها'
Add-ToolControl $monitorTools $transferPrograms;Add-ToolControl $popupTools $popupTransferPrograms
$tip.SetToolTip($transferPrograms,'انتخاب چند ردیف → تأیید ثبت EXE. هنگام رصد، ابتدا همان ثبت عادی متوقف می‌شود. قواعد تغییر نمی‌کنند.')
$tip.SetToolTip($popupTransferPrograms,'ثبت صریح EXE در برنامه‌ها؛ جدا از انتقال بدون ذخیرهٔ IP/دامنه.')
$transferPrograms.Add_Click({TryOp {$g=if($mainLiveTabs.SelectedTab -eq $processTab){$processGrid}elseif($mainLiveTabs.SelectedIndex -eq 1){$domainMain}else{$liveGrid};Transfer-ObservedPrograms $g}})
$popupTransferPrograms.Add_Click({TryOp {$g=if($popupLiveTabs.SelectedTab -eq $popupProcessTab){$popupProcessGrid}elseif($popupLiveTabs.SelectedIndex -eq 1){$domainPopup}else{$popupGrid};Transfer-ObservedPrograms $g}})
# A distinct third menu action; the existing two IP/domain actions remain prefill-only.
foreach($menu in $script:observedMenus){
 $item=New-Object Windows.Forms.ToolStripMenuItem;$item.Text='انتقال EXE ردیف به برنامه‌ها (ثبت با تأیید)';[void]$menu.Items.Add($item)
 $item.Add_Click({param($sender,$e)TryOp {Transfer-ObservedPrograms $sender.Owner.Tag.grid}})
}
Set-ProcessTransferControls
