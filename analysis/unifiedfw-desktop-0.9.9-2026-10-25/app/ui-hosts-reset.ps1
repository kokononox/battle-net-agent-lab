# Hosts-only recovery. Never shares the firewall Restore button or unsaved domain editor.
$hostsResetTab=Nested-Tab $hostSections 'پاک‌سازی و بازیابی'
$hostsResetGrid=Grid @(@('utc','زمان پشتیبان UTC'),@('operation','عملیات'),@('bytes','حجم بایت'),@('id','شناسه پشتیبان'))
$hostsResetGrid.ReadOnly=$true;$hostsResetGrid.MultiSelect=$false;$hostsResetGrid.RightToLeft='No'
$hostsResetDefault=Local-Button 'پیش‌فرض ویندوز + پاک‌سازی DNS'
$hostsDnsFlush=Local-Button 'فقط پاک‌سازی کش DNS';$hostsResetReload=Local-Button 'بازخوانی پشتیبان‌ها'
$hostsResetRestore=Local-Button 'بازیابی پشتیبان منتخب'
$hostsResetFolder=Local-Button 'پوشهٔ پشتیبان hosts'
$hostsResetHint=Label 'این عملیات همهٔ نگاشت‌های سفارشی hosts را حذف می‌کند؛ نه فقط موارد برنامهٔ ما. قواعد فایروال تغییر نمی‌کنند. پیش‌نویس‌ها باقی می‌مانند و Apply دوباره می‌تواند انسداد را برگرداند. بازیابی هم می‌تواند انسداد قبلی را برگرداند.'
$hostsResetPanel=Local-Page $hostsResetTab '' $hostsResetGrid @($hostsResetDefault,$hostsDnsFlush,$hostsResetReload,$hostsResetRestore,$hostsResetFolder)
$hostsResetPanel.Controls.Remove($hostsResetPanel.GetControlFromPosition(0,0));$hostsResetPanel.Controls.Add($hostsResetHint,0,0)
$hostsResetDefault.BackColor=[Drawing.ColorTranslator]::FromHtml('#FCE9E7');$hostsResetDefault.ForeColor=[Drawing.ColorTranslator]::FromHtml('#8A2424')
$hostsResetDefault.Add_Click({TryOp {BeginOp 'hosts_reset_prepare' @{}}})
$hostsDnsFlush.Add_Click({TryOp {
 if(ConfirmText 'فقط پاک‌سازی کش DNS ویندوز' 'فقط کش DNS ویندوز پاک می‌شود؛ فایل hosts، پشتیبان‌ها، قواعد فایروال، سرورهای DNS، Winsock و نشست‌های ETW تغییر نمی‌کنند. این کار اتصال موجود و کش داخلی برنامه‌ها را تضمیناً پاک نمی‌کند. Administrator لازم است.' 'FLUSH WINDOWS DNS CACHE'){BeginOp 'hosts_reset_dns_flush' @{confirmation='FLUSH WINDOWS DNS CACHE'}}
}})
$hostsResetReload.Add_Click({TryOp {BeginOp 'hosts_reset_list' @{}}})
$hostsResetRestore.Add_Click({TryOp {
 if($hostsResetGrid.SelectedRows.Count -ne 1){throw 'ابتدا بازخوانی پشتیبان‌ها و سپس یک ردیف را انتخاب کنید.'}
 BeginOp 'hosts_reset_restore_prepare' @{backup_id=[string]$hostsResetGrid.SelectedRows[0].Tag}
}})
$hostsResetFolder.Add_Click({TryOp {
 $folder=Join-Path $root 'private-state/hosts-reset-backups'
 if(-not (Test-Path -LiteralPath $folder -PathType Container)){throw 'هنوز پشتیبان پاک‌سازی در این نسخه ساخته نشده است.'}
 [void][Diagnostics.Process]::Start('explorer.exe',('"'+$folder+'"'))
}})
function Set-HostsResetControls([bool]$Busy){foreach($v in @($hostsResetDefault,$hostsDnsFlush,$hostsResetReload,$hostsResetRestore,$hostsResetFolder,$hostsResetGrid)){$v.Enabled=-not $Busy}}
function Accept-HostsResetResult($Result){
 if($Result.PSObject.Properties.Name -contains 'hosts_reset_backups'){
  $hostsResetGrid.Rows.Clear()
  foreach($item in @($Result.hosts_reset_backups)){$i=$hostsResetGrid.Rows.Add([string]$item.created_utc,[string]$item.operation,[string]$item.bytes,[string]$item.id);$hostsResetGrid.Rows[$i].Tag=[string]$item.id}
 }
 $tabs.SelectedTab=$hostsTab;$hostSections.SelectedTab=$hostsResetTab
 if($Result.PSObject.Properties.Name -contains 'hosts_reset_result'){
  Render-Hosts $Result.hosts
  $x=$Result.hosts_reset_result
  $message=if($x.operation -ceq 'reset'){'فایل hosts به پیش‌فرض ویندوز برگشت.'}else{'محتوای پشتیبان hosts بازیابی شد.'}
  $message+=' قواعد فایروال و پیش‌نویس‌ها تغییر نکردند. پشتیبان: '+$x.backup_filename
  if($x.dns_cache_flush.succeeded){$message+=' کش DNS پاک شد؛ اتصال‌های موجود و کش داخلی برنامه‌ها تضمیناً قطع/پاک نمی‌شوند.'}else{$message+=' هشدار: فایل hosts تأیید شد اما پاک‌سازی کش DNS موفق نبود. جزئیات را بررسی کنید؛ پاک‌سازی hosts را تکرار نکنید.'}
  $hostsSummary.Text=$message;$status.Text=$message
  # Nonmodal result: never start a nested message pump from backend completion.
  $hostsResetHint.Text=$message
 }
}
function Accept-DnsFlushResult($Result){
 $x=$Result.dns_cache_flush
 $message=if($x.succeeded){'کش DNS ویندوز پاک شد؛ hosts، قواعد و پشتیبان‌ها تغییر نکردند. اتصال موجود و کش داخلی برنامه‌ها تضمیناً پاک نمی‌شوند.'}else{'پاک‌سازی کش DNS موفق نشد؛ hosts، قواعد و پشتیبان‌ها تغییر نکردند. جزئیات خطا در گزارش است؛ بازنشانی hosts را تکرار نکنید.'}
 $hostsResetHint.Text=$message;$status.Text=$message
 $tabs.SelectedTab=$hostsTab;$hostSections.SelectedTab=$hostsResetTab
}
function Confirm-HostsResetPlan($Plan){
 $isRestore=$Plan.operation -ceq 'restore'
 $token=if($isRestore){'RESTORE HOSTS BACKUP'}else{'RESET WINDOWS HOSTS'}
 $action=if($isRestore){'hosts_reset_restore_apply'}else{'hosts_reset_apply'}
 $title=if($isRestore){'بازیابی سراسری hosts'}else{'حذف همهٔ نگاشت‌های سفارشی hosts'}
 $lines=@('SYSTEM-WIDE HOSTS ONLY / NO FIREWALL RESET',
 'روی همهٔ برنامه‌ها اثر دارد؛ نه فقط EXE منتخب. قواعد فایروال، VPN و سیاست Audit تغییر نمی‌کنند.',
 $(if($isRestore){'محتوای فایل با پشتیبان منتخب جایگزین می‌شود؛ انسدادهای قبلی هم ممکن است برگردند.'}else{'تمام نگاشت‌های سفارشی hosts، حتی مواردی که برنامهٔ ما نساخته، حذف می‌شوند.'}),
 'قبل از هر تغییر از محتوای فعلی پشتیبان گرفته و صحت آن بررسی می‌شود؛ شکست پشتیبان‌گیری عملیات را متوقف می‌کند.',
 'کش DNS ویندوز پاک می‌شود؛ تنظیم سرور DNS، Winsock و اتصال‌های موجود تغییر نمی‌کنند.',
 'پیش‌نویس محلی حفظ می‌شود؛ Apply دوباره می‌تواند نگاشت‌ها را بازگرداند.',
 'hosts باید موجود و قابل نوشتن باشد؛ قفل امنیتی، ReadOnly و مالکیت فایل به‌زور تغییر نمی‌کنند.',
 'پشتیبان‌ها در private-state\hosts-reset-backups همین پوشه‌اند؛ آن‌ها را خصوصی نگه دارید.',
 (ConvertTo-Json -InputObject $Plan -Depth 10),'',$token)
 if(ConfirmText $title ($lines -join "`r`n") $token){BeginOp $action @{confirmation=$token;backup_id=$Plan.backup_id;expected_sha256=[string]$Plan.expected_sha256;plan_digest=[string]$Plan.plan_digest}}
}
