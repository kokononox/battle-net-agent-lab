# Explicit opt-in persistent audit settings; no checkbox that silently changes Windows policy.
$auditStatusButton=Button 'وضعیت ثبت منع ویندوز';$auditEnableButton=Button 'فعال‌سازی ثبت تلاش‌های مسدودشده';$auditRestoreButton=Button 'بازگردانی سیاست ثبت قبلی'
$auditHint=Label 'ثبت منع هنوز بررسی نشده؛ ثبت ویندوز سراسری و ماندگار است، مستقل از Restore فایروال.'
$auditHint.MaximumSize=New-Object Drawing.Size(600,0)
$auditBar=Flow;foreach($v in @($auditStatusButton,$auditEnableButton,$auditRestoreButton,$auditHint)){$auditBar.Controls.Add($v)}
# Context actions stay near the monitor; do not consume the list's height with permanent paragraphs.
$auditPage=Tab 'ثبت منع / تنظیمات';$auditPanel=Stack $auditPage 2
$auditPanel.RowStyles[0].SizeType='AutoSize';$auditPanel.RowStyles[1].SizeType='Percent';$auditPanel.RowStyles[1].Height=100
$auditPanel.Controls.Add($auditBar,0,0)
$auditHelp=TextBox 700;$auditHelp.Multiline=$true;$auditHelp.ReadOnly=$true;$auditHelp.Dock='Fill';$auditHelp.ScrollBars='Vertical';$auditHelp.RightToLeft='Yes'
$auditHelp.Text="۱. ابتدا رصد جاری را متوقف کنید و Start.cmd را با Administrator باز کنید.`r`n۲. وضعیت ثبت را بخوانید. اگر Failure از قبل فعال است، نیازی به فعال‌سازی دوباره نیست؛ برنامه مالک آن تنظیم نمی‌شود.`r`n۳. فعال‌سازی فقط با تأیید دکمه‌ای انجام می‌شود. این تنظیم برای تمام ویندوز است و می‌تواند متادیتای اتصال برنامه‌های دیگر را در Security log ثبت کند و حجم لاگ را زیاد کند.`r`n۴. سپس رصد تازه را شروع و برنامهٔ هدف را اجرا کنید. تلاش منع‌شدهٔ ثبت‌شده در Security 5157 با پس‌زمینه و پالس قرمز، تعداد رویداد و زمان UTC نمایش داده می‌شود. این شمارش بسته یا HTTP نیست و عامل منع الزاماً این ابزار نیست.`r`n۵. بستن برنامه، پایان رصد، Restore فایروال و راه‌اندازی مجدد ویندوز، سیاست ثبت را برنمی‌گردانند. بازگردانی سیاست ثبت جداگانه و با تأیید است. Security log پاک نمی‌شود.`r`nپوشش کامل تضمین نیست: GPO، سیاست هر کاربر، محدودیت/دسترسی لاگ و تأخیر ثبت مؤثرند. رصد خط مبنا فرایندهای کوتاه‌عمر یا خارج‌شده را بدون هویت زنده حدس نمی‌زند. نبود ردیف منع، اثبات نبود تلاش نیست.`r`nرسید محافظت‌شده: %ProgramData%\UnifiedFirewallAudit-096\audit-state.json — حذف نکنید. در صورت خرابی رابط، Audit-Recovery.cmd با Administrator برای STATUS یا RESTOREAUDIT است، نه Restore فایروال. تغییرات بیرونیِ هم‌مقدار و رقابت هم‌زمان قابل کشف قطعی نیستند. برنامه تغییر آشکار سیاست را برای بازگردانی رد می‌کند."
$auditPanel.Controls.Add($auditHelp,0,1)
$null=New-MenuEntry $auditPage 'ثبت منع / تنظیمات ویندوز'
$denialHealth=Label 'WFP 5157: هنوز رصدی نداریم؛ نبود رویداد اثبات نبود تلاش نیست.'
$popupDenialHealth=Label $denialHealth.Text
# Always-visible summary alongside contextual tools, distinct from optional detailed legend.
$healthPanel=New-Object Windows.Forms.TableLayoutPanel;$healthPanel.Dock='Fill';$healthPanel.ColumnCount=1;$healthPanel.RowCount=2;$healthPanel.AutoSize=$true
$monitorLayout.Controls.Remove($liveStatus);$healthPanel.Controls.Add($liveStatus,0,0);$healthPanel.Controls.Add($denialHealth,0,1);$monitorLayout.Controls.Add($healthPanel,0,1)
$denialHealth.AutoSize=$false;$denialHealth.Dock='Fill';$denialHealth.Height=30;$denialHealth.AutoEllipsis=$true;$denialHealth.Font=New-Object Drawing.Font('Tahoma',9);$denialHealth.Add_MouseEnter({$tip.SetToolTip($denialHealth,$denialHealth.Text)})
Add-ToolControl $popupTools $popupDenialHealth
function Set-DenialControls {
 $enabled=($null -eq $script:job -and $null -eq $script:ptrJob)
 foreach($v in @($auditStatusButton,$auditEnableButton,$auditRestoreButton)){$v.Enabled=$enabled}
}
function Set-DenialHealth($Frame){
 $e=$Frame.event_evidence;$n=@($e.events|Where-Object{$_.kind -ceq 'wfp_connection_block'}).Count
 $last=@($e.events|Where-Object{$_.kind -ceq 'wfp_connection_block'}|Sort-Object observed_utc -Descending|Select-Object -First 1)
 $health=switch([string]$e.streams.wfp.status){'readable_logging_coverage_unverified'{'لاگ قابل خواندن؛ پوشش تأیید نشده'};'read_failed'{'خطای خواندن لاگ'};'not_available_or_disabled'{'لاگ در دسترس نیست / غیرفعال'};default{'جمع‌آوری نشده'}}
 $text='منع اتصال WFP: '+$n+' رویداد | '+$health+$(if($last.Count){' | آخرین UTC: '+$last[0].observed_utc}else{''})+$(if($e.truncated){' | ثبت محدود/ناقص'}else{''})+' | آبی: فعالیت مشاهده‌شده، نه تحویل؛ قرمز: منع ثبت‌شده. نبود رویداد، نبود تلاش را ثابت نمی‌کند.'
 $denialHealth.Text=$text;$popupDenialHealth.Text=$text
}
function Accept-AuditStatus($Value){
 $phase=if($null -ne $Value.receipt){[string]$Value.receipt.phase}else{'رسید متعلق به این ابزار ندارد'}
 $auditHint.Text='Failure: '+$Value.failure_enabled+' | Security قابل خواندن: '+$Value.security_log_readable_enabled+' | رسید: '+$phase+' | UTC: '+$Value.checked_utc+' | ماندگار؛ بازگردانی جداگانه'
}
$auditStatusButton.Add_Click({TryOp {BeginOp 'audit_status' @{}}})
$auditEnableButton.Add_Click({TryOp {
 $token='ENABLE BLOCKED CONNECTION LOGGING'
 $explanation=$auditHelp.Text+"`r`n`r`nفقط Failure در Filtering Platform Connection فعال می‌شود؛ Success قبلی حفظ می‌شود. هیچ قاعدهٔ فایروال یا hosts تغییر نمی‌کند، لاگ پاک/بزرگ نمی‌شود و GPO دور زده نمی‌شود.`r`nبرای ادامه دقیقاً بنویسید:`r`n"+$token
 if(ConfirmText 'تأیید ثبت سراسری و ماندگار منع اتصال' $explanation $token){BeginOp 'audit_enable' @{confirmation=$token}}
}})
$auditRestoreButton.Add_Click({TryOp {
 $token='RESTORE PREVIOUS AUDIT POLICY'
 if(ConfirmText 'بازگردانی جداگانهٔ سیاست ثبت' ($auditHelp.Text+"`r`nبازگردانی ممکن است ثبت منع در کل ویندوز را متوقف کند. فقط با رسید محافظت‌شدهٔ این ابزار؛ لاگ‌های قبلی حذف نمی‌شوند. اگر برنامه/مدیر دیگری به همین تنظیم متکی است ابتدا هماهنگ کنید.`r`n"+$token) $token){BeginOp 'audit_restore' @{confirmation=$token}}
}})
Set-DenialControls;Update-VerticalMenu
