# UI selection -> stable persisted code. Legacy vpn_allowlist is read-only compatibility, never silently applied.
function Resolve-PolicyMode([int]$PolicyIndex,[int]$ConnectionIndex){
 if($PolicyIndex -eq 0){return 'blacklist_only'}
 if($PolicyIndex -ne 1 -or $ConnectionIndex -notin @(0,1)){throw 'حالت سیاست و روش اتصال را انتخاب کنید.'}
 if($ConnectionIndex -eq 0){return 'direct_isolation'};return 'full_isolation'
}
function Get-PolicySelection([string]$Code){
 switch -CaseSensitive ($Code){
  'blacklist_only'{return [pscustomobject]@{policy=0;connection=1;legacy=$false}}
  'direct_isolation'{return [pscustomobject]@{policy=1;connection=0;legacy=$false}}
  'full_isolation'{return [pscustomobject]@{policy=1;connection=1;legacy=$false}}
  'vpn_allowlist'{return [pscustomobject]@{policy=1;connection=1;legacy=$true}}
  default{throw 'مود ذخیره‌شده شناخته نشد؛ تنظیمات خودکار تبدیل نمی‌شوند.'}
 }
}
function Get-IsolationReviewText($Review){
 $method=if($Review.PSObject.Properties.Name -contains 'connection'){[string]$Review.connection}else{'vpn'}
 $parts=New-Object Collections.Generic.List[string]
 $parts.Add('این تغییر برای کل ویندوز و تمام برنامه‌هاست؛ نه فقط EXEهای تیک‌خورده. ممکن است اینترنت سایر برنامه‌ها قطع شود. Administrator لازم است.')
 if($method -ceq 'direct'){
  $parts.Add('روش: ایزولاسیون معمولی. فقط IP/پورت‌های وایت‌لیست از رابط‌های موجود مجاز می‌شوند؛ VPN اجباری نیست. DNS، DHCP و انتقال VPN خودکار آزاد نمی‌شوند؛ نام‌گشایی و تمدید اتصال ممکن است قطع شود.')
 }else{
  $parts.Add('روش: فقط از VPN. وایت‌لیست فقط داخل رابط دقیق SSTP مجاز می‌شود؛ خروج مستقیم ممنوع است. انتقال محدود سرویس SSTP و DNS داخل تونل استثنا هستند؛ DNS/DHCP بیرون تونل آزاد نمی‌شوند.')
  if($null -ne $Review.vpn -and $Review.vpn.PSObject.Properties.Name -contains 'name'){$parts.Add('VPN منتخب: '+$Review.vpn.name+' | سرور: '+$Review.vpn.server)}
 }
 $parts.Add('خروجی پیش‌فرض هر سه پروفایل ویندوز مسدود می‌شود. مجوزهای خروجی محلی پس از ثبت تصویر پشتیبان غیرفعال می‌شوند؛ تعداد: '+$Review.quarantine_allow_count)
 $parts.Add('مقاصد مجاز و پورت‌ها:')
 foreach($w in @($Review.whitelist)){$parts.Add((@($w.remote_addresses) -join ', ')+' | '+$w.protocol+' | '+$w.remote_port)}
 $parts.Add('هم‌پوشانی با بلک‌لیست همین ابزار: '+@($Review.overlaps).Count+'؛ وایت‌لیست در روش منتخب مقدم است. Block دیگران و hosts حفظ می‌شوند و ممکن است اتصال مجاز را هم ببندند.')
 $parts.Add('محافظ SYSTEM در پس‌زمینه و پس از بستن رابط باقی می‌ماند. پایش دوره‌ای است، نه تضمین اتمی مقابل مدیر/GPO. نصب یا ذخیره به معنی فعال‌شدن نیست. تست نشت واقعی انجام نشده است.')
 $parts.Add('پیش‌فرض تنظیمات ایزولاسیون را خاموش نمی‌کند؛ برای برگشت فقط از بازیابی ایزولاسیون یا Isolation-Recovery.cmd استفاده کنید. شکست عملیات باعث آزادسازی خودکار نمی‌شود.')
 return $parts.ToArray() -join "`r`n`r`n"
}
function Get-IsolationStatusText($Value,[string]$Time){
 $method=if($Value.PSObject.Properties.Name -contains 'connection' -and $Value.connection -ceq 'direct'){'معمولی'}else{'VPN / SSTP'}
 $phase=[string]$Value.phase
 $text=if($phase -ceq 'not_configured'){'ایزولاسیون این ابزار تنظیم نشده است.'}elseif($phase -ceq 'restored'){'ایزولاسیون با درخواست شما بازیابی و غیرفعال شده است.'}elseif($phase -ceq 'armed' -and $Value.configuration_verified){
  if($Value.PSObject.Properties.Name -contains 'guardian_running' -and $Value.guardian_running -and $Value.PSObject.Properties.Name -contains 'guardian_heartbeat_fresh' -and $Value.guardian_heartbeat_fresh -and ($Value.PSObject.Properties.Name -notcontains 'guardian_last_error' -or -not $Value.guardian_last_error)){'تنظیمات فعال و محافظِ دارای گزارش تازه تأیید شدند؛ روش: '+$method}else{'انسداد پایه بررسی شد، اما اجرای محافظ با گزارش تازه هنوز تأیید نشده؛ دوباره وضعیت را بخوانید. روش: '+$method}
 }else{'وضعیت ایزولاسیون کامل تأیید نشد؛ Apply را تکرار نکنید و وضعیت/بازیابی را بررسی کنید.'}
 return 'آخرین بررسی '+$Time+' — '+$text+' | این نتیجه تأیید نبود نشتی نیست.'
}
