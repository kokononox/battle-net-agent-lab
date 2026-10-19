# S3 — بازیابی محدود اولیه موفق؛ نسخه سخت‌گیرتر هنوز عبور نکرده

## نتیجه دقیق دو نسخه
- نسخه اول source `40fd1b53b13cc03d77f0054dd467667958207474` در run `39187957739`:۱۶fixture و دو سناریوی واقعی full/partial_conflict روی runner موقت موفق شدند. driver آزمایش با Exit73 بدون cleanup خارج شد؛ task مستقل SYSTEM propertyهای برنامه‌ریزی‌شده را restore کرد، بدون fallback controller. تغییر مشخصات fixtureB به عنوان conflict حفظ شد، fixtureC نامرتبط دست‌نخورده ماند، replay درخواست restore تازه‌ای نداشت و task/ruleهای fixture پاک شدند. این آزمون روی دستگاه کاربر نبود.
- نسخه سخت‌گیرتر source `9f7b568c902c9028358d464e2d6bd8a9781feefb` در run `39188345339`:۱۷fixture پاس شدند، اما اجرای واقعی پیش از mutation در full_setup با `s3_no_real_profile_transition_available` متوقف شد؛ live scenarios خالی است. **این نسخه PASS نیست و مجوز Apply نداریم.**

## چرا نسخه تکمیلی و چرا توقف؟
مستند Microsoft برای DefaultOutboundAction، NotConfigured را GPO-only توصیف می‌کند. بنابراین نسخه تکمیلی، baseline محلی غیر Allow/Block را پیش از write رد می‌کند؛ همچنین شمار transition مشاهده‌شده را صریح می‌سنجد. [مرجع Microsoft](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps).

guard فعلی ترکیبی است: profileها باید سه مورد باشند، مقدارهای PersistentStore فقط Allow/Block و دست‌کم یکی Allow باشد. receipt مقدارهای baseline را منتشر نمی‌کند؛ **از کد توقف به‌تنهایی نمی‌توان مشخصاً NotConfigured، همه‌Block یا علت دقیق دیگر را نتیجه گرفت**. guard حذف یا دور زده نشده و setup runner برای گرفتن PASS دستکاری نشده است.

## گام بعد کم‌خطر
برای دانستن baseline قابل‌بازیابی روی Windows کاربر، فقط این read-only query لازم است؛ S1 قبلی ActiveStore/effective را داده بود، نه مقدار local ذخیره‌شده:

```powershell
Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name, DefaultOutboundAction
```

این خروجی سه نام profile و مقدارشان است، نه آدرس VPN/credential یا policy کامل. S2 تکرار، BAT99، Enable/Disable/EmergencyReset، Resume/Repair بازی یا upload backup خصوصی لازم نیست. WoW بسته و آپدیت Pause و تنظیمات فعلی حفظ شوند.

گام مهندسی باقی‌مانده: مشخص‌کردن علت دقیق baseline runner و روش مستند/آزموده برای برگشت مقدار محلی بدون تغییر معنای unset، سپس گذر gate سخت‌گیرتر؛ نه استفاده از PASS نسخه قدیمی به جای آن. هنوز بسته/لانچر S3 یا Apply به کاربر داده نشده و هیچ تغییر شبکه دستگاه کاربر از این آزمون انجام نشده است.

## حدود شواهد
compare-before-write این پیاده‌سازی اتمیک نیست و race بیرونی می‌ماند؛ حفظ fixtureِ تغییرکرده تضمین همه تغییرات هم‌زمان نیست. Allowهای موجود runner disable نشده‌اند، بنابراین actual default-deny/قطع اتصال موجود/IPv6 یا enforcement SSTP/Level3 آزمایش نشده است. fingerprint فایل و نبود telemetry در مقصد مجاز همچنان بازند. netsh import/reset یا overwrite کل policy استفاده نشده؛ WFP/IPsec/GPO/reboot/power-loss پوشش ندارند. فقط runner استاندارد Windows/Ubuntu، نه larger/paid runner؛ هزینه صفر تضمین نشده است.

## روش بررسی
هر نسخه یک JSON receipt مستقل است؛ نتیجه دو پیاده‌سازی با هم ادغام نشده است. profiler عمومی از کلیدهای nested جدول مصنوعی۱۷ردیفی ساخت؛ duplicate/null/mixed warnings ناشی از همین grain نادرست‌اند. تحلیل روی JSON اصلی با typed flags، case checks و بازخوانی مستقل انجام شد؛ چیزی حذف نشد. Hash چهار PS1 نسخه تکمیلی با CRLF بایت‌های آزموده‌شده مطابق است. run IDs شناسه‌اند، نه متغیر عددی قابل میانگین. شواهد محاسباتی همراه است؛ نمودار برای gate تشخیصی با نسخه‌های متفاوت مناسب نیست.
