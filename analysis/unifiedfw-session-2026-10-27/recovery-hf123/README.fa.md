# HF1.2.3 — اصلاح قرارداد بازیابی، فقط کاندید آفلاین

## رخداد واقعی و مرز نتیجه

کاربر پس از ری‌استارت و با SSTP خاموش گفت مرورگر روی Wi-Fi و LAN باز نمی‌شود. خروجی‌های ارسالی: ActiveStore و PersistentStore هر سه پروفایل Outbound=Block؛ DNS آزمایشی موفق (cache ممکن است)، TCP443 به مقصد آزمایشی ناموفق، پراکسی دستی/PAC گزارش‌شده غیرفعال/خالی. ژورنال محافظت‌شده phase=restored و restored=true برای سه پروفایل، before.default_outbound=NotConfigured داشت. checksum در دستور خواندنی تطبیق داشت؛ این به‌تنهایی اثبات صحت وضعیت runtime یا منشأ تغییر نیست.

پس از اجازهٔ صریح کاربر، دستور جداگانه ابتدا فقط تنظیمات پروفایل‌ها را در فایل محلی نسخه‌برداری کرد و سپس فقط DefaultOutboundAction سه پروفایل PersistentStore را Allow کرد. خروجی کاربر Allow در هر دو store، Enabled=True و ورودی مؤثر Block را نشان داد. کاربر سپس گفت مرورگر بدون VPN باز شد. فایل backup، مسیر شخصی، نام کاربری و raw ژورنال در مخزن ذخیره نشده‌اند. این **خروج مجاز به حالت عادی شبکه** بود، نه بازیابی دقیق baseline اولیه، نه qualification ایزولاسیون. دستور، ژورنال قدیمی را ویرایش نکرد. ری‌استارت پس از این تغییر آزموده نشده است.

## نقص‌های قطعی کد

1. Restore-IsoSession با phase=restored بدون خواندن تازه برمی‌گشت؛ label کهنه می‌توانست ناسازگاری را پنهان کند.
2. UI صرفاً با phase=restored، بازیابی/غیرفعال‌شدن را موفق اعلام می‌کرد، بدون اثبات وضعیت فعلی.
3. setter محلی NotConfigured را قبول می‌کرد و تست mock همین رفتار را موفق مدل می‌کرد. مطابق مستند Microsoft، NotConfigured برای DefaultOutboundAction فقط در GPO معتبر است؛ این قرارداد قابل اتکا برای local PersistentStore نبود.

[مرجع رسمی Set-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps).

این نقص‌ها **علت قطعی بازاعمال Block پس از reboot را ثابت نمی‌کنند**؛ provider persistence، controller دیگری، یا تغییر بیرونی هنوز تعیین نشده‌اند. علت خطای موقت 734 نیز نامعلوم باقی است.

## اصلاح پیاده‌شده در source overlay

- Prepare و Arm baseline محلی غیرصریح/NotConfigured را پیش از تغییر فایروال رد می‌کنند. Arm پیش از ایجاد transport نیز وضعیت local/effective را با baseline بررسی می‌کند. هیچ تبدیل خودکار NotConfigured→Allow نداریم.
- setter محلی فقط Allow/Block صریح را می‌پذیرد. این محدودیت برای DefaultOutboundAction است، نه DisabledInterfaceAliases یا سایر گزینه‌ها.
- قرارداد Ops یک ProfileEffectiveRead جداگانه می‌خواهد؛ fallback جعلی به خواندن local نداریم.
- Restore حتی برای label قدیمی restored، حضور مجدد قواعد owned، برابری تصویر قواعد foreign، baseline صریح پروفایل محلی و مقدار مؤثر آن را دوباره بررسی می‌کند؛ بدون هیچ auto-repair برای terminal mismatch.
- بعد از مراحل Restore، یک sweep تازه از تمام اجزای تحت مدیریت قبل از stamp موفقیت اجرا می‌شود؛ drift اجزای زودتر بازیابی‌شده نیز خطاست. هنوز خواندن‌های متوالی‌اند، نه تراکنش اتمیک علیه Admin/GPO/WFP.
- Summary برای restored مدرک تازه می‌گیرد، restoration_verified_now و restoration_reboot_qualified=false برمی‌گرداند. حتی task ثبت‌شدهٔ متوقف مانع تأیید نهایی است. Status صرفاً می‌خواند و Allow نمی‌کند.
- worker پس از cleanup task نیز به Summary تازه وابسته است؛ اگر تطبیق شکست بخورد، پاسخ موفق Restore نمی‌دهد.
- UI فقط boolean واقعی restoration_verified_now=true را موفقیت «همین بررسی» می‌داند؛ نبود flag، رشتهٔ True یا false پیام عدم تأیید می‌دهد. پایداری reboot/no-leak وعده داده نمی‌شود.
- Prepare/Apply روی ژورنال restored که با وضعیت جاری قابل تطبیق نیست متوقف می‌شود؛ journal قدیمی NotConfigured خودکار migrate/archive/adopt نمی‌شود. بعد از خروج دستی مجاز نیز baseline قدیمی را به‌دلخواه بازنویسی نمی‌کنیم. migration امن/رضایت‌دار هنوز لازم است.

## آزمون و تغییر fixtureها

۴۵ suite PowerShell گذشتند. ۵۳۳ متد Python اجرا شدند: ۵۳۱ pass و ۲ skip به دلیل نبود comparison source. ۱۰۰ فایل PS parse شدند. suite جدید ۴۹ assertion دارد: legacy NotConfigured قبل از write، baseline صریح Block بدون Allow ساختگی، local/effective mismatch، قاعدهٔ بازظاهرشده/foreign drift، sweep نهایی، Status بدون write، task باقی‌مانده، UI غیرگمراه‌کننده و شکست worker پس از cleanup.

fixture قبلی Test-IsolationCore که NotConfigured را به‌عنوان restore موفق local مدل می‌کرد عمداً با baseline صریح Allow جایگزین شد؛ تست جدید رفتار قدیمی را reject می‌کند. دو fixture دیگر برای فیلد نتیجهٔ تازه و import واقعی core به‌روز شدند. این به معنای اثبات provider Windows نیست؛ تست‌های جدید mock هستند. شکست اولیهٔ regression import شناسایی و اصلاح شد؛ نتیجهٔ نهایی همهٔ ۴۵ suite pass است.

Windows API، اجرای GUI واقعی، ACL، reboot، packet، سرعت و reconnect برای این patch آزموده نشده‌اند. transport compiler، محدودیت scope/owner، guardian و bulk helperها جز موارد نام‌برده در boundary checks تغییر نکرده‌اند.

## استقرار و اقدام بعد

**این فایل‌ها را روی نصب فعلی کاربر کپی نکنید.** هیچ نسخهٔ Windows قابل اجرا، runtime/EXE یا controller جدیدی نصب نشده؛ manifest بستهٔ قدیمی هم برای این تغییرها معتبر نیست. no_leak_certified و ready_for_apply=false باقی‌اند.

فعلاً اقدام تازه‌ای از کاربر لازم نیست؛ اینترنت بدون VPN به گفتهٔ او برگشته است. Apply، Restore، بستهٔ local-review و آزمون قطع‌و‌وصل تحت ایزولاسیون متوقف بمانند. گام بعد طراحی migration/ثبت محافظت‌شدهٔ خروج صریح به حالت عادی و بررسی خواندنی منشأ policy/controller persistence است؛ قبل از آماده‌شدن بسته و recovery path معتبر، آزمون مجدد live خواسته نشود. هدف همان فونداسیون کوچک نصاب Battle.net است.
