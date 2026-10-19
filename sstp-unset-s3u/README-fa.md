# S3U — صلاحیت‌سنجی تجربی بازگشت local NotConfigured، فقط CI

**فقط روی Windows موقت CI؛ بسته یا لانچر کاربری نیست.** S3 سخت‌گیرتر و guard آن دست‌نخورده می‌مانند. این آزمایش مستقل بررسی می‌کند آیا provider همان runtime می‌تواند property محلی را بعد از Block واقعاً به حالت قبلی NotConfigured برگرداند؛ نه اینکه NotConfigured را Allow حساب کند.

## چرا آزمایش مستقل؟
خروجی کاربر برای PersistentStore هر سه profile را NotConfigured نشان می‌دهد و S1 effective Allow و firewall enabled ثبت کرده بود. مستند Microsoft در Set-NetFirewallProfile و netsh، NotConfigured را GPO-only معرفی می‌کند. در S3 اولیه رفتار برگشت CIM مشاهده شد، اما این اختلاف سند/رفتار و حالت واقعی unset باید جدا بررسی شود. موفقیت این تست، متن سند را تغییر نمی‌دهد و به معنی supported بودن روی هر Windows یا مجوز Apply کاربر نیست.

## شاهد لازم
- baseline هر سه profile در PersistentStore باید NotConfigured باشد؛ baseline دیگر برای گرفتن PASS normalize نمی‌شود.
- snapshot CIM stored/effective، خواندن مستقل getterهای COM HNetCfg.FwPolicy2 و hash ویژگی‌های انتخاب‌شده ruleهای local قبل/بعد؛ مقادیر خام خصوصی آپلود نمی‌شوند.
- خواندن فقط‌خواندنی هفت مسیر ثابت profile در registry64: سه مسیر local DomainProfile/StandardProfile/PublicProfile و چهار مسیر policy Domain/Private/Standard/Public. فقط وجود کلید و همه valueهای مستقیم همان کلیدها با نوع/محتوا مقایسه می‌شوند؛ تمام registry، زیرکلیدها، WFP یا policy storeهای دیگر نیستند. Valueهای خام و مسیرهای فایل احتمالی فقط در پوشه ACL-دار CI می‌مانند. هیچ RegistryKey.SetValue/DeleteValue/CreateSubKey، reg.exe، reset یا import استفاده نمی‌شود.
- journal قبل تغییر، ACL خصوصی Admin/SYSTEM، task مستقل SYSTEM پیش از mutation؛ driver سه profile را موقتاً Block می‌کند، snapshot mutation را ثبت و با Environment.Exit(73) بدون cleanup خارج می‌شود.
- task بعد از۷۵ثانیه فقط همان DefaultOutboundActionها را با cmdlet provider به NotConfigured برمی‌گرداند؛ registry به طور مستقیم نوشته نمی‌شود. compare-before-write در این پیاده‌سازی اتمیک نیست.
- گیت فقط با برگشت دقیق CIM stored، effective CIM و COM، مقایسه دقیق value/نوع/وجود در همان کلیدهای registry، hash ruleهای منتخب برابر، خروج task صفر و حذف task خودش پاس می‌شود. تعداد valueهای DefaultOutboundAction قبل/حین/بعد گزارش می‌شود؛ معانی DWORD حدس زده نمی‌شوند.
- تکرار دو دور روی همان VM برای consistency همان اجرا، نه دو دستگاه مستقل. replay باید صفر restore write داشته باشد. fallback controller، اگر لازم شد، به معنی موفقیت timer نیست.

۱۳fixture درباره schema/identity/زمان/baseline و تصمیم restore/conflict وجود دارد. در setup که runtime یا baseline مناسب نیست، یا اگر provider فقط NotConfigured ظاهری بدهد ولی value/وجود registry متفاوت بماند، آزمون متوقف/ناموفق می‌شود؛ اختلاف پنهان یا guard حذف نمی‌شود.

## محدوده
فقط default outbound و task/فایل متعلق به آزمایش تغییر می‌کنند؛ rules موجود disable نمی‌شوند. بازی/VPN/Blizzard اجرا نمی‌شوند و SSTP، قطع VPN، DNS/CRL/OCSP، IPv6، اتصال باز یا default-deny واقعی آزمایش نیست. کل policy بازنویسی/ریست نمی‌شود. سیستم کاربر دست‌نخورده است، WindowsServer runner معادل Windows11 کاربر نیست؛ version/build/PowerShell در receipt ثبت می‌شوند. guard محیط CI جلوگیری از اجرای اتفاقی است نه attestation امنیتی.

موفقیت این مرحله به تنهایی guard S3 یا ready_for_user_apply را true نمی‌کند. تا نتیجه و طراحی مراحل بعد، کاربر Pause و تنظیمات فعلی را حفظ می‌کند؛ S2/دستور/backup upload/BAT99/Enable/Disable/Resume تازه لازم نیست.

مراجع:
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall
