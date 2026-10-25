# آزمون ماندگاری UserUUID پس از بوت واقعی ویندوز

## وضعیت و محیط لازم

ابزار آمادهٔ کنترل و اجرای دستی روی یک **ویندوز ماندگار با همان دیسک و پروفایل** است. اجرای دو job استاندارد GitHub-hosted به معنی reboot یک ویندوز نیست؛ job بعدی VM تازه دارد. workflow همراه این ابزار فقط کنترل‌های مصنوعی/DPAPI و ردکردن «بوت یکسان» را اجرا می‌کند؛ Battle.net یا ویندوز را اجرا/ری‌استارت نمی‌کند و نتیجهٔ مثبت ماندگاری تولید نمی‌کند.

- [رفتار runnerهای GitHub-hosted](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners)
- [LastBootUpTime در Win32_OperatingSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem)
- [دامنه و استثناهای DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

## اجرای واقعی، فقط روی همان ویندوز

نیازمند Python 3 و PowerShell/CIM استاندارد ویندوز است؛ وابستگی pip ندارد. فایل `reboot_probe.py` را از همین شاخه دریافت کنید و بین دو مرحله تغییر ندهید. با **همان کاربر ویندوز** اجرا کنید؛ دسترسی ادمین یا ارسال credential لازم نیست. اگر Python نصب نیست، به‌جای تغییر سیستم آزمایش ابتدا محیط مناسب را مشخص کنید.

1. Battle.net، نصاب، Agent و WoW را ببندید. وجود Agent.exe متعلق به برنامه‌ای دیگر هم محافظه‌کارانه مانع اجرای probe می‌شود.
2. روی ویندوزی که UserUUID مورد بررسی از قبل وجود دارد، اجرا کنید:

```powershell
py -3 .\reboot_probe.py before
```

فقط اگر وضعیت `prepared_waiting_for_manual_reboot` آمد ادامه دهید. اگر `value_absent_before` بود baseline قابل‌مقایسه نداریم؛ ابزار برای ساختن شناسه نصاب را اجرا نمی‌کند. خطا یا وجود state قبلی را با پاک‌کردن خودکار شواهد نادیده نمی‌گیرد.

3. پس از ذخیره‌کردن کارها، **خودتان از گزینهٔ Restart ویندوز استفاده کنید**. Shut down با Fast Startup، logoff، suspend یا بستن Agent جای reboot را نمی‌گیرد. ابزار هیچ دستور reboot، scheduled task، سرویس یا autorun نصب نمی‌کند.
4. با همان کاربر وارد همان ویندوز شوید؛ پیش از بازکردن دوبارهٔ Battle.net/نصاب/بازی اجرا کنید:

```powershell
py -3 .\reboot_probe.py after
```

اگر برنامه‌های هدف خودکار اجرا شده‌اند، نتیجه را «بدون هیچ فعالیت بین دو مرحله» معرفی نکنید. probe فرایندهای فعال فعلی را رد می‌کند، اما نمی‌تواند اجرای قبلی و بسته‌شدن آن‌ها را منتفی کند.

## خروجی و حریم خصوصی

- فقط JSON چاپ‌شدهٔ عمومی را می‌توان برای بررسی ارسال کرد. مقدار UserUUID، SID، MachineGuid، مسیر پروفایل، سریال volume، زمان خام بوت و hash شناسه در آن نیست.
- `before` مقدار و markerهای لازم را در `%LOCALAPPDATA%\BattleNetRebootProbe\private-state.dpapi` با DPAPI **CurrentUser** و ACL محدود می‌گذارد. **این فایل، پوشه یا snapshot آن را آپلود/commit نکنید.** پس از پایان بررسی می‌توان پوشهٔ خصوصی را دستی پاک کرد؛ probe شواهد قبلی را بازنویسی نمی‌کند.
- DPAPI با حالت machine-wide اجرا نمی‌شود. همان‌کاربر بودن به‌تنهایی اثبات همان دستگاه نیست؛ MachineGuid، پروفایل و سریال volume نیز به‌صورت خصوصی مقایسه می‌شوند. این markerها دفاع در برابر شبیه‌سازی/clone خصمانه یا تغییر ساعت نیستند.
- کلید Blizzard فقط خوانده می‌شود؛ ابزار مقدار آن را ایجاد، حذف یا اصلاح نمی‌کند. تنها فایل state و ACL پوشهٔ خصوصی خودش را می‌نویسد.

## تفسیر وضعیت‌ها

| وضعیت | تفسیر |
| --- | --- |
| `prepared_waiting_for_manual_reboot` | baseline خصوصی ثبت شد؛ هنوز آزمون reboot انجام نشده |
| `same_boot_not_a_reboot_test` | بوت یکسان است؛ هیچ نتیجهٔ مثبت ماندگاری مجاز نیست |
| `environment_changed` | marker محیط/پروفایل/دیسک یا کد ابزار عوض شده؛ مقایسه نامعتبر |
| `boot_time_check_failed` | ترتیب زمان baseline/بوت جدید/مشاهده معتبر نیست |
| `same_value_after_boot` | مقدار رجیستری قبل و بعد از حداقل یک بوت جدید، در markerهای محیط برابر، دقیقاً برابر است |
| `changed_value_after_boot` | دو مقدار معتبر برابر نیستند |
| `value_absent_after_boot` / `value_invalid_after_boot` | بعد از بوت مقدار معتبر قابل‌مقایسه نیست؛ آن را UUID متفاوت معرفی نمی‌کنیم |
| `blocked_target_running` | یکی از فرایندهای هدف اکنون فعال است؛ probe متوقف می‌شود |

حتی وضعیت مثبت فقط **registry-only** است: ارسال مجدد همان host_id در payload شبکهٔ پس از reboot را ثابت نمی‌کند. فعالیت بین دو مرحله/بازنویسی احتمالی منتفی نیست؛ استمرار بدون بازنویسی یا یکتایی هر نصب هم اثبات نمی‌شود. reinstall و فایل‌های WoW موضوع این ابزار نیستند.

## کنترل‌ها

۲۶ آزمون Python شامل تغییر marker محیط، بوت یکسان، ترتیب زمان، دادهٔ نامعتبر، منع نشت مقدار و منع ادعای شبکه است. نمونه‌های مثبت در unit test کاملاً مصنوعی‌اند. `native_control.py` روی runner ویندوز فقط DPAPI واقعی، رد دادهٔ رمز‌شدهٔ دستکاری‌شده، ACL خصوصی و ردکردن بوت یکسان را با شناسهٔ مصنوعی بررسی می‌کند؛ کلید Blizzard را نمی‌خواند/نمی‌نویسد. خروجی آن هرگز گزارش reboot واقعی نیست.
