# آزمون ری‌استارت ویندوز: ابزار کنترل‌شده، اجرای واقعی هنوز معلق

## وضعیت روشن

**هنوز نتیجه‌ای دربارهٔ ماندگاری UserUUID پس از reboot واقعی نداریم.** ابزار دو‌مرحله‌ای ساخته و کنترل شده، اما ویندوز ماندگار برای تکمیل مقایسه در این جلسه در دسترس نیست. این مرحله هیچ Battle.net، Install، دانلود بازی یا reboot واقعی اجرا نکرد.

workflowهای هدف فعلی روی `windows-2025` از نوع GitHub-hosted هستند. job دوم VM تازه است، نه ادامهٔ همان ویندوز بعد از reboot؛ بنابراین اجرای دو job را آزمایش ماندگاری نمی‌نامیم. این نتیجه محدودیت مسیر فعلی است، نه ادعای ناممکن‌بودن reboot روی هر زیرساختی.

منبع: [GitHub-hosted runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners).

## آنچه واقعاً اجرا شد

- 26 آزمون Python پاس شد؛ موارد مثبتِ مقایسهٔ بوت در unit test مصنوعی‌اند.
- کنترل بومی روی Windows runner، run `40152098346`، source `2533962409cf5bf3bb21d09589d3e3c67b8cae0d` اجرا شد.
- DPAPI CurrentUser: رمزگذاری/بازیابی و رد state دستکاری‌شده پاس شدند.
- ACL پوشهٔ خصوصی و دسترسی به LastBootUpTime پاس شدند.
- بوت واقعیِ یکسان به‌درستی با `same_boot_not_a_reboot_test` رد شد؛ این کنترل منفی است، نه reboot واقعی.
- `os_reboot_performed=false`، `target_launched=false`، `registry_target_modified=false` و `identifiers_or_hashes_exported=false`.

[شاهد ثابت کنترل بومی](../reports/prelogin-reboot-control-b1.json)، [وضعیت ماشین‌خوان آزمون](../reports/prelogin-reboot-test-status.json).

## آزمون واقعی روی چه محیطی؟

روی همان ویندوز/دیسک/پروفایل ماندگار که UserUUID معتبر دارد، بدون نصب مجدد بین مراحل. Python 3 لازم است و هیچ pip package لازم نیست. ابتدا برنامه‌های هدف را ببندید، سپس:

```powershell
py -3 .\reboot_probe.py before
```

فقط پس از `prepared_waiting_for_manual_reboot`، کارها را ذخیره کرده و خودتان **Restart ویندوز** را انجام دهید. بعد با همان کاربر، پیش از بازکردن دوبارهٔ Battle.net یا بازی:

```powershell
py -3 .\reboot_probe.py after
```

فقط JSON عمومی چاپ‌شده قابل ارسال است. فایل `private-state.dpapi` و پوشهٔ خصوصی آن نباید آپلود یا commit شوند. ابزار reboot، scheduled task، سرویس یا autorun ایجاد نمی‌کند و کلید Blizzard را فقط می‌خواند.

[راهنمای کامل و وضعیت‌های خروجی](../analysis-tools/prelogin-reboot/README.fa.md)، [کد probe](../analysis-tools/prelogin-reboot/reboot_probe.py).

## معیار پذیرش و حدود نتیجه

- SID، MachineGuid، پروفایل، سریال volume و کد ابزار به‌صورت خصوصی باید برابر باشند؛ LastBootUpTime باید از زمان ثبت baseline جدیدتر و قبل از مشاهدهٔ دوم باشد. تغییر ساعت/clone خصمانه از این کنترل‌ها منتفی نمی‌شود.
- اگر مقدار رجیستری بعد از بوت برابر باشد، فقط برابری همان مقدار در دو طرف حداقل یک بوت جدید ثبت می‌شود. فعالیت قبلی و بسته‌شدن خودکار برنامه‌ها یا بازنویسی احتمالی بین دو مرحله منتفی نیست.
- این probe **registry-only** است؛ ارسال دوبارهٔ همان host_id در پیام شبکهٔ پس از بوت را ثابت نمی‌کند.
- reboot با reinstall یکی نیست. یکتایی هر نصب، HWID دائمی، اتصال به حساب، ذخیرهٔ سرور و watermark فایل WoW همچنان از این مرحله نتیجه نمی‌شوند.

[نتیجهٔ قبلی a11: نوشتن و خواندن مستقیم پیش از لاگین](PRELOGIN-HOST-ID-REGISTRY-TRACE.fa.md) بدون تغییر باقی است؛ کنترل‌های این مرحله به آن reboot اضافه نمی‌کنند.
