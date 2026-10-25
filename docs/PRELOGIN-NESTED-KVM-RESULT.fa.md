# اجرای مهمان داخل GitHub: KVM و vCPU تأیید شدند، Windows هنوز بوت نشده

## پاسخ عملی

**در runner لینوکس GitHub، مهمان مصنوعی واقعاً اجرا شد.** پس مسیر مجازی‌سازی مهمان صرفاً فرض نظری نیست. این نتیجه هنوز «بوت موفق Windows» یا «ماندگاری UserUUID بعد از reboot» نیست.

در c2، `/dev/kvm` با API نسخهٔ 12 و user memory پشتیبانی شد. یک VM، 4KiB حافظه و یک vCPU ساخته شد. برنامهٔ ۷بایتی خود پروژه marker ثابت را به پورت I/O مجازی فرستاد و HLT کرد؛ هر دو خروج از `KVM_RUN` دریافت شدند، با failure_stage=0. دیسک، شبکه، BIOS، سیستم‌عامل و کد ثالثی در این مهمان وجود نداشت.

[شاهد ثابت اجرای مهمان](../reports/owned-kvm-guest-c2.json)، [شاهد قابلیت KVM](../reports/nested-linux-privileged-c2.json).

## تفاوت دو مسیر

| مسیر | مشاهده | نتیجهٔ مجاز |
| --- | --- | --- |
| Linux، کاربر عادی در c1 | /dev/kvm حاضر، open با permission_denied | آن کاربر دسترسی نداشت؛ فقدان مجازی‌سازی نتیجه نمی‌شود |
| Linux، privileged در c1/c2 | ایجاد VM و در c2 اجرای vCPU/marker/HLT موفق | اجرای مهمان مصنوعی با KVM در runner مشاهده‌شده تأیید شد |
| Windows / Hyper-V در c1 | probe_failed | فقط شکست ابزار؛ نه نبود Hyper-V |
| Windows / Hyper-V در c2 | powershell_timeout در سقف 90 ثانیه؛ facts نامعلوم | مسیر Windows نامشخص ماند؛ نبود قابلیت ادعا نمی‌شود |

در Linux از sudo فقط برای probe محدودِ کد خود پروژه استفاده شد؛ permission دستگاه، udev، گروه کاربر، feature، service یا تنظیم امنیتی تغییر نکرد. میزبان reboot نشد و Battle.net اجرا نشد. مسیر Windows پس از دو تلاش به‌عنوان نیاز مستقل باز می‌ماند؛ برای ادامهٔ KVM لازم نیست آن را موفق فرض کنیم.

## منابع ماشین و کار باقی‌مانده

در c2، runner لینوکس 2 CPU، حدود 7 GiB RAM و 12 GiB فضای آزاد گزارش کرد؛ QEMU از پیش موجود نبود. 12 GiB را برای دانلود رسانه، نصب Windows و رشد دیسک مهمان، headroom امن کافی نمی‌دانیم. این محدودیت برنامه‌ریزی است، نه ادعای ناممکن‌بودن هر روش thin provisioning.

منبع رسمی تصویر نامزد: [Windows Server 2025 Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025). صفحهٔ رسمی registration را پیش از download/install می‌خواهد؛ هیچ ثبت‌نامی با اطلاعات حدسی کاربر، دانلود تصویر یا پذیرش مجوزی در این مرحله انجام نشد. از image ناشناس یا فعال‌ساز استفاده نمی‌شود.

[حداقل رسمی فضای system partition](https://learn.microsoft.com/en-us/windows-server/get-started/hardware-requirements) 32 GB است؛ این با «مقدار مصرف فعلی فایل sparse روی میزبان» یکسان نیست. ظرفیت مجازی دیسک و فضای آزاد واقعی میزبان باید جدا کنترل شوند. Desktop Experience و فایل ISO نیز در برنامه‌ریزی فضا لحاظ می‌شوند.

گام‌های لازم:

1. تأمین image معتبر و مجاز و headroom واقعی دیسک، با پاک‌سازی محدود و صریح فقط ابزارهای غیرلازم runner موقت، نه فایل‌های مخزن یا کاربر.
2. نصب QEMU از منبع توزیع مورداعتماد و بوت Windows مهمان؛ اجرای مهمان ۱۶بیتی کوچک به‌تنهایی سازگاری Windows/x64 و درایورها را ثابت نمی‌کند.
3. نگه‌داشتن همان دیسک، Windows و پروفایل داخل **همان job میزبان**؛ reboot فقط مهمان و نه میزبان.
4. اجرای مقایسهٔ UserUUID قبل/بعد و تأیید تغییر بوت واقعی. private state و دیسک مهمان نباید artifact عمومی شوند.

## کیفیت و provenance

- c1: run `40153160310`، source `d72f4c472d6b00b9d71e62e86e102c14825ace30`، evidence `02d075e1a14f0b333cf00a450e92971c1712feb0`.
- c2: run `40153443222`، source `8cda46c6558ec0451f26dded23e5a859855fae50`، evidence `85a020390a98f191445acc3b1b22ca222b9545ab`.
- 28 آزمون قرارداد پاس شدند؛ C با `-Wall -Wextra -Werror` کامپایل شد. کنترل منفی محلی فاقد KVM نیز هیچ ادعای اجرای مهمان نداد.
- خروجی‌ها فقط boolean، شمارش منابع و hash **کد اجرایی خود probe** دارند؛ شناسهٔ کاربر/دستگاه یا hash شناسه منتشر نشده است.

[بازبینی ماشین‌خوان](../reports/prelogin-nested-kvm-review.json)، [وضعیت به‌روز آزمون reboot](../reports/prelogin-reboot-test-status.json)، [ابزار](../analysis-tools/prelogin-nested/README.fa.md).

## مرز نتیجه

`windows_guest_booted=false`، `windows_guest_reboot_tested=false` و `target_launched=false` باقی‌اند. هیچ نتیجهٔ تازه‌ای دربارهٔ ماندگاری UserUUID، یکتایی هر نصب، ذخیرهٔ سرور یا watermark فایل WoW از این مرحله نمی‌گیریم. هدف این مرحله فقط اعتبارسنجی مسیر زیرساخت بود.
