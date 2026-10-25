# نصب و reboot مهمان مستقل؛ بدون Battle.net یا دسترسی از راه دور

این مرحله فقط کنترل زیرساخت است. نتیجهٔ آن دربارهٔ UserUUID بلیزارد یا payload شبکه نیست و کنترل مصنوعی نباید به‌عنوان شناسهٔ واقعی معرفی شود.

## محدوده

- فقط GitHub-hosted Linux، attempt اول، شاخهٔ تحقیق و guard اختصاصی e1.
- همان ISO عمومی Microsoft ارزیابی Windows Server 2025 با اندازه و هش نمونهٔ d6. WIM index 2 گرافیکی از d6 تأیید شده است.
- نصب خودکار ارزیابی با پذیرش EULA نصب، بدون product key، فعال‌سازی، حساب آنلاین یا اتصال guest به اینترنت. حساب Administrator فقط محلی، موقت و رمز آن تصادفی تولید می‌شود. این مجوز تولید/استفادهٔ دائمی ایجاد نمی‌کند و جای Windows desktop در تست سازگاری Battle.net نیست.
- حد فضای واقعی قبل از دانلود 50 GiB و دیسک qcow2 مجازی 64 GiB است. فقط مسیرهای مجاز ابزارهای runner، طبق کد d6، در صورت نیاز پاک می‌شوند؛ workspace یا home کاربر حذف نمی‌شود. اگر ظرفیت کافی نباشد، توقف صریح، نه بزرگ‌نمایی ظرفیت مجازی.
- OVMF با NVRAM اختصاصی، KVM، 2 vCPU و 4 GiB RAM. بدون NIC، بدون VNC/RDP، بدون forward/tunnel و بدون نصب ابزار کنترل از راه دور. Secure Boot تضمین نشده؛ TLS و permissions میزبان تغییر نمی‌کنند. سه ارسال Space فقط در 15 ثانیهٔ اول برای boot DVD است.
- محیط نصب، دیسک، firmware vars، seed دارای رمز و لاگ‌ها موقت‌اند و خروجی عمومی نیستند؛ در خروج عادی/کنترل‌شده حذف می‌شوند. پایان runner هم محیط را از بین می‌برد.

## کنترل مهمان

FirstLogonCommands اسکریپت پروژه را از seed اجرا می‌کند. در Windows کامل build 26100، یک UUID آزمایشی در `HKCU\Software\BattleNetAgentLab\OwnedGuestControl` ساخته می‌شود، نه مسیر Blizzard. baseline شامل marker و boot time و SID/profile فقط داخل DPAPI CurrentUser همان مهمان ذخیره می‌شود. هیچ کدام یا هش آن‌ها منتشر نمی‌شود.

RunOnce همان پروفایل، بعد از `Restart-Computer`، baseline را باز و boot time جدیدتر از baseline و زمان ثبت، همان SID/profile، بازشدن DPAPI و حفظ marker را بررسی می‌کند. فقط سیگنال‌های boolean محدود از COM1 خارج می‌شوند. میزبان challenge تصادفی هر اجرا را تطبیق می‌دهد و آن را از خروجی حذف می‌کند. بدون دو سیگنال معتبر، Windows reboot تأیید نمی‌شود. این کانال رمزنگاری مستقل نیست؛ صرفاً ارتباط محلی مهمان آزمایشگاهی روی میزبان مورداعتماد است، نه attestation در برابر مهمان مخرب.

## گزارش و زمان

`reports/guest-boot-ci.json` وضعیت CI و `reports/guest-boot-runtime.json` شواهد محدود آزمایش هستند. source/run باید با e1 تطبیق داشته باشد. status=stopped با stage/error صریح هرگز موفقیت نیست. سقف پایش مهمان 60 دقیقه، step برابر 78 و job برابر 85 دقیقه است؛ download و ابزارها هم زمان می‌برند. برای طولانی‌ترکردن سرویس دائمی طراحی نشده است.

29 آزمون محلی شامل دروازهٔ اثبات، XML، challenge و عدم صدور اطلاعات خصوصی است؛ این آزمون‌ها نصب واقعی ویندوز را ثابت نمی‌کنند. مهمان باید خروجی واقعی خودش را بفرستد.

## نتیجهٔ e1 و تشخیص e2

e1، run `40161082563`، source `337e4b70532b4291cb020c90bfbdda1438fbc730`، evidence `650a75c3109a7f947d9de4b3f14996309cb913ab`: CI tests/preparation/sanitization همگی success، اما نتیجهٔ آزمایش `stopped/monitor/guest_timeout` بود. KVM و رسانهٔ پین‌شده تأیید شدند؛ هیچ first/second signal دریافت نشد. پس بوت Windows، reboot، DPAPI یا marker تأیید نشده‌اند. مقدار disk_actual_bytes=0 در e1 مقدار اولیهٔ اندازه‌گیری‌نشده است و نباید «هیچ نوشتنی انجام نشد» تعبیر شود.

e2 مشخصاً اجرای تشخیصی است: سقف monitor به 20 دقیقه، step به 48 و job به 55 دقیقه محدود شده است. این مهلت کوتاه‌تر را نباید اثبات عدم امکان نصب تعبیر کرد. WinPE تنها یک پیام دارای challenge از COM1 می‌فرستد؛ این پیام به‌تنهایی اثبات Windows نصب‌شده نیست. در چند نقطه screenshot خصوصی گرفته و با tesseract فقط به enum ثابت دسته‌بندی می‌شود؛ هیچ screenshot، متن OCR، شناسه یا لاگ خامی منتشر نمی‌شود. OCR ممکن است اشتباه کند و فقط قرینهٔ UI است، نه اثبات بوت/reboot. دیسک actual بعد از توقف QEMU حتی روی failure اندازه‌گیری می‌شود؛ مقدار نامعلوم null است. schema خروجی e2 نسخهٔ 2 است.

## e2: توقف در UEFI Shell؛ اصلاح پیشنهادی e3

e2، run `40165111430`، source `e92a798e26bd8199c5db20ca015bbbb2444dd482`، evidence `18217fef14e7542afafc4771a61a3ba8de949e76`: timeout با شش مشاهدهٔ OCR از UEFI Shell (ثانیه‌های 30/120/301/601/900/1150)، بدون WinPE/full-Windows signal؛ actual qcow2 پس از توقف 200704 بایت. این شواهد به توقف مسیر firmware boot اشاره دارند؛ علت دقیق شکست انتخاب DVD از OCR قابل اثبات نیست. مقدار actual صرفاً تخصیص فایل است، نه اثبات محتوای دیسک.

e3 به‌عنوان فرضیهٔ اصلاح: legacy `-boot order/once` حذف شد؛ هر سه drive با backend if=none و device صریح به AHCI متصل‌اند. DVD نصب ide.1 با bootindex=1، دیسک ide.0 با bootindex=2، seed ide.2 بدون bootindex است. هیچ Secure Boot/TLS/device permission میزبان دستکاری نمی‌شود. نتیجهٔ اصلاح فقط با اجرای واقعی تعیین می‌شود. اگر دو مشاهدهٔ آغازین همچنان UEFI Shell باشد و WinPE نیامده باشد، firmware_boot_failed و توقف زودهنگام ثبت می‌شود. در غیر این صورت سقف کنترل 40 دقیقه، step برابر 68 و job برابر 75 دقیقه است. هشت مشاهدهٔ enum حداکثر منتشر می‌شود، نه تصویر/متن OCR.
