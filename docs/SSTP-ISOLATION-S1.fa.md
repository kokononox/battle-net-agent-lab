# بازبینی SSTP و پیش‌بررسی S1

## دامنهٔ تأییدشده
کل Windows؛ VPN داخلی SSTP با نام `holand`. Connect-rus-v1.3.ps1 فقط برای پروفایل دیگر کاربر است. پیوست‌های powershell.exe شورتکات‌های تبدیل‌شده در آپلود بوده‌اند و کنار گذاشته شدند؛ اجرا/تحلیل/انتشار نشده‌اند.

## بازبینی فقط‌خواندنی Kill Switch فعلی
اسکریپت‌های ارسالی فقط خوانده شدند، نه اجرا. Connect-rus نام rus را hardcode می‌کند. KillSwitch1.2 نام rus را hardcode نمی‌کند؛ نخستین SSTP متصل را انتخاب می‌کند و این لزوماً holand نیست.

Kill Switch اجازه همه مقصدها و برنامه‌ها روی RemoteAccess، TCP443 به IPv4های سرور، DNS و DHCP دارد و default outbound را Block می‌کند. Allowهای فعال دیگر را خنثی نمی‌کند. بنابراین برابر با ایزولاسیون فقط‌Level3 نیست. Disable صرفاً گروه خودش و outbound defaults ذخیره‌شده را برمی‌گرداند؛ EmergencyReset مقدار Allow تحمیل می‌کند و بازیابی دقیق نیست. برای این مرحله هیچ کدام اجرا نشوند.

مخزن SSTP فقط خوانده شد و تغییر نکرد. هش مبنا: `36ca918bf2c06bc66c6b98057448dfac5ee653b4`؛ [ملاحظات امنیتی خود مخزن](https://github.com/nekirovoix/sstp/blob/36ca918bf2c06bc66c6b98057448dfac5ee653b4/docs/session-2026-10-05/docs/SECURITY-fa.md). تنظیم SSH، سرور یا رمز عبور لازم نیست.

## S1 فقط‌خواندنی، نه Apply
[منبع](https://github.com/kokononox/battle-net-agent-lab/tree/a9aec52a3c0983a103456d55a2ea5070d6f2ca53/sstp-preflight-s1): اسکریپت PowerShell5.1 مستقل، لانچر با مسیر مطلق PowerShell خود Windows، راهنمای فارسی. نیازی به Python یا runtime بسته‌های قبل نیست.

S1 پروفایل user/all-user هم‌نام را بدون انتخاب خودسرانه بررسی می‌کند؛ DNS سرور VPN و Level3، مسیر/interface، ActiveStore فایروال و خلاصه Allowهای موجود، قواعد گروه Kill Switch و کاندید اتصال SSTP را ثبت می‌کند. فایل خصوصی state را نمی‌خواند و فقط وجودش را می‌سنجد. گزارش JSON تنها نوشتن محلی آن است؛ DNS lookup ممکن است ترافیک ایجاد کند.

هیچ firewall/hosts/route/VPN تغییر، task یا backup/rollback ایجاد نمی‌شود. هیچ Resume/Update یا کنترل فرایند Blizzard وجود ندارد. گزارش همیشه ready_to_apply_isolation=false و rollback_prepared=false دارد. این پیش‌بررسی برای طراحی Apply بعدی است، نه مجوز اجرای آن.

IP دستی فعلاً لازم نیست؛ از پروفایل و DNS/اتصال خوانده می‌شود. snapshot DNS همه IPهای آینده CDN نیست؛ svchost PID و تطابق IP نیز binding اختصاصی به پروفایل را ثابت نمی‌کنند. IPv6، reconnect، DNS/bootstrap و CRL/OCSP بدون کاهش امنیت باید در طرح بعد حل شوند.

قبل Apply آینده، سیاست Allowهای موجود/GPO و backup کامل و بازیابی مستقل محلی/زمان‌دار باید آماده و تست شوند. کل Windows می‌تواند مرورگر/چت را هم قطع کند. Kill Switch فعلی کورکورانه Disable/Reset نشود. در این مرحله WoW بسته و آپدیت Pause است.

## آزمون و سؤال‌های باز
آزمون Windows تنها syntax/AST و۲۰ fixture مصنوعی را بررسی می‌کند؛ نه VPN واقعی، نه اعمال فایروال و نه بازی کاربر. رسید شامل scope صریح و hash اسکریپت است. Allowlist هم پاک‌بودن محتوا در مقصد مجاز یا نبود fingerprint فایل را ثابت نمی‌کند. بررسی N2 فعلاً متوقف است.

## رسید نهایی
منبع آزموده‌شده `3703c916bbf34907b67bb878039d74c63e867b1f`؛ run `39185272099`. syntax/AST و۲۰ fixture روی Windows PowerShell runner استاندارد windows-2025 پاس شدند. هیچ VPN/firewall واقعی در آزمون query یا تغییر نشده است. این اثبات سلامت شبکه کاربر نیست. [رسید](../reports/sstp-preflight-s1-build.json)؛ SHA256 اسکریپت `832e20b7c204a704a5928a837cef05731094b9a1a99542cd98eefea5ff300e34`.

خطای اولیه quoting عبارت if در YAML قبل از صدور رسید اصلاح شد؛ آن تلاش اولیه شاهد تست موفق نبود. لانچر با مسیر مطلق system PowerShell تثبیت شد. هیچ runner بزرگ/پولی فعال نشد؛ رایگان بودن سهمیه تضمین نشده است.
