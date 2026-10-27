# اولویت جاری: بازیابی قابل اتکا، نه آزمون ایزولاسیون

[تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [رخداد و اصلاح آفلاین HF1.2.3](../analysis/unifiedfw-session-2026-10-27/recovery-hf123/README.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json) مرجع ادامه‌اند.

کاربر پس از reboot با VPN خاموش اینترنت نداشت؛ هر دو store خروجی Block داشتند، درحالی‌که ژورنال restored/before=NotConfigured بود. با اجازهٔ صریح، فقط DefaultOutboundAction محلی سه پروفایل بعد از backup به Allow تغییر کرد؛ firewall روشن و effective inbound Block ماند. کاربر مرورگر بدون VPN را موفق گزارش کرد. این خروج به شبکهٔ عادی بود، نه restore دقیق baseline یا تأیید ایزولاسیون. علت تغییر/ماندن Block پس از reboot ثابت نشده است.

کد HF1.2.3 در کپی آفلاین اصلاح شد: NotConfigured محلی پیش از اعمال رد می‌شود، restored label مجوز عبور نیست، local/effective/rules تازه بررسی می‌شوند و UI بدون boolean اثبات تازه پیام موفق نمی‌دهد. ۴۵ suite PS، ۵۳۱ Python pass+۲ skip، ۱۰۰ parse و ۴۹ assertion جدید گذشتند. Windows patch/reboot/packet اجرا نشده؛ source overlay قابل استقرار نیست.

فعلاً کاربر اقدام جدیدی ندارد. همهٔ Apply/Restore و بسته‌های local-review/آزمون reconnect متوقف بمانند. دستورهای قدیمی اجرا نشوند. گام بعد migration محافظت‌شدهٔ legacy journal و ثبت خروج مجاز به حالت عادی و بررسی منشأ persistence است؛ journal NotConfigured خودکار به Allow تبدیل یا بازنویسی نشود. no-leak/عدم fingerprint هنوز تأیید نیست؛ هدف ابزار کوچک اختصاصی Battle.net است.
