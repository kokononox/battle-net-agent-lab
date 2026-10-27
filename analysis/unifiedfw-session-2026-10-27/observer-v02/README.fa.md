# مشاهده‌گر بومی SSTP v0.2 — فقط‌خواندنی

برخلاف kernel صرفاً تصمیم، این مرحله adapter واقعی Get-VpnConnection، RAS و IP Helper دارد. helperهای هویت ۰.۱.۲ بایت‌به‌بایت حفظ شده‌اند؛ wrapper پروفایل قطع‌شده/متصل و context کاربر و بازخوانی server/full-tunnel را اضافه می‌کند. ۸۴ بررسی مدل و کامپایل C# واقعی/layout x64 در Linux گذشتند؛ DLLهای Windows هنوز اجرا نشده‌اند.

بسته فقط حالت فعلی را مشاهده می‌کند. VPN قطع/وصل نشود؛ Apply/Restore، DNS، hosts، route یا قواعد فایروال تغییر نمی‌کنند. candidate یکتا صرفاً برای تشخیص انتخاب می‌شود، نه برای تأیید سیاست. اطلاعات نام/سرور/IP/GUID/LUID/handle فقط در حافظه‌اند و گزارش حاوی وضعیت/کد است. [راهنمای اجرا و مرز نتیجه](package/README-FA.txt).

در حالت disconnected، GUID/scope/name/server/full-tunnel و نبود RAS متناظر با بازخوانی بررسی می‌شوند؛ live binding اختراع نمی‌شود. در حالت connected، GUID پروفایل به نشست RAS، projection IPv4 و GUID/index/NET_LUID رابط با بازخوانی پیوند می‌خورد. alias ناامن، metadata متناقض، VPN دیگر، تغییر حین خواندن و context اشتباه رد می‌شوند.

نکتهٔ معماری تأییدشده در مدل: CurrentUser از دید SYSTEM همان پروفایل کاربر نیست. روش امن تعامل observer کاربر با guardian SYSTEM هنوز ساخته نشده است. helper فعلی IPv4 projection می‌خواهد؛ برای IPv6-only اجازه گسترده نمی‌دهد. endpoint سرور، bootstrap DNS/TLS، enforcement، تعلیق/rebind، اتصال مجدد یا نبود نشتی در این مرحله تأیید نمی‌شوند.

نسخه zip در مخزن نیست؛ هش و اندازه در PACKAGE-SUMMARY.json است. raw binding/credentials/private journal منتشر نشده‌اند. این مرحله وارد guardian یا HF1.2.2 نشده است. گام بعد یک اجرای خواندنی روی همان وضعیت فعلی سیستم Windows و بررسی گزارش است، بدون تغییر VPN یا ایزولاسیون.
