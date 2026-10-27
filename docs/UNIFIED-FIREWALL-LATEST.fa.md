# ادامهٔ فعلی Unified Firewall

اول [تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [مشاهده‌گر مقصد v0.3](../analysis/unifiedfw-session-2026-10-27/endpoint-v03/README.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json) را بخوانید.

v0.2 قبلاً در دو اجرای واقعی connected روی Windows زنجیرهٔ profile/RAS/interface را تأیید کرده است. اکنون v0.3 برای مشاهدهٔ cache محلی، process و TCP/443 آماده است؛ فقط ۵۸ assertion مدل/adapter جدید و ۸۴ lifecycle در Linux، نه تأیید زندهٔ endpoint. PID مشترک مالکیت سرویس نیست و Authenticode برای پرهیز از retrieval شبکه‌ای ضمنی فراخوانی نمی‌شود.

گام بعد تنها اجرای بستهٔ جداگانهٔ v0.3 با VPN در وضعیت فعلی و دریافت JSON است. Apply/Restore/قطع و وصل درخواست نشود. bootstrap DNS/TLS، امضا/service-tag، reconnect، executor و guardian تأیید نشده‌اند. استقلال از کارت فیزیکی شرط طراحی است؛ تعویض واقعی Wi-Fi/Ethernet آزموده نشده. no-leak و عدم ارسال fingerprint تأیید نمی‌شوند.
