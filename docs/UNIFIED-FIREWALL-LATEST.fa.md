# ادامهٔ فعلی Unified Firewall

اول [تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [رسید واقعی مشاهده‌گر Windows](../analysis/unifiedfw-session-2026-10-27/observer-v02/windows-results/REVIEW.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json) را بخوانید.

هر دو اجرای واقعی v0.2 در حالت connected زنجیرهٔ profile/RAS/interface را تأیید کردند. این تأیید اتصال مجدد نیست؛ binding با اجرای قبلی مقایسه نشده و حالت قطع/connecting آزموده نشده است. endpoint، bootstrap DNS/TLS و executor/guardian همچنان بازند. HF1.2.2 نیز هنوز کاندید آفلاین است.

اکنون آزمون مشاهده‌گر تکرار نشود؛ اقدام تازه‌ای از کاربر لازم نیست. گام بعد طراحی مشاهدهٔ endpoint/pin/service به‌صورت فقط‌خواندنی و با بیان ابهام PID مشترک، پیش از suspend/rebind است. Apply، تغییر VPN، بازکردن عمومی DNS/443 یا خاموش‌کردن TLS پیشنهاد نشده‌اند.

شرط جدید کاربر: اکنون دانگل USB وای‌فای، بعداً Ethernet. طراحی نباید به کارت فیزیکی ثابت وابسته باشد؛ جابه‌جایی واقعی و DHCP/DNS/route زیر ایزولاسیون هنوز آزموده/حل نشده‌اند.
