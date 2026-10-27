# ادامهٔ فعلی Unified Firewall

[تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [رسید موفق مقصد Windows](../analysis/unifiedfw-session-2026-10-27/endpoint-v031/windows-results/CONNECTED-REVIEW.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json) مرجع ادامه‌اند.

پس از بازگرداندن پروفایل تازه به full-tunnel، v0.3.1 روی Windows تکمیل شد: هویت profile/RAS/interface در دو مشاهدهٔ داخل اجرا ثابت، یک سرویس در host، یک TCP443 و یک candidate پایدار مرتبط با cache محلی. این تأیید همبستگی endpoint است؛ pin مصوب، service tag، امضا، bootstrap DNS/TLS، reconnect تحت ایزولاسیون، guardian، no-leak یا Apply تأیید نشده‌اند.

آزمون مشاهده‌گر تکرار نشود؛ اکنون اقدام تازه‌ای از کاربر لازم نیست. گام بعد توسعهٔ آفلاین ورودی صریحاً تأییدشدهٔ مقصد و طرح bootstrap/reconnect است. cache خودکار pin نشود، استثنای گسترده ساخته نشود. هدف ابزار اختصاصی نصاب Battle.net است، نه افزودن داشبورد. اتصال فعلی LAN گزارش کاربر است، نه اندازه‌گیری carrier در receipt یا qualification تعویض رابط.
