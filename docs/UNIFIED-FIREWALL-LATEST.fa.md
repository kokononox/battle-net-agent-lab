# ادامهٔ فعلی Unified Firewall

مرجع ادامه: [تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [بازبینی محلی draft](../analysis/unifiedfw-session-2026-10-27/local-review-v01/README.fa.md)، [bootstrap gates](../analysis/unifiedfw-session-2026-10-27/exact-transport-plan-v01/BOOTSTRAP-GATES.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json).

بعد از مشاهدهٔ موفق v0.3.1 و draft آفلاین، adapter واقعی بازبینی محلی ساخته شد: readerهای قبلی بدون تغییر، نمایش raw فقط روی console، challenge دستی و revalidation پس از prompt. تغییر binding/flow/host/IP نتیجه را رد می‌کند. ۶۴ assertion جدید و رگرسیون ۶۱+۸۴+۸۶ گذشت؛ اجرای واقعی Windows این بسته هنوز نداریم.

این فقط acknowledge بازبینی draft در یک invocation است، نه pin مصوب فایروال، approval authority محافظت‌شده یا persistent approval. ready_for_apply=false، bootstrap DNS/TLS، guardian/executor و no-leak تأییدنشده‌اند. کاربر فقط بستهٔ جداگانه را با وضعیت فعلی اجرا و JSON sanitized را برگرداند؛ raw console/screenshot ارسال نشود. Apply/Restore/قطع‌و‌وصل درخواست نشود. هدف ابزار کوچک نصاب Battle.net است.
