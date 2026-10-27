# ادامهٔ فعلی Unified Firewall

مرجع ادامه: [تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [طرح حمل دقیق](../analysis/unifiedfw-session-2026-10-27/exact-transport-plan-v01/README.fa.md)، [دروازه‌های bootstrap](../analysis/unifiedfw-session-2026-10-27/exact-transport-plan-v01/BOOTSTRAP-GATES.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json).

پس از مشاهدهٔ موفق Windows v0.3.1، سازندهٔ draft آفلاین مقصد دقیق ساخته شد؛ ۸۶ assertion گذشت. برای هر IP صریح، template محدود SstpSvc/TCP443 می‌سازد؛ CIDR/wildcard/رنج و approval ساختگی رد می‌شوند. Any-interface فقط متعلق به template حمل دقیق است، نه ترافیک برنامه. digest به profile/scope/owner/server/IP وابسته است، اما امضا یا approval نیست. برنامه همیشه draft غیرقابل‌اجرا می‌دهد و ready_for_apply=false است.

هیچ native adapter approval، bootstrap DNS/TLS سرد، executor/guardian یا Apply کامل نشده است. مورد بعد adapter بازبینی محلی و اتصالش به هویت تازه است؛ تا حل gateها هیچ اجرای فایروال یا آزمون زندهٔ reconnect انجام نشود. کاربر فعلاً اقدام یا بستهٔ تازه برای اجرا ندارد. هدف همان ابزار کوچک اختصاصی نصاب Battle.net باقی است.
