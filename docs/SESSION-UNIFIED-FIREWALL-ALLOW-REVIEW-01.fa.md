# ادامه: تشخیص فقط‌خواندنی علت رد Allowها

## رسید کاربر

نخستین اجرای RUNTIME-CAPTURE-01 روی Windows PowerShell5.1 x64 صحت payload، خواندن candidate و یک مشاهدهٔ فایل را تأیید کرد، سپس در read_only_firewall_gate با کد ufw_runtime_unreviewed_allow_rules_no_launch متوقف شد. consent، audit، فرزند تشخیصی، READY، capture و ذخیرهٔ پیشنهاد انجام نشدند؛ audit_recovery_required=false. این توقف علت دقیق یا هویت قاعده را مشخص نمی‌کند و اثبات خطرناک‌بودن آن نیست. رسید پالایش‌شده در runtime-capture-v01/evidence/Windows-first-run-stopped-unreviewed-allow.json ثبت شد. ادعاهای موفقیت بومی به همان مراحل محدودند؛ runtime کامل تأیید نشده است. فایروال/VPN جدید کاربر در این مرحله دوباره پرس‌وجو نشده‌اند.

## تحویل

[ALLOW-REVIEW-01](../analysis/unifiedfw-session-2026-10-27/allow-review-v01/README.fa.md) مستقل و فقط‌خواندنی است. فقط ActiveStore را می‌خواند و شمارش ثابت دسته‌های mismatch را می‌نویسد. candidate، baseline، Security log و journal audit باز نمی‌شوند؛ هیچ Allow، تغییر تنظیم audit، query شبکه یا اجرای نصب‌کننده وجود ندارد. bootstrap پس از hash verification تنها سه فایل خود بسته را Unblock می‌کند و RemoteSigned فقط در process جاری اعمال می‌شود؛ Bypass یا تغییر دائمی policy ندارد.

معیار قبول نسخهٔ runtime ضعیف یا اصلاح نشده است؛ predicate همان SstpSvc/مسیر دقیق svchost/TCP443/۱تا۸IP صریح/بدونdynamic است. کد endpoint عین تابع قبلی و مرجع gate فقط برای آزمون خارج ZIP نگه‌داری می‌شود. دسته‌بندی برای هر شرط مستقل دلیل می‌دهد. مسیر دارای متغیر محیطی، casing سرویس، keyword و سایر شکل‌ها صرفاً با معیار دقیق قبلی سنجیده می‌شوند؛ ابزار هویت یا معادل‌بودن آن‌ها را حدس نمی‌زند.

- reason_counts هم‌پوشان‌اند؛ جمع آن‌ها تعداد قواعد نیست.
- خطای خواندن فیلتر جدا و incomplete است، نه mismatch قطعی/قبولی.
- نام/ID/شرح rule، مسیر/IP، keyword و متن خطا در diagnostic صادر نمی‌شوند.
- snapshot اتمیک نیست؛ حتی نتیجهٔ بدون mismatch اجازهٔ اجرای هدف، Apply یا تضمین no-leak نیست.
- ابزار هیچ rule را غیرفعال/حذف نمی‌کند و توصیهٔ چنین کاری برای عبور از gate ندارد.

## اعتبارسنجی و ادامه

۱۶۱۷ assertion مدل، شامل تطبیق predicate در۵۱۲ ترکیب و۱۸حالت endpoint؛۷سناریوی aggregate/خطا و بررسی privacy، بدون اختیار اجرا و parse/عدم وجود فرمان‌های تغییردهنده. pin دو وابستگی، parse سه فایل PS، bootstrap، manifest و ZIP استخراج‌شده بررسی شده‌اند. بومی Windows5.1/cmdletهای جدید هنوز اجرا نشده‌اند. هش/اندازه در allow-review-v01/PACKAGE-SUMMARY.json است؛ ZIP در مخزن منتشر نمی‌شود.

گام کاربر: استخراج پوشهٔ جدید، Run-Review.cmd با همان حساب و administrator، بدون انتخاب candidate یا اجرای نصب‌کننده؛ فقط diagnostic جدید UFW-ALLOW-REVIEW-01-*.json برگردد. سپس علت غالب و میزان incomplete بررسی شود؛ بدون نام/IP/مسیر خصوصی و بدون ضعیف‌کردن gate تصمیم بعدی گرفته شود. تست capture، audit recovery و انتساب واقعی همچنان معوق‌اند.

بازتولید: `python build.py --pwsh <pwsh>` در allow-review-v01؛ آزمون Test-AllowReview.ps1 نیز مستقیم قابل اجراست. مرجع endpoint و guard با سورس runtime قبلی متن‌به‌متن کنترل می‌شوند. وضعیت تاریخی و baselineهای کاربر تغییر نکرده‌اند.
