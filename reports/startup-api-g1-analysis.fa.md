# G1 — محتوای مقصدهای باقی‌مانده با انتساب مستقیم به پردازش

## نتیجهٔ اصلی
این روش جدید، شکاف محتوایی nydus.battle.net و us.cdn.blizzard.com را برای نمونه‌های startup این اجرا پر کرد. gate بومی Windows برای اولین درخواست root، اولین درخواست child، ارسال چندقطعه‌ای و WSASend چندبافری پاس شد؛ سپس و فقط سپس bootstrap واقعی دانلود و اجرا شد. دادهٔ synthetic از evidence واقعی جداست.

۴ پردازش زنده (۲ Setup و ۲ Agent) با hash، WinVerifyTrust و ناشر Blizzard تأیید و پیش از resume instrument شدند. ۸۵ input event، صفر drop گزارش‌شده، صفر script error و صفر api_input_gap ثبت شد. ۵۸ درخواست خروجی با انتساب PID/hash مشخص استخراج شد. صفر drop گزارش‌شده به معنی تضمین پوشش تمام APIها یا کل ترافیک نیست.

## محتوای درخواست‌های واقعی
| مقصد | تعداد در این نمونه | محتوا |
| --- | --- | --- |
| nydus.battle.net | ۲ | GET /geoip، از دو Setup نسخهٔ1.19.3.3219 و2.0.0.4232. هدرهای Host، Accept و User-Agent نسخهٔ Bootstrapper. بدون query یا body. |
| us.cdn.blizzard.com | ۱ | GET /tpr/bnt004/data/3b/e4/3be490f39c76a7b9ce1da05a8aad907c، از Setup اصلی. فقط Host و Connection: keep-alive، بدون query یا body. |
| level3.blizzard.com | ۵۴ | GET مسیرهای data/config/patch/index، برخی Range، برخی User-Agent نسخهٔ Agent؛ از Setup و Agent. |
| ocsp.digicert.com | ۱ | GET حاوی OCSPRequest کدگذاری‌شده در URL؛ این بار مستقیماً از Setup دارای hash=de5d… ثبت شد. |

همهٔ ۵۸ مورد از نظر framing HTTP کامل و body صفر بایت داشتند. مدل CPU مرجع در target/headers/body آن‌ها نبود. این نتیجه به معنی صفر اطلاعات خروجی نیست: نسخهٔ نرم‌افزار، مسیر و محدودهٔ فایل و دادهٔ گواهی در درخواست‌ها قرار دارند. نبود CPU literal به معنی نبود شناسهٔ opaque نیست. مسیر /geoip با درخواست تعیین منطقه بر پایهٔ IP سازگار است، اما پاسخ و نقش ضروری آن برای آپدیت ثبت/آزمون نشده است.

## OCSP؛ رفع یک ابهام قدیمی فقط برای نمونهٔ جدید
URL درخواست جدید باز شد و ساختار دقیق OCSPRequest مطابق RFC6960 تفسیر شد: الگوریتم hash، issuerNameHash، issuerKeyHash و serialNumber گواهی. OpenSSL مستقل مقادیر را عیناً تأیید کرد. شماره‌سریال، شمارهٔ گواهی است نه فیلد سریال سخت‌افزار؛ هویت زنجیرهٔ گواهی و مشترک یا دستگاه‌محور بودن آن هنوز تعیین نشده است.
این درخواست جدید در callback داخل PID Setup ثبت شده است؛ برخلاف چهار درخواست F4 که PID آن‌ها نامعلوم بود. این مدرک جدید، انتساب درخواست‌های قدیمی F4 را به‌طور عقب‌گرد ثابت نمی‌کند. بدنهٔ خالی به معنی نبود ارسال نیست؛ CertID در URL است.
استاندارد: https://www.rfc-editor.org/rfc/rfc6960 بخش4.1.1 و پیوستA.1.1.

## آنچه هنوز اثبات نشده
- آزمایش فقط startup نسخه‌های Setup/Agent در VM تازه است، نه آپدیت کامل WoW یا کلاینت نصب‌شدهٔ کاربر.
- هنوز اثبات نشده بستن تله‌متری، آپدیت کامل را سالم نگه می‌دارد یا تله‌متری از مسیر دیگر نمی‌رود.
- هیچ response body، تحویل/ذخیرهٔ سرور، fingerprint فایل دانلودی یا انتقال A→B آزمون نشده است.
- درخواست به هر چهار Host از پیش انتخاب‌شده ثبت شد؛ این به معنی پوشش همهٔ مقصدها و همهٔ APIها نیست.
- child gating و instrumentation زمان‌بندی را تغییر می‌دهند؛ شناسه‌های opaque بدون schema یا مقایسهٔ مستقل تفسیر نمی‌شوند.
- شواهد CPU در درخواست تله‌متری TLS اجرای E2 مستقل و همچنان برقرار است؛ G1 تله‌متری را خاموش نکرد.

## provenance و بازتولید
Run: 39166365884
Source: 86ad2d71b8c21e2b3df01d1ede3b65c86eaa16a9
Receipt: eb2e0c235abb13806b90f7fa0bc97fc022bc2265
Raw: reports/startup-api-g1.json در receipt ثابت بالا.
تحلیل: python privacy-api/analyze_report.py reports/startup-api-g1.json analysis-output/api-g1
گزارش JSON تحلیل شامل hash فایل خام، درخواست‌های دو مقصد هدف و CertID رمزگشایی‌شده است. شمارش و bodyها از مسیر مستقل JSON خام بازبینی شدند. دادهٔ reference CPU و fixture به‌عنوان ترافیک جست‌وجو یا شمارش نشده‌اند.

## ایمنی و وضعیت بعدی
فقط runner استاندارد windows-2025؛ هیچ larger runner یا گروه پولی فعال نشد. وضعیت سهمیه/تعرفهٔ عادی حساب مستقل است. Windows read-only token، child environment پاک، ناشر Ubuntu جدا. بدون login، install action، درخواست بازی، تغییر hosts یا دخالت در سیستم کاربر و G:\World of Warcraft. آزمون‌های محلی۱۴ مورد API و۴۲ مورد پارسر مشترک و gate بومی موفق بودند.
اجرای جدیدی در انتظار نیست. ادامهٔ مناسب: طراحی آزمون کنترل‌شدهٔ بستن فقط مقصد تله‌متری، با همین روش انتساب و پایش مسیرهای جایگزین؛ نه اعلام آماده‌بودن یک پروفایل «فقط آپدیت» و نه ادامهٔ آپدیت بازی کاربر بدون طرح آزمون مشخص.
