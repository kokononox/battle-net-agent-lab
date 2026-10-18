# تحویل مرحلهٔ ۰٫۲۴ — اتصال پیکربندی به نسخه

در ادامهٔ [۰٫۲۳](UPDATER-SESSION-0.23.fa.md)، کاربر خواست مسئلهٔ مرحلهٔ اول واقعاً حل شود، نه اینکه درخواست مبهم plan رسمی به او سپرده شود. **فعلاً هیچ اقدام/فایل/اجازهٔ تازه‌ای از کاربر لازم نیست.**

## پیشرفت واقعی
کلید ProductConfig در نسخهٔ ذخیره‌شده موجود بود ولی در TargetSnapshot قدیمی نگهداری نمی‌شد. از روی آن، پیکربندی دقیق 53020d32e1a25648c8e1eafd5771935f را از دو آرشیو عمومی GitHub پیدا کردیم؛ هیچ درخواست تازه‌ای به CDN بازی انجام نشد. فایل ۱۵٬۷۶۴ بایت است و MD5/SHA256 هر دو کپی با یکدیگر، و MD5 با کلید سطر EU نسخهٔ تاریخی 12.1.5.70448 تطبیق دارد. این هویت محتواست، نه امضای ناشر یا استقلال دو آرشیو.

product_policy_facts.py به همان versions bytes/target/config bind می‌کند، نگاشت platform/architecture، زبان‌های پشتیبانی‌شده و alias، و extra_tags دامنه‌دار را صرفاً گزارش می‌کند. enGB→enUS صریح است؛ text/speech جدا می‌مانند؛ alias تغییر‌یافته نیاز به بازبینی/replan را علامت می‌زند. region از زبان حدس زده نمی‌شود و نبود extra_tags به disabled بودن feature تعبیر نمی‌شود. مسیر/عملیات install/uninstall/delete/registry config inert است و اجرا نمی‌شود. mapping/schema ناشناخته و alias چرخه‌ای رد می‌شود؛ نسخهٔ ثابت در الگوریتم hardcode نیست. تست آینده 20.2.1.91234 synthetic است، نه انتشار واقعی.

review_candidate_product_facts با gate هویت کامل candidate موجود متصل شد و روی copied metadata/SQLite اجرا شد. برنامهٔ نامزد و payloadهای بازی بدون تغییر ماندند. گزارش مستقل به کلید و هش جدول وصل است؛ checkpoint قدیمی بدون migration معتبر به policy-complete تبدیل نمی‌شود. هیچ reader زنده/transport/installer تازه‌ای اضافه نشد.

## چرا منابع مستقل را بی‌بررسی کپی نکردیم
battlenet.nix منطق OR در یک type و AND میان typeها، و نگه‌داشتن base برای alternate صریح دارد؛ مدل آن برای enUS تاریخی با candidate ما برابر است. اما wow.nix آن revision فقط release metadata است، نه plan کامل نصب WoW. steed بالاترین دسته را به‌دلیل بازهٔ exclusive رد می‌کند و AND برچسب‌ها در Download تاریخی مجموعهٔ متفاوتی می‌دهد. مثال حداقلی چندزبان هم ثابت می‌کند برابری تک‌زبان برای بستن policy عمومی کافی نیست. هیچ‌یک oracle رسمی یا جایگزین اثبات نسل نصب نیست. [گزارش منشأ](../updater-core/research/PRODUCT-CONFIG-AND-SOURCES.md).

## تست و مرز ادعا
۲۶ تست تازه: ۲۵ synthetic + یک fixture عمومی؛ مجموع Linux ۶۴۸ (۶۴۲ synthetic، شش public fixture). Windows/Python 3.12.10 برابر ۲۸۶ با صفر failure/error/skip. شمار پلتفرم‌ها جمع نشود. source bf26248d0f454c0f8c30ba20949e547af1ab919d و receipt 5b499291cfd424163776c98601c40b54afb0838b. [رسید](../updater-core/reports/WINDOWS-PRODUCT-FACTS-CI-to-share.json). این‌ها صحت reader/آزمون‌ها را نشان می‌دهند، نه صحت کامل updater.

## ادامهٔ درست
1. استفاده از facts بازیابی‌شده برای محدودکردن قواعد مجهول feature/variant/dependency؛ بدون فرض‌کردن disabled یا کپی heuristic prototype.
2. طراحی reader/capture مشخص برای ترجیحات تازه و نسل فعال Windows؛ Active=1 یا نام بالاتر idx کافی نیست و V8 ناشناخته حدس زده نمی‌شود.
3. بعد از این گیت‌ها: reuse/حجم دقیق، انتقال واقعی/recovery، writer/rollback/activation، آزمون روی کپی مستقل، سپس UI/release.

مرحلهٔ اول هنوز باز است؛ required_set_selected/active_generation_proven/installation_ready/apply_authorized=false و required_network_download_bytes=null. فعلاً تقاضای کپی بازی، اجرای update/repair رسمی، admin/ACL change یا آپلود گسترده نکنید. هر تست رسمی آینده باید اول دامنهٔ bounded clone/network/write/privacy داشته باشد و جداگانه تأیید شود. متادیتا/کش فعلی حفظ شود؛ دوباره دانلود نشود. مخزن با همین وضعیت همگام شده، ولی پروژه هنوز اپدیتر قابل نصب نیست.
