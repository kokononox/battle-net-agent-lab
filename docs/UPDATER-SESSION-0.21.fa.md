# تحویل بازیابی محلی commit نیمه‌تمام — ۰٫۲۱

ادامهٔ [۰٫۲۰](UPDATER-SESSION-0.20.fa.md). سورس فعلی updater-core/. reusable/version-independent بودن محصول حفظ شده؛ 12.1.5.70448 فقط target تاریخی pinned است.

## انجام‌شده
TransferController.reconcile_pending یک API جدا، نیازمند approved=True و grant/baseline منطبق است. همهٔ stage lockها را نگه می‌دارد، فقط یک segment دقیقاً مطابق Range رزروشده را بررسی می‌کند و SHA journal پیشین را با بازسازی predecessor اثبات می‌کند. stageهای دیگر و shared archive ETag/total باید منطبق بمانند. SHA همهٔ prefixها تازه بررسی می‌شود؛ برای شیء کامل، EKey/CKey/checksum کامل نیز دوباره بررسی می‌شوند. فایل ناقص full_object_verified=false می‌ماند و eligibility/apply صادر نمی‌شود.

پس از اثبات، cursor یک واحد جلو می‌رود و pending=false می‌شود؛ reserved_requests و reserved_body_bytes همان مقادیر می‌مانند. API fetch callback نمی‌گیرد، شبکه/تکرار/ادامهٔ خودکار ندارد. ادامه تنها با restore صریحِ Rangeهای باقی‌ماندهٔ همان grant است؛ serialized grant هنوز به approved=True تازه نیاز دارد.

اگر journal stage هنوز پیشین است، prefixها کنترل می‌شوند اما pending بدون تغییر می‌ماند. دادهٔ orphan، segment اضافه، corruption، changed source/target/baseline، conflict entity، journal قبلی اثبات‌نشده و lock رهاشده پذیرفته/پاک نمی‌شوند. predecessor غیرcanonical ممکن است fail-closed شود. توقف سخت داخل critical section می‌تواند lock باقی بگذارد؛ بازیابی خودکار آن پیاده نشده است.

## آزمون واقعی
۲۶ تست تازه روی هر backend: دادهٔ کامل/ناقص، قطعهٔ دوم و predecessor غیرخالی، source مشترک و entity متفاوت، corruption با digest دستکاری‌شده، هویت‌ها، ثابت‌ماندن بودجه، fault قبل/بعد ledger و reconciliation در process تازه. Linux: ۵۶۲ تست؛ Windows/Python 3.12.10: ۲۰۰ تست با صفر failure/error/skip. شمار پلتفرم‌ها جمع نشود.

source commit: dfb11f5e894e807e6559213fc4d484cf6a334b0d؛ receipt commit: 5a824e882443ddebc3a8e5dbb47c30ed134df005. ZIP بعد از تولید، استخراج و CRC/hash و regression آن کنترل می‌شود. فقط source/tests/fixture عمومی کوچک و receiptهای حداقلی منتقل می‌شوند؛ نه payload بازی/decoded بزرگ/SQLite/transcript/credential.

## باقی‌مانده و مرزها
retirement و scope تازه برای attempt بدون commit، recovery واقعی disk-full/power loss/abandoned lock و CDN/TLS عملیاتی هنوز qualify نشده‌اند. policy مستقل Alternate/Talebound/variant/dependency/patch، preferences تازه، active generation، reuse نصب و حجم‌ها، CASC writer/rollback/activation، E2E روی کپی Windows و UI باقی‌اند. installation_ready=false و apply_authorized=false؛ required_network_download_bytes=null و native_windows_staging_backend_qualified=false باقی است.

هیچ دسترسی به بازی، CDN بازی، scan، admin، repair یا تغییر permission انجام نشده؛ workflow مستقل Agent دست‌نخورده است. کاربر Windows و فضای آزمایشی دارد؛ فعلاً کپی یا اجرای زنده‌ای درخواست نشده. cache/metadata پروژه حفظ و دوباره دانلود نشوند.

[رسید Windows](../updater-core/reports/WINDOWS-RECONCILE-CI-to-share.json) · [QA](../updater-core/QA.json) · [مرز بازیابی](../updater-core/research/RECONCILIATION-SAFETY.md) · [کارهای باقی‌مانده](UPDATER-REMAINING.fa.md)
