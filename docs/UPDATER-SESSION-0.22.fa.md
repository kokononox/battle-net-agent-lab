# تحویل بستن صریح scope ناموفق — ۰٫۲۲

ادامهٔ [۰٫۲۱](UPDATER-SESSION-0.21.fa.md). سورس فعلی updater-core/. محصول reusable و مستقل از جفت نسخهٔ ثابت می‌ماند؛ 12.1.5.70448 فقط snapshot تاریخی pinned است.

## انجام‌شده
transfer_scope.py سه API جدا دارد: retire_uncommitted، approve_successor و create_successor؛ هرکدام approved=True لازم دارد. بازنشستگی فقط وقتی pending وجود دارد و journal تمام stageها دقیقاً هنوز مطابق ledger است انجام می‌شود. SHA prefixها تازه خوانده، همهٔ lockها نگه داشته و receipt ثابت قبل از retired marker منتشر می‌شود. commit بدون ledger باید ابتدا reconcile شود؛ این مسیر آن را دور نمی‌زند.

grant v2 nonce تصادفی تازه و digest pinned سابقه دارد؛ ledger v2 prior_scopes را حفظ می‌کند. receiptهای قبلی شامل grant و pending ledger و شمار رزرو قبلی‌اند؛ chain prefix دقیقاً کنترل می‌شود. شمار جدید per-scope جداست ولی lifetime تمام رزروهای قبلی را جمع می‌کند؛ درخواست/بایت ناموفق پس داده نمی‌شود. حذف سابقه/receipt، hardlink و فساد، grant قدیمی یا عادی با history خالی، تغییر checkpoint/source/baseline متوقف می‌شود. v1 با سابقهٔ خالی خوانده می‌شود. سقف ۱۶ scope قبلی و ۲۵۶ KiB هر receipt است.

این APIها هیچ fetch/step، retry یا ادامهٔ خودکار، scan، orphan adoption/deletion یا lock breaking ندارند. fault بین receipt و marker فقط با اقدام صریح و برابری دقیق همان receipt قابل تکمیل است. fault قبل/بعد successor publication آزموده شده است. سابقهٔ مشارکتی امضا یا دفاع در برابر مهاجم/rollback کل workspace نیست. equality baseline ورودی، اندازه‌گیری تازهٔ نصب زنده نیست.

## آزمون واقعی و همگام‌سازی
۳۳ تست lifecycle روی هر backend، شامل دو process تازه و restore، faultها، بودجهٔ انباشته، prefix/receipt خراب، حذف سابقه، hardlink، سقف و v1. Linux: ۵۹۵ تست؛ Windows/Python 3.12.10: ۲۳۳ تست؛ صفر failure/error/skip. شمار پلتفرم‌ها جمع نشود.

source commit: 97e9dbd96e68e0ea22b4d3d97df49d705f3cb88d؛ receipt commit: aa1bfd781012f36af19fa0bf20f8baaa2a31b630. ZIP از source/test/fixture عمومی کوچک و گزارش حداقلی ساخته و پس از استخراج CRC/hash و regression آن کنترل می‌شود؛ payload بازی، decoded بزرگ، SQLite، transcript و credential منتقل نمی‌شوند.

## مرزها و ادامه
hard crash حین lock، disk-full واقعی، power loss، CDN/TLS عملیاتی و qualification تولیدی باز هستند. policy مستقل Alternate/Talebound/variant/dependency/patch، preferences تازه، active generation، reuse نصب و حجم دقیق، CASC writer/rollback/activation، E2E روی کپی Windows و UI باقی‌اند. installation_ready=false، apply_authorized=false، required_network_download_bytes=null و native_windows_staging_backend_qualified=false.

قدم بعد: بستن evidenceهای policy/نسل فعال و طراحی backend فقط‌خواندنی bounded قبل از probe زنده؛ APIهای grant تازه به معنی مجوز فعلی درخواست CDN نیستند. این مرحله هیچ دسترسی بازی/CDN، scan، admin، repair یا تغییر ACL نداشت؛ workflow مستقل Agent تغییر نکرد. کاربر Windows و فضای تست دارد؛ فعلاً کپی یا اجرای زنده درخواست نشده. cache و metadata قبلی حفظ شوند، دوباره دانلود نشوند.

[رسید Windows](../updater-core/reports/WINDOWS-SCOPE-CI-to-share.json) · [QA](../updater-core/QA.json) · [مرز lifecycle](../updater-core/research/SCOPE-RETIREMENT-SAFETY.md) · [کارهای باقی‌مانده](UPDATER-REMAINING.fa.md)
