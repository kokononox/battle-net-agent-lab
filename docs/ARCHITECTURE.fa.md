# معماری و مرز اعتماد

## ساختار مخزن

- `downloader/`: منبع بازیابی‌شدهٔ همان بستهٔ تحویلی TagFix، تست‌ها، راهنماهای فارسی و شواهد آزمون‌های آن. فایل‌های این انتشار دست‌نخورده و با `PACKAGE-MANIFEST.json` تطبیق شده‌اند.
- `scripts/`: آزمایش مستقل bootstrap روی Windows GitHub؛ observer، snapshotهای native، GUI فقط‌خواندنی، validator و publisher.
- `tests/`: تست‌های ایمنی آزمایش GitHub، جدا از ۴۴۶ تست دانلودر.
- `evidence/user/`: پنج گزارش تصمیم‌ساز `to-share` کاربر، بدون تغییر؛ منشأ و SHA256 در INDEX.
- `evidence/github/`: خلاصهٔ دارای مرجع گزارش bootstrap واقعی. اصل گزارش‌های خودکار در `reports/` است.
- `docs/`: تحویل جلسه، معماری، تاریخچه، محدودیت شواهد، گام بعد و دامنهٔ sync.

## جریان دانلودر

`target_metadata` → download/encoding/catalog inventories → برنامهٔ محتوا → شناسایی بازاستفادهٔ محلی → اثبات payload → صف conditional → scope نسخه/پروفایل.

- `repair_core.py` و `decoded_payload.py`: اندازه/هش، BLTE و انتشار امن خروجی در Lab؛ تعمیر مصنوعی جدا. هیچ فعال‌سازی CASC واقعی ندارد.
- `local_casc.py`: inventory نسل‌های idx مشاهده‌شده، checksum و محدوده/ابهام archive، dedup wrapper/direct، اثبات کامل EKey/chunk/CKey با بودجه و checkpoint. انتخاب نسل فعال اثبات نشده است.
- `legacy_reuse.py`, `reuse_coordinator.py`: واردکردن اثبات‌های کش/staging قبلی؛ decoded-only جایگزین encoded نشده و هم‌پوشانی دوبار کم نمی‌شود.
- `transfer_routes.py`, `acquisition_runner.py`: دریافت محدود/مسیر و قرارداد پاسخ. شبکه یا فایل نامعتبر به عنوان موفق پذیرفته نمی‌شود.
- `local_review.py`: ادامه از session و snapshot ذخیره‌شدهٔ همان Lab، نه جست‌وجوی newest/random در سیستم. pointer اتمیک و نگهداری checkpointهای ارجاع‌شده؛ batch ناتمام ممکن است تکرار شود.
- `installed_metadata.py`, `metadata_delta.py`: تفاوت منطقی old/new metadata؛ عدد کاتالوگ نه حجم اینترنت.
- `update_scope.py`: projection محافظه‌کارانهٔ platform/architecture/region/locales و تفکیک اثبات موجود. OR زبان‌ها، AND ابعاد، حفظ shared؛ category/alternate دلیل حذف نیست. policy نهایی vendor اثبات نشده.
- TagFix: یک `?` پایانی برای tag شناخته‌شده، qualifierهای اختیاری acct/geoip فقط شمارش، نه مقدار یا مبنای انتخاب. token واقعاً ناشناخته fail closed می‌شود؛ حدس منطقه/زبان از نام حساب ممنوع.
- `downloader_controller.py`, `windows_app.py`: اتصال عملیات به رابط Windows؛ موفقیت کاربر برای مسیرهای اجراشده شاهد است، نه تست جامع تمام Windows/NTFS/قطع برق.

## قوانین ایمنی محلی

Lab خارج از پوشهٔ بازی و ترجیحاً دیسک محلی NTFS. source فقط‌خواندنی؛ بازی و updater هنگام اثبات محلی بسته باشند. fingerprint و file set محافظ منطقی‌اند، جای snapshot سیستم‌عامل/قفل واقعی فایل را نمی‌گیرند. تغییر منبع ادامه را مسدود می‌کند؛ هیچ اسکن کامل یا حذف PRIVATE خودکار برای رفع خطا انجام نشود.

مقادیر SQL/rich metadata یا prefix یک idx کافی برای قبول asset نیستند؛ اثبات کامل لازم است. unsupported/encrypted را خراب اعلام نکنید. نسخهٔ هدف، EKey/CKey، checkpoint، Lab و storage source نباید بین اجراهای نامرتبط مخلوط شوند.

## آزمایش GitHub

Workflow روی تغییر `scripts/**`, `tests/**`, workflow یا dispatch اجرا می‌شود؛ schedule ندارد. Windows job هشت دقیقه، فقط contents:read؛ fresh GitHub-hosted Windows الزامی و state قبلی Battle.net ممنوع. Installer HTTPS با redirect allowlist، سقف body ۱۲۸MiB و deadline دریافت بررسی می‌شود؛ اجرای Setup فقط پس از Authenticode معتبر/ناشر مجاز و با environment محدود و stdin بسته.

Snapshot process/TCP از Toolhelp32 و GetExtendedTcpTable است؛ command line، environment، path خام یا متن log منتشر نمی‌شود. GUI فقط PIDهای مشاهده‌شده، sessionها و desktop capability، حداکثر ۸ پنجره/۳۲ کنترل و deadline چهار ثانیه برای هر probe؛ تنها WM_GETTEXT با timeout کوتاه روی کلاس‌های محدود. edit/rich-edit/hidden/unknown/Chromium خوانده نمی‌شوند. captionها هم فقط به label/marker ثابت تبدیل می‌شوند. UI سفارشی/زبانی ناشناخته ممکن است unrecognized بماند؛ نبود کنترل استاندارد دلیل نبود پنجره نیست.

فقط JSON اعتبارسنجی‌شده آپلود می‌شود. Ubuntu job تمیز جدا آن را دوباره validate و در reports commit می‌کند؛ هیچ installer در writer job اجرا نمی‌شود. cap دریافت Setup سقف شبکهٔ child نیست؛ مصرف child فقط با زمان محدود است. runner دورریختنی امنیت در برابر باینری مخربِ امضاشده را تضمین نمی‌کند. هیچ حساب یا secret تنظیم نشده است.

## اجرای آزمون بدون اجرای برنامهٔ واقعی

از ریشه: `python -m unittest discover -s tests -q` (ایمنی Agent).

از `downloader/`: `python -m unittest discover -s tests -q` (دانلودر).

این دستورات خودشان نصب Battle.net یا اتصال Lab کاربر را شروع نمی‌کنند. Workflow در Windows مرحلهٔ observer واقعی جدا دارد. برای اجرای رابط، راهنمای `downloader/WINDOWS-PREVIEW-fa.md` و `UPDATE-SCOPE-fa.md` را بخوانید؛ صرف sync درخواست تست تازه از کاربر نیست.
