# G43 — کشف metadata عمومی، بدون اجرای نصاب

این پوشه آزمایش پژوهشی است؛ محصول، allowlist و catalog G37 را تغییر نمی‌دهد.

1. discover.py: درخواست‌های ثابت bna/versions و bna/cdns با HTTPS، بدون cookie/credential/query/body و بدون follow redirect. parse محدود PSV؛ فقط اگر جفت v1 پیدا نشود v2 مشخص را امتحان می‌کند.
2. configs.py: انتخاب ثابت region=us و سرور HTTPS اعلام‌شده us.cdn.blizzard.com، دریافت سه config با کلید32hex و MD5 مطابق bytes واقعی. ProductConfig فقط JSON data است؛ دستورهایش اجرا نمی‌شوند.
3. manifests.py: فقط سه metadata کوچک encoding/install/download با اندازهٔ دقیق اعلام‌شده؛ BLTE با N/Z و checksum/size/key، سپس parse محدود IN/DL. E/F/ناشناخته، دادهٔ خراب، trailing یا zlib expansion رد می‌شوند. encoding هنوز برای نگاشت CKey/EKey parse نمی‌شود.
4. test_manifest.py: پانزده تست آفلاین با fixtureهای عمومیِ ثبت‌شده و ممنوعیت socket/opener. از ریشهٔ repo اجرا کنید:

```bash
python analysis-tools/public-manifest-g43/test_manifest.py
```

دریافت آنلاین فقط پژوهشی و یک‌باره است؛ scriptها روی snapshot موجود overwrite نمی‌کنند. پیش از دریافت تازه، مسیر snapshot جدید و بررسی انسانی لازم است؛ این‌ها broker نهایی، ضد replay سراسری یا اثبات نبود fingerprinting نیستند. تمام decoded metadata داده است؛ هیچ PE یا فایل نام‌برده در manifest اجرا/نصب نمی‌شود. public-fixtures.json برای اجرای تست‌ها کافی است و نیاز به دریافت آنلاین ندارد.

نتیجه: reports/public-manifest-g43/RESULT.fa.md. metadata-pins.review-only.json عمداً catalog قابل‌بارگذاری G37 نیست. فایل‌های نصب هنوز به URLهای محتوای لازم برای Windows نگاشت نشده‌اند؛ tag selection و dependency Agent باز است.
