# G44 — نگاشت کاملاً آفلاین encoding

این مرحله تنها snapshot عمومی G43 را می‌خواند. هیچ HTTP/TLS client، API دانلود، اجرای payload یا نصب ندارد. کاتالوگ G37 و allowlist را تغییر نمی‌دهد.

## اجرا از clone حاوی G43 و G37
وابستگی‌ها: Python3، pandas و NumPy. از ریشهٔ repo:

```bash
python analysis-tools/encoding-map-g44/test_offline.py
python analysis-tools/encoding-map-g44/analyze.py
```

analyze.py منبع G43 را با source-inputs.json پین می‌کند، metadata را با codec خالص G43 دوباره decode و hash-check می‌کند، EN را parse و IN/DL را join می‌کند. پس از محاسبهٔ اصلی، یک join pandas و unpackbits NumPy مستقل کنترل عددی را انجام می‌دهند. در محیط توسعهٔ /data/g44، مسیر /data/g43 به‌صورت fallback فقط برای fixtureهای محلی پشتیبانی می‌شود؛ در clone، هر دو زیر reports همان repo هستند.

فایل‌های خروجی زیر reports/encoding-map-g44 می‌روند؛ مسیرهای نصبِ داخل manifest هرگز روی filesystem نصب ساخته نمی‌شوند. فایل CSV نگاشت کامل برای انتشار است؛ install-mapping.json محلی مفصل‌تر و تکراری است. source-inputs.json نسبت به snapshot زندهٔ بعدی خودکار به‌روزرسانی نمی‌شود؛ دریافت تازه باید مرحلهٔ پژوهشی صریح دیگری باشد.

encoding.py فقط EN v1، hash16، صفحه/رکورد محدود و sentinel دقیق را می‌پذیرد. ESpecها داده‌اند، نه کد؛ footer حفظ‌شده تفسیر معنایی کامل نشده است. codec.py فقط پنج جزء خالص G43 را بدون تغییر نگه می‌دارد. legacy_compatibility از G37 فقط loader آفلاین موجود را برای اثبات رد schema پژوهشی می‌خواند؛ آن را تغییر نمی‌دهد.

Windows_literal_tag_candidates فهرست نهایی نصب نیست: Volatile، locale policy، OS override و Agent هنوز بازند. مسیرهای پیشنهادی CDN هنوز request نشده‌اند، SHA-256 payloadها null است و همه pending هستند. تعداد اشیای نامزد196 از سقف64 نمونهٔ G37 بیشتر است؛ این کد آن سقف را دور نمی‌زند.

نتیجه و شواهد: reports/encoding-map-g44/RESULT.fa.md.
