# دریافت و بازتولید بستهٔ پرتابل

ZIP اصلی: `Portable-Retail-Sample.zip`، اندازهٔ دقیق **169,779,901 بایت** (حدود 161.9MiB). فایل اصلی بدون بازبسته‌بندی نگهداری می‌شود. SHA256:

```text
9bd063f6dc6b8304df1fd939d24c01389abc0d4ff78f8c68463e4e0b2610bc0b
```

وضعیت انتشار، نام asset و hashها در [manifest](../evidence/portable/ASSET-MANIFEST.json) ثبت می‌شود. اگر وضعیت pending است، هنوز لینک دانلود تأییدشده‌ای وجود ندارد. محل انتشار فعلی GitHub Releases مخزن خصوصی با tag واقعی `retail-research-2026101` است. ZIP عمداً داخل Git یا به صورت base64 چندتکه commit نمی‌شود.

## انتشار تأییدشده

[Release موجود](https://github.com/kokononox/battle-net-agent-lab/releases/tag/retail-research-2026101) سه asset دارد: ZIP اصلی، ZIP companion و فایل checksum. tag واقعی `retail-research-2026101` است (بدون رقم 6 پایانی). اندازه و SHA256 اعلام‌شدهٔ GitHub هر سه با نسخهٔ محلی تطبیق داده شده‌اند؛ این رسید دانلود مجدد مستقل نیست. دو ZIP گزارشِ اضافی در SHA256SUMS اختیاری‌اند و روی Release بارگذاری نشده‌اند؛ گزارش‌های لازم داخل companion قرار دارند.

ZIP companion snapshot قبلی با ۲۷۸ آزمون است؛ کد تازهٔ مشاهده‌گر و ممیزی activation در آخر شاخهٔ پژوهش با suite ۳۳۸تایی قرار دارد. assetهای تأییدشده تعویض نشدند.

## بازتولید با کد فعلی، بدون تغییر fixture

ZIP اصلی کد تاریخی با سقف کوچک‌تر Encoding ESpec دارد؛ اجرای runner داخل همان ZIP می‌تواند با `encoding_geometry_limit` متوقف شود. برای نسخهٔ اصلی manifest را دستکاری نکنید و فایل اصلاح‌شده روی fixture نریزید. کد آخر شاخهٔ پژوهش یا companion source archive را جدا داشته باشید و از پوشهٔ `downloader/patch_audit_lab` اجرا کنید:

```sh
python -B reproduce_portable.py --fixture /path/to/extracted/Portable-Retail-Sample
```

مسیر بالا نمونه است؛ مسیر پوشه‌ای را بدهید که `PORTABLE-MANIFEST.json` در آن است. runner تنها ماژول‌های کنار خودش را import می‌کند، نه کد داخل fixture. صحت manifest شامل hash کد تاریخی نیز بررسی می‌شود، ولی آن کد تاریخی اجرا نمی‌شود. شبکه در wrapper ممنوع است؛ `-B` از ساخت pycache جلوگیری می‌کند. خروجی JSON چاپ می‌شود و فایلی به نصب بازی نوشته نمی‌شود.

## فایل‌های لازم

1. ZIP اصلی: Encoding رسمی کامل، متادیتای ثابت، source کوچک، patch و target decoded.
2. کد فعلی repo شامل runner، اصلاح `encoding_target.py` و وابستگی‌های patch-audit.
3. گزارش‌های `research/portable-retail-reproduction` و `research/synthetic-casc-storage` برای شواهد و مرز اعتبار.
4. manifestهای `evidence/portable/` برای سلامت ZIP و فایل‌های داخل آن.

companion code ZIP از کد پژوهشی و گزارش‌ها ساخته می‌شود؛ نصب‌کننده/فایل اجرایی Windows نیست. دادهٔ ۲۰۰مگابایتی Encoding داخل companion تکرار نمی‌شود و ZIP اصلی جدا لازم است. fixture، کل Lab نیست؛ PRIVATE/SQLite و proofهای کامل کل نصب در آن نیستند.

هیچ خروجی آزمایش را به پوشهٔ بازی کپی نکنید. این بسته مجوز تغییر `.build.info`، اجرای صف دانلود گسترده، تعمیر نصب یا فعال‌سازی واقعی نیست.

اصلاح parser در checkpoint binding/extension: مقدار فیلد header در سازندهٔ v5 برابر `0x154` است؛ `0x258` طول copy حالت افزونه‌دار بود، نه مقدار مجاز دوم آن فیلد. [گزارش اصلاح و شواهد](../downloader/patch_audit_lab/research/binding-extension-9824/README-fa.md). fixture و assetهای Release تغییر نکردند.
