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

مشاهده‌گر جاری نسخهٔ ۳ و suite جاری ۳۶۰تایی است؛ [گزارش payload/rollback](../downloader/patch_audit_lab/research/primary-payload-9824/README-fa.md). payload واقعیِ shmem کاربر هنوز در fixture نیست؛ نمونه‌های جدید generated-only هستند و rollback اجرا نمی‌شود. ZIP companion همچنان snapshot تاریخی ۲۷۸تایی است؛ از آخر شاخه برای کد جدید استفاده کنید.

**milestone تازه:** نمونهٔ واقعی fixture با [کد جدید ذخیره‌سازی پژوهشی](../downloader/patch_audit_lab/research/retail-storage-poc/README-fa.md) به data/index رفت و native EKey/CKey را خواند. suite جاری ۳۹۵ است. خروجی prefix-placeholder دارد و نصب‌پذیر نیست؛ fixture اصلی و companion تاریخی Release تعویض نشده‌اند. کد جاری و runner از آخر شاخه لازم‌اند.


## آخرین مرحله: prefix بازسازی‌شده، نه activation نصب

کد جاری [archive-prefix-9824](../downloader/patch_audit_lab/research/archive-prefix-9824/README-fa.md) در خروجی پژوهشی جدید ۱۶ هدر ۳۰بایتی و ۱۶ فایل index/۱۷ رکورد می‌سازد؛ نمونهٔ واقعی با native خوانده شد. suite جاری ۴۲۴ با صفر skip است. seed ورودی پژوهشی است، نه هویت نصب Windows؛ این خروجی نصب‌پذیر نیست. گزارش ۳۹۵تایی بالاتر تاریخی است و placeholder نمونهٔ آن حفظ شده است. ZIPهای Release تغییری نکردند؛ ماژول‌های تازه از شاخهٔ پژوهش لازم‌اند.


## آخرین مرحله: نام مصنوعی → seed → prefix

[name-seed-9824](../downloader/patch_audit_lab/research/name-seed-9824/README-fa.md) مدل محدود ASCII را با دستورهای اصلی ۷ تابع خالص در Linux i386 تطبیق می‌دهد؛ فرمول MD5 نام رایانه + نام canonical ذخیره‌سازی است. suite جاری ۴۵۳/صفر skip؛ نمونهٔ واقعی با seed مشتق‌شده بازخوانی شد. Agent.exe یا API ویندوز اجرا نشده و هیچ نام/path واقعی از کاربر گرفته نشده است. ZIP اصلی و companion Release تعویض نشدند؛ برای این مرحله source آخر شاخه لازم است.


## جدیدترین مرحله: چرخهٔ تک‌آبجکتی با حفظ مبدأ

[retail-update-cycle](../downloader/patch_audit_lab/research/retail-update-cycle/README-fa.md) یک source واقعی را حفظ می‌کند، patch را اعمال و target را append می‌کند، سپس sequence ایندکس را در control پژوهشی منتشر می‌کند. ۹ توقف subprocess با resume و native readback موفق؛ suite فعلی ۴۹۰/صفر skip. journal/قفل/انتشار این آزمایش معادل اجرای Windows Agent نیستند؛ activation کامل نداریم. ZIP اصلی و companion قدیمی عوض نشده‌اند؛ source آخر شاخه و دستورهای گزارش جدید را استفاده کنید. هیچ اسکن یا دانلود گستردهٔ جدید لازم نیست.


## نتیجهٔ جدید sequence visibility

[sequence-visibility-9824](../downloader/patch_audit_lab/research/sequence-visibility-9824/README-fa.md): چهار تابع اصلی Agent در harness محدود با helperهای mock بررسی شدند. بازگشت صفر reader در خطای bind تزریقی، سلامت target را اثبات نمی‌کند؛ cache ممکن است جلو رفته باشد و refresh بعدی retry نکند. گیت مستقل native مرحلهٔ قبلی لازم می‌ماند. ۱۴۴۰ بردار parity و ۵۲۰ تست/صفر skip؛ این اجرای Windows Agent یا نصب واقعی نیست. باینری/fragment خام و ZIP جدید منتشر نشده‌اند؛ source شاخه به‌روز است.


## قرارداد اصلی bind و V8

[گزارش V8](../downloader/patch_audit_lab/research/bind-contract-9824/README-fa.md): V7 قبلی صرفاً با CascLib خوانده شده بود و bind خود Agent 9824 آن را رد کرد. اکنون ۱۶ ایندکس V8 در harness اصلی bind/parser پذیرفته شد؛ lookup کامل source/target موفق و spanها مستقل با Python بررسی شدند. این writer نصب نیست؛ ساخت V8 فقط در پوشهٔ owned تازه است و ZIP اصلی دست‌نخورده. ۵۶۳ آزمون/صفر skip، ۱۴۲۴ بردار؛ برای source جدید از شاخه استفاده کنید و فایل‌های fixture داخل ZIP را جایگزین نکنید.


## چرخهٔ V8 با گیت اجباری و resume

[retail-v8-cycle](../downloader/patch_audit_lab/research/retail-v8-cycle/README-fa.md): چرخهٔ owned تازه با source واقعی، append هدف، binder اصلی پیش/پس publication و readback مستقل؛ ۹ توقف سخت/resume و خطای نگاشتِ مانع انتشار موفق بودند. ۶۰۱ آزمون/صفر skip. این writer Lab یا نصب اصلی نیست؛ فایل‌های fixture یا ZIP را تعویض نکنید. Windows واقعی و object read/merge کامل هنوز بررسی نشده‌اند.
