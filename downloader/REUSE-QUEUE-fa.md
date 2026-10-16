# کش قبلی + CASC محلی → صف دریافت یکتا

این مرحله سه بخش اجرایی دارد: واردسازی ادعاهای قدیمی، تأیید مجدد/ادغام شواهد و
ساخت صف مشروط دریافت. **نه GUI ویندوز است و نه نصب/نویسندهٔ CASC**.

## ورودی‌ها و مرز اعتماد

`legacy_reuse.py` سه قالب موجود پروژه را می‌شناسد:

- `decoded_v030`: فایل `PRIVATE-Decoded-Staging-Manifest.json` و root انتخاب‌شدهٔ
  Decoded-Staging؛ رکورد decoded به CKey و اندازهٔ هدف فعلی متصل می‌شود.
- `download_v025`: فایل `PRIVATE-Targeted-Download-Receipt.json` و root انتخاب‌شدهٔ
  Run؛ مسیر نسبی Targeted-Staging و EKey/اندازه/CK فعلی باید منطبق باشند.
- `supply_cache`: فایل `PRIVATE-Targeted-Supply-Plan.json` و root انتخاب‌شدهٔ cache
  قبلی؛ candidateها فقط نشانی برای بازبررسی هستند. state قدیمی اثبات نیست.

خواندن JSON تا ۴ MiB است، نه سقف اشتباه ۶۴ KiB. JSON با کلید تکراری، ورودی
بیش‌ازحد، مسیر traversal، drive/UNC/ADS، نام‌های رزروشده و case-alias رد می‌شود.
تکرار دقیق یک candidate decoded در alternatives همان supply plan فقط یک‌بار
ثبت می‌شود؛ تعارض محتوا/اندازه یا مسیر هم‌نام casefold پذیرفته نیست.

**مسیر مطلق staging/source_root و cdn_origin داخل JSON هرگز دنبال نمی‌شوند.**
root را فراخواننده صریح انتخاب می‌کند. ورودی‌ها فقط خوانده می‌شوند و اجرا نمی‌شوند.
هیچ جست‌وجوی بازگشتی کامپیوتر یا استخراج token/حسابی وجود ندارد.

نسخهٔ قدیمی به‌تنهایی باعث رد محتوای یکسان نمی‌شود؛ اما کلیدهای کامل و اندازه‌ها
باید به برنامهٔ هدف فعلی متصل شوند و داده دوباره تأیید شود. ادعایی که در هدف منتخب
فعلی نیست، جدا شمارش می‌شود، نه اینکه فایلش مفقود یا خراب معرفی شود.

## ادغام و تأیید

`reuse_coordinator.inventory` منابع زیر را ثبت می‌کند:

- importهای بالا؛
- نامزدهای صریح `cache_evidence.Candidate`؛
- جفت inventory/checkpoint محلی که **خود همین Lab** ساخته و EKey/CKey کاملش
  تأیید شده است. plan ID و snapshot ID باید دقیقاً یکی باشند. sourceها دوباره از
  نظر fingerprint/file set کنترل می‌شوند؛ انتخاب active generation انجام نمی‌شود.

گزارش قدیمی cache یا receipt «موفق» به‌تنهایی اثبات نیست. تنها اثبات کامل محلیِ
متعلق به Lab با منابع ثابت قابل‌ارث‌بری است. آن اثبات‌ها حتی با بودجهٔ صفر وارد
checkpoint جدید می‌شوند تا بررسی cache دیگر مانع استفاده از اثبات موجود نشود.

`verify_batch` دارای سقف تعداد/بایت و checkpoint مستقل است. فایل encoded با
EKey/chunk/CKey کامل و decoded با CKey کامل بررسی می‌شود. اگر receipt/manifest
SHA-256 داشته باشد، آن هم باید منطبق باشد. برای encoded دارای SHA، خواندن دوم
فایل **در بودجه حساب می‌شود**. فایل بد، رمزگذاری‌شده، محدودشده یا هنوز pending،
بدون اثبات قابل‌بازاستفاده حساب نمی‌شود. فایلِ نبود‌ه در لحظهٔ ثبت، در صورت ظاهر
شدن بعدی نیاز به inventory تازه دارد؛ منبع تازه مخفیانه وارد checkpoint نمی‌شود.

برای یک EKey، اثبات مستقل encoded موجود می‌تواند بررسی نسخهٔ تکراری cache را
غیرضروری کند. این حالت `already_verified_same_target` است، نه تأیید فایلِ خوانده‌نشده.

## صف خروجی

`make_queue` برای هر EKey کامل هدف دقیقاً یک ردیف می‌سازد و همهٔ مشخصات/مسیرهای
انتخاب‌شدهٔ برنامهٔ مبنا را حفظ می‌کند:

- `encoded_available`: حداقل یک representation encoded با اثبات کامل موجود است.
- `decoded_content_only`: محتوای decoded تأییدشده موجود است، ولی representation
  encoded هدف اثبات نشده؛ خودکار از حجم encoded کم نمی‌شود و transcode فرض نمی‌شود.
- `conditional_download`: مسیر پشتیبانی‌شده موجود است، ولی منبع encoded اثبات نشده.
- `unresolved_plan`: نگاشت/حدود/مسیر لازم اثبات نشده؛ تبدیل حدسی به direct ممنوع است.

فیلد `conditional_transfer` از availability جداست؛ decoded-only هم ممکن است هنوز
برای representation encoded نامزد مشروط دریافت باشد. هم‌پوشانی cache/CASC یا دو
کپی فایل، فقط یک‌بار به حساب EKey کم می‌شود. pending و نبود نامزد، اثبات فقدان نیست.
`required_network_download_bytes` همچنان null و `installation_ready` برابر false است.

`checked_queue` پیش از استفادهٔ گزارش، plan ID، source snapshot و هویت DBهای خصوصی
شواهد را دوباره بررسی می‌کند. هنگام کپی/مصرف واقعی منبع هم باید بازتأیید انجام شود؛
fingerprint جای snapshot اتمیک OS یا قفل Battle.net/WoW نیست.

## API توسعه‌ای

```python
import legacy_reuse as legacy
import reuse_coordinator as reuse

summary, inventory = reuse.inventory(
    lab, plan_db,
    imports=[legacy.Import('download_v025', receipt_path, old_run_root)],
    local_inputs=[(local_inventory_db, local_checkpoint_db)])
progress, checkpoint = reuse.verify_batch(lab, plan_db, inventory)
# برای ادامهٔ batch ناقص با منابع ثابت:
progress, next_checkpoint = reuse.verify_batch(
    lab, plan_db, inventory, previous=checkpoint)
queue_summary, queue_db = reuse.make_queue(
    lab, plan_db, inventory, next_checkpoint)
checked_summary = reuse.checked_queue(lab, plan_db, queue_db)
```

این کد نمونهٔ توسعه است، نه درخواست اجرای کاربر روی بازی اصلی. DBهای inventory،
evidence و queue دارای مسیر/کلید/مختصات خصوصی‌اند؛ ارسال نشوند. گزارش aggregate
مسیر خصوصی ندارد. فایل‌های PRIVATE و فایل‌های بازی را برای ادامه نفرستید.

## اصلاح دقیق تست 403 مرحلهٔ قبل

برنامهٔ مبنا مسیرها را درست با `archive_range` و `advertised_direct` ثبت کرده بود،
ولی **harness تست نمونه** اشتباهاً دنبال نام `archive` می‌گشت و archive_range را به
درخواست مستقیم EKey تبدیل می‌کرد. 403 همان درخواست، مدرک مسدودبودن CDN نبود.

`transfer_routes.py` حالا فقط دو نام دقیق را قبول می‌کند:

- archive_range → کلید آرشیو اعلام‌شده + offset مشخص، درخواست دقیق Range؛
- advertised_direct → EKey مستقیمِ اعلام‌شده، بدون offset/کلید آرشیو.

نام ناشناخته توقف می‌دهد؛ fallback مستقیم، HTTP یا میزبان جایگزین ندارد. Spec به
نسخه/configهای رسمی EU و مشخصات ردیف متصل می‌شود و فقط برای دریافت در Lab است.
فراخواننده باید row را از برنامه/صف معتبر بگیرد و target رسمی را تازه بررسی کند؛
این تابع یک row ساختگی را به سند امضاشدهٔ ناشر تبدیل نمی‌کند.

با مسیر اصلاح‌شده سه payload رسمی، جمعاً ۳٬۴۵۳ بایت، با Range دریافت و با EKey/
chunk/CKey کامل تأیید شدند. سپس در archive/index مصنوعی محلی هم تأیید شدند.
این نه نصب واقعی کاربر است، نه اثبات دسترس‌پذیری تمام میلیون‌ها مسیر یا همهٔ انواع
فشرده‌سازی. گزارش شکست اولیه حفظ شده و گزارش اصلاح جداست.

## نتایج و باقی‌مانده

آزمون ادغام با برنامهٔ کامل ۲٬۸۸۱٬۶۱۹ شیء و سه payload رسمی در fixtureهای ساخته‌شده
اجرا شد: دو encoded قابل‌بازاستفاده، یک decoded-only، بدون دوباره‌شماری و بدون کم
کردن decoded-only از encoded. تطبیق مستقل همهٔ ردیف‌های صف، مشخصات/مسیر/تصمیم و
flag دریافت را بدون اختلاف تأیید کرد. این **نمونهٔ نصب/کش واقعی کاربر نیست**.

۲۷۶ تست موفق، شامل توقف/ادامه و مرگ واقعی process، ثبت شده‌اند. همهٔ فایل‌های
Python بستهٔ پیشین بدون تغییر مانده‌اند. فایل‌های تازه به آن متصل شده‌اند.

قدم‌های لازم باقی‌مانده: runner دریافت از صف با محدودیت روشن و UI/آزمون Windows،
سیاست نهایی زبان/manifestهای نصب و full closure، و سپس نویسنده/فعال‌سازی/بازیابی
CASC در محیط دورریختنی. هیچ فایل بازی کاربر، .build.info یا تنظیماتش تغییر نکرده است.
هدف اصلی بررسی تله‌متری WoW پس از آماده‌شدن این پیش‌نیاز حفظ شده است.
