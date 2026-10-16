# payload اصلی shmem و مسیر ورودی نام — Agent 9824

> در [milestone بعدی](../retail-storage-poc/README-fa.md)، A/B در مسیر تخصیص first-fit به طول/نشانی فضای آزاد وصل شدند و نمونهٔ واقعی تا data/index و native readback پیش رفت. suite جاری ۳۹۵ است؛ این receiptهای ۳۶۰تایی تاریخی‌اند.


## نتیجه و حدود

ساختار محدود payload اصلی `0x2ab8` از مصرف‌کننده و نویسندهٔ خود Agent استخراج شد، نه صرفاً از تفاضل اندازه‌ها: دو آرایهٔ اعداد unsigned چهل‌بیتی big-endian، ظرفیت `0x442 = 1090` و مسیر ذخیره/بازگردانیِ رکورد در حالت ۲. این **اثبات کامل allocator، سلامت نصب یا writer آمادهٔ بازی نیست**. Agent اجرا نشد؛ هیچ shmem واقعی کاربر آزمایش نشد؛ فایل بازی/Lab و assetهای Release تغییر نکردند.

باینری ثابت: Agent 2.41.1.9824، PE32/i386، SHA256:
`b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`.

رسیدهای جدید: **۲۷ byte anchor، ۲۴ direct call، ۳ branch edge و یک import** روی باینری واقعی ثابت تطبیق یافتند؛ verifier مرحلهٔ قبل نیز پیش‌نیاز اجراست. [رسید باینری](AGENT-PRIMARY-STATIC.json)، [حدود و hash قطعات disassembly](DISASSEMBLY-MANIFEST.json).

## اتصال به payload واقعیِ mapping

- مسیر init در `0x712030` نشانی `object+0x48` را به wrapper `0x71e0a2` می‌دهد؛ wrapper به binder `0x71e0dd` می‌رود.
- خروجی binder در `0x71e280` دو pointer متوالی می‌نویسد: control base و base + DWORD در `control+0x10c`. بنابراین در این کلاس، `object+0x4c` pointer payload است.
- مصرف‌کنندهٔ `0x7114e2` همین pointer را می‌خواند و در مسیر بازسازی آن را به `0x722bd6` می‌دهد.
- این کلاس را با کلاس index که pointerهای `+0x38/+0x3c` دارد یا شیء callback هم‌نشانی اشتباه نکنید؛ offsetها بدون زنجیرهٔ call/pointer قابل تعمیم نیستند.

## هندسهٔ محدود اثبات‌شده

| offset نسبت به payload | داده یا کاربرد مشاهده‌شده |
| --- | --- |
| `0x00` | state: reset/rebuild مقدار ۰؛ مسیرهای update/recovery بین ۱ و ۲ |
| `0x04` | تعداد رکورد؛ append از آن برای index استفاده می‌کند و سپس افزایش می‌دهد |
| `0x08` | index ذخیره‌شده برای بازگردانی |
| `0x0c` | هنوز تفسیر نشده؛ reset بررسی‌شده این word را صفر نمی‌کند |
| `0x10` و `0x14` | مقدار قدیمی آرایهٔ B به صورت low/high DWORD |
| `0x18` و `0x1c` | مقدار قدیمی آرایهٔ A به صورت low/high DWORD |
| `0x20` | شروع آرایهٔ A؛ هر رکورد ۵ بایت big-endian |
| `0x156a` | شروع آرایهٔ B؛ هر رکورد ۵ بایت big-endian |
| `0x2ab4..0x2ab7` | چهار بایت انتهایی تفسیرنشده |

`0x20 + 1090*5 = 0x156a` و `0x156a + 1090*5 = 0x2ab4`؛ ظرفیت علاوه بر هندسه، در سازندهٔ `0x722bd6` با ثابت `0x442` محدود می‌شود. reader `0x722f00` مقدار را با shift-left هشت‌بیتی می‌سازد؛ writer `0x7100d0` از انتهای خروجی بایت‌های کم‌ارزش را می‌نویسد. نام‌های A/B عمدی‌اند: مدل فعلاً ادعای مشخصات کامل allocation/free-space یا تفسیر همهٔ فیلدها ندارد.

## update و بازگردانیِ مشاهده‌شده

در `0x722e88`:
1. index و دو مقدار قدیمی ذخیره می‌شوند؛ B در `0x10/0x14` و A در `0x18/0x1c`.
2. fence، ثبت `state=2` و fence.
3. نوشتن مقدار جدید A، سپس B.
4. fence، ثبت `state=1` و fence.

در `0x722e3f` فقط اگر state برابر ۲ باشد، مقدارهای ذخیره‌شده به B و سپس A برمی‌گردند؛ پس از fence، state به ۱ می‌رود. caller `0x722b05` نیز شرط state=2 و فراخوانی این مسیر را دارد. state=2 صرفاً «فساد داده» نیست؛ Agent برای آن مسیر rollback دارد. state=1 نیز به تنهایی سلامت یا امکان اجرای بازی را ثابت نمی‌کند.

این **ردیابی استاتیک store/fence است**، نه آزمایش crash، atomicity دیسک، دوام برق یا پروتکل کامل هم‌زمانی. ابزار جدید هیچ‌یک از این storeها را روی فایل اجرا نمی‌کند.

## مشاهده‌گر جدید؛ فقط‌خواندنی و محدود

[shmem_primary_readonly.py](../../shmem_primary_readonly.py) در [shmem_readonly.py](../../shmem_readonly.py) ادغام شد؛ خروجی outer observer اکنون `shmem-bounded-observation-3` است.

- طول دقیق payload، stateهای محدود ۰/۱/۲ و count حداکثر ۱۰۹۰ بررسی می‌شوند.
- در state=2، index باید داخل count باشد؛ مقدارهای saved باید در محدودهٔ ۴۰‌بیتی باشند. این شرط آخر **سیاست محافظه‌کارانهٔ observer** است؛ خود writer Agent در نوشتن ۵ بایت truncate می‌کند و رد چنین مقدارهایی در Agent اثبات نشده است.
- فقط در حافظه شمارش می‌شود که بازگرداندن دو مقدار قبلی چند field را تغییر می‌داد؛ فایل بازسازی‌شده، مقدار رکوردها و saved values صادر نمی‌شوند.
- state ناشناخته/مقدار خارج مدل باعث توقف می‌شود؛ این توقف گواه خراب بودن نصب نیست.
- فیلد `payload_layout_decoded` در outer observer همچنان false است: هندسهٔ این زیرساختار شناخته شده، اما semantics کامل payload نه. `installation_ready` و `coherent_live_snapshot_proven` همواره false باقی مانده‌اند.
- محدودیت‌های قبلیِ فایل صریح `shmem`، سقف ۶۴KiB، دو read، بررسی هویت فایل، عدم scan/network/write همچنان برقرارند. دو read برابر جای قفل Agent یا snapshot سیستم‌عامل را نمی‌گیرد.

فرمان روی **کپی صریح و آفلاین** فایل، نه نصب زنده:

```bash
python shmem_readonly.py --shmem PATH_TO_COPIED_SHMEM
```

## پیشرفت مستقل در ورودی نام قفل

`0x71c325` مسیر ورودی را به `0x712bc9` می‌دهد و خروجی string را در `object+0x0c` ذخیره می‌کند. تابع آماده‌سازی، predicate مسیر rooted را صدا می‌زند؛ مسیر rooted از wrapper `0x67a5d6` به normalizer `0x86398b` می‌رود. مسیر relative ابتدا helper cwd و سپس join `0x50045e → 0x86367d → 0x86398b` را طی می‌کند. import واقعی `GetCurrentDirectoryW` نیز بررسی شد.

normalizer بررسی‌شده separatorهای slash/backslash و مؤلفه‌های `.`/`..` را پردازش می‌کند و slash `/` تولید می‌کند. در پایان، فقط drive letter شکل `X:/` را در بازهٔ A..Z lowercase می‌کند؛ **lowercase کردن تمام مسیر معادل آن نیست**. این تابع normalizer لغوی است، نه اثبات resolution یکسان junction/symlink یا file identity.

هنوز port کامل و سازگار با همهٔ حالت‌های Windows/UNC/encoding و تطبیق با نام نصب واقعی نداریم. استفادهٔ مستقیم از `Path.resolve()` یا `normcase()` به عنوان معادل Agent مجاز فرض نشده است. پژوهش مرحلهٔ قبل دربارهٔ `Global\` + ورودی نام پابرجاست؛ binding واقعی و تعامل mutex روی Windows آزمایش نشده‌اند.

## آزمون و بازتولید

**۳۶۰ آزمون، صفر failure/error/skip**؛ ۲۲ test method تازه نسبت به checkpoint ۳۳۸تایی. [رسید آزمون و hash کد](TEST-RESULTS.json)، [لاگ کامل](ALL-TESTS.log)، [مشاهده‌های صرفاً ساختگی](GENERATED-OBSERVATIONS.json).

موارد تازه شامل endian/order نامتقارن بالای ۳۲ بیت، ظرفیت و آخرین slot، state ناشناخته، index خارج count، saved خارج سیاست ۴۰بیتی، عدم تغییر ورودی/صدور مقادیر، ادغام v4/v5، و mutation تک‌تک anchor/call/branch/import است. داده‌های payload ساختگی‌اند؛ تطبیق کد روی Agent واقعی ثابت جداگانه انجام شده است.

```bash
python agent_primary_payload_audit.py --agent PATH_TO_PINNED_AGENT
SYNTHETIC_NATIVE_DIR=PATH_TO_EXISTING_NATIVE_ORACLES python -B -m unittest discover -s tests -v
```

اجرای تست به oracleهای native قبلاً ساخته‌شده نیاز دارد؛ صفر skip گزارش‌شده مربوط به محیط دارای آن oracleهاست. receiptهای ۳۰۸/۳۱۸/۳۳۸تایی پوشه‌های قبل تاریخی‌اند، نه suite فعلی.

## مانع بعدی برای updater

اکنون مرحله از header به ساختار داخلی و مسیر rollback رسیده است. گام بعدی باید اتصال این رکوردها به تخصیص فضای data و ترتیب append/index publication را مشخص کند؛ سپس طرح writer آزمایشی روی کپی مجزا قابل ارزیابی است. writer واقعی `.build.info`، closure کامل target، snapshot نصب واقعی و آزمایش Windows/crash هنوز اثبات نشده‌اند. این مرحله به اسکن دوبارهٔ payloadها یا دانلود دوبارهٔ fixture نیاز نداشت.
