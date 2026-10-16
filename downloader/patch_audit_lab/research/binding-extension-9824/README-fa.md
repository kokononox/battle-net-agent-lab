# Agent 9824: binding نام guard، directory افزونه و اصلاح header

> checkpoint بعدی [payload و ورودی نام](../primary-payload-9824/README-fa.md) هندسهٔ آرایه‌ها و rollback را ردیابی و بخشی از شکاف normalizer را پر می‌کند. مشاهده‌گر جاری نسخهٔ ۳ و suite جاری ۳۶۰ است؛ receiptهای این پوشه تاریخچهٔ ۳۳۸تایی‌اند.


## نتیجه و اصلاح صریح

ممیزی تازه روی Agent hash-pinned: **۳۲ byte anchor، ۹ call، ۷ branch و دو import** تأیید شد. ممیزی publication و mapping قبلی نیز پیش‌شرط اجرا شدند؛ اعداد تازه با شمارنده‌های قبلی جمع نمی‌شوند. **۳۳۸ آزمون با صفر failure/error/skip** شامل ۲۰ test method تازه گذشت؛ یک آزمون قبلی نیز به‌دلیل برداشت اشتباه header اصلاح شد.

**اصلاح checkpoint قبلی:** در سازندهٔ v5، فیلد DWORD در `+0x04` با `0x154` پر می‌شود، *پیش از* `cmovne` که فقط طول copy را در ESI به `0x258` تغییر می‌دهد. آن cmov مقدار ذخیره‌شده در فیلد را تغییر نمی‌دهد. پس `0x258` را نباید به‌عنوان مقدار فیلد headerِ آن سازنده پذیرفت. parser قبلی و آزمون ساختگی پذیرش آن اشتباه بودند؛ آن آزمون شاهدی از فایل واقعی نبود.

`shmem_readonly.py` اکنون فقط فیلد `0x154` را برای محدودهٔ v5 شناخته‌شده می‌پذیرد و **declared_header_field** را از **constructor_copy_bytes** تفکیک می‌کند. JSON خروجی نسخهٔ ۲ دارد و برای سازگاری `header_bytes` را با معنی «مقدار فیلد» نگه می‌دارد. مشاهده‌گر، verifier عمومی همهٔ فرمت‌های CASC نیست.

این محدودسازی سیاست خود مشاهده‌گر بر اساس سازنده‌های بررسی‌شده است؛ اثبات نمی‌کند Agent هر فایل دیگری را رد می‌کند. هیچ فایل واقعی کاربر، fixture اصلی یا Release asset دستکاری نشده است.

## ۱. منبع نام و انتخاب نوع قفل

در مسیر init در `0x71c6cd..0x71c711`:

- `object[0x2c] == 4` یا `5`: low byte آرگومان guard برابر صفر می‌شود؛ شاخهٔ critical section انتخاب می‌شود.
- سایر مقادیر در این مسیر: low byte برابر ۱ باقی می‌ماند؛ شاخهٔ mutex انتخاب می‌شود.
- نام از **control_base + 8** گرفته و به guard در `object+0x70` داده می‌شود.

`0x722378` فقط low byte آرگومان را برای حالت guard مصرف می‌کند. این اعداد، **mode شیء runtime** هستند، نه version DWORD فایل shmem. بنابراین نمی‌توان گفت «protocol v5 یعنی قفل محلی»؛ ارتباط mode ورودی با protocol و نصب واقعی باید جدا ثابت شود.

در `0x71e01f`، نام سازنده به‌صورت هفت بایت literal `Global\`، سپس بایت‌های ورودی و NUL ساخته می‌شود. شرط طول prefix+input حداکثر ۲۵۵ بایت است. در همین تابع hash کردن یا escape دیده نمی‌شود؛ **canonicalization ورودی پیش از رسیدن به این تابع هنوز بازیابی نشده**. از نام نمی‌توان binding رمزنگاری‌شده به build، target یا مسیر نصب را نتیجه گرفت. parser نیز `name_source_binding_proven=false` را نگه می‌دارد و نام را صادر نمی‌کند.

شواهد: `guard-mode-name-binding.asm`، `guard-init.asm`، `constructor-name.asm` و callهای سازندهٔ v4/v5.

## ۲. ساخت یا بازکردن mutex

در helper `0x72221f`، نام پس از عبور از helperهای تبدیل به API ویندوز می‌رسد:

- **CreateMutexW** با initial-owner برابر صفر؛
- در شاخهٔ خطای ۵، **OpenMutexW** با desired-access برابر `0x00100000` و inherit=false؛
- شکست Open با خطای ۲ می‌تواند حلقهٔ create/open را تا سقف پنج بار تکرار کند.

فراخوان‌ها با IAT واقعی تطبیق داده شدند. encoding دقیق ورودیِ helperهای تبدیل، ACL/هویت اجرای نصب واقعی و سازگاری دسترسی handle با همهٔ عملیات بعدی تست نشده‌اند. این helper به‌تنهایی قرارداد امن هم‌زمانی با Agent را به writer مستقل نمی‌دهد؛ Windows اجرا نشده و هیچ mutex واقعی ساخته نشده است.

شواهد: `mutex-create-open.asm` و import receipt.

## ۳. directory افزونهٔ v5

در سازنده، پاک‌کردن bit پایین flags، طول copy را تعیین می‌کند: اگر سایر bitها صفر باشند copy=`0x154`، در غیر این صورت copy=`0x258`؛ فیلد header همچنان `0x154` است. header موقت به طول `0x258` ابتدا zero می‌شود.

تابع `0x71dfb6` در شاخهٔ مشخصی، وقتی flag bit1 و request bit0 برقرار باشند، **slot صفر** را ثبت می‌کند:

| offset نسبت به control | شاهد |
| --- | --- |
| `0x150` | flags؛ bit0 شاخهٔ ویژهٔ bind، bit1 شرط slot0 در مسیر بررسی‌شده |
| `0x154` | bitmap directory؛ bit0 برای slot0 set می‌شود |
| `0x158 + slot*4` | آرایهٔ اندازه؛ slot0=`0x228` |
| `0x1d8 + slot*4` | آرایهٔ offset؛ slot0 پس از align بخش اصلی قرار می‌گیرد |

با هندسهٔ v5 بررسی‌شده، بخش اصلی در `0x1000` به طول `0x2ab8` است؛ align آن `0x4000` می‌شود. slot0 در offset `0x4000` به طول `0x228` قرار می‌گیرد و اندازهٔ فایل سازنده پس از page-align برابر **`0x5000` (۲۰ KiB)** است، نه ۱۶ KiB. وجود flag bit1 لزوماً وجود slot0 را ثابت نمی‌کند؛ request gate هم هست.

consumer تشخیصی `0x71dc3a`، flags bit1 و bitmap bit0 را جدا می‌سنجد، offset slot0 را به base می‌افزاید و helper تشخیص state را صدا می‌زند. آن helper DWORD نخست را برای مقدارهای ۱ یا ۲ می‌شناسد. معنی کامل stateها، سایر فیلدهای `0x228` و layout اصلی `0x2ab8` هنوز استخراج نشده‌اند؛ نام‌گذاری پایدار/قفل‌شده یا تفسیر recovery به آن‌ها نداده‌ایم.

شواهد: `v5-constructor.asm`، `extension-directory.asm`، `extension-diagnostic-consumer.asm` و `extension-diagnostic-state.asm`.

## ۴. رفتار مشاهده‌گر اصلاح‌شده

این ابزار همچنان فقط فایل صریح `shmem` تا ۶۴ KiB را دوبار می‌خواند، symlink/reparse/hardlink را رد می‌کند و شبکه/نوشتن/اسکن directory/خواندن archive ندارد.

- فقط flags شناخته‌شدهٔ ۰..۳ و slot0 را در policy محدود می‌پذیرد؛ ناشناخته‌ها را رد می‌کند، بدون ادعای خراب‌بودن فایل واقعی.
- slot فعال باید اندازهٔ `0x228`، offset شناخته‌شدهٔ `0x4000` و بازهٔ قابل‌خواندن داشته باشد؛ overlap/offset عظیم/truncation رد می‌شوند.
- اندازهٔ واقعی فایل را با اندازهٔ aligned سازنده **مقایسه و گزارش** می‌کند؛ تفاوت به‌تنهایی نصب را خراب اعلام نمی‌کند. داشتن حداقل بایت‌های descriptor برای مشاهده کافی است، نه اثبات فایل کامل.
- payload اصلی و محتوای افزونه را صادر یا decode نمی‌کند؛ فقط شناخته‌شدن state نخست را به‌صورت boolean گزارش می‌کند.
- prefix نام سازنده کنترل می‌شود، اما خود نام، متن تشخیصی و مسیر شخصی صادر نمی‌شوند. این بررسی جای binding واقعی به نصب را نمی‌گیرد.
- `coherent_live_snapshot_proven` و `installation_ready` همواره false می‌مانند.

همهٔ کنترل‌های افزونه **ساختگی**‌اند. گزارش generated قدیمی که فیلد `0x258` را قبول می‌کرد تاریخی و superseded است؛ حذف یا به‌جای شاهد واقعی بازنویسی نشده است.

## بازتولید و مرز کار

```sh
python -B agent_binding_extension_audit.py --agent /path/to/Agent.9824.exe
python -B shmem_readonly.py --shmem /path/to/copied/shmem
SYNTHETIC_NATIVE_DIR=/path/to/native-oracles python -B -m unittest discover -s tests -v
```

ریشهٔ اجرا `downloader/patch_audit_lab` است. ممیزی تنها SHA256 ثابت `b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5` را می‌پذیرد. فایل‌های manifest، receipt، نتایج آزمون و generated observations کنار همین گزارش‌اند. باینری اجرا یا دوباره دانلود نشده است.

اکنون **منبع نام guard و predicate انتخاب mode در یک مسیر ثابت مشخص‌اند**، اما canonicalization نام، binding واقعی نصب/target و mode نصب کاربر هنوز ثابت نیستند. فقط directory و بخشی از مصرف slot0 روشن شده، نه payload کامل یا updater نهایی. ترتیب `.build.info`، full-build closure، آزمایش هم‌زمانی Windows و دوام قطع برق همچنان بازند.

قدم بعدی هدفمند: دنبال‌کردن ورودی canonical نام و مصرف بخش اصلی `0x2ab8`، سپس تطبیق با snapshot واقعی کوچک در زمان مناسب. اسکن میلیون‌ها payload یا تغییر header واقعی برای آزمون لازم یا مجاز نشده است؛ فعلاً کاری از کاربر درخواست نشده است.
