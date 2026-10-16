# چرخهٔ واقعیِ تک‌آبجکتی Retail در کپی پژوهشی

> یافتهٔ بعدی: [قرارداد bind اصلی و V8](../bind-contract-9824/README-fa.md). ایندکس V7 چرخهٔ قبلی فقط با CascLib تأیید شده بود؛ parser خود Agent 9824 آن را رد می‌کند. مجموعهٔ تازهٔ V8 در harness اصلی inner-bind پذیرفته شد؛ این Windows I/O یا read-path کامل Agent نیست. نتایج و اعداد پایین تاریخی‌اند؛ suite فعلی ۵۶۳ آزمون است.

> مرحلهٔ بعد: [sequence visibility](../sequence-visibility-9824/README-fa.md) نشان داد در مسیر nonthrowing با helperهای mock، reader ممکن است پس از bind ناموفق صفر برگرداند و cache را جلو ببرد. چرخهٔ این گزارش به آن return متکی نبود و native readback صریح داشت؛ رسیدهای ۴۹۰تایی زیر تاریخی و معتبرند. suite فعلی ۵۲۰ آزمون است.

## نتیجهٔ جدید

از یک storage تازه که **فقط مبدأ واقعی** در آن وجود داشت، پچ واقعی `ZBSDIFF1` اعمال شد، هدف با رابطهٔ رسمی `b:{256K*=z}` دقیقاً encode شد، در انتهای archive اضافه شد و سپس با sequence ایندکس منتشر شد. خوانندهٔ مستقل مبتنی بر توابع واقعی CascLib، مبدأ و هدف را با EKey کامل و CKey بازخوانی کرد. اجرای دوباره پس از تکمیل، هیچ فایلی را تغییر نداد.

**۴۹۰ آزمون؛ صفر failure/error/skip** در اجرای مستند: ۴۵۳ آزمون قبلی + ۳۷ آزمون جدید. علاوه بر suite، آزمایش بازتولیدپذیرِ جدا در ۹ نقطهٔ مشخص subprocess را با `os._exit(91)` متوقف کرد؛ هر ۹ مورد پس از راه‌اندازی دوباره به نتیجهٔ معتبر رسیدند. این قطع فرایند است، **نه قطع برق یا اثبات تمام حالت‌های crash**.

این milestone یک مسیر معتبر «مبدأ موجود → پچ → append هدف → انتشار index → resume» را نشان می‌دهد؛ **آپدیتر عمومی، نصب قابل‌اجرای WoW یا activation کامل نیست**.

## چه چیزی واقعاً تغییر کرد؟

| جزء | پیش از چرخه | پس از چرخه |
|---|---|---|
| `data.000` | ۶۶۸ بایت | ۸۵۶ بایت |
| prefix واقعی پژوهشی | ۱۶ هدر ۳۰بایتی | همان ۴۸۰ بایت، بدون تغییر |
| source span | offset=480، size=188 | همان بایت‌ها، بدون تغییر |
| target span | وجود ندارد | offset=668، size=188 |
| indexها | ۱۶ فایل، ۱۷ رکورد | ۱۸ رکورد انتخاب‌شده؛ فایل‌های قدیمی حفظ شده‌اند |
| sequence باکت هدف (۲) | ۱ | ۲ |
| sequence باکت مبدأ (۵) | ۱ | ۱ |
| allocator مدل‌شده | فضای آزاد از ۶۶۸ | فضای آزاد از ۸۵۶ |

فایل جدید هدف `0200000002.idx` است. انتخاب از **sequence داخل control** انجام می‌شود، نه از بیشترین نام فایل. آزمایش orphan نشان داد حتی با وجود این نامِ جدیدتر، control با sequence=1 هنوز هدف را قابل مشاهده نمی‌کند؛ writer هم فایل بدون journal متعلق به خود را تصاحب یا overwrite نمی‌کند.

- source EKey: `914fcad4f4fcf4abb0ba52b197bb066f`
- source CKey مشتق‌شده: `98ad7b81687304aa0e99cf326200adfe`؛ این مقدار انتظار مستقل از Encoding نیست.
- patch EKey: `5b933d49c411cc964fe009a18d6c2af9`؛ پچ ۱۱۷ بایت.
- target CKey از متادیتای مستقل Encoding: `3d42bf2e42127f313b0ec64cb440cde9`
- target EKey: `faedca88d0a0ab30dae5519239582d31`
- target encoded SHA256: `73bb9f2ec6c3dba2dbe61d5aa7e5bd4560f0d96c53972adb7472894d4f69b364`
- source و target هرکدام ۱۵۸ بایت encoded و ۳۳٬۹۴۰ بایت decoded دارند.

هویت storage همچنان **مثال مصنوعی** `LAB-PC` و `C:\Games\World of Warcraft\Data` است. مشتق seed با harness مرحلهٔ قبلی مقایسه شد. نام واقعی رایانه، مسیر واقعی نصب و cwd ویندوز کاربر مشاهده نشده‌اند.

## ترتیب و مرز انتشار

۱. بررسی کامل ورودی و storage متعلق به آزمایش؛ قفل همکاری `flock`.
۲. ایجاد **journal اختصاصی آزمایش** با UUID فضای کاری، hash marker و هدف ثابت.
۳. append هدف بدون دست‌زدن به ۶۶۸ بایت اولیه؛ flush و fsync.
۴. نوشتن index موقت؛ انتشار نام بدون overwrite.
۵. bind پژوهشی: بازخوانی native هدفِ staged با EKey/CKey، پیش از تغییر control.
۶. انتشار control جدید با sequence هدف=2؛ بازخوانی و ثبت journal تکمیل‌شده.

۹ مرز توقف: `prepared`، `target_half_appended`، `target_data_synced`، `index_temp_synced`، `index_named`، `index_bound`، `control_temp_synced`، `control_published` و `committed`.

پیش از `control_published`، خواننده فقط مبدأ را مشاهده کرد، حتی وقتی target و index جدید روی دیسک بودند. در دو مرز آخر هدف نیز مشاهده شد. پس از resume همهٔ موارد ۸۵۶ بایت، دو آبجکت معتبر و اجرای دوبارهٔ بی‌تغییر داشتند. ردشدن bind در یک آزمایش جدا، control قدیمی را حفظ کرد؛ retry موفق بود.

## شاهد مستقل و تفاوت با Agent واقعی

- `cycle_oracle.cpp` از `CaptureIndexHeader_V2` و `CaptureGuardedBlock2` واقعیِ CascLib ثابت استفاده می‌کند. انتخاب sequence از control و سیاست هدرهای reserved، **کد پژوهشی ما** هستند؛ این اجرای reader خود Agent نیست.
- wrapper `native_status` علاوه بر انتخاب ۱۶ index، `real_object_oracle` مرحلهٔ قبل را برای source و سپس target فراخوانی می‌کند؛ آن ابزار parser واقعی هدر CascLib و کنترل‌های مستقل span، chunk، EKey و CKey را دارد. این `CascOpenStorage` کامل نیست.
- بایت‌های مسیر publication در Agent 9824 دوباره بررسی شدند؛ این شاهد استاتیک است، نه runtime ویندوز.
- انتشار index در این نمونه با **Linux `renameat2(RENAME_NOREPLACE)`** انجام می‌شود، نه اجرای `MoveFileExW`. نسخهٔ اولیهٔ توسعه با hardlink با شرط ایمنی `st_nlink==1` ناسازگار بود؛ پیش از اجرای موفق و suite نهایی به rename بدون overwrite تغییر کرد. fallback مبتنی بر hardlink نداریم.
- control با **تعویض اتمیک کل فایل پژوهشی** منتشر می‌شود؛ این همان store یک DWORD در header Agent نیست و atomicity چندباکتی/دوام Agent را اثبات نمی‌کند.
- journal و `flock` اختصاصی آزمایش‌اند؛ هیچ ادعایی دربارهٔ journal، mutex، mapping یا recovery واقعی Windows نداریم.
- CLI برای advance ابزار native را اجباری می‌گیرد. API پایین‌سطح `advance` hook اعتبارسنجی قابل تزریق دارد و پیش‌فرض آن فقط بررسی Python است؛ از نتیجهٔ آن به‌تنهایی نباید native verification استنتاج کرد.
- رسید origin امضای ناشر نیست؛ اعتبار ورودی از manifest/hashهای ثابت و بازتولید متادیتای fixture می‌آید. MD5 شناسهٔ TACT است، نه امضای دیجیتال.

## اجرا روی Linux، فقط پوشهٔ تازه

از ریشهٔ `patch_audit_lab` اجرا کنید. به CascLib تمیز در commit `38a34665624b8775bb875274b36191b21c38d97b`، g++، OpenSSL، zlib و native harness مرحلهٔ name-seed نیاز است. build شبکه ندارد. `$TOOLS` باید از قبل پوشهٔ موجود و جداگانه باشد؛ `$NEW_STORE` و `$NEW_EXPERIMENT` نباید وجود داشته باشند. مسیرها را به بازی یا Lab ندهید.

```sh
sh research/retail-update-cycle/native/build.sh "$CASCLIB" "$TOOLS"
python -B retail_update_cycle.py init --fixture "$PORTABLE" --out-new "$NEW_STORE" --isolated-oracle "$NAME_SEED_ORACLE"
python -B retail_update_cycle.py status --root "$NEW_STORE"
python -B retail_update_cycle.py advance --root "$NEW_STORE" --native-object-oracle "$TOOLS/real_object_oracle"
python -B research/retail-update-cycle/run_experiment.py --fixture "$PORTABLE" --out-new "$NEW_EXPERIMENT" --native "$TOOLS" --name-oracle "$NAME_SEED_ORACLE"
```

برای suite کامل، علاوه بر متغیرهای مراحل قبل، `CYCLE_NATIVE_DIR="$TOOLS"` را تنظیم کنید؛ دستور دقیق متغیرها در `TEST-RESULTS.json` آمده است. بدون ورودی‌های صریح، ۳۷ آزمون این مرحله skip می‌شوند؛ در اجرای ثبت‌شده هیچ skip وجود نداشت.

## مدارک

- [خروجی ۹ سناریو، orphan و bind](EXPERIMENT-RESULTS.json)
- [نتیجهٔ ۴۹۰ آزمون و hash کد](TEST-RESULTS.json) · [لاگ کامل](ALL-TESTS.log)
- [رسید build بومی](NATIVE-BUILD-RECEIPT.json)
- [شاهد استاتیک publication در Agent ثابت](AGENT-PUBLICATION-STATIC.json)
- [runner قابل بازتولید](run_experiment.py) · [کد چرخه](../../retail_update_cycle.py)
- [مرحلهٔ قبلی name-seed](../name-seed-9824/README-fa.md)

## مرز بعدی

هنوز فقط یک گزینهٔ پچ، یک archive، یک نسخهٔ index تازه، control محدود v5 و هویت ASCII مصنوعی پشتیبانی می‌شود. next-cycle عمومی، چندباکتی، rollover، Unicode، نصب واقعی Windows، فایل‌های root/install/download، مجموعهٔ کامل build و `.build.info` پیاده/اثبات نشده‌اند. crash بین هر دستور، هنگام fsync یا rename، خرابی دیسک، قطع برق و نویسندهٔ غیرهمکار پوشش داده نشده‌اند؛ فایل موقت ناشناخته عمداً fail-closed می‌شود، نه پاکسازی خودکار.

گام بعد بررسی قرارداد واقعی control/visibility و activation کامل در کپی Windowsِ جداست؛ این fixture کوچک نصب WoW نیست و نباید صرفاً با تعویض `.build.info` آن را نصب معتبر معرفی کرد. اصل Portable، Release، بازی و Lab در این مرحله تغییر نکردند؛ دانلود یا اسکن مجدد payloadها انجام نشد.
