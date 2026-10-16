# Agent 9824: شواهد ایستای control، sequence و flush

> checkpoint بعدی: [publication، مصرف sequence و قفل‌ها](../publication-static-9824/README-fa.md)، مجموع ۳۱۸ آزمون. این گزارش ۳۰۸تایی برای سابقه حفظ شده است.


## نتیجهٔ این checkpoint

ممیزی خودکار بر باینری واقعیِ hash-pinned اجرا شد: **۲۴ byte anchor، هفت فراخوانی مستقیم و چهار فراخوانی API از import table** تأیید شدند. ممیزی executable را اجرا نمی‌کند. مشاهده‌گر محدود و فقط‌خواندنی `shmem_readonly.py` نیز اضافه شد؛ آزمون آن فقط روی فایل‌های ساختگی است، چون shmem واقعی کاربر در بستهٔ portable وجود ندارد.

**۳۰ آزمون جدید؛ مجموع ۳۰۸ آزمون با صفر failure/error/skip.** این ۳۰ آزمون کنترل ساختار/ایمنی و verifier هستند؛ تحلیل روی باینری واقعی علاوه بر suite اجرا شده و در AGENT-ACTIVATION-STATIC.json ثبت شده است. آزمون‌های قبلی ۲۷۸تایی و ZIP companion منتشرشده snapshot قبلی‌اند و تغییر داده نشده‌اند.

## آنچه اکنون به کد واقعی متصل شده است

### ۱. منشأ pointer نگاشت

مسیر `0x72e265` تابع `0x86c8e5` را با offset صفر و اندازهٔ درخواستی صفر (نگاشت باقی فایل) صدا می‌زند. wrapper از importهای **CreateFileMappingW** و **MapViewOfFile** استفاده می‌کند. سپس `0x86c784` pointer پایهٔ mapping را به شیء خروجی در offset `0x18` منتقل می‌کند؛ bind در `0x71e16c` همان pointer را می‌خواند. بنابراین در این مسیر مشخص، بررسی DWORD نسخه از ابتدای view فایل می‌آید، نه از pointer دلخواه یا payload وسط فایل.

این نتیجه شرط‌های محیط واقعی، نام/هویت فایلِ نصب کاربر و تمام modeهای ممکن را اثبات نمی‌کند. نام فایل کنترل از مسیر سازنده با رشتهٔ `shmem` ساخته می‌شود؛ protocol کنترل با revision خود فایل `.idx` یکی نیست.

### ۲. هندسهٔ سازنده و pointer payload

| فیلد در view کنترل | مشاهدهٔ کد ثابت |
| --- | --- |
| `0x00` | protocol 4 یا 5 در شاخه‌های بررسی‌شده |
| `0x04` | constructor v4: `0x150`؛ v5: `0x154` یا `0x258` |
| `0x08..0x107` | فیلد نام ۲۵۶بایتی؛ مشاهده‌گر محتویات آن را منتشر نمی‌کند |
| `0x108` | اندازهٔ بخش بعدی: `0x2ab8` |
| `0x10c` | offset بخش بعدی: سازندهٔ v4=`0x150`؛ سازندهٔ v5=`0x1000` |
| `0x110..0x14f` | حلقهٔ بازیابی/آغازین، ۱۶ مقدار ۳۲بیتی sequence را اینجا کپی می‌کند |
| `0x150` در v5 | فیلد flag؛ bit پایین، شاخهٔ ویژه‌ای در bind دارد؛ معنی همهٔ bitها بازیابی نشده |

کد bind پس از بررسی‌ها، pointer دوم را `mapping_base + DWORD[0x10c]` قرار می‌دهد. v4 با offset+payload برابر `0x2c08` به اندازهٔ `0x2c10` align می‌شود؛ حالت پایهٔ v5 با `0x3ab8` به `0x4000` align می‌شود. v5 مسیر extension نیز دارد؛ بنابراین 16KiB قانون عمومی همهٔ فایل‌های shmem نیست.

این جدول **قرارداد کامل فایل** نیست. اعتبار hash/binding نصب، layout بخش payload، ساختار آزادسازی فضا و extensionها را از روی این چند فیلد نتیجه نگیرید. سیاست مشاهده‌گر دربارهٔ headerهای شناخته‌شده و NUL-terminated بودن نام، محافظ محدود خود ابزار است؛ به معنی اثبات رد همهٔ موارد دیگر توسط Agent نیست.

### ۳. ترتیب واقعیِ helper flush

در `0x71e887` مسیر ساخت/نوشتن جدول، سپس helper `0x71f1f1` و سپس بستن handle و bind جدول دیده می‌شود. داخل helper:

1. `0x71f21f` به wrapper همگام‌سازی می‌رود؛ wrapper در `0x864dca`، **FlushFileBuffers** را صدا می‌زند.
2. gate خطا پیش از مرحلهٔ rename است؛ موفقیت sync شرط ادامهٔ این مسیر است.
3. sequence بعدی و نام index توسط `0x71f0d3` ساخته می‌شوند؛ نام‌ساز مقدار را bswap می‌کند و پسوند `.idx` می‌گذارد.
4. `0x71f2af` به wrapper تغییر نام می‌رود؛ import واقعی **MoveFileExW** است و در این wrapper **flags=0** ارسال می‌شود.
5. شکست rename، حداکثر سه تلاش با sequenceهای متفاوت دارد؛ موفقیت helper سپس اجازهٔ ادامه به bind جدول را می‌دهد.

این مشاهده به معنی «همهٔ update اتمیک است» نیست. flags=0 در این helper، قرارداد عمومی replace/write-through برای کل update نیست. payload archive، همهٔ lockها، publication سراسری، بازیابی برق و زمان نوشتن `.build.info` هنوز به این زنجیره متصل و اثبات نشده‌اند.

### ۴. چرا «بزرگ‌ترین filename» به‌تنهایی کافی نیست؟

CascLib مرجع برای reader خود بیشینهٔ version filename هر bucket را برمی‌گزیند. Agent در مسیر بررسی‌شده sequenceهای header را هم دارد. هنوز ادعا نمی‌کنیم این جدول در همهٔ حالت‌ها تنها مرجع انتخاب بازی است؛ اما این تفاوت کافی است که writer نباید صرفاً فایل با بزرگ‌ترین شماره را فعال فرض کند.

در fixture ساختگی، sequence=7 و فایل‌های 7 و 8 داده شدند. مشاهده‌گر وجود فایل مرجع 7 و نسخهٔ جدیدتر 8 را جدا گزارش کرد؛ 8 را جای مرجع ننشاند. در fixture بدون فایل 7، وجود 8 نبود مرجع را پنهان نکرد. این آزمونِ رفتار ابزار است، نه trace runtime Agent.

## استفادهٔ توسعه‌دهنده

از ریشهٔ `downloader/patch_audit_lab`:

```sh
python -B agent_activation_audit.py --agent /path/to/Agent.9824.exe
python -B shmem_readonly.py --shmem /path/to/copied/shmem --index-name 0000000007.idx
```

اولی فقط exe با SHA256 ثابت پژوهش را می‌پذیرد و JSON چاپ می‌کند. دومی فقط فایل صریحی با نام `shmem` را، حداکثر 64KiB، دوبار می‌خواند؛ archive یا index payload را باز نمی‌کند، directory scan ندارد، شبکه و نوشتن ندارد. نام index اختیاری و فقط inventory نام‌هاست؛ خواندن فایل index صورت نمی‌گیرد. symlink/reparse/hardlink رد می‌شوند.

دو خواندن یکسان و fingerprint ثابت، snapshot هماهنگِ یک Agent درحال اجرا را ثابت نمی‌کند؛ mapped write ممکن است mtime قابل‌اتکایی نداشته باشد. خروجی همواره `coherent_live_snapshot_proven=false`، `sequence_is_active_for_game_proven=false` و `installation_ready=false` دارد. این ابزار را health check یا اجازهٔ نصب معرفی نکنید. فعلاً اجرای جدیدی از طرف کاربر درخواست نشده است.

## مرز کار و ادامه

همهٔ شواهد تازه روی Agent ثابت و داده‌های تولیدی به‌دست آمده‌اند؛ اصل ZIP portable، نصب و Lab کاربر تغییر نکردند. **هنوز updater قابل‌استفاده روی بازی نداریم.** گام بعد: استخراج layout و binding بخش payload/extension، دنبال‌کردن publication sequence زیر lock و سپس ارتباط آن با writer واقعی `.build.info`؛ بعد مقایسه با یک snapshot کوچکِ واقعی و کنترل‌شده، نه اسکن دوبارهٔ payloadها.
