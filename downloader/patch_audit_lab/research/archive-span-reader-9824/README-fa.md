# هدر آرشیو و آدرس‌دهی اصلی Agent؛ پل پژوهشی به آرشیوهای شماره‌دار

> مرحلهٔ بعد، خواندن اصلی: [archive-io-9824](../archive-io-9824/README-fa.md) مسیر اصلی انتخاب بازه/آرشیو تا ReadFile تطبیق‌یافته به Linux pread64 را اجرا کرده است؛ open/cache هنوز adapter است. خوانندهٔ اصلی شمارهٔ ۱۰۲۳ را رد می‌کند؛ پذیرش آن در getter خالص این گزارش به معنی پذیرش کل reader نبود. suite تازه ۷۵۳ آزمون/صفر skip است؛ نتایج این checkpoint تاریخی حفظ شده‌اند.

## نتیجهٔ قابل اتکا

**تابع اصلی بررسی هدر ۳۰بایتی و دو getter اصلی شمارهٔ آرشیو/offset payload اجرا شدند؛ نه مدل جایگزین آن‌ها.** پنج تابع خالص بدون تغییر، با ۱۲۹۳ بایت کد و ۲۲۰ بایت دادهٔ فقط‌خواندنی، در Linux i386 آزمایش شدند. این harness هیچ helper شبیه‌سازی‌شده ندارد؛ checksum و hash نیز همان توابع اصلی‌اند.

خروجی lookup اصلیِ checkpoint قبلی، در driver پژوهشی به این parser/getterها و سپس reader مستقل Python وصل شد. source و target واقعی در کپی‌های کوچک با شماره‌های **۰، ۳، ۴ و ۱۰۲۳** بازخوانی و EKey، دو checksum، BLTE و CKey تأیید شدند. این چهار کپی، **fixture هدر/آبجکت با prefix صفر** هستند، نه storage کامل چندآرشیوی یا نصب آماده. قرار دادن توابع در یک زنجیره کار driver ماست؛ caller کامل Agent و بازکردن/خواندن فایل با Agent اجرا نشده‌اند.

گیت تازه در `retail_span_cycle.py`، علاوه بر bind و lookup اصلی، تأیید اصلی هدر و آدرس را نیز قبل و بعد از انتشار و در اجرای تکراری الزام می‌کند. تمام **۹ توقف سخت subprocess و ادامه** موفق بودند. تزریق یک بیت خراب به ورودی parser هدف، موجب رد واقعی تابع اصلی شد؛ caller پژوهشی control قدیمی و journal آماده را حفظ کرد و پس از برداشتن تزریق ادامه موفق شد.

**۶۹۶ آزمون، صفر failure/error/skip**؛ ۵۰ آزمون تازه. ماتریس جداگانهٔ **۲۶۳۱ بردار** با مدل مطابق بود: ۵۵۵ پذیرش و ۲۰۷۶ رد. هر ۲۴۰ خرابی تک‌بیتی هدر سالم رد شد.

## دقیقاً چه چیزی اجرا شد؟

| تابع | بازهٔ VA، انتهای انحصاری | نقش |
| --- | --- | --- |
| hash1 | `0x72345c–0x723848` | hash اصلی ۳۲بیتی |
| checksum | `0x713c27–0x713c8c` | کنترل checksum وابسته به موقعیت |
| parse_span | `0x713c8c–0x713d2a` | بررسی هدر و ساخت رکورد ۴۰بایتی |
| archive_number | `0x700696–0x7006a4` | `address >> 30`، خروجی ۶۴بیتی |
| payload_offset | `0x7006a4–0x7006b4` | `(address & 0x3fffffff) + 30` |

۳ جدول پرش hash در مجموع ۱۵۶ بایت و جدول checksum شانزده‌تایی ۶۴ بایت‌اند. دو call مستقیم parser به checksum و hash بررسی شدند؛ helper یا call غیرمستقیم وجود ندارد. بایت‌های ELF با PE ثابت مقایسه شده‌اند؛ ورودی با mprotect فقط‌خواندنی است، stack غیرقابل‌اجرا و هیچ segment همزمان writable/executable نیست. رسید شامل SHA256 کد و binary محلی است؛ این رسید **امضای دیجیتال یا تضمین ضد دست‌کاری مهاجم نیست**.

PE همان Agent 9824 با SHA256 زیر است؛ کل فایل اجرایی اجرا یا به مخزن اضافه نشد:

```text
b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5
```

## نکتهٔ مهم: parser هدر با validator کامل آبجکت فرق دارد

در همین تابع اصلی، فقط داشتن حداقل ۳۰ بایت، checksum موقعیت، hash هدر و flag برابر صفر یا یک کنترل می‌شود. سپس key از ترتیب معکوس برگردانده، اندازهٔ LE32 خوانده و نشانی **ارسالی caller** در رکورد ذخیره می‌شود. این نشانی از محتوای هدر کشف نمی‌شود.

آزمون‌های native نشان دادند:

- مقدار available=30 برای پذیرش یک هدر سالم با اندازهٔ اعلامی ۱۸۸ کافی است؛ تابع، وجود کل span یا سلامت payload را اثبات نمی‌کند.
- اندازه‌های اعلامی صفر یا `0xffffffff`، و byte21 غیرصفر، با checksumهای بازساخته‌شده می‌توانند در parser پذیرفته شوند.
- flag=1 در parser معتبر است، ولی reader آبجکت دادهٔ ما فقط flag=0 را می‌پذیرد؛ flag=1 مربوط به مصرف عادی داده فرض نمی‌شود.
- checksum موقعیت تنها بخش ۳۲بیتی نشانی را مصرف می‌کند. همان هدر در نشانی با اختلاف `1<<32` نیز می‌تواند معتبر بماند؛ getter شمارهٔ جدید را برمی‌گرداند. **بنابراین هدر به‌تنهایی شمارهٔ آرشیو یا هویت نصب را احراز نمی‌کند.**

این‌ها قرارداد مشاهده‌شدهٔ یک تابع خالص‌اند، نه ادعای آسیب‌پذیری یا نبود کنترل در لایه‌های بالاتر Battle.net. reader مستقل ما همچنان کلید کامل، اندازهٔ مورد انتظار، flag/byte رزروشده، مرز segment، فایل صریح متناظر، payload و CKey را کنترل می‌کند. هیچ fallback به آرشیو دیگر یا جست‌وجوی خودکار فایل وجود ندارد.

## نمونهٔ واقعی و آدرس‌های غیرصفر

برای هر چهار شمارهٔ آرشیو، رکورد V8 با `base=(archive<<30)+offset` ساخته شد. **lookup اصلی** همان base و span را برگرداند. parser اصلی هدر را بررسی کرد؛ getter اصلی شمارهٔ آرشیو و payload offset را برگرداند؛ سپس Python از فایل صریح `data.NNN` خواند و مستقل decode کرد. نام فایل و عملیات فایل‌خوانی سیاست adapter ما هستند، نه خروجی تابع open اصلی Agent.

| آبجکت | offset هدر در فایل | offset payload برگشتی | span / encoded / decoded |
| --- | --- | --- | --- |
| source | ۴۸۰ | ۵۱۰ | ۱۸۸ / ۱۵۸ / ۳۳۹۴۰ |
| target | ۶۶۸ | ۶۹۸ | ۱۸۸ / ۱۵۸ / ۳۳۹۴۰ |

EKey هدف `faedca88d0a0ab30dae5519239582d31` و CKey مستقل Encoding هدف `3d42bf2e42127f313b0ec64cb440cde9` است. CKey مبدأ `98ad7b81687304aa0e99cf326200adfe` **محاسبه‌شده از decode** است، نه expected مستقل. این مرحله پچ یا payload جدیدی دانلود نکرد؛ encodedهای ۱۵۸بایتی پیش‌تر اثبات‌شده دوباره استفاده شدند.

نسخهٔ اصلی تک‌آرشیوی مرحلهٔ قبل تغییر نکرد؛ SHA256 آرشیو ۸۵۶بایتی آن:

```text
0bc16095b26bc8d1e0c8d3aaba86502e9938f932ccf093e0c135531f1f2861b1
```

## چرخه و recovery

ورودی جدید سه oracle را الزام می‌کند: bind، lookup و span. base cycle و gate lookup قبلی تغییر نکردند. گیت اضافه زیر همان قفل پژوهشی پایه اجرا می‌شود. در ورودی source، payload offset اصلی ۵۱۰ و در target مقدار ۶۹۸ است. عدم وجود oracle، hash نامعتبر، کلید/اندازهٔ ناهماهنگ، هدر خراب، فایل کوتاه یا لینک، موجب توقف می‌شود.

در fault experiment **فقط ورودی هدر هدف در مرز parser** تغییر کرد؛ فایل واقعی archive یا index candidate دست‌کاری نشد. false اصلی parser، قبل از انتشار control توسط کد ما رد شد. recovery پس از حذف تزریق با هدر واقعی موفق بود. ۹ توقف، همان نقاط سخت قبلی را می‌آزمایند؛ اجرای تکراری گیت‌ها را دوباره بررسی کرد و هیچ فایل را تغییر نداد. دادهٔ اولیه، prefix و ۱۶ index اولیه و store قبلی حفظ شدند.

این journal، flock و publication همچنان Linux سفارشی‌اند؛ توقف subprocess اثبات قطع برق، Windows lock یا atomicity کل آپدیت نیست.

## بازتولید

دستورها از ریشهٔ package؛ همهٔ outها باید جدید و خارج از بازی/Lab اصلی باشند:

```bash
PYTHONPATH=. python -B research/archive-span-reader-9824/native/build.py \
  --agent /path/to/pinned-Agent.9824.exe --out-new ./NEW-SPAN-NATIVE

PYTHONPATH=. python -B research/archive-span-reader-9824/run_experiments.py \
  --span-oracle ./NEW-SPAN-NATIVE/span_reader_oracle \
  --lookup-oracle /path/to/lookup-native/lookup_merge_oracle \
  --prior-owned-store /path/to/completed-lookup-research-store \
  --out-new ./NEW-SPAN-EXPERIMENT

PYTHONPATH=. python -B research/archive-span-reader-9824/run_cycle_experiments.py \
  --prior-owned-cycle /path/to/completed-v7-research-cycle \
  --bind-oracle /path/to/bind-native/bind_contract_oracle \
  --lookup-oracle /path/to/lookup-native/lookup_merge_oracle \
  --span-oracle ./NEW-SPAN-NATIVE/span_reader_oracle \
  --out-new ./NEW-SPAN-CYCLE
```

برای suite کامل، متغیرهای checkpoint قبلی را نگه دارید و `SPAN_READER_ORACLE` و `SPAN_PRIOR_STORE` را هم تنظیم کنید؛ دومی completed owned lookup store است. نبود ورودی در محیط دیگر باعث skip می‌شود؛ **اجرای ثبت‌شدهٔ این گزارش صفر skip داشت**.

مدارک: `FRAGMENT-BUILD-RECEIPT.json`، `EXPERIMENT-RESULTS.json`، `CYCLE-EXPERIMENT.json`، `TEST-RESULTS.json` و `ALL-TESTS.log`. فقط source، disassembly متنی و رسیدها منتشر می‌شوند؛ PE، ELF، raw fragment، index یا archive جدید منتشر نمی‌شود. Portable/Release اصلی و بازی/Lab اصلی تغییر نکردند.

## مرز نتیجه و قدم بعد

**پل ایندکس → lookup اصلی → parser/checksum و آدرس اصلی → reader مستقلِ تأییدشده اکنون آزمایش شده است.** reader مستقل همچنان فایل را می‌خواند و BLTE را decode می‌کند؛ نه Agent. این proof آماده‌بودن updater یا نصب کامل چندآرشیوی نیست.

قدم بعد باید مسیر اصلی object-read و archive-open/map/read را در callerهای مرتبط جدا و اجرا کند، نه صرفاً getterها را. شواهد استاتیک پیشین برای `0x7006b4 → 0x711307` و caller خواندن هدر در `0x7012ad → 0x713c8c` نقطهٔ شروع‌اند؛ این callerها در harness این مرحله اجرا نشده‌اند. Windows mapping/locking/publication، نصب واقعی، activation، Unicode و heap/مسیرهای بزرگ همچنان باز هستند؛ writer پژوهشی را به نصب اصلی متصل نکنید.
