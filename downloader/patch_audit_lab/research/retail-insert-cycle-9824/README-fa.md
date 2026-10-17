# چرخه V8 با gate اجباری lookup → درج کش → پارسر span

ادامه checkpoint داده واقعی `9e3b895b5b515244d7cbc9d0aacda238a2da0c55`؛ فقط برای پوشه پژوهشی جدید و مستقل. این یک updater قابل استفاده روی نصب اصلی نیست.

## آنچه اضافه شد

`retail_insert_cycle.py` چرخه موجود `retail_v8_cycle` را بدون تغییر منطق publication/journal آن، با یک gate اضافی اجباری می‌پوشاند:

1. bind اصلی فایل‌های index و انتخاب sequence دقیق توسط gate موجود چرخه.
2. lookup/iterator/merge/range اصلی از طریق `retail_lookup_cycle.gate`.
3. مصرف `returned_offset` و `returned_span` همین lookup در خواندن native؛ دیگر ورودی probe صرفاً آدرس مستقل ثابت نیست. محدودیت fixture همچنان بازه‌های شناخته‌شده source/target است و lookup قبلی آن‌ها را با policy کنترل می‌کند.
4. constructor، درج hash table، read و reuse کش اصلی در یک پردازش برای چهار خواندن متوالی؛ نه یک پردازش جدید برای هر read.
5. پارسر هدر و getterهای اصلی آدرس روی بایت‌های برگشتی از read.
6. کنترل مستقل Python برای EKey/CKey، BLTE و SHA-256 payload واقعی.

این ELFهای محدود در پردازش‌های جدا اجرا می‌شوند؛ یک پردازش کامل Agent یا زنجیره یکپارچه داخلی خود Agent نیستند. تنها چهار خواندن مرحله کش در یک پردازش مشترک انجام می‌شود.

## چرا snapshot موقت؟

فیکسچر چرخه V8 layout سخت‌گیرانه دارد و نباید marker مخصوص آزمون درج کش به آن اضافه شود. gate زیر lock همکاری‌کننده چرخه، `data.000` را می‌خواند، با `view['data']` تطبیق می‌دهد و یک snapshot موقت بایت‌به‌بایت در پوشه‌ای جدا می‌سازد. read اصلی روی این snapshot اجرا می‌شود، نه مستقیماً روی فایل زنده چرخه. هویت فایل چرخه پس از native read دوباره کنترل می‌شود و پوشه موقت پاک می‌شود.

بنابراین:

- marker جدید در چرخه، Portable، Lab یا بازی نوشته نمی‌شود.
- read native اثبات‌شده روی snapshot یکسان است؛ نه Windows file handle واقعیِ چرخه.
- این راهکار عامدانه جایگزین ادعای ادغام کامل object reader یا semantics فایل زنده Agent نیست.

## نتیجه اجرا

73 تست، بدون failure/error/skip:

- 31 تست درج/کش مصنوعی قبلی دوباره اجرا شدند.
- 18 تست payload واقعی checkpoint قبلی دوباره اجرا شدند.
- 24 تست جدید چرخه و gate، شامل 9 توقف واقعی child process با exit=91 و بازیابی آن‌ها.

این عدد با 814 تست تاریخی جمع نشده است. ماتریس 1024 سناریویی checkpoint قدیمی مجدداً اجرا نشده است.

در حالت اولیه/منتشرنشده، آدرس‌های خوانده‌شده `[480,480,480,480]` است. در حالت candidate و پس از انتشار، `[480,668,480,668]` است. هر gate چهار read، یک open و یک constructor دارد. referenceها حین read برابر 2 و پس از آن 1 هستند؛ validator payload واقعی آن را الزام می‌کند.

تست مسیر معمول، ترتیب سه gate را مشاهده کرد: current-source، candidate-source+target، published-source+target. رد gate قبل از transaction هیچ تغییری ایجاد نکرد. رد candidate اجازه انتشار control نداد. رد gate پس از publication، journal را prepared باقی گذاشت و اجرای بعدی آن را با gate معتبر committed کرد.

## توقف و بازیابی

| نقطه توقف | اندازه data در توقف | هدف منتشر شده؟ | بازیابی و no-op بعدی |
| --- | --- | --- | --- |
| prepared | 668 | خیر | موفق |
| target_half_appended | 762 | خیر | موفق |
| target_data_synced | 856 | خیر | موفق |
| index_temp_synced | 856 | خیر | موفق |
| index_named | 856 | خیر | موفق |
| index_bound | 856 | خیر | موفق |
| control_temp_synced | 856 | خیر | موفق |
| control_published | 856 | بله | موفق |
| committed | 856 | بله | موفق |

برای تمام 9 حالت، توقف خروجی موفق معمول نداشت و کد خروج دقیقاً 91 بود. پس از توقف، status به visibility واقعی control وفادار ماند؛ وجود فایل index با شماره بالاتر به‌تنهایی target را قابل مشاهده نکرد. پس از resume، هدف committed شد، prefix/source و indexهای اولیه تغییر نکردند و advance بعدی no-op بدون تغییر فایل بود.

تست‌های منفی شامل خطای native read، status=0 با short-read، رد پارسر native، oracle با digest غلط، lock نویسنده همکاری‌کننده، خرابی source، خرابی candidate index و marker اضافی در layout strict است. faultهای gate در تست‌ها صریحاً تزریق شده‌اند؛ آزمایش موفق معمول و 9 بازیابی از oracle واقعی استفاده کرده‌اند.

## بازتولید

چهار oracle را با سازنده‌های ثبت‌شده و `Agent.9824.exe` پین‌شده بسازید. یک چرخه V7 پژوهشی committed با نمونه Portable تأییدشده لازم است. از نصب بازی یا Lab به عنوان ورودی استفاده نکنید. `retail_update_cycle.create` با `name_seed_model.model('LAB-PC', ...)` برای این اجرا استفاده شد؛ هویت واقعی نصب یا اجرای native تابع نام ادعا نمی‌شود. منشأ PA/Encoding قبلاً با Portable تأیید شده است؛ runner دوباره Encoding 200MB را hash نمی‌کند و فقط چرخه strict و payloadهای پین‌شده را کنترل می‌کند.

نمونه ساخت prior با کد بازبینی‌شده، در مسیرهای فیزیکی بدون symlink و خروجی جدید:

```python
from pathlib import Path
import portable_run, source_binding as b
import retail_update_cycle as old
import name_seed_model as names
fixture = Path('/absolute/Portable-Retail-Sample')
proof = portable_run.run(fixture)
w = b.Watch()
source = w.read(fixture / 'source.blte')
patch = w.read(fixture / 'sample.zbsdiff')
origin = {
    'format': 'cycle-portable-input-proof-1',
    'original_fixture_manifest_verified': True,
    'source_full_ekey_verified': proof['source_full_ekey_verified'],
    'patch_hash_verified': proof['patch_hash_verified'],
    'target_ckey': proof['target_ckey'],
    'encoding_proof': proof['encoding_proof'],
    'source_ckey_is_derived_not_independent': True,
}
prior = Path('/absolute/new-owned-v7-cycle')
old.create(prior, source, patch,
           names.model('LAB-PC', r'C:\Games\World of Warcraft\Data'), origin)
old.advance(prior)
w.check()
```

سپس از ریشه `downloader/patch_audit_lab`:

```bash
PYTHONPATH=. python -B research/retail-insert-cycle-9824/run_experiments.py \
  --prior-owned-cycle /absolute/new-owned-v7-cycle \
  --out-new /absolute/new-evidence \
  --bind-oracle /absolute/bind-native/bind_contract_oracle \
  --lookup-oracle /absolute/lookup-native/lookup_merge_oracle \
  --span-oracle /absolute/span-native/span_reader_oracle \
  --insert-oracle /absolute/insert-native/archive_insert_oracle \
  --real-payload-fixture /absolute/real-insert-probe-fixture
```

`--real-payload-fixture` خروجی آماده‌شده checkpoint قبلی `retail_insert_probe.py` است؛ وجود آن هر 73 تست را اجرا می‌کند. بدون آن فقط 24 تست جدید چرخه اجرا می‌شود. runner از prior فقط می‌خواند؛ template و normal و کل نتایج در out-new جدید هستند. تست‌ها از template به پوشه‌های موقت کپی می‌گیرند. رسید هر چهار oracle، خروجی اولیه/committed، log و نتایج 9 بازیابی همراه گزارش نگهداری شده‌اند.

## هنوز اثبات نشده

- Windows، SEH، قفل واقعی Agent، eviction/growth و allocator عمومی.
- برق‌رفتگی، reset سیستم، reorder/cache واقعی دیسک یا journal خود Agent. این آزمایش process-exit در مرزهای مشخص و journal سفارشی Linux است.
- Native BLTE decoder یا اجرای کامل reader سطح‌بالای Agent.
- نصب واقعی، build کامل، انتخاب خودکار source/target دلخواه، یا سازگاری کل Lab کاربر.
- CKey منبع همچنان از decode مشتق شده است و مدرک مستقل دیگری برای آن ایجاد نشده.

قدم پژوهشی بعدی باید مرز snapshot/فایل واقعی و object-reader سطح بالاتر را روشن کند؛ نتایج این مرحله نباید جای اثبات publication ویندوز یا آمادگی نصب استفاده شوند.
