# ادامه جلسه: lookup اصلی، درج کش و 9 بازیابی

## وضعیت جدید

بعد از checkpoint `9e3b895b5b515244d7cbc9d0aacda238a2da0c55`، `retail_insert_cycle.py` اضافه شد. این wrapper از همان چرخه strict V8 و journal سفارشی Linux استفاده می‌کند و gate اجباری bind/lookup اصلی → درج/کش اصلی → پارسر هدر اصلی → کنترل Python برای payload واقعی را در status و advance وارد می‌کند.

آدرس read از `lookup_gate_objects.returned_offset` و span از نتیجه واقعی lookup می‌آید؛ policy محدود این fixture همچنان offsets=480/668 و span=188 است. cache در هر gate یک پردازش مشترک برای چهار read دارد. initial source-only است؛ candidate و published شامل source و target هستند.

به cycle هیچ marker اضافه نشد. native read روی snapshot موقت بایت‌به‌بایت برابر با data.000 زیر lock همکاری‌کننده انجام می‌شود؛ نه روی فایل زنده چرخه. تمام ELFها در یک پردازش یکپارچه Agent نیستند. اصل فایل چرخه در gate هویت‌سنجی می‌شود و snapshot پاک می‌شود.

## آزمون واقعی این checkpoint

73 تست بدون failure/error/skip: 49 تست درج قبلی دوباره اجرا شدند و 24 تست جدید چرخه اضافه شد. هر 9 failpoint چرخه در child process با خروج 91 متوقف شد، status درست را نشان داد، با gateهای native بازیابی و committed شد و advance بعدی idempotent بود.

ترتیب visibility در 7 مرحله اول source-only و در control_published/committed شامل target بود. اندازه‌ها: prepared=668، target_half_appended=762، بقیه=856. prefix/source و indexهای اولیه در بازیابی حفظ شدند. یک gate چهار read با یک open و یک constructor داشت.

موارد منفی شامل رد native read/parser، short-read با status صفر، oracle خراب، lock، source و candidate index خراب، و marker اضافی بود. رد candidate مانع control publish شد. رد postpublish پیش از commit نیز در اجرای بعدی درست بازیابی شد؛ این rollback انتشار نیست.

814 تست تاریخی و ماتریس 1024 قدیمی دوباره اجرا نشده‌اند. Windows، قطع برق، reader کامل Agent و آمادگی نصب همچنان اثبات نشده‌اند. بازی اصلی، Lab، Portable و `.build.info` دست‌نخورده‌اند؛ main و Release نیز تغییری ندارند.

## شواهد و ادامه

- `research/retail-insert-cycle-9824/TEST-RESULTS.json`: شمارش و محدودیت‌ها.
- `RECOVERY.json`: نتیجه تک‌تک 9 توقف.
- `INITIAL.json`, `COMMITTED.json`: trace واقعی gate.
- چهار `*-BUILD-RECEIPT.json` و `TESTS.log`.
- `run_experiments.py`: بازتولید در خروجی جدید، با prior V7 پژوهشی committed؛ README روش تهیه prior با Portable تأییدشده را توضیح می‌دهد.

مسیرهای موجود این اجرا (مسیر فیزیکی، چون /data symlink است):

- `/vercel/sandbox/data/lookup-insert-legacy-cycle`: prior committed؛ تغییر ندهید.
- `/vercel/sandbox/data/lookup-insert-final-evidence`: شواهد، template و normal.
- `/vercel/sandbox/data/cycle-bind-native/bind_contract_oracle`
- `/vercel/sandbox/data/cycle-lookup-native/lookup_merge_oracle`
- `/vercel/sandbox/data/retail-span-native/span_reader_oracle`
- `/vercel/sandbox/data/insert-native-final/archive_insert_oracle`

ادامه پیشنهادی: بررسی محدود و مستند مرز snapshot در برابر خواندن مستقیم فایل پژوهشی تحت lock، سپس reader سطح بالاتر. از ادعای Windows publication یا updater آماده، بر پایه نتایج process-exit Linux خودداری شود.
