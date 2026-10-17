# مرحله ۱: خواندن مستقیم از فایل پژوهشی، بدون snapshot

این مرحله محدودیت snapshot در checkpoint `262cab2a7cfed8d66870663219c7e59426ca525e` را در فیکسچر owned Linux برطرف می‌کند. نصب بازی یا Lab ورودی این ابزار نیست.

## مسیر جدید

- `retail_v8_cycle.locked` پس از گرفتن همان flock قبلی، یک lease محدود به root، پردازش و عمر context ثبت می‌کند. خارج از context، روی root دیگر یا پس از خروج، خواندن مستقیم رد می‌شود. منطق transaction/publication عوض نشده است.
- `agent_archive_direct.native` علاوه بر lease، کل layout سخت‌گیرانه و payloadهای پین‌شده V8 را بررسی می‌کند. سپس فقط `data.000` همان root را با O_RDONLY، O_NOFOLLOW و O_NONBLOCK باز می‌کند؛ fstat، regular-file، nlink=1 و هویت فایل با نام موجود تطبیق داده می‌شود.
- descriptor فقط‌خواندنی فایل و descriptor همان lock به child بومی منتقل می‌شوند. child نیز F_GETFL را بررسی و descriptor نوشتنی را رد می‌کند.
- آداپتور CreateFileW دیگر openat مسیر ندارد: برای نام دقیق data.000، descriptor پین‌شده را با Linux dup تکثیر می‌کند. constructor و insertion اصلی روی این handle اجرا می‌شوند. پس «یک create-adapter call» را نباید با اجرای واقعی CreateFileW ویندوز یا یک openat داخلی اشتباه گرفت.
- کد اصلی cache/read چهار خواندن را در همان پردازش انجام می‌دهد. بایت‌ها با pread مستقل از همان inode مقایسه می‌شوند. پیش و پس از child، descriptor، فایل نام‌دار، marker و lock دوباره هویت‌سنجی می‌شوند.
- parser/getter اصلی و کنترل EKey/CKey/BLTE مستقل مثل قبل اجباری‌اند. هیچ کپی آرشیو یا marker اضافه ساخته نمی‌شود.

## ساخت بومی

`research/archive-direct-9824/native/` از harness قبلی درج کش مشتق شده است. همان 31 fragment اصلی Agent 9824 بدون تغییر در آدرس اصلی نگاشت می‌شوند؛ آداپتور سیستم‌عامل و admission driver تغییر کرده‌اند. فرمت receipt جدید `agent-archive-direct-build-1` است تا نتوان oracle قبلی openat را به‌جای آن استفاده کرد.

پروفایل بومی جدید عمداً محدود است: archive=0، offsetهای 480/668، طول 188، حداکثر چهار read، فقط mode=read. driver درخواست نوشتنی و FD نوشتنی را پیش از constructor رد می‌کند. allocator محدود، lockهای داخلی trace-only و سایر محدودیت‌های قبلی همچنان برقرارند.

## آزمون واقعی

117 تست بدون failure/error/skip:

- 73 تست قبلی دوباره اجرا شدند، شامل 9 بازیابی مسیر snapshot برای رگرسیون.
- 24 تست چرخه مستقیم، شامل 9 توقف process با exit=91 و resume موفق.
- 20 تست مرزی direct/lease/FD.

مرزهای جدید شامل نبود lock، root دیگر، lease منقضی، یکسان‌بودن inode واقعی، FD فقط‌خواندنی، رد FD نوشتنی توسط خود native، رد write mode، symlink، hardlink، layout اضافی، آدرس آرشیو دیگر، target خارج از انتهای فایل، خطاهای open/read، EOF موفق ولی ناقص، تغییر درجا و تعویض path حین child، رقابت روی lock و عدم نشت context پس از exception است.

در 9 بازیابی مستقیم، پیش از control_published فقط source دیده شد؛ پس از آن source و target دیده شدند. همه resumeها committed و اجرای بعدی no-op شدند. snapshot_created در تمام gateهای مسیر مستقیم صفر بود. همان 668 بایت prefix+source و indexهای اولیه حفظ شدند.

این نتایج با 814 تست تاریخی جمع نشده‌اند. قطع برق، Windows و build کامل اجرا نشده‌اند.

## بازتولید

از ریشه `downloader/patch_audit_lab` و مسیرهای فیزیکی بدون symlink:

```bash
PYTHONPATH=. python -B research/archive-direct-9824/native/build.py \
  --agent /absolute/Agent.9824.exe --out-new /absolute/new-direct-native
PYTHONPATH=. python -B research/retail-direct-cycle-9824/run_tests.py \
  --prior-owned-cycle /absolute/committed-owned-v7-cycle \
  --real-payload-fixture /absolute/real-insert-probe-fixture \
  --out-new /absolute/new-direct-evidence \
  --bind-oracle /absolute/bind-native/bind_contract_oracle \
  --lookup-oracle /absolute/lookup-native/lookup_merge_oracle \
  --span-oracle /absolute/span-native/span_reader_oracle \
  --insert-oracle /absolute/insert-native/archive_insert_oracle \
  --direct-oracle /absolute/new-direct-native/archive_direct_oracle
```

prior V7 و payload fixture همان ورودی‌های owned checkpointهای قبلی هستند. runner فقط از آن‌ها می‌خواند، دو template و normal جدید می‌سازد و تست‌ها روی کپی‌های موقت اجرا می‌شوند. دوباره فایل Encoding 200MB اسکن یا دانلود نمی‌شود.

## مرز اثبات

این قفل فقط نویسندگان همکاری‌کننده را هماهنگ می‌کند. lease و receipt امضای امنیتی یا دفاع در برابر Python مهاجم نیستند. کنترل هویت، تغییرات آزمایش‌شده را کشف می‌کند؛ مقاومت قطعی در برابر نویسنده غیرهمکار که state/timestamps را جعل و بازگرداند ادعا نمی‌شود.

هرچند فایل این بار واقعاً زنده است، object reader کامل Agent، native BLTE، Windows I/O/SEH، allocator عمومی، eviction/growth و Windows publication همچنان اثبات نشده‌اند. گام بعد ساخت CLI سرتاسری برای همین جفت پین‌شده در workspace جدید است؛ نه تعمیم بی‌مدرک به اپدیتر کامل بازی.
