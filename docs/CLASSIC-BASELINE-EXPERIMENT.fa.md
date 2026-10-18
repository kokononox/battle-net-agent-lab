# نصب پایهٔ آزمایشی Classic بدون ورود حساب

کاربر پس از دریافت نتیجهٔ متادیتا، دانلود/نصب واقعی Classic در Windows VM دورریختنی و جدا از Retail را تأیید کرد. این مرحله فقط ساخت baseline است، نه آزمایش آپدیت از نسخهٔ قدیمی، نه برنامهٔ updater مستقل و نه اثبات سیاست Retail.

## محدودهٔ اجرای یک‌باره

- فقط main push با پیام مجوز دقیق، run_attempt=1 و github-hosted Windows 2025. هیچ dispatch، self-hosted یا دستگاه کاربر؛ هیچ retry mutation و هیچ نصب زمان‌بندی‌شدهٔ تکراری.
- bootstrap موجود با ناشر/امضای Blizzard، کنترل فرایند و listener پیش/پس از درخواست و محیط فاقد credential مخزن حفظ می‌شود. توکن محلی فقط در حافظه است. توکن حساب درخواست نمی‌شود.
- نسخهٔ فعلی EU از HTTPS رسمی پیش از شروع دوباره خوانده می‌شود؛ نسخهٔ مشاهده‌شدهٔ قبلی hardcode نیست. کشف نسخه، نصب دقیق همان build را تضمین نمی‌کند: پس از اعلام completion توسط Agent، فقط `.build.info` نصب تازه با سقف 64KiB بررسی می‌شود؛ mismatch به معنای baseline تأییدنشده است، نه نصب خراب.
- مقصد یک زیرپوشهٔ تازه و خالی با run_id زیر RUNNER_TEMP، روی درایو fixed و بدون reparse در زنجیرهٔ مقصد است. summary اولیهٔ Agent باید خالی باشد. محصول فقط wow_classic_era است. هیچ مسیر واقعی کاربر، Retail، فایل قدیمی، اسکن یا repair/uninstall/update درخواست نمی‌شود.
- پیش از initialization حداقل **40GiB فضای آزاد هم در volume مقصد و هم system volume** لازم است. همین کنترل محل متداول Agent/ProgramData و مقصد TEMP را می‌پوشاند؛ Agent ممکن است از دیگر مکان‌های داخلی استفاده کند و این اثبات همهٔ محل‌های staging نیست. در طول مشاهده اگر هر یک زیر **10GiB** برسد، آزمایش متوقف و پاکسازی فرایندها تلاش می‌شود. این threshold، تضمین اندازهٔ نصب یا محافظ اتمیک در برابر پرشدن دیسک نیست.

## درخواست‌های محلی و فرم

منبع مسیرهای API غیررسمی: bnet-toolbox commit `d4956d9aa3eaa858b1d2606093298c066ec8a2b7`، فایل bnet_toolbox/tools.py. رفتار فرم و مدل‌ها با Battle.Net-Installer commit `3aa2d98d866b393197da0b75d7381b7fff495ad9`، مسیر BNetInstaller/Endpoints/Install/InstallEndpoint.cs و Models بررسی شد؛ پیش‌فرض کشور آمریکا و MonitorPid ساختگی آن کپی نشد. هیچ binary از این ابزارها اجرا نمی‌شود.

بعد از handshake موجود، GET /game باید خالی باشد؛ یک POST /install با محصول Classic و مسیر رسمی EU patch service، و فقط در صورت فرم شناخته‌شده، یک POST /install/wow_classic_era به مقصد تازه ارسال می‌شود. endpoint دستورالعمل Agent از طرح legacy `http://eu.patch.battle.net:1119` استفاده می‌کند؛ این دریافت HTTPS مستقیم ما نیست و رمزنگاری همهٔ ترافیک Agent ادعا نمی‌شود. مسیرهای repair/update/uninstall/hardware/account/session مجاز نیستند. region EU انتخاب آزمایش است، نه کشور یا حساب کاربر.

در form، authentication/min_spec/game_dir باید ساختار شناخته‌شده و error=0 داشته باشند؛ فیلد ناشناخته، EULA یا خطای هر بخش به توقف می‌انجامد. هیچ پذیرش خودکار EULA، جعل country/geo-IP یا دورزدن حداقل سخت‌افزار انجام نمی‌شود. توقف روی فرم به معنی الزام عمومی login یا خرابی نیست. حتی POST اولیه ممکن است متادیتا یا ترافیک فرزند ایجاد کند و جزو مجوز جدید است.

حداکثر 120 مشاهدهٔ GET /game/wow_classic_era با فاصلهٔ 10 ثانیه و پنجرهٔ 20 دقیقه؛ هر درخواست یک‌بار، پاسخ پذیرفته‌شده 64KiB با یک sentinel، timeout I/O ده ثانیه. handshake جداگانه یک درخواست است؛ شمار total_local_requests در گزارش فقط عملیات پس از آن است و حداکثر 124 دارد. کل workflow حداکثر 35 دقیقه دارد. این‌ها سقف سخت ترافیک child نیستند. سقف 64MiB مرحلهٔ متادیتا به نصب تعمیم داده نمی‌شود و جمع catalogue حدود 7.93GiB هم تضمین ترافیک یا حجم نصب نیست.

## نتیجه و ماندگاری

`baseline_agent_complete` فقط یعنی Agent installed و download_complete را true گزارش کرده و هویت build در `.build.info` تازه با snapshot کشف برابر است؛ اثبات صحت تمام فایل‌ها، امکان ورود/اجرای بازی یا موفقیت آپدیت آینده نیست. بازی اجرا نمی‌شود. فرایندهای مشاهده‌شده در finally متوقف می‌شوند؛ تضمین صفر child باقیمانده ادعا نمی‌شود و حذف VM مرز نهایی است.

محتوای بازی یا فایل `.build.info` به artifact، مخزن یا chat صادر نمی‌شود؛ فقط گزارش سخت‌گیرانهٔ enum/Boolean/hash/اندازه و error code عددی منتشر می‌شود. این بدان معناست که نصب baseline با پایان VM **ماندگار نمی‌ماند**. برای آزمایش نسخه‌به‌نسخه، baseline قدیمی معتبر باید در همان آزمایش نهایی در دسترس باشد؛ نگهداری یا آپلود چندگیگی خودکار به این مجوز اضافه نشده است.

nested handshake در گزارش فقط scope راه‌اندازی و `/agent` را توصیف می‌کند؛ false بودن game_download_requested در آن ادعایی دربارهٔ POSTهای بعدی نیست. مجوز و تلاش نصب در فیلدهای outer صریح‌اند. publisher جدا روی Linux فقط گزارش schema-validated و source/run-bound را commit می‌کند؛ هیچ credential نوشتن مخزن در فرایند مشاهده وجود ندارد.
