# تطبیق بنرها و opcodeهای آغاز V2 با باینری موجود

## نتیجهٔ تازه و مرز آن
**هر دو بنر V2 ضبط‌شده در Wow.exe موجود شناسایی شدند، با تفاوت terminator:** روی شبکه newline پایانی دارند؛ در باینری همان متن بدون newline، با NUL پایانی ذخیره شده است. این تطبیق با hash ورودی و آدرس دقیق کنترل شد.

در همان خوشهٔ رشته‌ها، نشانگرهای `NetClient.cpp`، `NetClient::CleanupConnectionInfo`، `NetClient::CertStore::PublicKeyEntry`، `NetClientJoinInfo` و `WowAuthCrypto::Certificate` نیز وجود دارند. این‌ها بافت روشنِ مؤلفهٔ شبکه/گواهی را نشان می‌دهند، اما **تابع مصرف‌کننده، dispatcher یا محل فعال‌سازی رمزنگاری از کد بازیابی نشد**.

این مرحله نه decrypt انجام داد، نه کلید استخراج کرد و نه مسیر CPU/BIOS تا ارسال را مشخص کرد. نام Certificate به‌تنهایی الگوریتم یا کلید نشست را تعیین نمی‌کند.

## منبع و فرض نسخه
مبنای پیام‌های شبکه، گزارش مرحلهٔ `b57ae91fe8ba9827d03be8d1655c3cb2a87df57c` است. بیلد دقیق کلاینت capture از آن مرحله هنوز مستقل تأیید نشده است. وجود بنرهای یکسان در باینری، **سازگاری با خانوادهٔ پروتکل V2** را تقویت می‌کند؛ هویت قطعی فرایند ضبط‌شده، استفادهٔ زنده از همین literal یا یکسان‌بودن بیلد را ثابت نمی‌کند.

Wow.exe با SHA256 `1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a` و wow_loader.dll با SHA256 `c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c` با pinهای قبلی تطبیق دارند. libxell.dll موجود نیز کامل خوانده و hash شد؛ در این اسکریپت hash آن با pin تاریخی جداگانه مقایسه نشده و این محدودیت در inventory آمده است.

## دو آدرس معتبر برای بنرها
همهٔ آدرس‌های این بخش RVA در Wow.exe هستند؛ image base ترجیحی 0x140000000.

| بنر ذخیره‌شده | RVA | terminator باینری |
|---|---|---|
| WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2 | 0x414F098 | NUL |
| WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2 | 0x414F0D0 | NUL |

متن هر کدام 52 بایت است؛ با NUL باینری یا newline شبکه 53 بایت می‌شود. جستجوی اولیهٔ literal کاملِ بنر شبکه با newline نتیجه نداشت؛ پس از بررسی substring، شکل بدون newline شناسایی و بایت‌به‌بایت تأیید شد. **نبود تطبیق در جستجوی اول، نبود بنر در باینری نبود.** محل/روش افزودن newline در کد هنوز تعیین نشده است.

## بافت مؤلفه، نه دسترسی به سورس
چند نشانگر مجاور:
- RVA 0x414F148: `Expected (m_netState == NS_INITIALIZED), got %d`.
- RVA 0x414F178: `Cert store init failed`.
- RVA 0x414F200: نام فایل منبع تعبیه‌شدهٔ `NetClient.cpp`؛ مسیر build-server در گزارش عمومی حذف شد و hash کامل رشته ثبت است.
- RVA 0x414F250: نام نوع `WowAuthCrypto::Certificate` در متن WowGetRawTypeName.
- RVA 0x414F300: نام نوع مرتبط با `NetClient::CertStore::PublicKeyEntry`.
- RVA 0x414F370: نام `PacketPipe_CliSvr.inl` در مسیر تعبیه‌شده.

وجود مسیر تعبیه‌شده به معنی داشتن فایل سورس، PDB منطبق یا آدرس بدنهٔ تابع نیست. مجاورت رشته‌ها dataflow یا مالکیت کد را ثابت نمی‌کند. رشته‌های تنظیمات توسعه/گواهی در این ناحیه به‌عنوان راه استخراج کلید یا راه تغییر تنظیمات پیشنهاد نشدند؛ هیچ تنظیمی تغییر نکرد.

## ارجاع به بنرها چه شد؟
برای دو رشته، تمام بایت‌های متن و NUL، صفحهٔ مجاور `[0x414F000,0x4150000)` و یک صفحهٔ کنترل بررسی شد.

- **ارجاع نحوی RIP-relative به داخل خود دو بنر: صفر** در دامنهٔ scanner بخش‌های اجرایی.
- **اشاره‌گر دارای relocation نوع DIR64 به داخل بنرها: صفر**.
- نمایش دقیق ابتدای بنرها به‌شکل RVA32 یا preferred-VA64 در فایل: صفر.
- یک دیکد RIP احتمالی به جای دیگری از صفحهٔ مجاور وجود دارد؛ مقصد داخل متن `CGAzeriteEmpoweredItem_C` است، نه بنر. این مورد با CFG واقعی اثبات نشده و مصرف‌کنندهٔ V2 نامیده نشد.
- 15 اشاره‌گر DIR64 به صفحهٔ مجاور وجود دارند؛ همه به نام نوع‌های اشیای بازی از خانوادهٔ CG مانند CGObject_C/CGItem_C/CGPlayer_C می‌رسند. آن جدول را جدول handler شبکه معرفی نکردیم.
- کنترل مثبت MOV شناخته‌شدهٔ entry stub در RVA 0x1DA9B4 به global 0x4AD5F38 پیدا شد. دیکد هم‌پوشان آن، یک تابع مستقل دیگر نیست و کنترل مثبت، کامل‌بودن پوشش همهٔ روش‌های آدرس‌دهی را ثابت نمی‌کند.

جستجو، آدرس محاسبه‌شده/رمزشده، ورود pointer از آرگومان، split immediate، کد تغییرکرده یا ماژول‌های خارج از سه فایل موجود را پوشش نمی‌دهد.

## پنج opcode مشاهده‌شده: عدد پیدا شد، handler نه
اعداد مرحلهٔ capture به‌شکل DWORD کامل little-endian در کل فایل‌ها، در همهٔ alignmentها، جستجو شدند:

| opcode | معنای منطبق در مرجع capture | Wow.exe | wow_loader.dll | libxell.dll |
|---|---|---:|---:|---:|
| 0x440001 | AUTH_SESSION | 1 | 0 | 0 |
| 0x440003 | AUTH_CONTINUED_SESSION | 0 | 0 | 0 |
| 0x440005 | ENTER_ENCRYPTED_MODE_ACK | 2 | 0 | 0 |
| 0x4C0000 | AUTH_CHALLENGE | 230 | 5 | 0 |
| 0x4C0004 | ENTER_ENCRYPTED_MODE | 3 | 0 | 0 |

این شمارشِ literal است، نه تعداد call، پیام، handler یا ارجاع معتبر. هیچ‌کدام از 236 تطبیق Wow.exe در بخش executable نیستند. بسیاری در بافت داده‌های 16بیتی/جدول قرار دارند؛ نوع معنایی همهٔ این ساختارها بازسازی نشده است.

تنها تطبیق عددی AUTH_SESSION در RVA 0x487F1FE، alignment برابر 2 نسبت به DWORD دارد و نزدیک اشاره‌گرهای relocation-backed به `ERR_DUEL_REQUESTED` و `ERR_DUEL_CANCELLED` است. بایت و context آن ثبت شد، اما اتصال مستقلی به handler شبکه ندارد؛ مجاورت این عدد را شاهد dispatch احراز هویت نمی‌شماریم.

در loader، دو تطبیق عدد AUTH_CHALLENGE داخل بخش executable هستند. فقط یکی روی مرز immediate چهاربایتی یک دیکد احتمالی قرار می‌گیرد: `xor eax, 0x4c0000` در RVA 0x14995D7. GNU objdump همین opcode را تأیید کرد؛ این فقط تطبیق دستور/عدد است و **نقش پروتکلی، reachability یا ارتباط با پردازش AUTH_CHALLENGE را ثابت نمی‌کند**. برای مورد دوم، مرز immediate متناظر در پنجرهٔ decoder پیدا نشد؛ آن را call site یا opcode شبکه ننامیدیم. سه تطبیق دیگر در داده‌اند، از جمله `.eid`؛ وجود عدد در آن بخش هم به‌تنهایی معنایی ندارد.

نام کامل پنج پیام CMSG_/SMSG_ به‌صورت ASCII/UTF-16LE در سه فایل پیدا نشد. دو متن دارای AUTH_CHALLENGE در Wow.exe، در واقع `AUTH_CHALLENGE_UI_INVALID` و `AUTH_CHALLENGE_FINISHED` هستند و در خوشهٔ نام‌های رویداد UI قرار دارند؛ نام wire opcode محسوب نشدند.

## بازبینی محدود دامپ‌های موجود
دو دامپ کرش قبلی با hashهای ثبت‌شده دوباره فقط برای شش متن مشخص (دو بنر با newline، دو بنر بدون newline و دو نام پیام حالت رمز‌شده) در ASCII و UTF-16LE جستجو شدند. هیچ literal متناظری در بایت‌های فایل پیدا نشد.

این جستجوی محدود، بازسازی همهٔ رشته‌های مجازی از روی rangeهای جداگانهٔ dump، پیدا کردن کد آماده‌شده یا بررسی کل حافظهٔ اصلی نیست؛ از آن نتیجهٔ «رشته هرگز در runtime وجود ندارد» نمی‌گیریم. هیچ جستجوی کلید، ticket یا secret انجام نشد و dump تازه‌ای ایجاد نشد.

## کنترل کیفیت
- verifier مستقل از producer، با regex lookahead همهٔ رشته‌ها و DWORDها را دوباره در بایت‌های اصلی جستجو و section/alignment/context هر تطبیق را کنترل کرد.
- بنرهای نرمال‌شده، hash آن‌ها و رشته‌های source/type مجاور دوباره از فایل خوانده شدند.
- relocationها مستقلاً پیموده شدند و اشاره‌گرهای جدول CG و دو متن ERR_DUEL کنترل شدند.
- حساب displacement سه دیکد RIP (یک مورد صفحهٔ مجاور و دو مورد کنترل، شامل overlap) از بایت‌ها تأیید شد؛ کشف کامل کاندیداهای RIP توسط verifier بازپیاده‌سازی نشده است.
- دستور XOR لودر با decoder دوم تأیید شد؛ هیچ CFG یا dataflow شبکه از آن استخراج نشد.
- جستجوی narrow dump مستقلاً تکرار شد. محدوده و محدودیت هر کنترل در verification.json مشخص است.

## جمع‌بندی و تصمیم
**اضافه شد:** دو آدرس دقیقِ بنر V2 در باینری موجود و بافت نام‌های NetClient/Certificate در اطراف آن‌ها. تفاوت newline/NUL هم روشن شد و جلوی نتیجه‌گیری منفی اشتباه از جستجوی literal کامل را گرفت.

**اضافه نشد:** آدرس تابع پردازش V2، جدول dispatcher معتبر، نقطهٔ واقعی initialize شدن cipher در این باینری، کلید نشست یا decrypt محتوای بعد از ACK. زنجیرهٔ CPU/BIOS → فیلد پیام → serialization → ارسال همچنان حل‌نشده است.

این مسیرِ lookup مستقیم/نحوی را به‌عنوان کشف handler ثبت نمی‌کنیم. ادامهٔ مؤثر نیازمند اتصال معتبر از داده به کد، کد runtime قابل‌انتساب یا نماد منطبق است؛ نه دنبال‌کردن جدول CG یا تکرار همان اسکن با تعداد بیشتری از کلمات. از کاربر اجرای ابزار، تغییر تنظیمات، نصب، capture یا کرش تازه خواسته نشده است.

main و GUI BIOS Path 0.2 دست‌نخورده‌اند. هیچ فایل ورودی اجرا یا patch نشد؛ attach، تغییر protection و خواندن زندهٔ فرایند انجام نشد.

## فایل‌ها و بازتولید

```bash
export INPUT_DIR=/path/to/pinned-binaries
export DUMP_DIR=/path/to/existing-crash-dumps
python3 source/discover.py
# References requires NumPy and Capstone (tested 5.0.9):
python3 source/references.py
python3 source/triage.py
# Verification requires stdlib Python and GNU objdump:
python3 source/verify.py
```

اگر dumpها در DUMP_DIR نباشند، discovery نبود ورودی را ثبت می‌کند و ادعای بررسی آن‌ها ندارد. برای بازتولید همین گزارش، هر دو dump با نام/hash ثبت‌شده لازم‌اند. باینری‌ها و dumpها در بسته/مخزن نیستند. فقط literalهای عمومی برنامه، context کوتاه بایت، hash و یافته‌های محدود ثبت شده‌اند. reference/capture-anchors.json مبنای پنج opcode و بنر شبکه را ثبت می‌کند؛ خود capture و اطلاعات نشست در این بسته نیست.
