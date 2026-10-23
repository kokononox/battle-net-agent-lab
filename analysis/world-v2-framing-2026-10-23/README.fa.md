# قاب‌بندی V2 و گذار مشاهده‌شده به حالت رمز‌شده

## نتیجهٔ اصلی
در سه اتصال F03/F04/F05، **قاب‌بندی پیام‌های V2 و تبادل فعال‌سازی رمزنگاری با شواهد پروتکلی مشخص پشتیبانی شد**؛ نه با حدس از entropy یا ناخوانابودن بایت‌ها. اکنون مرز خارجی همهٔ 319 پیامِ ثبت‌شده در شش جریان جهت‌دار مشخص است. 12 پیام ابتدایی با opcode آشکار و ساختار محدود احراز هویت تطبیق دارند؛ 307 پیام بعدی tag غیرصفر دارند و محتوای آن‌ها همچنان opaque است.

**هیچ payload رمز‌شده‌ای decrypt نشده، هیچ کلید نشستی استخراج نشده و ارسال CPU/BIOS اثبات نشده است.** نتیجهٔ تازه دربارهٔ framing و تبادل فعال‌سازی حالت است، نه بازیابی منطق جمع‌آوری سخت‌افزار.

## منبع و هویت نسخه
ورودی همان gg.pcapng.gz با SHA256 `a2a64675789826b39995a85cb59ca8e4d9ba03c7d72611ae9924de489b286257` است. بازسازی transport در این مرحله جداگانه انجام شد و hash/طول تمام جریان‌ها با مبنای commit `3d2dfeb13556162b96626c27cddda94bacddaffb` برابر شد. هیچ ضبط تازه‌ای گرفته نشد.

منابع عمومی TrinityCore در commit ثابت `dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae` فقط **مرجع ساختاری قابل‌تطبیق** هستند. از آن‌ها نتیجه نمی‌گیریم سرور ضبط‌شده TrinityCore است یا بیلد دقیق کلاینت حتماً 12.1.5.70448 بوده است. blob SHA1 و SHA256 شش فایل منبع کنترل شد؛ فقط excerptهای مرتبط با انتساب و شمارهٔ خط در `reference/public-sources.json` نگه داشته شدند، نه کل فایل‌های حاوی مثال کلیدهای پروژه.

## قالبی که واقعاً با ضبط سازگار شد
بنر کامل، 53 بایت است و در هر دو جهت پسوند ` - V2\n` دارد:

```text
WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2
WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2
```

پس از بنر، قالب خارجی این است:

```text
uint32 little-endian Size
byte Tag[12]
byte Body[Size]  // چهار بایت اول در حالت آشکار opcode است
```

Size شامل opcode چهار‌بایتی است، ولی شامل header شانزده‌بایتی نیست. مرز پیام بعدی `offset + 16 + Size` است. این مدل، بدون resync، پرش دلخواه یا بایت باقی‌مانده، تمام شش جریان منتخب را تا انتهای بایت‌های ضبط‌شده پیمود. تعریف header و بنر V2 در مرجع عمومی با این ساختار تطبیق دارد.[^https://github.com/TrinityCore/TrinityCore/blob/dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae/src/server/game/Server/WorldSocket.h][^https://github.com/TrinityCore/TrinityCore/blob/dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae/src/server/game/Server/WorldSocket.cpp]

مرز پیام، اندازه و tag حتی در بخش opaque قابل‌ردیابی‌اند؛ **opcode و بدنهٔ آن بخش از چهار بایت تصادفی/رمزشده نام‌گذاری نشده‌اند**.

## توالی آغازین قابل‌تطبیق
مقادیر عددی زیر با opcodeهای مرجع پین‌شده تطبیق دارند؛ این انتساب با طول/شکل بدنه و ترتیب دوطرفه نیز کنترل شد، نه صرف یک عدد.[^https://github.com/TrinityCore/TrinityCore/blob/dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae/src/server/game/Server/Protocol/Opcodes.h]

1. سرور: `0x4C0000`، مطابق SMSG_AUTH_CHALLENGE؛ Size=69 و بدنهٔ بدون opcode برابر 65 بایت است. با 32 بایت DOS challenge، 32 بایت challenge و یک بایت سازگار است.
2. کلاینت F03: `0x440001`، مطابق CMSG_AUTH_SESSION؛ بدنه 913 بایت است. طول ticket ثبت‌شده در فیلد موردانتظار 832 و دقیقاً برابر remainder است. خود ticket، digest و challenge خوانده/تفسیر یا منتشر نشدند.
3. کلاینت F04/F05: `0x440003`، مطابق CMSG_AUTH_CONTINUED_SESSION؛ بدنهٔ 80بایتی با اندازه‌های فیلدهای مرجع سازگار است. این نام پیام به‌تنهایی نقش دقیق یا مقصد نهایی اتصال را ثابت نمی‌کند.
4. سرور: `0x4C0004`، مطابق SMSG_ENTER_ENCRYPTED_MODE؛ Size=73 و بدنهٔ 69بایتی، شامل int32، امضای 64بایتی و یک بایت flags است. بیت Enabled در هر سه اتصال یک و بیت‌های padding صفرند.
5. کلاینت: `0x440005`، مطابق CMSG_ENTER_ENCRYPTED_MODE_ACK؛ Size=4 و بدنهٔ بدون opcode خالی است.
6. پیام‌های بعدی در هر دو جهت tag غیرصفر دارند. در هر شش جریان، پس از این نقطه بازگشت به tag صفر مشاهده نشد.

اندازه‌ها و شکل محدود این پیام‌ها با reader/writerهای احراز هویت مرجع تطبیق دارند. در قالب مرجع، پیام فعال‌سازی **امضا و flag** حمل می‌کند، نه کلید نشست به‌صورت مستقیم؛ نام EncryptionKey در کد منبع را شاهد حضور کلید قابل‌استفاده در packet نمی‌نامیم.[^https://github.com/TrinityCore/TrinityCore/blob/dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae/src/server/game/Server/Packets/AuthenticationPackets.h][^https://github.com/TrinityCore/TrinityCore/blob/dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae/src/server/game/Server/Packets/AuthenticationPackets.cpp]

## مرزهای دقیق در همین ضبط
offsetها صفرمبنا و از شروع TCP application stream، شامل بنر 53بایتی، هستند. این‌ها آدرس حافظه، RVA یا offset فایل pcapng نیستند.

| اتصال | پیام اول کلاینت طبق مرجع | اولین پیام tag غیرصفر کلاینت | اولین پیام tag غیرصفر سرور |
|---|---|---:|---:|
| F03 | AUTH_SESSION | 1006 | 227 |
| F04 | AUTH_CONTINUED_SESSION | 173 | 227 |
| F05 | AUTH_CONTINUED_SESSION | 173 | 227 |

ترتیب مشاهده‌شده در capture برای هر سه اتصال: تکمیل challenge سرور، auth کلاینت، enable سرور و ACK کلاینت است؛ اولین بایت پیام‌های tag غیرصفر پس از مشاهدهٔ ACK است (ممکن است در همان سگمنت پس از ACK قرار بگیرد). زمان/شمارهٔ frame از رسیدن واقعی fragmentهای IP به بایت‌های مربوط محاسبه شد، نه انتساب همهٔ بایت‌های datagram به اولین fragment.

در مرجع، handler مربوط به ACK، cipher را initialize می‌کند؛ رفتار tag در حالت initializeنشده/شده نیز متفاوت است. ترکیب این رفتار با opcode، اندازه، flag فعال و ترتیب دوطرفهٔ مشاهده‌شده، شاهد پروتکلیِ مشخصی برای گذار به حالت رمز‌شده است.[^https://github.com/TrinityCore/TrinityCore/blob/dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae/src/server/game/Server/WorldSocket.cpp][^https://github.com/TrinityCore/TrinityCore/blob/dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae/src/common/Cryptography/Authentication/WorldPacketCrypt.cpp]

**مرز ادعا:** tagهای cryptographic با کلید معتبر verify نشده‌اند. الگوریتم/کلید واقعی همین بیلد به‌طور مستقل از باینری بازسازی نشده و امضای پیام فعال‌سازی نیز verify نشده است. بنابراین ادعا «AEAD با موفقیت باز شد» نیست. صفر/غیرصفر بودن tag به‌تنهایی هم دلیل کافی نبود؛ تبادل مشخص آغاز اتصال مبنای نتیجه است.

## کنترل کیفیت
- بازسازی transport با روشی جدا از اسکریپت مرحلهٔ قبل انجام و hash همهٔ جریان‌های جهت‌دار با مبنای منتشرشده برابر شد؛ IP fragmentation پیش از TCP پردازش شد.
- walker مستقل با int.from_bytes و slicing، مرز/طول/tag/opcode آشکار هر 319 پیام را دوباره کنترل کرد؛ نیاز به pandas یا قالب tabular برای decode این باینری نبود.
- هفت آزمون منفی (بنر نسخهٔ غلط، طول صفر، طول بیش از حد، header/body ناقص، opcode challenge غلط و Enabled خاموش) رد شدند. این‌ها fuzzing جامع یا اثبات امنیت parser نیستند.
- شماره‌های opcode برای هیچ‌یک از 307 پیام opaque تفسیر نشدند. None در ستون opcode/name برای این پیام‌ها **عمدی** است؛ مقدار صفر یا دادهٔ گم‌شدهٔ تصادفی نیست و fill نشد.
- خروجی message-boundaries.csv یک ردیف به ازای پیام خارجی دارد؛ نه یک ردیف به ازای packet شبکه. چند پیام می‌توانند در یک TCP segment باشند یا یک پیام در چند segment/fragment پخش شود.
- سنجه‌ها برای اندازه و قاب‌بندی‌اند؛ chart حجم/زمان‌بندی نمی‌تواند مقدار فیلد سخت‌افزار را ثابت کند. برای این سؤال پروتکلی نمودار ساخته نشد.

F01/F02 چون آغاز و بنر ندارند، وارد این مدل آغازین نشدند. کامل مصرف‌شدن بایت‌های هر جریان منتخب به معنی پوشش کل عمر نشست یا تفسیر کامل پیام‌ها نیست.

## تصمیم ادامه
ابهام مرحلهٔ قبل محدودتر شد: اکنون صرفاً با «چند بایت باینری نامشخص» روبه‌رو نیستیم؛ آغاز V2، توالی احراز هویت، فرمان enable/ACK و مرز پیام‌های بعدی مشخص‌اند. بااین‌حال برای نسبت‌دادن محتوای پس از گذار به CPU/BIOS به plaintext/schema معتبر یا وضعیت نشست منطبق نیاز است. کلید، ticket یا secret از این بسته استخراج نشد و کلیدهای نمونهٔ پروژهٔ عمومی، کلید همین نشست فرض نشدند.

**گام بعدی پیشنهادی:** تطبیق محدود همین opcodeها و ساختار V2 با باینری ثابت پروژه، برای مشخص‌کردن نقطهٔ پردازش پیام/ورود به حالت؛ نه تکرار ضبط، حدس‌زدن opcode از ciphertext یا وعدهٔ دیکد بدون کلید. این گزارش آن تطبیق باینری را انجام‌شده نمی‌نامد. فعلاً از کاربر نصب، capture یا کرش تازه لازم نیست.

main و GUI BIOS Path 0.2 تغییر نکردند. هیچ ورودی اجرا، patch، attach یا protection تغییر داده نشد.

## فایل‌ها، حریم داده و بازتولید
گزارش، CSV مرزها، سورس خواننده و excerptهای عمومی در بسته‌اند. capture، جریان‌های خام، IP/MAC، ticket، digest، challenge، signature و tagهای واقعی منتشر نشده‌اند؛ work محلی در بسته/مخزن نیست.

```bash
python3 -m pip install -r source/requirements.txt
export CAPTURE=/path/to/gg.pcapng.gz
python3 source/reassemble.py
python3 source/frame.py
python3 source/verify.py
```

reference/capture-baseline.json همان مبنای بی‌نامِ مرحلهٔ قبلی است. مرجع عمومی پین‌شده برای انتساب معنای پنج opcode و اندازهٔ فیلدهاست؛ فایل‌های آن اجرا نشدند. excerptها به TrinityCore Project با مجوز GPL-2.0-or-later منتسب‌اند. متن کامل منابع اختیاری در work محلی بررسی شد و به‌جای افزودن کل منبع، URL، blob hash، SHA256 و excerpt مرتبط نگه داشته شد.
