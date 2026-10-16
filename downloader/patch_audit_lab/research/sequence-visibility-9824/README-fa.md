# Sequence visibility: آزمایش چهار تابع اصلی Agent با I/O شبیه‌سازی‌شده

## نتیجهٔ تعیین‌کننده

**صفرِ بازگشتیِ reader و برابری cache با header، به‌تنهایی اثبات موفقیت bind نیستند.** در مسیر محدود و nonthrowing بررسی‌شده، اگر open موفق و bind ناموفق باشد، reader ابتدا cache را جلو می‌برد، خطا را به logger می‌فرستد، اما از متغیر دیگری صفر برمی‌گرداند. فراخوانی فوری بعدی به‌علت برابری sequenceها open/bind را تکرار نمی‌کند.

این صرفاً حدس از disassembly نیست: چهار تابع اصلی Agent 9824، مجموع **۸۵۷ بایت بدون تغییر**، در ELF محدود Linux i386 اجرا و با مدل مقایسه شدند. **۱٬۴۴۰ بردار** تمام ۱۶ باکت، سه نوع فراخوانی، شش mode و پنج رابطهٔ unsigned sequence را پوشش دادند؛ helper errorها deterministic تزریق شدند. همه مطابق مدل بودند. ۱۵ سناریوی مشخص نیز جدا ثبت شده‌اند.

**۵۲۰ آزمون؛ صفر failure/error/skip**: ۴۹۰ آزمون قبلی + ۳۰ آزمون جدید. بازخوانی مستقل source و target نمونهٔ واقعی مرحلهٔ قبلی، فقط‌خواندنی دوباره موفق شد.

**حد مهم:** helperهای فایل، bind، logging، serializer و frame/SEH جایگزین پژوهشی هستند. خود Agent.exe، APIهای Windows و bind واقعی Agent اجرا نشده‌اند. این نتیجه اثبات خرابی نسخهٔ نصب‌شده، وقوع این خطا در محصول، یا نبودِ handling در لایه‌های بالاتر نیست.

## یافته‌ها

| وضعیت تزریقی | return | header | cache | نتیجهٔ محدود |
|---|---:|---|---|---|
| writer موفق، header/cache=1 و خروجی helper=2 | ۰ | ۲ | ۲ | هنگام bind، cache=2 ولی header هنوز 1 است |
| writer: خطای ساخت نام، serialize یا flush | کد خطای mock | ۱ | ۱ | bind فراخوانی نمی‌شود |
| writer: bind خطا می‌دهد | کد خطای mock | ۱ | ۲ | header منتشر نمی‌شود؛ cache جلو افتاده است |
| reader: cache<header، open و bind موفق | ۰ | ثابت | برابر header | نام‌ساز همان sequence header را دریافت می‌کند |
| reader: open خطا می‌دهد | خروجی error-converter mock | ثابت | قدیمی | bind فراخوانی نمی‌شود |
| reader: open موفق و bind خطادار | **۰** | ثابت | برابر header | خطا log می‌شود، return صفر است |
| reader دوباره، پس از ردیف قبل | **۰** | ثابت | برابر header | open و bind تکرار نمی‌شوند |
| reader: cache>header با مقایسهٔ unsigned | ۱ | ثابت | قدیمی | مسیر خطا؛ فایل باز نمی‌شود |
| reader: cache=header یا mode در ۲/۴/۵ | ۰ | ثابت | ثابت | refresh رد می‌شود؛ صفر به معنی bind جدید نیست |

عدد ۷۳ در آزمایش‌ها فقط یک error token مصنوعی است، **نه تفسیر یک کد خطای واقعی Windows**. نتیجهٔ error-converter و تولید sequence بعدی نیز mock هستند؛ الگوریتم increment/wraparound واقعی از این آزمایش استنتاج نمی‌شود. mode شیء runtime است، نه شمارهٔ نسخهٔ پروتکل control.

## چرا reader صفر برمی‌گرداند؟

در تابع `0x71ec75`:

- `0x71ed11`: متغیر EBX صفر می‌شود.
- `0x71ed5a`: cache پیش از bind به مقدار header تغییر می‌کند.
- `0x71ed8e`: bind فراخوانی می‌شود؛ نتیجه در ESI قرار می‌گیرد.
- در خطای bind، شاخهٔ logging اجرا می‌شود.
- `0x71edcd`: مقدار **EBX** به EAX بازگشتی منتقل می‌شود، نه ESI.

در مقابل، orchestrator نویسنده در `0x71e9b7` از **ESI** برمی‌گردد و caller `0x71c119` فقط در نتیجهٔ صفر، DWORD مربوط به sequence را در `control+0x110+4*bucket` می‌نویسد. [رسید بایت/فراخوانی](CONTROL-FLOW-NOTES.json).

این نتیجه به رفتار helperهای **برگشت‌پذیر و nonthrowing** محدود است. exception، SEH واقعی، توقف در logger یا بازیابی لایهٔ بالاتر خارج از این آزمایش‌اند.

## مرز دقیق اجرای کد اصلی

| تابع اصلی | بازه، انتهای انحصاری | بایت |
|---|---|---:|
| caller انتشار header | `0x71c119..0x71c18e` | ۱۱۷ |
| wrapper خوانندهٔ header | `0x71c555..0x71c59d` | ۷۲ |
| orchestrator نویسنده | `0x71e887..0x71e9c1` | ۳۱۴ |
| refresh خواننده | `0x71ec75..0x71edd7` | ۳۵۴ |

این چهار تابع همان بایت‌های PE ثابت‌اند و VA اصلی حفظ شده است. هر fragment در ELF نهایی hash-check شد. ۳۰ callsite مستقیم بررسی شدند: ۲ فراخوانی بین توابع اصلی و ۲۸ فراخوانی به ۱۷ مقصد stub. هیچ callsite غیرمستقیم یا مقصد ناشناخته در این بازه‌ها پذیرفته نمی‌شود.

Stubها عملیات واقعی فایل/rename/flush/bind را انجام نمی‌دهند؛ خروجی‌ها صریح‌اند و ترتیب/پارامترهای فراخوانی را ثبت می‌کنند. frame helper فقط قرارداد stack موردنیاز مسیرهای معمول را برقرار می‌کند؛ SEH، FS/TLS و unwinding ویندوز را اجرا نمی‌کند. حالت داخلی helper خواننده روی ۱ ثابت است و open-flags=6 مسیر این fixture را می‌آزماییم؛ همهٔ حالت‌های API فایل پوشش داده نشده‌اند.

Canaryها تمام ۸۱۹۲ بایت object/control مصنوعی را، جز DWORD انتخاب‌شدهٔ header و cache، بررسی می‌کنند. این canary حافظهٔ fixture است، نه اثبات ایمنی حافظهٔ کل Agent. ELF فاقد dynamic linker/imports، segment قابل‌نوشتن و اجرا هم‌زمان و stack اجرایی است. harness فقط stdin/stdout و exit لینوکس را استفاده می‌کند. باینری یا fragment خام منتشر نشده است.

## تأثیر روی طراحی آپدیتر

- **شرط موفقیت را return صفر یا cache==header تعریف نمی‌کنیم.** گیت معتبر باید وضعیت bind و بازخوانی مستقل index/span و EKey/CKey را ثابت کند.
- از جلو رفتن cache نمی‌توان انتشار header یا سلامت target را نتیجه گرفت.
- پس از bind ناموفق، نباید فرض کرد refresh بعدی حتماً دوباره تلاش می‌کند؛ حالت ناموفق باید صریح و fail-closed باشد. این مرحله recovery یا reset واقعی Agent را پیاده نمی‌کند.
- چرخهٔ قبلی قبلاً قبل از publication، native readback صریح داشت و به return reader Agent متکی نبود؛ نتیجهٔ قبلی با این یافته نقض نمی‌شود. [آزمایش قبلی](../retail-update-cycle/README-fa.md).
- موفقیت Windows، visibility بین processها، mutex/mapping، دوام دیسک و activation کامل هنوز ثابت نشده‌اند.

## اجرای بازتولیدپذیر

از ریشهٔ `patch_audit_lab`، روی Linux x86 با پشتیبانی اجرای ELF i386 و ابزارهای binutils. `AGENT` باید همان Agent 9824 ثابت با SHA256 زیر باشد:

`b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`

خروجی‌ها باید پوشهٔ تازه باشند؛ به بازی، Lab یا fixture اصلی اشاره نکنید. build و experiment دانلود ندارند.

```sh
PYTHONPATH=. python -B research/sequence-visibility-9824/native/build.py --agent "$AGENT" --out-new "$NEW_NATIVE"
python -B research/sequence-visibility-9824/run_experiments.py --oracle "$NEW_NATIVE/sequence_visibility_oracle" --out-new "$NEW_EXPERIMENT"
SEQUENCE_VISIBILITY_ORACLE="$NEW_NATIVE/sequence_visibility_oracle" python -B -m unittest discover -s tests -p test_sequence_visibility.py -v
```

برای cross-check فقط‌خواندنی نمونهٔ موفق قبلی، به runner گزینه‌های `--cycle-store "$OWNED_CYCLE" --cycle-native "$CYCLE_TOOLS"` را بدهید. این cross-check مستقل از helperهای mock است و به معنی bind واقعی Agent روی فایل نیست.

suite کامل علاوه بر env مراحل قبل به `SEQUENCE_VISIBILITY_ORACLE` نیاز دارد. در نبود harness، ۱۶ تست fragment این مرحله skip می‌شوند؛ در اجرای ثبت‌شده هیچ skip نبود. ۱۴ تست مدل بدون harness قابل اجرا هستند.

## مدارک و ادامه

- [آزمایش ماتریس و ۱۵ سناریو](EXPERIMENT-RESULTS.json)
- [نتیجهٔ ۵۲۰ آزمون](TEST-RESULTS.json) · [لاگ](ALL-TESTS.log)
- [رسید build و call graph](FRAGMENT-BUILD-RECEIPT.json)
- [مدل و مقایسه](../../agent_sequence_visibility.py) · [harness](native/harness.s)
- چهار فایل `.asm` کنار این گزارش، disassembly محدود همین توابع‌اند.

گام بعد شناسایی قرارداد واقعی bind و رفتار لایهٔ بالاتر در خطا، و سپس visibility/قفل‌های Windows در کپی جداست. تا آن زمان این شواهد نباید به writer نصب اصلی یا فعال‌سازی `.build.info` تبدیل شوند. بازی، Lab، Portable و assetهای Release در این مرحله تغییر نکردند؛ source دو مرحلهٔ قبلی هم تغییر نکرده است.
