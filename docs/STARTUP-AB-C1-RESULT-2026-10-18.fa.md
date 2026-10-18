# نتیجه مقایسه A/B محدود c1

## نتیجه کوتاه
در یک شروع اجرای ۱۲۰ ثانیه‌ای در هر یک از دو VM مستقل تازه، مسدودسازی فقط telemetry-in.battle.net از طریق hosts با نبود مشاهده اتصال عمومی به نام/آدرس شناخته‌شده همان مقصد همراه بود؛ در عین حال Continue صفحه زبان و process Agent در هر دو حالت مشاهده شد. این یک نتیجه مثبت محدود برای همین مسیر آغاز اجراست، نه تضمین حریم خصوصی و نه تأیید آپدیت بازی.

## شواهد
- run: 39158224605
- source: 200c3d0911fa3b82dd30fd31b6f05279b913132c
- receipt commit: 4a2baf5b178e21997f8726fbac89940ddf6781b2
- reports/startup-ab-c1-baseline-{intervention,network,bootstrap}.json
- reports/startup-ab-c1-block_telemetry-{intervention,network,bootstrap}.json
- محاسبات: reports/startup-ab-c1-evidence.json

| کنترل/مشاهده | عادی | فقط دامنه مسدود |
| --- | --- | --- |
| image ویندوز | 20261007.264.1 | 20261007.264.1 |
| build ویندوز | 26100 | 26100 |
| هش bootstrap با pin برابر | بله | بله |
| فایل Agent کاندیدِ بررسی‌شده | هش مشترک | هش مشترک |
| resolver سیستم برای target در شروع | public_only | loopback_only |
| SNI عمومی telemetry-in.battle.net | مشاهده شد | مشاهده نشد |
| flow عمومی به IP قبلی target | مشاهده شد | مشاهده نشد |
| Continue صفحه زبان | continued | continued |
| process Agent | مشاهده شد | مشاهده شد |
| Install یا ورود یا آپدیت بازی | درخواست نشد | درخواست نشد |
| capture و parser | موفق | موفق |

هش bootstrap در هر دو: de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf.
هش فایل Agent کاندید در هر دو: 7d20ba6ef1d34a3cedbd7d3fd7c14228f173668a9a1e338351d529048de45079. این هویت همه binaryهای child یا ماژول‌های واقعاً استفاده‌شده در هر TLS connection را ثابت نمی‌کند.

baseline هیچ hosts تغییری نداشت (hosts_restored=false در آن طبیعی است). arm مسدود هر دو نگاشت IPv4/IPv6 loopback را تأیید کرد و bytes hosts موقت را در پایان بازگرداند (hosts_restored=true). BATهای کاربر اجرا نشدند. سیستم و بازی کاربر دست‌نخورده است.

## تفسیر محدود
- baseline سه flow row با SNI target و هشت row به IP پیش از مداخله 136.110.153.89 داشت؛ arm مسدود در هر دو معیار صفر بود. flow row، تعداد درخواست نیست و IP با نام دامنه یکی نیست. headline با دو مسیر شمارش مستقل بررسی شده است.
- در arm مسدود us.version.battle.net، level3.blizzard.com، us.cdn.blizzard.com و nydus.battle.net از SNI/HTTP Host دیده شدند. محتوای HTTPS این مسیرها رمزگشایی نشده است؛ هیچ ادعایی درباره نبود فیلد سخت‌افزاری در مسیرهای مجاز نداریم.
- تفاوت nydus/ocsp در نام‌های مشاهده‌شده میان دو arm، به‌تنهایی fallback تله‌متری نیست؛ nydus در b1 بدون محدودیت هم مشاهده شده بود. TCP sampling/اتصال‌های کوتاه و تفاوت زمان/backend می‌توانند نام‌ها را متفاوت کنند.
- نبود SNI یا اتصال به IP قدیمی تضمین نبود مقصد جایگزین، IP مستقیم دیگر، QUIC/DoH یا تله‌متری روی مسیر مشترک نیست. capture از NIC و parser prefix محدود است؛ loopback ترافیک آن نیز پوشش کامل ندارد. این آزمایش محتوای payload، login، کلاینت کامل یا update WoW را نسنجیده است.
- دوره مشاهده بعد از launch حدود ۱۲۰ ثانیه برای هر arm است؛ یک اجرا در هر arm اثبات آماری و تضمین رفتار همیشگی نمی‌دهد. هیچ فایل یا raw capture یا کلید صادر نشد؛ فقط JSON سفیدلیست.

## شکاف بعدی و شرط ادامه
برای سؤال اصلی «مسیرهای مجاز چه چیزی ارسال می‌کنند؟» به نام/IP بیشتر نیاز نداریم؛ اکنون باید binary/ماژول TLS واقعاً اجراشده در processهای هدف با hash/مسیر انتساب داده شود و امکان مشاهده محتوای درخواست به‌شکل محدود، بدون ورود به حساب، بدون تغییر trust یا غیرفعال‌کردن بررسی TLS سنجیده شود. تکرار همان تست hosts یا SSLKEYLOGFILE بدون شاهد جدید پیشرفت محتوا محسوب نمی‌شود. اگر ابزار مشاهده محتوا ممکن نبود، نتیجه باید نامعلوم اعلام شود، نه امن.

پرسش اثرانگشت فایل و انتقال A→B باز است و این نتیجه به آن پاسخ نمی‌دهد. فعلاً دلیل جدیدی برای resume/restore/delete نصب کاربر نداریم.
