# چه می‌دانیم، چه را نباید نتیجه بگیریم

| شاهد | نتیجهٔ مجاز | نتیجهٔ نامجاز |
|---|---|---|
| گزارش scope Windows کاربر | profile projection و تفکیک local proof برای نسخه‌های pinشده کامل شده | حجم قطعی اینترنت، صف نهایی نصب یا latest بودن target |
| ۱٬۵۰۰٬۰۶۴ اثبات کامل local | payloadهای بررسی‌شده سالم/قابل‌بازاستفاده در قرارداد ابزار | full install closure، نسل فعال CASC یا آمادهٔ نصب بودن |
| ۳۱٬۱۰۳ unsupported/encrypted | decoder مسیر پشتیبانی ندارد | همه خراب‌اند یا باید دانلود شوند |
| ۵٫۱۱۳GB new + ۲٫۲۳۷GB retained conditional | اندازهٔ نمایش کامل encoded در گروه‌های مشخص | جمع این دو برابر اندازهٔ آپدیت است |
| خواندن ۱۱۶٫۷GB یا پوشهٔ ۳٫۸۸GB | IO محلی یا فضای اشغال‌شده | مصرف همان اندازه اینترنت |
| status bootstrapper_observed_agent_not_observed | Setup در نمونه‌های محدود دیده شد، Agent دیده نشد | نصب کامل، Agent قطعاً وجود ندارد، علت stall قطعاً زبان است |
| TCPهای نمونه خالی | در زمان نمونه‌گیری اتصال مربوط ثبت نشده | هیچ ارتباط شبکه‌ای رخ نداده |
| رشتهٔ hardware/CLIENT_RANDOM در باینری | سرنخ استاتیک برای بررسی | دادهٔ واقعی ارسال‌شده یا TLS key قابل‌استفاده |
| SNI/اتصال به telemetry-in.battle.net | مقصد دامنه‌ای و زمان اتصال، با انتساب process در حد ابزار | مسیر URL، body، فیلدهای hardware یا انتساب حساب |

## سابقهٔ تله‌متری؛ اعتبار محدود به گزارش تاریخی

در متن جلسات قبلی از `myapp.exe` و `wow_loader.dll`، نشانه‌های OpenSSL/SChannel، libcurl/SChannel در loader و رشته‌های `https://telemetry-in.battle.net/`، multipart/mixed و `telem-boundary` صحبت شده است. این sync باینری‌ها را دوباره تحلیل/اجرا نکرده؛ این‌ها **یافتهٔ گزارش‌شدهٔ قبلی، نه تأیید مستقل تازه** هستند. loader سفارشی ممکن است با بازی رسمی رفتار یکسان نداشته باشد.

همچنین اتصال منتسب به Wow.exe و SNIهای `telemetry-in.battle.net` و `eu.account.battle.net` در سابقه آمده؛ بدنهٔ درخواست و فهرست قطعی فیلدهای سخت‌افزاری هنوز حاصل نشده است.

Prototype observer v0.1 به‌صورت ZIP پیوست شده بود؛ محتوا/راهنما بررسی شد، در این محیط روی WoW واقعی اجرا نشد. آزمون مصنوعی Frida/SSPI reconstruction در Linux را تست موفق Windows/WoW ننامید. تلاش واقعی `SSLKEYLOGFILE` خروجی کلید قابل‌استفاده نداده؛ وجود عبارت CLIENT_RANDOM در exe آن را اصلاح نمی‌کند. hook/proxy/injection/خواندن حافظه را بدون دلیل و طرح امن تکرار نکنید و برای ادامه anti-cheat را دور نزنید.

## provenance و reproducibility

پنج JSON کاربر در `evidence/user/` دست‌نخورده‌اند؛ hash و provenance در `evidence/INDEX.json`. همهٔ پیوست‌های قدیمی منتقل نشده‌اند؛ این بسته شاهدهای تعیین‌کنندهٔ آخر را دارد. ادعای جدید باید به اصل گزارش، نسخهٔ ابزار و platform مربوط متصل باشد.

آزمون ۴۴۶تایی دانلودر Linux است؛ تست full manifest بیش از ۲٫۸میلیون ردیف در انتشار قبلی انجام شده و TagFix آن را مجدداً اجرا نکرده است. در sync فقط unit suite دوباره اجرا می‌شود. اثبات Windows کاربر مربوط به عملیات واقعی گزارش‌شده است، نه پوشش تمامی تست‌های Linux یا writer پیاده‌نشده.

گزارش schema1 تاریخی را با validator schema2 جدید بازنویسی نکنید. اصل commit قدیمی معتبرِ تاریخی باقی می‌ماند؛ گزارش تازه schema2 دارای source_commit/run_id/run_attempt است. نبود خروجی تازه نشانهٔ موفقیت workflow نیست.
