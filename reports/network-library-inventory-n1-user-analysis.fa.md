# نتیجه اجرای N1 روی سیستم کاربر — مسیر CEF مطرح شد، موتور TLS هنوز ثابت نیست

## اجرای ابزار
گزارش کاربر window_ended، error_code=null، sampling_errors=0 و limit_hit=false دارد.۱۲ چرخه نمونه‌برداری،۹ فرایند با هویت/امضای verified و۱۳ فایل ماژول شناخته‌شده با PE parsed و بدون table cap ثبت شده‌اند. این اجرای واقعی ارسالی کاربر است، نه گزارش مستقل امضاشده یا اثبات همه شاخه‌های کد. preconditions از prompt تأیید شده؛ Pause بودن UI به‌طور مستقل اندازه‌گیری نشده است.

## فرایند صاحب HTTPS
هر سه tuple عمومی TCP/443 در این نمونه به process_index=5، battle.net.exe معتبر Blizzard نسبت داده شده‌اند:3.125.253.166،2.21.23.89،54.69.78.197. این index فقط داخل همین فایل است؛ با index6 گزارش T1.1 یا PID قدیمی یکی فرض نشود. تغییر IP/تعداد نسبت به نمونه قبل آزمون A/B یا بهبود privacy نیست.

همان فرایند libcef.dll و chrome_elf.dll را بار کرده است؛ همچنین ws2_32،winhttp،wininet،secur32 وsspicli حاضرند. libcef همان فایل هش‌شده‌ای است که در گزارش ماشین ثبت است؛ مسیر کامل صادر نشده است. این شناسایی **CEF در فرایند دارای اتصال** است، نه اثبات عبور هر اتصال از CEF/BoringSSL.

PE این libcef دارای exportهای شناخته‌شده CEF است، اما SSL_write وSSL_write_ex در exportهای استانداردِ بررسی‌شده دیده نشده‌اند. importهای WSASend/WSASendTo،WinHTTP وInitializeSecurityContext/AcquireCredentialsHandle دیده شده‌اند. نتیجه عملی: اتکا به hook ساده SSL_write export در همین فایل جواب آماده‌ای نیست؛ از نبود export، نبود TLS/رمزنگاری یا نبود upload نتیجه نگیریم. وجود import هم فقط وجود مسیر قابل فراخوانی است، نه شاهد call واقعی.

## چه چیزی هنوز نامعلوم است؟
- استفاده واقعی از BoringSSL/OpenSSL/Schannel/WinHTTP برای هر اتصال، و علت دقیق فقدان input capture در T1.1.
- hostname و محتوای سه اتصال جدید/چهار اتصال نمونه قبل؛ IP به‌تنهایی telemetry یا بی‌ضرر بودن را ثابت نمی‌کند.
- داده‌های hardware/personal در HTTPSهای بدون پوشش؛ N1 اصلاً payload/کلید نمی‌خواند و hook ندارد.
- delay import (در libcef حاضر ولی بررسی نشده)، static/dynamic resolving و UDP/QUIC. جدول PE فایل دیسک، memory image دقیق را ثابت نمی‌کند.

sample_observations جمع ردیف‌های TCP منطبق در snapshotهاست و اگر چند اتصال همزمان به همان remote tuple باشد می‌تواند از sample_count بیشتر شود؛ تعداد درخواست، بایت یا snapshot مستقل از آن نسازیم. module_samples کمتر از۱۲ در بعضی PIDها الزاماً خطا نیست؛ فرایندها طی بازه ممکن است ظاهر/ناپدید شوند و زمان ظهور از این گزارش اثبات نشده است.

## تصمیم و گام بعد
دیگر inventory مشابه یا تعویض BAT لازم نیست. گام بعدی مناسب، **مشاهده call واقعی APIها با شمارنده و دسته‌بندی caller-module** برای همان فرایندهای امضاشده است: WSASend/send و APIهای WinHTTP/WinINet/SSPI؛ قبل از انتخاب نقطه پیش-TLS. این مرحله باید ciphertext را نیز فقط به‌عنوان count/length تشخیص دهد، چون T1 عمداً Winsock غیر HTTP را صادر نمی‌کرد. این هنوز رمزگشایی یا اثبات محتوای upload نیست.

در این پاسخ N2 ساخته/اجرا یا runner تازه‌ای فعال نشده است؛ API route observer با hook، تغییر دامنه نسبت به N1 بدون hook است و پیش از تحویل باید fixture/native gate مستقل، caveat پایداری و معیار توقف داشته باشد. فعلاً Pause حفظ شود، نیازی به Resume یا تکرار N1 نیست؛ TLS/cert/security پایین آورده نشود. سؤال fingerprint A→B باز است.

[ورودی](network-library-inventory-n1-user.json) · [شواهد](network-library-inventory-n1-user-analysis.json) · [اسکریپت تحلیل و کنترل مستقل](../analysis/network-library-inventory-n1-user-analysis.py).
