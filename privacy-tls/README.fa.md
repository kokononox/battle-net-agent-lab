# مشاهده PID زنده و ورودی API شبکه/TLS — d1

هدف: دیگر به فایل Agent کاندیدِ پیدا‌شده در دیسک اتکا نکنیم؛ PID زنده را به image path/hash/Authenticode پیوند دهیم و در صورت امکان ورودی API خروجی را در همان process ببینیم. این رمزگشایی ترافیک ضبط‌شده با کلید TLS نیست.

## دامنه و اجازه محدود
فقط VM تازه GitHub-hosted windows-2025، attempt=1 و push message مشخص. هیچ game، حساب، Install یا legal acceptance؛ فقط همان Continue زبان با helper محدود. bootstrap باید همان SHA256 ثابت آزمایش c1 و امضای Blizzard را داشته باشد. بدون تغییر hosts، trust store، TLS verification، نتیجه API یا bytes بافر. Hook با Frida حافظه/زمان‌بندی فرایند را تحت تأثیر قرار می‌دهد؛ این محدودیت صریح است. هیچ کار ضد anti-cheat یا instrumentation در WoW وجود ندارد. این ابزارها برای PC کاربر نیستند.

## وابستگی و self-test
Frida 17.24.2 و typing_extensions با نسخه و hash ثابت از PyPI. Windows wheel رسمی پیش از ساخت workflow دانلود و SHA256 آن بررسی شد؛ APIهای cancellation/session از همان wheel بررسی شدند. Source pathهای قدیمی core.py در upstream فعلی دیگر موجود نبودند؛ برای سازگاری به package واقعی متکی هستیم.

پیش از اجرای کلاینت، worker مصنوعی خودمان با WinHTTP بدون proxy و فقط 127.0.0.1:1 یک بافر JSON با cpu مصنوعی می‌دهد. باید hook/decoder آن را ببیند؛ در غیر این صورت آزمایش کلاینت شروع نمی‌شود. مقدار مصنوعی هرگز به اینترنت فرستاده نمی‌شود و نتیجه self-test از شواهد کلاینت جداست. این self-test فقط مسیر WinHttpSendRequest را می‌سنجد، نه درستی همه APIها یا موفقیت TLS واقعی.

## انتساب process و ابزار
- حداکثر ۸ PID از نام‌های محدود Battle.net؛ QueryFullProcessImageName و GetProcessTimes از handle فرایند گرفته می‌شود. hash image واقعی تا ۱۲۸ MiB و ناشر Blizzard/Authenticode باید تأیید شود؛ image basename باید مطابق باشد. پس از attach، path و creation time دوباره بررسی می‌شود تا PID reuse کاهش یابد. از هر PID فقط یک تلاش؛ processهای کوتاه ممکن است از دست بروند.
- مسیرها/creation time/command line منتشر نمی‌شوند؛ فقط basename دسته‌بندی‌شده، hash، امضا، category مسیر و شماره عمومی پوشه Agent در صورت وجود. moduleهای بارگذاری‌شده فقط در categoryهای ثابت شبکه گزارش می‌شوند؛ بارگذاری به معنی فراخوانی نیست.
- اگر اجرای Frida فقط با یک کتابخانه حضور داشته باشد، استفاده واقعی از آن ثابت نیست؛ فقط دریافت buffer event از hook شاهد فراخوانی API در همان PID/hash است.
- APIهای WinHTTP، WinINet، EncryptMessage در SSPI و SSL_write/SSL_write_ex در libsslهای exportشده مشاهده می‌شوند. static/nonexported OpenSSL/BoringSSL، QUIC، API دیگر، call قبل attach و requestهای تکه‌تکه می‌توانند خارج پوشش باشند. نصب hook هر ۵۰۰ms برای moduleهای دیررس بررسی می‌شود. هیچ نقطه اجرای ناشناخته با offset حدسی patch نمی‌شود.

## کمینه‌سازی داده
هر buffer خروجی حداکثر ۱۶ KiB فقط در حافظه VM به collector محلی می‌رود، نه به artifact/GitHub. حداکثر ۱۲۸ buffer per process و ۵۱۲ event در گزارش. gzip/deflate فقط تا ۶۴ KiB decode می‌شود؛ JSON/form keys فقط تا عمق ۸ و ۵۱۲ key بررسی می‌شود. فقط نام‌های ثابت و ازپیش‌معلومِ فیلدها (مثل cpu، gpu، device_id، os_version) و نوع داده/طول/حالت API/host hint صادر می‌شوند؛ نه مقدار key، نه body، URL، header، token، TLS key یا path. کلید عمومی «memory» به‌تنهایی شاهد مقدار سخت‌افزار واقعی نیست. host ممکن است از handle map یا HTTP/1 plaintext بیاید؛ این را با انتساب قطعی به flow شبکه یکی نمی‌کنیم. headerهای HTTP/2 و داده باینری ناشناخته رمزگشایی/تفسیر نمی‌شوند.

API success فقط مقدار بازگشتی محلی است؛ async/timeout/ارسال‌نشدن ممکن است مطرح باشد. بافر ورودی به API، درخواست دریافت‌شده یا پذیرفته‌شده سرور را ثابت نمی‌کند. bufferهای چند API می‌توانند یک محتوا را چندبار نشان دهند؛ تعداد event برابر تعداد درخواست نیست. نبود key hint، نبود تله‌متری یا نبود اطلاعات سخت‌افزاری را ثابت نمی‌کند.

## حفظ ایمنی گزارش
گزارش فقط سفیدلیست metadata است و در runner تمیز دوباره بررسی می‌شود. raw packet و مقادیر API صادر نمی‌شوند. Console فقط status/countهای ثابت دارد و exception text/stack از فرایند منتشر نمی‌شود. شکست attach با phase/class/numeric code محدود گزارش می‌شود. job مشاهده حداکثر ۱۲ دقیقه، مشاهده startup پس از launch حدود ۱۲۰ ثانیه؛ child network سقف سخت بایتی ندارد. ماشین در پایان دور ریخته می‌شود.

پرسش آپدیت کامل و انتقال فایل A→B همچنان باز است.
