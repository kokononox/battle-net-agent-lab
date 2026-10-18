# e1 — نمونه واقعی بافرها با اجازه صریح کاربر

کاربر روشن کرد که مقادیر ماشین موقت باید بررسی شوند و محدودیت صرف نام‌فیلد کافی نیست. در d2، self-test پاس شد، Agent زنده در Agent.9824 با hash b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5 و امضای Blizzard شناسایی شد و ورودی واقعی EncryptMessage شامل HTTP POST به telemetry-in.battle.net دیده شد. قالب بدنه هنوز decode نشده بود؛ نام‌فیلد صفر، شاهد نبود اطلاعات سخت‌افزاری نیست. فایل Agent زنده 7275216 بایت بود، متفاوت از Agent کاندید 540880 بایتی بررسی‌های قبلی.

این اجرا با همان bootstrap pin و همان scope تازه/بدون حساب/بدون بازی، نمونه‌های واقعی API input را با sequence و alias context نگه می‌دارد: حداکثر ۶۴ نمونه، ۱۶ KiB هر بافر، مجموع ۲۵۶ KiB. مسیر اجرایی و آدرس حافظه منتشر نمی‌شود. Authorization/Proxy-Authorization/Cookie/Set-Cookie در headerهای HTTP/1 پوشانده می‌شوند؛ خود body و مقدارهای آزمایشی در گزارش جدا base64+SHA256 ذخیره می‌شوند تا بتوان قالب باینری/فشرده/چندبخشی را تحلیل کرد. هیچ حساب یا فایل شخصی کاربر روی VM وجود ندارد؛ env فرزند کلید GitHub ندارد. این تغییر در اشتراک‌گذاری مخزن ایجاد نمی‌کند و گزارش نمونه‌ها در همان مخزن کاربر است؛ عدم وجود هر نوع شناسه/credential در body ناشناخته را تضمین نمی‌کنیم.

reference فقط CPU model، build ویندوز، RAM کل و تعداد processor منطقی ماشین موقت است، نه سیستم کاربر؛ برای مقایسه با مقادیر در درخواست. به SID، serial، account، license key یا رمز نیازی نیست و از میزبان دریافت نمی‌شود. یک dump باینری بافر، به معنی ذخیره‌شدن محتوا در سرور نیست. context alias فقط سرنخ reassembly در process است و به‌تنهایی انتساب قطعی به socket/سرور نیست.

گزارش live metadata به schema v2 می‌رود و صریحاً raw_values_headers_bodies_exported=true دارد؛ گزارش جدا api-buffer-samples.json مجوز values را منعکس می‌کند و validator سقف/هش را بررسی می‌کند. رسیدهای d1/d2 حفظ می‌شوند. self-test مصنوعی هرگز وارد نمونه‌های واقعی نمی‌شود. هیچ TLS trust/verification یا مقدار بازگشتی API تغییر نمی‌کند.

بخش‌های زیر تاریخچه طراحی d1/d2 هستند؛ محدودیت «فقط نام‌فیلد، بدون body در خروجی» فقط متعلق به آن نسخه‌هاست و e1 طبق توضیح بالا فرق دارد.

---

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

## اصلاح محدود d2 پس از توقف ایمن d1
run 39159715814 در self-test مرحله attach متوقف شد و هیچ کلاینت واقعی اجرا نشد. بررسی wheel دقیق نشان داد wrapperهای sync جدید Frida 17.24.2 پارامتر cancellable را مانند نسخه قدیمی قبول نمی‌کنند و cancellation از context manager/thread-local به _invoke می‌رسد. d2 از with Cancellable استفاده می‌کند؛ dependency/هدف/سقف‌ها تغییر نمی‌کنند. receipt d1 حفظ می‌شود، d2 یک commit/nonce و گزارش جدا دارد. اگر self-test دوباره شکست بخورد، کلاینت اجرا نمی‌شود و تکرار کور مجاز نیست.
