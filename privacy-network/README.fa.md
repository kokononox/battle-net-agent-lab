# ضبط محدود متادیتای آغاز اجرا — b1

هدف: رفع شکاف DNS اجرای a1 و مشاهده hostname از SNI یا Host در ترافیک واقعی. این آزمایش آپدیت بازی یا انتقال A→B نیست.

فقط GitHub-hosted Windows تازه، attempt=1 و commit message مشخص. bootstrap رسمی با کنترل امضای موجود؛ فقط Continue صفحه زبان. بدون Install، پذیرش حقوقی، حساب یا بازی. محیط فرزند فاقد tokenهای GitHub است. آزمون SSLKEYLOGFILE دوباره انجام نمی‌شود.

Pktmon داخلی ویندوز، فقط NIC، ۱۵۳۶ بایت از هر بسته، ETL circular با درخواست سقف ۳۲ MiB. سقف فایل ETL پس از اجرا نیز کنترل می‌شود (تا ۶۴ MiB برای تفاوت پیاده‌سازی ابزار)، و PCAPNG تا ۱۲۸ MiB پردازش می‌شود. circular ممکن است ابتدای ضبط را بازنویسی کند. حداکثر مشاهده bootstrap پس از اجرا ۱۲۰ ثانیه؛ کل job حداکثر ۱۰ دقیقه. سقف سخت بایتی برای دانلودهای child وجود ندارد. ضبط شامل ترافیک سیستم ماشین موقت هم می‌شود، اما گزارش فقط flowهای TCP مرتبط با tuple نمونه‌برداری‌شده برای processهای هدف را منتشر می‌کند. raw capture فقط در پوشه موقت است و هرگز artifact نمی‌شود؛ بعد از تحلیل حذف می‌شود.

نمونه‌برداری ۱۰۰ میلی‌ثانیه‌ای از PID/name و local/remote tuple؛ IP/port محلی وارد خروجی نمی‌شود. این انتساب رمزنگاری‌شده یا پوشش کامل نیست؛ اتصال کوتاه و PID/tuple reuse ممکن است مشکل بسازد.

Parser محدود و بدون وابستگی خارجی: pcapng Ethernet/raw IP، IPv4/IPv6 بدون fragmentation/extension، UDP DNS responses، prefix پیوسته اولیه TCP برای SNI ClientHello یا Host/method اولین HTTP request. URL، query، headerهای دیگر، body و کلیدها صادر نمی‌شوند. capture truncation، gap، prefix/flow limits و خطاها گزارش می‌شود. TCP reassembly کامل ندارد؛ out-of-order و prefix ازدست‌رفته می‌توانند نام میزبان را پنهان کنند. SNI می‌تواند نام outer زیر ECH باشد؛ Host/SNI مالکیت سرور یا محتوای واقعی HTTPS را اثبات نمی‌کند. DNS/cache نام‌های کاندید است، نه انتساب قطعی درخواست DNS به PID.

DNS probe جدید وضعیت cmdlet، category محدودشده، HRESULT و شکل خروجی روش قبلی را ثبت می‌کند؛ exception/message یا مسیر خام صادر نمی‌شود. cache خالی اکنون JSON ساختاریافته دارد، نه خروجی خالی. این فقط رفع یک failure mode محتمل است؛ تا نتیجه نیاید علت اجرای a1 ثابت نیست.

از دو فایل امضاشده بررسی‌شده، فقط SHA256 و وجود چند رشته ثابت مرتبط با شبکه/TLS ثبت می‌شود. وجود یک رشته DLL یا libssl نه import معتبر است و نه استفاده در اتصال؛ نبودش هم نبود کتابخانه را ثابت نمی‌کند. فایل Agent کاندیدِ روی دیسک الزاماً همان فایل process هر flow نیست.

خروجی فقط JSON سفیدلیست، روی runner تمیز دوباره اعتبارسنجی می‌شود. محتوا رمزگشایی نمی‌شود و عدم ارسال اطلاعات سخت‌افزاری تضمین نمی‌شود. نام دامنه ممکن است اطلاعات شناسایی داشته باشد؛ labelهای شبیه شناسه طولانی hex/UUID/numeric حذف می‌شوند. این redaction تشخیص جامع همه شناسه‌ها نیست؛ هیچ حساب شخصی در آزمایش وجود ندارد.

مستندات دستورها:
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap
