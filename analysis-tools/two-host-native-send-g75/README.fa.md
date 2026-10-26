# G75 — کنترل قبل از send واقعی، فقط برنامهٔ آزمایشی x86/x64

این مرحله adapter پژوهشی محدود به synchronous Winsock `send` را با Frida replacement **قبل از فراخوانی تابع اصلی** می‌آزماید. برنامهٔ تازه‌کامپایل‌شدهٔ C# از P/Invoke واقعی استفاده می‌کند؛ گیرندهٔ فیزیکی فقط loopback است. هیچ attach به Battle.net، دانلود خارجی، تغییر firewall/certificate/allowlist، login یا Install انجام نمی‌شود. main و Unified Firewall Desktop 0.9.10 دست‌نخورده‌اند.

## قرارداد محدود و fail-closed
- در هر socket فقط یک تلاش send با flags صفر، حداکثر 16KiB و دقیقاً یک HTTP/1.1 کامل قابل بررسی است. تلاش ناقص، اضافی یا دوم رد می‌شود؛ بین sendهای برنامه بافرسازی و جعل return count انجام نمی‌شود.
- درخواست باید هم از سیاست عمومی G74 عبور کند و هم **از ابتدا byte-for-byte canonical باشد**. adapter بازنویسی انجام نمی‌دهد و برای سازگاری درخواست مبهم را ارسال نمی‌کند. مقدار بازگشتی تابع اصلی و last error حفظ می‌شود؛ رد برابر SOCKET_ERROR/WSAEACCES است.
- `getpeername` باید دقیقاً IPv4 loopback و port اختصاصی fixture را نشان دهد. تصمیم با snapshot bounded از buffer گرفته می‌شود. ارسال از کپی خصوصی همان snapshot است، نه pointer قابل تغییر برنامه؛ کنترل mutation همزمان این اتصال تصمیم به bytes را می‌آزماید.
- پاسخ controller فقط boolean واقعی true را می‌پذیرد. نبود پاسخ باعث انتظار fail-closed می‌شود؛ watchdog مستقل host برنامه را در timeout خاتمه می‌دهد. TLS opaque رد می‌شود. WSASend در این fixture عمداً بدون صداکردن تابع اصلی رد می‌شود تا راه دورزدنِ همان API مجاور باز نماند.
- خاموش‌شدن/خرابی همهٔ لایه‌های injection و همهٔ APIهای دیگر پوشش داده نشده؛ fail-open نبودن در کل OS ادعا نمی‌شود. native exception بعد از تلاش تابع اصلی به‌عنوان original_called=true/unknown گزارش می‌شود، نه رد پیش از ارسال.

## کنترل‌ها
برای هر معماری 24 مورد: درخواست‌های عمومی CDN/Range/metadata، ورودی خصوصی یا نامنطبق، framing/TLS/Host نامعتبر، benign غیرcanonical، دو send واقعی از قطعات یک header، تلاش WSASend، peer نادرست، پاسخ controller با type نادرست، flags ناپشتیبانی‌شده، payload خصوصی پس از send مجاز، و تغییر buffer برنامه هنگام توقف برای تصمیم.

برنامهٔ مالک تازه spawn می‌شود، داخل Job با kill-on-close قرار می‌گیرد، image/path/hash آن guard می‌شود و سپس attach/resume می‌شود. آماده‌شدن hook، معماری runtime، خروج native، تعداد صداخوردن original و receipt واقعی گیرنده باید با انتظار برابر باشند. خطا یا شکست یک مورد کل مجموعه را متوقف می‌کند؛ retry خودکار انجام نمی‌شود.

**اتصال TCP از قبل وجود دارد:** چون کنترل در send است، connect برای تعیین peer قبلاً رخ داده است. موارد ردشده باید صفر payload به گیرنده برسانند، نه صفر اتصال TCP. نتیجهٔ G74 دربارهٔ صفر اتصال فقط برای relay آن harness بود و به این لایه تعمیم داده نمی‌شود.

## چیزی که این نمونه نیست
این adapter نصب‌کننده، پراکسی شفاف، مسیر TLS یا ابزار آمادهٔ استفاده نیست. partial sends/async I/O و fragmentation واقعی client عمداً برای سازگاری باز نشده‌اند؛ policy snapshot ثابت است و seqn/short alias/UAهای تازه همچنان محدودند. sendto، kernel I/O، API/فرایندهای دیگر و مسیرهای بدون injection ممکن است bypass باشند. endpoint واقعی و TLS binding برای Battle.net پیاده نشده است. timing، selection، ترتیب و تعداد درخواست‌های عمومی همچنان می‌تواند کانال اطلاعاتی باشد؛ نبود fingerprint ادعا نمی‌شود.
