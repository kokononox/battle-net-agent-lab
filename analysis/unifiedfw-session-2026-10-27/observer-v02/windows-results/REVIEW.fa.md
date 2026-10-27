# نتیجهٔ واقعی Windows — مشاهده‌گر v0.2، فقط حالت متصل

هر دو گزارش روی Windows PowerShell 5.1.26100.6899، ۶۴بیتی، payload معتبر و یک candidate قابل مشاهده را ثبت کرده‌اند. در هر اجرا `diagnostic_completed=true`، `vpn_state=connected`، `selected_profile_matched=true`، `identity_chain_verified=true` و `identity_chain_status=identity_chain_observed` است. هیچ خطای native ثبت نشده است.

این تأیید بومی زنجیرهٔ پروفایل → RAS → projection/interface در **داخل هر اجرا** است. گزارش‌ها binding خام را منتشر نمی‌کنند؛ `binding_compared_to_previous=false` در هر دو اجراست. بنابراین از برابر بودن گزارش‌های پالایش‌شده نمی‌توان ثابت کرد همان نشست در فاصلهٔ دو اجرا برقرار مانده، reconnect رخ داده یا هویت binding قبلی با تازه مقایسه شده است.

endpoint، DNS bootstrap، TLS bootstrap، guardian و مجوز Apply همچنان false هستند. هیچ درخواست تغییر فایروال/VPN یا dial/hangup ثبت نشده است. disconnected، connecting، reboot، reconnect و نبود نشتی در این دو گزارش آزموده نشده‌اند.

این آزمون تکرار نشود؛ فعلاً اقدام تازه‌ای از کاربر لازم نیست. گام بعد بررسی مشاهدهٔ endpoint مرتبط با پروفایل و مشخص‌کردن مرز pin/هویت service است، پیش از هر executor برای suspend/rebind. تشخیص PID مشترک svchost به‌تنهایی نباید مالکیت قطعی سرویس روی flow یا کفایت TLS/DNS تلقی شود. هیچ اجازهٔ عمومی یا تغییر امنیتی خودکار تجویز نمی‌شود.

## شرط تازهٔ نوع اتصال فیزیکی

کاربر گفت دو اجرای فعلی با دانگل USB وای‌فای انجام شده‌اند و بعداً قرار است کابل Ethernet استفاده شود. خود JSON نوع carrier را اندازه‌گیری نکرده؛ این بخش گزارش مستقیم کاربر است. شرط طراحی: حمل SSTP به نام/شمارهٔ کارت فیزیکی بایند نشود؛ data فقط روی هویت معتبر SSTP مجاز بماند.

بازبینی و مدل کامپایلر نشان داد قانون حمل فعلی InterfaceAlias/InterfaceType=Any دارد، اما همچنان program/service/IP/TCP443 دقیق است؛ قوانین data و DNS به رابط SSTP/RemoteAccess محدودند. مدل جداگانه تغییر نام/index فیزیکی را مستقل از قواعد تشخیص داد؛ این آزمون واقعی جابه‌جایی کارت نیست. با همان alias ممکن است index/نشست VPN عوض شود، پس مشاهدهٔ هویت و rebind لازم باقی است.

پیکربندی IP، DHCP، route، DNS و احتمال IPv6 متفاوت در کارت تازه زیر ایزولاسیون هنوز حل/آزموده نشده‌اند. هیچ استثنای عمومی یا تغییر تنظیم برای رفع ظاهری اضافه نشده است. Windows Ethernet و تعویض واقعی کارت تأیید نشده؛ کاربر فعلاً شبکه را عوض نکند.
