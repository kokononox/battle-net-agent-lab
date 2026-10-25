# G23 — کنترل مستقل TLS ویندوز؛ بدون اجرای Setup

پرسش: آیا کلاینت استاندارد Windows/.NET با همان سیاست شبکه و بررسی ابطال روشن، مستقل از نصاب، خطای گواهی می‌دهد؟

## دامنهٔ دقیق
فقط یک اتصال SslStream به `us.version.battle.net:443`، از loopback/proxy، در Job بدون breakaway. ریشهٔ Job خود helper ساخته‌شده از source همین commit است، نه فایل دلخواه؛ helper با SHA-256 پیش از gate تثبیت، با FileStream قفل و suspended به Job اختصاص داده می‌شود. همان کنترل native مالک TCP/هویت/Job در هر ارسال برقرار است. هیچ HTTP request، حساب، بازی یا اجرای نصاب Battle.net وجود ندارد. Prepare هیچ Setup یا گواهی دانلود نمی‌کند. baseline canary فقط TCP پورت1119 است، نه TLS.

## اعتبارسنجی؛ بدون bypass
AuthenticateAsClientAsync برای نام دقیق us.version.battle.net، با SslProtocols.None (انتخاب سیستم‌عامل) و checkCertificateRevocation=true انجام می‌شود. callback فقط در نبود همهٔ SslPolicyErrors، نبود خطاهای زنجیره، وجود گواهی و مشاهدهٔ RevocationMode.Online اجازهٔ پذیرش می‌دهد. NameMismatch/Revoked/OfflineRevocation/UnknownStatus/UntrustedRoot/NotTimeValid و نبود chain رد می‌شوند. خودآزمایی native پیش از تغییر OS این شرط‌ها را تست می‌کند. هیچ callback همیشه-true، CA تازه، تغییر رجیستری TLS، آزادسازی CRL/OCSP یا خاموش‌کردن بررسی وجود ندارد.

callback فقط flags زنجیره، enum خطای SSL، تعداد chain elements و SHA-256 گواهی عمومی leaf را ثبت می‌کند؛ subject، issuer، DER، random، token و متن Exception منتشر نمی‌شوند. تنها یک اتصال داریم؛ پس خروجی callback به همین کنترل مشخص مربوط است، برخلاف eventهای Schannel کل VM. TLS معمول این client خودش است؛ MITM یا رمزگشایی اتصال Setup انجام نمی‌شود.

## کش و پنجرهٔ مشاهده
هیچ گرمایش هدفمند گواهی/CRL/OCSP، پاک‌کردن cache یا TLS به مقصد پیش از gate وجود ندارد. cache از پیش موجود image رانر اندازه‌گیری نشده؛ «cold/empty cache» ادعا نمی‌شود. cache داخلی‌ای که همین handshake تحت gate استفاده کند، بخشی از نتیجه است. deadline احراز TLS ۴۵ ثانیه و Job observation ۷۵ ثانیه است؛ deadline/EOF قبل از callback پاسخ قطعی به علت revocation نیست.

## نتیجه و بازیابی
سیاست firewall و استثناهای بازیابی عین G22 پس از تغییر شمارهٔ مرحله‌اند. گزارش صریحاً installer_launched=false و control_launched را جدا دارد؛ success آزمایش یعنی مشاهدهٔ کنترل و بازیابی، نه TLS موفق یا نصب موفق. نتیجهٔ authentication_failed یک نتیجهٔ آزمایش است، نه دلیل ضعیف‌کردن شرط‌ها. publisher Linux جدا فقط گزارش دارای hash/source/run صحیح را artifact می‌کند. Desktop 0.9.10 و G22 دست‌نخورده‌اند.

مرز آزمایش در برابر Administrator مخرب/تزریق در Runner، همهٔ brokerها و نبود تمام انواع نشت اثبات نشده است. اگر گواهی در callback نرسد، از رخدادهای VM نباید انتساب قطعی ساخت.
