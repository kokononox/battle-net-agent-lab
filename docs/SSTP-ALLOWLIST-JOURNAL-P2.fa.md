# P2 — نتیجهٔ زیرساخت journal و تصمیم بازگردانی

## نتیجه
**PASS محدود: ۳۰ بررسی بومی Windows PowerShell 5.1، و ۷ fixture محلی اعتبارسنجی رسید. محصول هنوز آمادهٔ اعمال روی دستگاه کاربر نیست.**

- منبع: [4efed37494e718bc8a5833bbb4899e34623557c5](https://github.com/kokononox/battle-net-agent-lab/tree/4efed37494e718bc8a5833bbb4899e34623557c5/sstp-allowlist-backend)
- اجرا: [39198636057](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39198636057)، job موفق ۲۷ثانیه، windows-2025 استاندارد. این نتیجه به معنی آزمون روی Windows کاربر نیست.
- [رسید محدود](../reports/sstp-allowlist-journal-p2-build.json)؛ artifact12163200625، digestZIP برابر `5d996fe93002589495e939bb4d85133f2fb2218501508d0db8070886e9bb1568`.
- ZIP دانلود شد؛ digest، schema، source/run، پرچم‌های دامنه و هش سه فایل PowerShell تأیید شدند. هش فایل‌های checkout ویندوز با CRLF تطبیق دارد؛ اختلاف اولیه با LF محلی ناشی از پایان خط بود، نه نتیجهٔ ردشدهٔ آزمون.

## آنچه ساخته و بررسی شد
1. پوشهٔ وضعیت اختصاصی با ACL محافظت‌شده برای Administrators/SYSTEM و کنترل مالک؛ رد استفاده پس از فعال‌شدن inheritance. مسیر شبکه، نسبی و دارای .. رد می‌شود. بررسی reparse در کد وجود دارد ولی fixture reparse اجرا نشده است.
2. قفل فایل انحصاری در مدت فراخوانی، جلوگیری از استفادهٔ همزمان، revision مورد انتظار برای جلوگیری از overwrite با وضعیت قدیمی.
3. نوشتن فایل موقت، Flush(true)، جایگزینی اتمی فایل و نگهداری نسخهٔ قبل؛ خواندن دوباره بعد از نوشتن. roundtrip، revision، نسخهٔ پشتیبان و نبود فایل موقت باقیمانده بررسی شد.
4. تغییر checksum، JSON خراب و نبود primary با backup سالم -> recovery_required؛ نوشتن خودکار متوقف می‌شود. خرابی هر دو فایل -> توقف. این تست شبیه‌سازی خرابی فایل است، نه قطع برق یا crash حین syscall.
5. تصمیم‌های **خالص** بازگردانی: فقط مقدار اولیهٔ دقیق؛ اختلاف خارجی یا مالکیت تأییدنشده توقف؛ guard تأییدنشده اجازهٔ restore نمی‌دهد. guard فقط وقتی همهٔ readbackها و policy تأیید و journal سالم باشد و تعارض نباشد، قابل برنامه‌ریزی برای حذف است.

## مرز ادعا
- **هیچ تنظیم firewall، VPN، hosts، route یا DNS تغییر نکرد؛ DNS هم query نشد. هیچ resident/service/task ساخته نشد.** فقط فایل‌های آزمون در پوشهٔ GUID اختصاصی ساخته و حذف شدند؛ journal خصوصی upload نشد.
- این مرحله backend اجرایی کامل، state machine عملیات write-ahead یا Enable/Disable نهایی نیست. دادهٔ state فعلاً payload عمومی آزمایش است، نه قرارداد تأییدشدهٔ snapshot واقعی قواعد.
- guard واقعی نصب نشده است؛ booleanهای GuardVerified/OwnershipVerified ورودی fixture هستند، نه تشخیص واقعی سیستم. بنابراین تصمیم‌گیر خالص به‌تنهایی تضمین ایمنی restore یا نبود نشتی نیست.
- SHA256 برای خرابی تصادفی است، نه مقابله با مدیر مخرب. قطع برق، خرابی دیسک، reboot با policy فعال، چند فرایند واقعی همزمان، و race مهاجم هم‌سطح در این اجرا qualified نیستند.
- [نیاز قطعی](SSTP-ALLOWLIST-REQUIREMENTS.fa.md) دست‌نخورده است: فقط مقصدهای allowlist از SSTP، fail-closed، اتصال دستی، LAN بسته، بدون انقضا و بدون برنامهٔ مقیم. journal بعد از بسته‌شدن برنامه دادهٔ خود را نگه می‌دارد، ولی این آزمون به‌تنهایی ماندگاری policy فایروال پس از reboot را ثابت نمی‌کند.
- ready_for_user_apply=false، enforcement_tested=false، user_device_tested=false. هیچ چیزی روی دستگاه کاربر اعمال نشده است.

## گام بعد
تکمیل قرارداد snapshot و عملیات write-ahead، adapter محدود فایروال، شناسایی Allowهای محلی/GPO و guard واقعی؛ سپس qualification رابط SSTP و قطع‌وصل/IPv6/DNS/boot. تا قبل از آن، دستور Enable/Disable قابل اجرا تحویل نشود. guard از نوع BlockAll روی runner راه‌دور بدون طراحی جداگانه اجرا نشود: explicit Block می‌تواند Allow کانال کنترل CI را هم مغلوب کند. timeout/task آزمون‌های قدیمی CI نباید وارد محصول بدون انقضا شود.
