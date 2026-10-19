# P6 — شناسایی RAS/SSTP با GUID، projection و شناسهٔ رابط؛ فقط‌خواندنی

## نتیجه و مرز ادعا
**۴۰ بررسی در Windows PowerShell5.1 x64 پاس شد.** اندازه/offsetهای interop با probe مستقل C++ از Windows SDK تطبیق داده شد؛ منطق تصمیم، ورودی‌های منفی و فراخوانی‌های بومی IP Helper/RAS آزمایش شدند. محیط CI **صفر اتصال RAS فعال** داشت؛ projection واقعی SSTP و زنجیرهٔ هویت دستگاه کاربر در این اجرا آزمایش نشده‌اند. هیچ policy شبکه اعمال نشد و محصول نهایی آمادهٔ Apply نیست.

- منبع موفق: [a3f13770aac2056c8c05bde23b86d8ad0cb6a4a9](https://github.com/kokononox/battle-net-agent-lab/tree/a3f13770aac2056c8c05bde23b86d8ad0cb6a4a9/sstp-ras-identity)
- اجرای موفق: [39205045945](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39205045945)، job۴۲ثانیه، windows-2025 استاندارد، timeout چهار دقیقه.
- [رسید محدود](../reports/sstp-ras-identity-p6-build.json)، artifact12164813210، SHA256 ZIP: `3199bdfddb4b6b9f97d15fb1133fa2095d008f6926c3934ad7eb6e6208f1403a`.
- دانلود ZIP و digest، schema، source/run و هش پنج فایل RasIdentity.cs، Policy.ps1، Inspect-RasIdentity.ps1، Test-RasIdentity.ps1 و AbiProbe.cpp با پایان خط checkout ویندوز تأیید شد. هشت fixture محلی اعتبارسنجی رسید نیز پاس شد.

## مسیر هویت؛ جایگزین alias-only
1. Get-VpnConnection در هر دو scope به‌طور کامل خوانده می‌شود؛ فقط یک SSTP فعال و GUID یکتای آن در کل فهرست پذیرفته می‌شود.
2. RasEnumConnectionsW باید همان guidEntry را دقیقاً یک بار ببیند؛ name و scope با profile و device-type با vpn تطبیق می‌یابند. handle و correlation GUID باید موجود باشند.
3. IPv4 کلاینت از projection همان handle با RasGetProjectionInfoW(RASP_PppIp) خوانده می‌شود؛ آدرس باید معتبر و فقط روی یک interface محلی دیده شود. interface باید PPP و operational Up باشد؛ duplicate IP یا interface مبهم به توقف منجر می‌شود، نه انتخاب اولین نام.
4. index گزارش‌شدهٔ .NET از IP Helper به NET_LUID، سپس GUID و دوباره index تبدیل می‌شود؛ GUID باید با adapter برابر باشد. نام interface به‌تنهایی در تصمیم نهایی نقشی ندارد.
5. خواندن مجدد profile/RAS/projection/interface باید handle، correlation، profile/scope، IPv4، index، NET_LUID و GUID را پایدار ببیند. این خواندن‌های متوالی، snapshot اتمیک kernel نیستند و تغییر بلافاصله پس از پایان بررسی را پوشش نمی‌دهند.

**نکتهٔ ضروری:** luid داخل RASCONN، logon-session LUID است، نه NET_LUID رابط. ابزار آن را به IP Helper نمی‌دهد؛ NET_LUID از interface index مشتق می‌شود. IPv4 projection نیز IP کلاینت PPP است، نه IP سرور transport SSTP. این دو شناسه/آدرس نباید به اشتباه برای rule bootstrap استفاده شوند.

DLLهای P/Invoke به System32 محدودند. APIهای credential، dial، hangup یا تغییر policy فراخوانی نمی‌شوند. شمارندهٔ RAS حداکثر۱۲۸ است و bounds/اندازهٔ رکورد کنترل می‌شود. نام، IP، GUID، handle و phonebook-path فقط دادهٔ داخلی حافظه‌اند و به گزارش صادر نمی‌شوند.

## آزمون‌ها و اصلاح نخست
- دو parser check، نه مقایسهٔ مستقل SDK برای size/offset/constants، مسیر مثبت و هجده شاخهٔ رد هویت، استقلال از alias، رد نوع رشته‌ای به‌جای bool/count، کلید اضافی، ورودی صفر handle/index، خواندن adapter و roundtrip واقعی index/NET_LUID/GUID، و availability فراخوانی RAS بررسی شدند. check پایانی شمارنده هم در۴۰check گنجانده شده است.
- RAS enumeration در CI موفق و count=0 بود. تابع projection روی handle واقعیِ یک SSTP زنده اجرا نشده است؛ ورودی صفر پیش از تماس با DLL رد می‌شود. اندازهٔ ساختار projection با SDK بررسی شده، نه نتیجهٔ مثبت زندهٔ آن.
- [اجرای نخست39204694514](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39204694514)، منبعa397ed97c54fa929d5e2eba1e22ec526ce8d8e01 بعد از دو parser check، در اولین تطبیق ABI متوقف شد. هیچ فراخوانی live RAS/IP Helper از آن مسیر انجام نشد.
- RAS header دارای packing چهار‌بایتی است؛ interop پیش‌فرض اصلاح شد به Pack=4 و RASCONNW x64 با size۱۳۸۸. اجرای جدید، نه تغییر معیار به اندازهٔ غلط، با SDK پاس شد. x86/ARM64 در این CI qualified نشده‌اند؛ launcher در Windows x64 از PowerShell بومی استفاده می‌کند.
- [رسید نخست](../reports/sstp-ras-identity-p6-first-build.json)، artifact12165282036، digestZIP `5ae4372c75e1819ad63cd4248b799c3cf691bbfb6d9f30ebe12b707020c1ceda`؛ digest و هش پنج منبع اولیه نیز تأیید و شاهد شکست حفظ شد.

## بستهٔ تکمیلی دستگاه کاربر
**Sstp-RAS-Identity-ReadOnly-v1.zip** برای اجرای عادی با همان حساب قبلی آماده شد. [manifest](../reports/sstp-ras-identity-package.json)؛ SHA256 ZIP: `ddedb84c5de3f67c2059294e6032bc637c97c319db1c06999f0ab4b246469244`.

بسته حاوی inspector، policy تصمیم، helper C#، launcher و راهنماست؛ هیچ exe نصب‌شونده، driver، سرویس یا task ندارد. هش سه منبع اصلیِ داخل ZIP دقیقاً با هش checkout آزموده‌شدهٔ ویندوز برابر است. helper داخل فرایند موقت PowerShell کامپایل می‌شود و compiler ممکن است فایل موقت بسازد؛ فقط‌خواندنی یعنی policy را تغییر نمی‌دهد، نه اینکه هیچ فایل موقتی در runtime ایجاد نمی‌شود.

کاربر پس از استخراج کامل و در حالی که SSTP دستی متصل است، **01-Inspect-RAS.cmd** را با همان حساب عادی اجرا و **SstpRasIdentityReport.json** را ارسال می‌کند. این **گزارش جدید هویت** است، نه تکرار شمارش قبلی SstpBindingReport.json. elevation، حساب مدیر دیگر، reconnect اجباری یا تغییر تنظیمات خواسته نشده است. خطا/عدم دسترسی نیز باید به صورت همان report ارسال شود؛ نبود دسترسی به معنی نبود اتصال نیست.

گزارش فقط وضعیت/boolean/count/error-code و نسخهٔ OS/بیت پردازش را دارد. هیچ رمز، گواهی، نام واقعی، IP یا GUID صادر/آپلود نمی‌شود. API خواندن credential وجود ندارد؛ اتصال VPN و DNS query هم انجام نمی‌شود. پس از نوشتن گزارش فرایند خارج می‌شود.

## کار باقی و وضعیت
اگر identity_chain_observed=true هم شد، فقط زنجیرهٔ چند خواندن جاری تأیید شده است؛ نه اثر فیلتر فایروال، ماندگاری روی reconnect/boot یا نبود نشتی. firewall_filter_binding_qualified، enforcement_tested و ready_for_user_apply عمداً false می‌مانند. برخورد IP، IPv6-only، تغییر اتصال یا interface مبهم اجازهٔ fallback alias-only نمی‌دهد.

[گزارش قبلی کاربر](sstp-binding-user-inspection-analysis.fa.md) یک SSTP فعال،۱۰۰Allow محلی/مؤثر، stored outbound=NotConfigured و مسیرهای پیش‌فرض بیرون candidate را نشان داده بود؛ آن داده‌ها جایگزین بررسی RAS نیستند. گزارش تکمیلی P6 هنوز دریافت نشده است.

backend مؤثرِ guard/profile/Allowهای قبلی، قرارداد کامل snapshot و مدیریت GPO/unmanaged/inbound/LAN هنوز باید تکمیل و qualified شوند؛ سپس packet مستقل، DNS/IPv6، قطع‌وصل و boot. این بسته نسخهٔ Enable/Disable محصول نیست و هیچ تغییری روی دستگاه کاربر از این گفتگو اعمال نشده است.

## مبنای رسمی
- [RasEnumConnectionsW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumconnectionsw): active connections، handle و entry؛ حد و اندازهٔ ساختار.
- [RASCONN](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376725(v=vs.85)): guidEntry متناظر entry GUID، flag all-users، luid مربوط به logon session.
- [RASPPPIP](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa377634(v=vs.85)): نتیجهٔ PPP IPv4 و آدرس کلاینت.
- [Get-VpnConnection](https://learn.microsoft.com/en-us/powershell/module/vpnclient/get-vpnconnection?view=windowsserver2025-ps): Guid و scope phonebook.
- [Network Interfaces](https://learn.microsoft.com/en-us/windows/win32/network-interfaces): تفاوت ifIndex، NET_LUID، ifGuid و alias و امکان بازیافت برخی شناسه‌ها.
