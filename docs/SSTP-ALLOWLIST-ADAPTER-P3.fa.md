# P3 — adapter بومی قواعد فایروال غیرفعال

## نتیجه
**PASS محدود: ۲۹ بررسی بومی روی Windows PowerShell 5.1، همراه ۷ fixture محلی اعتبارسنجی رسید.** چهار قاعدهٔ Allow غیرفعال در PersistentStore ساخته، فیلترهایشان خوانده و سپس حذف شدند. هیچ قاعده‌ای فعال نشد، default پروفایل‌ها تغییر نکرد و قواعد آزمایشی باقیمانده صفر است.

- منبع موفق: [ecf2c0e0e0cc2e1100bbb3e2e63930732df44d51](https://github.com/kokononox/battle-net-agent-lab/tree/ecf2c0e0e0cc2e1100bbb3e2e63930732df44d51/sstp-allowlist-adapter)
- اجرای موفق: [39199602299](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39199602299)، job برابر۴۳ثانیه، windows-2025 استاندارد.
- [رسید موفق](../reports/sstp-allowlist-adapter-p3-build.json)، artifact12163411337، SHA256 ZIP: `3c5faa9fceb0eab25120a56a69ee9763b83d36201862fff17a8c5bee70bf3dc9`.
- ZIP دانلود شد؛ digest، schema محدود، source/run و هش Firewall.ps1، Test-Firewall.ps1 و وابستگی Policy.ps1 با پایان خط checkout ویندوز تأیید شدند.

## پیاده‌سازی و دامنهٔ آزمون
- adapter با cmdletهای واقعی NetSecurity کار می‌کند؛ تمام قواعد جدید **Enabled=False** هستند. هیچ دستور فعال‌کردن قاعده یا تغییر default پروفایل در آن نیست. این backend کامل Enable/Disable نیست و هنوز به journal اجرایی متصل نشده است.
- چهار قالب: مقصدهای IP مجاز؛ DNS TCP53؛ DNS UDP53؛ bootstrap SSTP با TCP443، IP مشخص، program=svchost.exe و service=SstpSvc. سه قالب اول alias صریح و InterfaceType=RemoteAccess دارند؛ bootstrap نیز alias صریح دارد و InterfaceType=Any. DNS و transport این اجرا فقط قالب ذخیره‌شده‌اند؛ هیچ DNS query یا اتصال SSTP صورت نگرفت.
- alias شامل wildcard، Any، hostname به‌جای IP، subnet، spec با کلید اضافه یا interface_type تضعیف‌شده رد می‌شود. فهرست آدرس‌ها canonical و deduplicate می‌شود.
- نام و group دارای GUID اختصاصی؛ نام موجود overwrite نمی‌شود. snapshot شامل خواص CIM قاعده و هر هفت filter و نمای شروط است؛ statusهای runtime از fingerprint کنار گذاشته می‌شوند.
- حذف با spec معتبر، Enabled=False و fingerprint ذخیره‌شدهٔ دقیق؛ readback قبل و بعد. تغییر خارجی description یکی از قواعد خود تست شبیه‌سازی شد؛ حذف با hash قدیمی متوقف و قاعده حفظ شد. پس از بازگردانی description، hash تطبیق کرد و حذف/replay بی‌اثر پاس شدند.
- baseline خواص انتخاب‌شدهٔ سه profile در PersistentStore/ActiveStore و خواص rule-level قواعد محلی موجود قبل/بعد برابر بود. **این مقایسه شامل تمام filterهای قواعد دیگر، تمام WFP یا وضعیت سرویس‌های ثالث نیست.** در کد مسیر تغییر قواعد موجود وجود ندارد؛ cleanup فقط GUID/group همین اجرا و قاعدهٔ غیرفعال را می‌پذیرد.
- هیچ resident/service/task یا انقضا اضافه نشد. DNS، VPN، hosts، route و دستگاه کاربر تغییر نکردند. برخلاف P2، در این مرحله خود store فایروال با قواعد **غیرفعال** آزمایشی تغییر کرد؛ ادعای «هیچ نوشتن فایروالی نشده» نادرست است.

## اجرای اول و اصلاح
[اجرای39199357447](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39199357447) از منبع62788c8bb86c4e00021ebe7c512a5495d73f2ce4 بعد از۱۲بررسی هنگام lookup قاعدهٔ ناموجود متوقف شد؛ passed=false و baselineها برابر و باقی‌مانده صفر ثبت شد. پیام جزئی provider به عمد در خروجی محدود منتشر نشد، بنابراین نوع دقیق exception از این شاهد قابل انتساب نیست.

lookup اصلاح شد: اکنون ابتدا enumerate موفق PersistentStore انجام و سپس Name دقیق فیلتر می‌شود؛ permission/provider error هرگز به‌معنی absence تفسیر نمی‌شود. اجرای تازه با source جدید موفق بود، نه rerun همان source. رسید ناموفق حفظ شده است: [رسید اول](../reports/sstp-allowlist-adapter-p3-first-build.json)، artifact12162819302، SHA256 ZIP: `22bd49f468c65cce99f79e4cae1e398cd2df70292fc05cacb4a878225f898cea`.

فیلد disabled_rules_created=true در schema رسید اول ثابت بود و **دلیل ساخته‌شدن قاعده در اجرای اول نیست**؛ شکست قبل از اولین New رخ داده بود. در اجرای جدید این فیلد حذف و verified_disabled_rules_created از شمارش ساخت+readback موفق محاسبه شد. مقدار قدیمی برای استنتاج استفاده نشود.

## کار باقیمانده و شرط توقف
**ready_for_user_apply=false؛ enforcement_tested=false؛ sstp_binding_tested=false؛ user_device_tested=false.**

رابط استفاده‌شده در fixture فقط یک interface موجود runner است؛ SSTP نیست. ذخیره‌شدن InterfaceAlias و RemoteAccess، اثبات اتصال قواعد به پروفایل SSTP یا بسته‌ماندن VPN دیگر/alias reuse پس از reconnect نیست. هنوز آزمون packet واقعی، قطع‌وصل، DNS/IPv6/boot و no-leak انجام نشده است.

گام بعد: قرارداد snapshot و write-ahead journal برای اعمال/بازگردانی، adapter قواعد موجود/Allowهای محلی و توقف در GPO/unmanaged، guard واقعی و جلوگیری از transition نیمه‌کاره، سپس qualification اتصال واقعی SSTP و inbound/LAN و lifecycle. default Block به‌تنهایی با وجود Allowهای قبلی کافی نیست. explicit BlockAll هم استثناهای Allow را مغلوب می‌کند و policy دائمی مناسب نیست؛ روی runner راه‌دور بدون طراحی ایزولاسیون جداگانه اجرا نشود. هیچ نسخهٔ قابل نصب یا فرمان Enable جدید به کاربر تحویل نشده است.

## مبنای رسمی
- [New-NetFirewallRule، شروط InterfaceAlias/InterfaceType](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps)
- [تقدم قواعد Windows Firewall](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules): Allow صریح بر default Block مقدم، Block صریح بر Allow متعارض مقدم؛ outbound هم همین تقدم را دارد.
- [نیاز قطعی کاربر](SSTP-ALLOWLIST-REQUIREMENTS.fa.md)، [P1](SSTP-ALLOWLIST-POLICY-P1.fa.md)، [P2](SSTP-ALLOWLIST-JOURNAL-P2.fa.md).
