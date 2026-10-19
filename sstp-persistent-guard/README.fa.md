# P10 — گارد پایدارِ گذار، آزمون محدود به یک executable
کتابخانهٔ داخلی؛ نه نسخهٔ آمادهٔ Enable/Disable و نه کیل‌سوییچ کامل SSTP.

## طراحی
گارد گذار یک explicit outbound Block در PersistentStore روی همهٔ profile/interface/protocol/addressها است. برای محصول Scope=WholeMachine برنامه Any است؛ CI **هرگز آن دامنه را فعال نمی‌کند** و فقط Scope=Fixture با مسیر executable یکتای آزمایش دارد. explicit Block مجوزهای SSTP را هم خنثی می‌کند؛ بنابراین گارد حالت نهایی نیست و Release فقط باید پس از تأیید پیش‌فرض Block، قرنطینهٔ Allowهای قبلی و قواعد مجاز مقید به SSTP توسط coordinator انجام شود. آن coordinator و شرط آزادسازی هنوز نوشته/qualified نشده‌اند.

ایجاد اولیه غیرفعال است؛ سپس original کامل raw rule و هفت filter در journal امن P2 ثبت می‌شود. ایجاد قبل از journal شکست بخورد، orphan فقط غیرفعال خواهد بود و خودکار adopt/delete نمی‌شود. Hold/Release فقط Enabled همین قانون را با write-ahead، lock، revision و readback کامل تغییر می‌دهند. journal خراب/گمشده یا تغییر در هر فیلد owned، حتی label، موجب توقف است. pending فقط تصویر دقیق before/after را می‌پذیرد. Release بازگردانی به Enabled=False اصلی است، نه حذف یا reset. پس از شروع Release، Hold دوباره مجاز نیست. API داخلی جای اثبات شرط coordinator را نمی‌گیرد.

گارد native پس از خروج فرایند می‌ماند؛ هیچ task، resident، watchdog، expiry، rollback زمان‌دار یا ضعف TLS اضافه نمی‌شود. ماندگاری reboot و اعمال واقعی boot هنوز آزموده نشده است. SHA احراز اصالت در برابر admin مهاجم نیست؛ read/check/set اتمیک نیست و lock جلوی admin مستقل را نمی‌گیرد.

## آزمون
در Windows CI دو executable همسان با مسیر متفاوت ساخته می‌شود. فقط برنامهٔ A تحت Block است؛ B کنترل هم‌زمان است. DNS برای github.com صرفاً setup آزمایش است؛ probe فقط TCP/443 به یک IPv4 مشخص، بدون HTTP، credential یا payload کاربردی برقرار می‌کند. پیش‌شرط هر دو اتصال موفق، هنگام Hold دو بار A ناموفق/B موفق، بعد از Release هر دو موفق است. اعمال‌کننده یک powershell.exe جدا است که **پیش از probe خارج می‌شود**. این یک مشاهدهٔ محدودِ بستن اتصال TCP تازه است، نه pcap، تست ترافیک اتصال‌های قبلی، همهٔ IPها/پروتکل‌ها یا اثبات no-leak.

شش خروج ناگهانی فرایند و شش recovery تازه، ازجمله Release مستقیم از Hold ناقص، بررسی می‌شود. drift owned label/filter، journal گمشده/خراب و idempotency بررسی می‌شوند. cleanup مستقل CI فقط همان نُه fixture با Group و strict hash کامل original/Enabled است؛ از recovery محصول جدا است. baseline نامرتبط rule و هر هفت filter/profile با P8 پیش/پس برابر باید باشد. فقط receipt محدود/hashها upload می‌شوند، نه IP انتخابی، raw inventory، journal یا نام executable موقت.

این جزء تغییر profile default، ادغام با P9، effective GPO/rules، بسته‌های IPv6، LAN، DNS محصول، هویت/قطع‌وصل SSTP، عدم‌نشت یا reboot را qualified نمی‌کند. دستگاه کاربر تغییر نمی‌کند؛ ready_for_user_apply=false.

## منابع طراحی
- تقدم explicit Block بر Allow و استثناها: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
- Set-NetFirewallProfile و محدودیت مستند NotConfigured برای GPO، که باید پیش از profile adapter روی store هدف راستی‌آزمایی شود: https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps
