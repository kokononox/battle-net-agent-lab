# P3 — adapter واقعی قواعد غیرفعال، نه Enable نهایی

این ماژول با cmdletهای واقعی NetSecurity در PersistentStore کار می‌کند، اما **همهٔ قواعد جدید را Enabled=False می‌سازد**. هیچ مسیر فعال‌سازی قاعده یا تغییر default پروفایل ندارد. اجرای آن روی سیستم کاربر هنوز مجاز/آماده نیست.

چهار قالب سخت‌گیرانه دارد: مقصد allowlist و DNS UDP/TCP فقط با alias صریح و InterfaceType=RemoteAccess؛ bootstrap با alias صریح uplink، TCP443 به IPهای مشخص، program=svchost.exe و service=SstpSvc. alias دارای wildcard و Any، مقصد hostname/Any/subnet، spec دارای کلید اضافی یا تضعیف‌شده رد می‌شود. IPهای DNS و transport نمونهٔ آزمایش‌اند و اتصال واقعی انجام نمی‌شود.

برای هر قاعده شناسهٔ GUID اختصاصی و group مشخص وجود دارد؛ تصادم نام توقف می‌دهد. rule و هر هفت filter واقعی خوانده می‌شوند. hash از ویژگی‌های CIM به جز statusهای runtime و از نمای خوانای شروط ساخته می‌شود. حذف فقط با spec معتبر، وضعیت غیرفعال مورد انتظار و fingerprint ذخیره‌شدهٔ دقیق انجام می‌شود؛ اختلاف خارجی توقف می‌دهد. این روش در برابر مدیر همزمان مخرب یا جعل journal تضمین نمی‌دهد.

تست native فقط چهار قاعدهٔ Allow غیرفعال می‌سازد و حذف می‌کند، با شبیه‌سازی ویرایش description یکی از قواعد خودش و بررسی امتناع از حذف. قواعد موجود تغییر نمی‌کنند. خواص انتخاب‌شدهٔ پروفایل stored/effective و خواص rule-level قواعد محلی قبل/بعد مقایسه می‌شوند؛ این مقایسه ادعای snapshot تمام WFP یا filterهای قواعد دیگر نیست. cleanup فقط GUID همین اجرا و group دقیق و Enabled=False را می‌پذیرد؛ فایل خصوصی یا snapshot خام منتشر نمی‌شود.

**هنوز حل نشده:** پیوند واقعی و غیرقابل اشتباه رابط SSTP، رفتار reconnect/alias reuse، DNS/IPv6/boot، اجرای guarded transition و قرارداد write-ahead journal، مدیریت Allowهای دیگر/GPO، رفع تداخل Blockهای قبلی و کنترل inbound/LAN. نوشتن و خواندن InterfaceAlias اثبات محدودشدن بسته‌ها به VPN نیست. P2 هنوز به این adapter برای Apply متصل نشده است؛ هیچ ادعای نبود نشتی یا دستور Enable/Disable نهایی وجود ندارد.

پیش‌فرض مستند Windows: explicit Allow بر default Block مقدم است و explicit Block بر Allow متعارض؛ به همین دلیل BlockAll دائمی با Allow استثنا روش صحیح این محصول نیست.
منابع:
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
