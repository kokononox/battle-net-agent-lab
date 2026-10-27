# حمل متعلق به نشست، در همان جریان و همان دفتر بازیابی

این ادامهٔ backend محلی است؛ نه بستهٔ تشخیصی جدید و نه ورودی آمادهٔ اجرای Windows. `OwnedTransport.ps1` و `MixedPolicyBackend.ps1` اضافه شده‌اند و state machine قبلی برای plan مشترکِ حمل و quarantine گسترش یافته است. qualifier بومی همچنان بسته است: observer اتصال واقعی SSTP، review زنده، quiescence و UI بازیابی مستقل هنوز bind نشده‌اند. هیچ فایروال واقعی Windows در این مرحله تغییر نکرد.

## مسیر واحد

1. baseline فاقد نام حمل همان نشست باشد؛ برخورد نام حتی در یکی از دو store توقف می‌دهد.
2. intent ساخت نوشته و readback شود؛ حمل با Enabled=False ساخته شود.
3. هر هفت فیلتر، Local/Active correspondence، program/service/protocol/port/address و نبود bypass/negation/dynamic address بررسی شوند. همهٔ مشخصات واقعیِ ساخته‌شده در **result دارای observed pair** ذخیره و readback شوند.
4. فقط پس از این materialization، intent فعال‌سازی حمل مجاز است؛ فیلترهای واقعی با همان receipt مطابقت داده شوند، نه فقط با چند فیلد template.
5. حمل فعال شود، سپس Allowهای local/effective دقیقاً بازبینی‌شده غیرفعال شوند. profile/default/Block/inbound/ازقبل‌disabled دست‌نخورده بمانند.
6. guard محدودیت برقرار باشد؛ RuntimeBridge همان coordinator قبلی رصد/audit/reducer را اجرا کند. هیچ مقصد برنامه یا فرزند/سرویس خودکار Allow نمی‌شود.
7. با audit-clean و quiescence و رضایت خروج، inverseها معکوس اجرا شوند: قواعد محلی → غیرفعال‌سازی حمل → حذف **فقط حمل غیرفعال همان نشست**. baseline دقیق دوباره سنجیده و journal بسته شود.

برای این کار coordinator یا journal دوم ساخته نشده است. `Get-UfwLocalBackendState` همان ترتیب intent/result/inverse را parse می‌کند؛ فقط result ساخت حمل، operation و observed pair را دربر می‌گیرد. سایر operation/resultها فرمت قبلی را نگه داشته‌اند. mode محلی قبلی همچنان regression می‌شود.

## محدودیت قاعدهٔ بومی

نام/گروه/marker از session_id تصادفی همان storage و binding مشاهدهٔ SSTP ساخته می‌شوند. spec فقط یک قرارداد دادهٔ خصوصی است؛ shape/hash آن **اثبات اتصال یا رضایت نیست**. callbackهای واقعی باید actor، مشاهدهٔ تازهٔ اتصال و review را به آن bind کنند؛ receipt قابل‌بارگذاریِ approval=true نداریم.

native creation فقط PersistentStore، ابتدا disabled، Outbound/Allow، System32 svchost، SstpSvc، TCP/443 و ۱تا۸IP literal canonical بازبینی‌شده را می‌پذیرد. پارامترهای cmdlet از یک dictionary ثابت ساخته می‌شوند؛ ورودی arbitrary parameter پذیرفته نمی‌شود. native adapter مسیر را با SystemDirectory واقعی، SHA256 مورد بازبینی و امضای معتبر Microsoft تطبیق می‌دهد. امضا و hash تضمین ضد مدیر مخرب نیستند و هنوز روی Windows این جریان اجرا نشده است.

AppPath، ServiceName و DynamicTransport نام‌های خام CIM هستند؛ Program، Service و DynamicTarget ممکن است projection نمایشی PowerShell باشند. checker بر کلاس‌ها و propertyهای خام تکیه دارد، نه حدس از خروجی Format-List. IsNegated و OverrideBlockRules نباید true باشند. property ناشناختهٔ قاعده/فیلتر حمل رد می‌شود، نه نادیده. metadata و تمام فیلترهای شناخته‌شده در materialization نگه داشته می‌شوند؛ پیش از enable تغییر آنها جز Enabled و metadata مشاهده‌ایِ مشخص‌شده پذیرفته نمی‌شود.

InterfaceAlias/InterfaceType این **حمل زیرساختی** Any است؛ این ادعای محدودشدن دادهٔ برنامه به NIC تونل نیست. خام InterfaceType در receipt pin می‌شود، ولی عدد آن برای اثبات Any یا application binding تفسیر نشده است. تنها محدودیت‌های service+program+TCP443+endpointهای دقیق برای این حمل استفاده می‌شوند. در این مرحله grant دادهٔ برنامه صفر است؛ binding دادهٔ برنامه به تونل هنوز هدف نسخهٔ بعد است.

حذف با InputObject تازه از PersistentStore انجام می‌شود، نه wildcard، prefix، Name یا Group عمومی. adapter حذف، InstanceID/Enabled/Description/RuleGroup را دوباره با spec می‌سنجد؛ backend علاوه بر آن تمام snapshot/فیلتر/receipt را تطبیق داده است. قاعدهٔ foreign، enabled ناشناس، تغییرکرده یا نیمه‌ساخته کورکورانه حذف نمی‌شود.

## قطع در میانه و بازیابی

- crash بعد از ساخت disabled ولی پیش از result: saved create intent و تطبیق کامل قرارداد اجازهٔ reconcile/cleanup همان disabled rule را می‌دهند؛ نبود result هرگز مجوز enable نیست.
- پس از materialization، جابه‌جایی حتی property شناخته‌شدهٔ دیگر با receipt توقف می‌دهد.
- exception بعد از enable، disable یا remove: intent معکوس/مستقیم باقی است و مشاهدهٔ دقیق before/after تعیین می‌کند آیا اثر انجام شده؛ عملیات کورکورانه تکرار نمی‌شود.
- اگر شکل نیمه‌ساخته، فیلتر خوانده‌نشده، source غیر Local، مبدأ جابه‌جاشده یا head نامطمئن باشد، pending باقی می‌ماند. پاکسازی خودکار برای «سبزشدن تست» نداریم.
- forward guard هنگام disconnect باید ادامه را ببندد؛ نه DNS/443 عمومی اضافه شود و نه quarantine بعدی با حمل تأییدنشده جلو برود. native اتصال واقعی این guard هنوز تکمیل نشده؛ fixture قطع پیش از enable را می‌آزماید.
- recovery باید بدون اینترنت ممکن باشد: guard فاز restore/recovery، actor/audit/quiescence/exit consent را می‌سنجد، نه شرطِ دوباره‌وصل‌شدن SSTP. ساخت/امضاسنجی قاعده در recovery دوباره اجرا نمی‌شود. UI/قفل سراسری/pending scanner این ورودی مستقل هنوز تکمیل نشده‌اند.

## شواهد، بدون ادعای qualification Windows

آزمون mixed همان coordinator اصلی، backend مشترک، journal فایل واقعی و RuntimeBridge/reducer موجود را اجرا می‌کند. rule provider، رخدادها، audit API و رضایت/qualification فرضی‌اند؛ Windows API واقعی اجرا نشده است. سناریوهای normal، effect نامعلوم، create/enable بی‌اثر، exception بعد از اثر و disconnect بررسی می‌شوند. همچنین مرزهای durable رفت/برگشتِ چهار عملیات ناهمگون جدا قطع و از journal بازشده در همان پردازش بازیابی می‌شوند. فرایند تازهٔ Windows یا power-loss واقعی نیست.

آزمون دست‌کاری شامل service/program/port/address عمومی، unknown property، bypass، negation، تغییر receipt، برخورد نام و تغییر spec است. در حالت عادی، قبل از quarantine حمل فعال و هنگام خروج آخر از همه حذف می‌شود؛ Capture از رصدگر موجود استفاده می‌کند و هدف واقعی اجرا نمی‌شود. شمارش دقیق در `evidence/mixed-policy-backend-tests.json` و گزارش کلی در `evidence/QA-SUMMARY.json` است.

## کار اجراییِ باقی‌مانده

- bind observer تازهٔ SSTP و هویت svchost/برنامه، review محلی دقیق و انقضای رضایت به spec/plan؛ در capture قطع یا تغییر اتصال واقعاً دیده شود.
- bind guard واقعی audit/quiescence/exit، قفل سراسری و pending scanner به ورودی مستقل recovery.
- بازبینی هزینهٔ full-filter recheckهای تکراری؛ performance برای ۱۰۶قاعده روی Windows اندازه‌گیری نشده و مسیر فعلی بهینه یا آمادهٔ انتشار معرفی نمی‌شود. مشاهدهٔ ترتیبی compare-and-swap اتمیک علیه GPO/admin نیست.
- سپس یک بستهٔ واحد و آزمون هدفمند Windows؛ نه درخواست تکرار inventory موفق یا ارسال snapshot خصوصی.

SSTP ازقبل‌متصل دامنهٔ نسخهٔ نخست است. cold-start/reconnect/reboot/underlay-switch پشتیبانی‌شده ادعا نمی‌شوند؛ هدف یک پروفایل برنامه‌محور فعال و ابتدا Battle.net باقی است. هنوز نصب کامل، no-leak یا جلوگیری fingerprint تضمین نشده است.

## مراجع قرارداد بومی

- https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/remove-netfirewallrule?view=windowsserver2025-ps
- کلاس‌های خام در MicrosoftDocs/win32، زیر `desktop-src/FWP/wmi/wfascimprov/`: MSFT_NetApplicationFilter، MSFT_NetServiceFilter، MSFT_NetProtocolPortFilter، MSFT_NetAddressFilter، MSFT_NetInterfaceFilter، MSFT_NetInterfaceTypeFilter و MSFT_NetNetworkLayerSecurityFilter.
