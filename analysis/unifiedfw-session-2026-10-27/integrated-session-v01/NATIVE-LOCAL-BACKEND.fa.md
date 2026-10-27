# اتصال اجرایی قواعد محلی به جریان موجود

این ادامهٔ همان `integrated-session-v01` است؛ بستهٔ تشخیصی جدید یا دستور اجرای Windows نیست. کد بومیِ تغییر فقط `Enabled` و بازگردانی قواعد محلی اضافه شده، ولی ورودی زنده، حمل SSTP متعلق به نشست و review نهایی هنوز کامل نیستند. `ready_for_apply=false` باقی است.

## پیاده‌سازی واقعی در سورس

`NativePolicyIO.ps1` یک IO بومی تعریف می‌کند: PersistentStore و ActiveStore با TracePolicyStore، سه profile و هر هفت فیلتر وابسته. دو بار همهٔ فیلترها خوانده و مقایسه می‌شوند؛ برخلاف inventory قبلی، بازخوانی صرفاً header نیست. بااین‌حال این مشاهدهٔ ترتیبی نه snapshot اتمیک WFP است، نه قفل علیه تغییر GPO/admin. داده‌ها فقط برای نشست محلی‌اند؛ هیچ private snapshot کاربر خوانده، دریافت یا منتشر نشده است.

`Name` نمایشی PowerShell لزوماً property خام CIM نیست؛ شناسهٔ خام بومی `InstanceID` است. backend همان شناسه را با نام مشاهده‌شده تطبیق می‌دهد و نام دارای wildcard را به پارامتر Name یک cmdlet تغییردهنده نمی‌فرستد. comparator قبلی برای InstanceID اصلاح شد؛ تمام propertyها و فیلترهای ناشناخته همچنان مقایسه می‌شوند. رکورد تاریخی با Name از fixture قدیمی برای regression قابل‌مقایسه مانده، اما backend بومی InstanceID می‌خواهد.

برای Allow فعالِ outbound، تنها source=Local با نام یکتای case-insensitive و رکورد local/effective کاملاً مطابق پذیرفته می‌شود؛ source path در binding تازه نگه داشته می‌شود و برابری نام به‌تنهایی مجوز نیست. وجود Allow غیرقابل‌تطبیق، AllowBypass/enum ناشناخته، profile غیر Block، فیلتر نامطمئن یا drift توقف می‌دهد. خروجی planner هنوز **پیشنهاد quarantine برای review محلی** است، نه رضایت برای خاموش‌کردن خودکار ۱۰۶قاعدهٔ قبلی.

تنها فراخوانی تغییردهندهٔ جدید این است:

```powershell
Set-NetFirewallRule -InputObject $native -Enabled $enabled -Confirm:$false -ErrorAction Stop
```

`$native` باید یک شیء CIM تازه‌خوانده‌شده از PersistentStore و متعلق به همان intent ثبت‌شده باشد. برنامه، سرویس، آدرس، پورت، profile، default، Block، inbound یا قاعدهٔ ازقبل‌غیرفعال تغییر نمی‌کنند. این backend هیچ Allow تازه‌ای نمی‌سازد و transport writer نیست. در این محیط Set-NetFirewallRule واقعی اجرا نشده است.

`LocalPolicyBackend.ps1` از همان journal فایل واقعی و همان coordinator استفاده می‌کند: baseline → intent → اثر → readback → result. قبل از هر اثر، head واقعی journal، baseline و ترتیب intentها کنترل می‌شوند. بررسی کلی policy جز تغییرات Enabled متناظر با prefix مجاز، نباید تفاوتی نشان دهد. فراخوانی بدون saved intent، جهش ترتیب یا تغییر plan رد می‌شود. backend از طریق `New-UfwLocalCoordinatorBindings` مرحله‌های Backup/SaveIntent/Observe/Mutate/Verify/SaveResult/Restore/Finish موجود را می‌بندد؛ coordinator اصلی دوباره نوشته نشده است.

## بازیابی و خطا

اثرِ رخ‌داده با result گم‌شده، موفقیتِ فرضی یا قاعدهٔ حذف‌شده تلقی نمی‌شود. recovery فقط دو حالت دقیق before/after مربوط به آخرین intent با اثر نامعلوم را می‌پذیرد؛ بقیهٔ policy باید با prefix مجاز مطابق باشد. inverse به ترتیب معکوس، با restore_intent قبل از اثر و restore_result بعد از readback انجام می‌شود. ابهام checkpoint/head توقف می‌دهد، نه بازنویسی یا اعتماد به حافظهٔ قدیمی. برای retry بعد از بازگشت اثر و خطای provider، اثر دوباره اجرا نمی‌شود اگر before دقیق تأیید شود.

guard مستقل و صریح برای actor/review/fresh SSTP و برای audit-clean، quiescence و exit consent لازم است. این guardها هنوز به UI/observer بومی نهایی bind نشده‌اند و با مقدار true از فایل کاربر جایگزین نمی‌شوند. recovery محلیِ prefix پیاده شده؛ scanner قفل سراسری/pending نشست، ورودی مستقل Windows و بازیابی حمل هنوز کامل نیستند. بسته‌شدن قبلی journal هم برای ادعای مطابقت تازه کافی نیست: recovery دوباره baseline را می‌سنجد و drift را رد می‌کند.

## مرز آزمون

آزمون داخلی روی Linux/PowerShell7 اجرا شد: coordinator اصلی با همین backend محلی و journal فایل واقعی؛ provider اثر در حافظه و capture/qualification فرضی‌اند. reader بومی واقعی هم با cmdletهای fixture و serializer CIM موجود اجرا شد؛ نه MI API واقعی Windows. تست‌های خطا شامل اثر پس از exception، اثر اجرا‌نشده، head نامطمئن، guard refusal، تغییر فیلتر/مبدأ/قاعده/profile، ترتیب نادرست، restore پس از اثر و بازکردن دوبارهٔ journal هستند. برای دو قاعده، تمام مرزهای durable مسیر رفت/برگشت جدا قطع و از فایل بازخوانی می‌شوند. این reopen در همان پردازش آزمون است، نه تأیید اجرای recovery در یک پردازش تازهٔ Windows.

گزارش دقیق در `evidence/local-policy-backend-tests.json` و مجموعهٔ کلی در `evidence/QA-SUMMARY.json` است. AST نیز تنها یک setter خصوصی با پارامترهای InputObject/Enabled/Confirm/ErrorAction را مجاز می‌داند. تست PowerShell5.1 یا دوام power-loss/ACL جریان جدید Windows ادعا نشده است. خواندن کل فیلترها چندبار هزینه‌بر است؛ benchmark یا ادعای سرعت روی ۱۰۶قاعده نداریم. سقف زمان بین cmdletها بررسی می‌شود و cmdlet درحال‌اجرا hard timeout ندارد.

## باقی‌مانده تا یک بستهٔ واحد قابل‌آزمون

- plan و dispatcher مشترکِ transport متعلق به نشست و quarantine، همراه ایجاد/حذف محدود همان transport؛ backend فعلی عمداً plan شامل transport را اجرا نمی‌کند و scope آن local_quarantine_backend_development است.
- bind review برنامه/endpoint/هویت SSTP تازه و تشخیص قطع اتصال؛ مقصد برنامه در زمان اجرا پیشنهاد می‌شود، انتخاب فایل مجوز مقصد نامعلوم نیست.
- bind guard واقعی quiescence/audit/exit، قفل سراسری و recovery مستقل محلی به ورودی واحد؛ سپس qualification بومی با یک آزمون هدفمند.

هیچکدام با «qualified» کردن fixture یا جابه‌جایی checksum رفع نمی‌شوند. تا تکمیل این اتصال‌ها، نه ZIP جدید، نه درخواست تست/فایل خصوصی از کاربر و نه ادعای آمادهٔ Apply. دامنهٔ نخست همان SSTP ازقبل‌متصل، صفر grant دادهٔ برنامه در رصد و بدون ادعای reconnect/reboot/جلوگیری fingerprint است.

## مراجع قرارداد بومی

- Microsoft MSFT_NetFirewallRule: InstanceID و Enabled=1/2، Action و Direction، source tracing — https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule
- Microsoft Set-NetFirewallRule: مجموعه‌پارامتر InputObject و Enabled؛ PersistentStore در برابر ActiveStore — https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule?view=windowsserver2025-ps
