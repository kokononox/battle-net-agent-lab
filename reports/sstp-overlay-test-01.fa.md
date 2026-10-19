# نسخهٔ آزمون ۰٫۱ — فهرست مجاز مستقل روی تونل

## نتیجه و محدوده
بستهٔ محدودِ قابل‌آزمون ساخته شد؛ **نه کیل‌سوییچ کامل و نه گواه نبود نشتی کل Windows**. کنترل اتصال VPN و فایل SstpKillSwitch-v1.2 دست‌نخورده‌اند. هیچ تنظیمی روی دستگاه کاربر از این محیط اعمال نشد.

این معماری به‌جای بازنویسی اتصال/نشست SSTP یا قرنطینهٔ همهٔ Allowهای واقعی، فقط Block متمم IPهای انتخابی را روی InterfaceType=RemoteAccess اضافه می‌کند. Blockهای صریحِ غیرمتعارض با مقصدهای مجاز، اجازهٔ عمومیِ تونل را برای سایر مقصدها خنثی می‌کنند؛ هیچ Allow جدیدی ساخته نمی‌شود. محافظت بیرون تونل همچنان به سیاست قبلی وابسته است و ضعف‌های استثنای DNS/TCP443 و Allowهای قبلی آن اصلاح نشده‌اند. همهٔ RemoteAccessها پوشش داده می‌شوند، نه فقط پروفایل یا RAS-session منتخب.

## کد و اجرای نهایی
- source: `885cdea9622e68dbfde86ed744880efd23f4561c`
- [اجرای ویندوز 39306646656](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39306646656)، job118245332029، Success، کل۴m۲s.
- ۲۵۷ بررسی pure روی محاسبات IPv4/IPv6 و پذیرش دقیق وضعیت enforcement.
- ۴۰ بررسی native؛ ۱۲ خروج کارگر با کد موردانتظار: ۹موفق، ۲قطع عمدی73 و ۱رد تعارض مالکیت.
- دو fault قبل/بعد از اولین تغییر Enabled، بازیابی در process تازه؛ Disable آزمایشی حتی هرگونه ActiveStore-query را رد می‌کند تا به VPN متصل/Full وابسته نباشد.
- شش جفت TCP connect IPv4 برای A هدف و B کنترل؛ مقصد عمومیِ عددی انتخاب‌شده از setup lookup github.com، پورت443؛ بدون HTTP/credential/application payload. کنترل همیشه اتصال موفق داشت. Worker پیش از probe خارج شده بود.
- سیاست نامرتبط طبق قرارداد P8 برابر؛ foreign display changes=0؛ remaining objects=0.
- ساخت و Dispose یازده کنترل پنجره در Windows موفق؛ کلیک واقعی کاربر روی دکمه‌های GUI آزموده نشد.
- RemoteAccess واقعی صرفاً با سه قانون **غیرفعال** stage/readback/remove شد. اعمال فعال CI فقط روی exe fixture GUIDدار با InterfaceType=Any بود. هیچ full-machine یا RemoteAccess-wide Block فعال روی runner ایجاد نشد.

SHA256 ZIP رسید=`9c8eff9ac97b155d814944425f888c0c702e7b430056754e649df0c22cbce347`. digest واقعی ZIP، نام/اندازهٔ یگانهٔ build-receipt.json، schema/source/run، نوع و مقدار counts، flags و SHA256 هر۱۶فایل کد در checkout با LF/CRLF مستقل تطبیق داده شدند. سبز بودن UI تنها معیار نبود.

## طراحی اعمال و بازگشت
سه قانون Block خودی: guard موقتِ منطقیِ گذار و دو متمم v4/v6، همگی PersistentStore. guard روی RemoteAccess است، نه کل دستگاه؛ «موقت» یعنی فقط هنگام عمل روشن است، نه دارای انقضای زمانی. ایجاد اولیهٔ هر سه غیرفعال است. تصویر raw rule و هفت filter با journal P2 خصوصی Admin/SYSTEM، lock مستقل عملیات، revision و write-ahead ثبت می‌شود.

Enable: audit دقیق → guard on → بررسی ActiveStore → v4/v6 on → audit/ActiveStore → guard off → audit نهایی. Disable: guard on → v4/v6 off → guard off، با بررسی PersistentStore و بدون نیاز به اتصال VPN/Full در ActiveStore. این فقط محدودیت خود ابزار را برمی‌دارد؛ policy قبلی را به Allow تبدیل نمی‌کند. Remove فقط قواعد غیرفعال خودی با تصویر دقیق را حذف می‌کند؛ Group یا DisplayName مجوز حذف نیست. حفظ journal بعد از حذف برای تداوم مالکیت/کنترل باقی‌ماندن قواعد است، نه برنامهٔ مقیم.

Prepare از resolver فعلی Windows snapshot دامنه می‌گیرد؛ DNS به مسیر VPN pin نشده و کاربر پیش از lookup هشدار می‌بیند. تغییر config بعد از Prepare باعث رد Enable می‌شود. تغییر فهرست فعال در این نسخه Disable/Prepare/Enable است؛ بین آن‌ها فقط محافظت قبلی وجود دارد و live-update اتمیک ادعا نشده. IP مشترک مجوز انحصاری hostname نیست. private IP/LAN target پذیرفته نمی‌شود؛ DNS خصوصی داخل VPN استثنای اختصاصی ندارد.

PrimaryStatus خام باید OK=1 باشد. EnforcementStatus قواعد فعال با Profiles=Any باید Full=1 تنها، یا مجموعهٔ دقیق Full=1 و InactiveProfile=5 باشد. inactive-only، duplicate، unknown و همهٔ خطاهای دیگر ازجمله FirewallOff/Disabled/InterfaceResolutionEmpty رد می‌شوند. این وضعیت API، گواه packet barrier یا ماندن شرایط پس از تغییر آینده نیست.

guard به‌صورت خودکار بر اثر exit/error/timer برداشته نمی‌شود. journal خراب/backup-only یا ownership drift باعث توقف می‌شود، نه reset. توقف بین ایجاد غیرفعال و capture original به staging غیرقابل adoption خودکار می‌انجامد؛ آن مرحله هنوز guard فعال نمی‌سازد. administrator متخاصم و تغییر همزمان خارج lock پوشش تضمین نیستند.

## سوابق دقیق اجراها
1. [run39304479507](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39304479507)، sourcef193f909444678f74535473e127466c320b758f3: PASS اولیهٔ موتور، pure247/native40،۱۲worker،۲fault،۶pair،remaining0، baseline policy برابر و **۲اختلاف نمایشی خارجی**. هنوز UI smoke و گیت Full/OK جدید نداشت. ZIP رسید `190ef9fe4f578465b5612bad4d25a9b6d42dd9056af6958e3c5b0be060aa32d0` و۱۶hash مستقل تأیید شدند.
2. [run39305596172](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39305596172)، sourcece1bcebbb0c32134658e78bc73db1631c56f2297: UI موفق، native پس از۴check روی انتظار خروج اولین Worker رد شد. آن نسخه خطای child را به parent منتقل نمی‌کرد؛ علت دقیق از رسید همان اجرا استنتاج نشد. cleanup0، policy برابر، display0. ZIP=`26fece4d0149394fafec49a115cbed57801e72ceea8afc8f417af9fd90c000b9`،hashها تأیید شد.
3. [run39306221744](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39306221744)، source637090974d69dd4b167351372c685ca1dfa52123: انتقال bounded نتیجهٔ Worker و مقادیر خام CIM اضافه شد؛ native دوباره پس از۴check رد شد. این بار خطا روشن بود: guard با Primary=1 و EnforcementStatus=[5,1] مواجه شد؛ گیت تک‌عضوی Full، ترکیب مستند Full+InactiveProfile را بیش‌ازحد سخت‌گیرانه رد می‌کرد. دو rule غیرفعال دیگر status=[4]/Primary=2 داشتند. فقط همین اعدادِ خودی ثبت شد، نه نام/IP/journal. cleanup0 و policy برابر/display0. ZIP=`6e1ffd1739943bdb98d8a512d48666b7f01b8c1c3cd95727c9439fc831a6c181`،hashها تأیید شد.
4. اجرای نهایی ترکیب دقیق۱/۵ را با الزام وجود Full و PrimaryOK و رد خطاهای دیگر می‌پذیرد؛۱۰unit منفی/مثبت به pure افزوده شد. شرط Full حذف نشد؛ پروفایل/فایروال تغییر نکرد و نتیجهٔ packet/test برای سبزکردن ضعیف نشد. اعداد اجراهای قبلی به counts نهایی اضافه نشده‌اند. صفر نهایی به گذشته تعمیم داده نشده است.

## بستهٔ کاربر
فایل Sstp-Whitelist-Test-0.1.zip شامل۱۱فایل runtime، راهنمای فارسی آفلاین، رسید نهایی و manifest است؛ fixture exe، journal و inventory خصوصی داخل آن نیستند. همهٔ runtimeها با payload source تأییدشده byte-for-byte تطبیق داده شدند؛ بازخوانی ZIP و hash تک‌فایل‌ها انجام شد. Start.cmd فقط پنجره را با UAC باز می‌کند؛ هیچ Enable خودکار ندارد. Enable + exit و Disable + exit پایان process اختصاصی را در طراحی اجرا می‌کنند؛ سرویس/task/watchdog/expiry ساخته نمی‌شود. Disable.cmd مستقل از اتصال فعلی VPN مسیر بازگشت را فراهم می‌کند.

## مرز حل‌نشده
real_sstp_tested=false؛ remote_access_packet_tested=false؛ ipv6_packet_tested=false؛ disconnect/reboot/user_device_tested=false؛ ready_for_production=false. TCP تازهٔ IPv4 != جریان قدیمی/UDP/ICMP یا pcap. Persisting policy != تضمین no-leak boot. preflight وجود SSTP و default Block، گواه سلامت کامل کیل‌سوییچ قبلی نیست. این تحویل برای آزمون محدود و برگشت‌پذیر کاربر است، نه جایگزینی بی‌خبرِ شرط نبودنشتی.

## منابع رسمی
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule
- https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule
