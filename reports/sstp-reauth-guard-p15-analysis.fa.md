# P15 — آزمون بومیِ اتصال TCP قدیمی و گارد ALE reauthorization

## نتیجهٔ qualified
**PASS محدودِ دو اتصال localhost؛ نه VPN disconnect، نه no-leak کل Windows و نه بسته آماده کاربر.**

- source: `45c56e1805a2da1835d5862b854c9f3f496163af`
- [اجرای نهایی run39298529079](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39298529079)
- checks=160؛ fault_cases=5؛ fresh_process_recoveries=5.
- existing_flow_cases=2، یکی IPv4 و یکی IPv6؛ post_guard_payload_bytes=0 در گیرندهٔ محلی، در بازه اندازه‌گیری هر case.
- control_roundtrips=6؛ fresh_flow_cases=2؛ owned_conflict_stops=3 سناریو، نه تعداد callها.
- fixture_sets=7؛ cleanup_sets=7؛ remaining_objects=0؛ هر set سه object معلوم دارد.
- baseline کامل Windows Firewall قرارداد P8 برابر=True؛ foreign display changes=0. این baseline کامل raw WFP نیست.
- ZIP SHA256=`d1f33fa4f2815cafea44ada5561b4000a69aba3c5fc961c496c6d3894f697fa1`. digest واقعی ZIP، نام/اندازه فایل، schema، source/run، counts، false ماندن scopeها و SHA256 هشت فایل کد با LF/CRLF checkout مستقل بررسی شدند. سبزبودن UI به‌تنهایی ملاک نبود.

## تغییر اجرایی، نه مدل تشخیص هویت
یک sublayer و دو filter پایدار/INDEXED بدون provider برای ALE_AUTH_CONNECT_V4/V6 ساخته شدند. شرط هر filter: ALE_APP_ID دقیقِ exe آزمایشی و FWPM_CONDITION_FLAGS با FWP_MATCH_FLAGS_ALL_SET روی FWP_CONDITION_FLAG_IS_REAUTHORIZE؛ action=BLOCK. AppID از API رسمی گرفته می‌شود؛ basename تصادفی و private ACL محدودیت اجباری fixture هستند. Windows SDK رسمی GUID/ساختار/constantها را می‌دهد، نه ABI یا GUID دست‌ساز.

این primitive **هر reauthorization** را برای A رد می‌کند، نه فقط reason=POLICY_CHANGE. ممکن است reauthorization مشروعِ pending connection یا تغییر interface هم قطع شود؛ چنین مصرفی برای محصول دائمی qualified نشده است. هیچ PERMIT اضافه نمی‌کند؛ initial authorization را هم خودش مسدود نمی‌کند. بنابراین **نه allowlist مقصد است و نه transition guard کامل** و نباید به‌تنهایی Enable شود. کنترل اتصال جدید نیازمند P14/سیاست مقصد/مسیر و گارد مشترک است؛ این integration در P15 انجام نشده است.

سه object باید همگی absent یا همگی exact-installed باشند. providerKey=NULL، marker، نام/شرح، flags دقیق بدون DISABLED/بیت ناشناخته، layer/sublayer، BLOCK، context، weight دقیق، شناسه‌های runtime غیرصفر/یکتا، AppID و mask/type/match هر دو condition قبل/بعد commit و در process تازه ممیزی می‌شوند. weight0x5a23 باید در همان write transaction آزاد باشد. ترتیب conditionها با GUID تطبیق داده می‌شود.

install/remove در یک transaction و journal P2 با ACL ادمین/SYSTEM، operation lock، hash exe، write-ahead installing/removing و recovery معلوم اجرا شدند. پنج fault همان before-native، بعد اولین Add داخل TX، پس از commit نصب، پس از اولین Delete داخل TX و پس از commit حذف‌اند؛ چهار TerminateProcess و یک خروج عمدی PowerShell با73. همه پنج مورد با process تازه از all-none/all-exact بازیابی شدند. corrupt primary با backup recovery_required باعث توقف Remove شد؛ backup مجوز حدس/adoption نیست. مدیر محلی متخاصم خارج مدل است.

## آزمون دریافت، دقیقاً چه چیزی را نشان داد
همه ترافیک آزمایش به127.0.0.1 یا::1 بود؛ DNS یا مقصد عمومی برای payload استفاده نشد. گیرنده C# فقط fixture است و WFP/سیاست را تغییر نمی‌دهد. A و B از باینری یکسان با path متفاوت‌اند و پیش از نصب guard، socket باز و echo موفق داشتند.

برای هر خانواده:
1. handshake tag مصنوعی از شمارنده payload جدا شد. اولین پیام nonce با۳۲بایت ASCII و newline یک‌بایتی ارسال شد؛ گیرنده دقیقاً۳۳بایت برای A و B ثبت کرد.
2. guard نصب شد؛ helper کاملاً خارج شد و audit تازه installed را تأیید کرد. برنامه‌های fixture فقط برای بازنگه‌داشتن socket قدیمی زنده بودند؛ نگهبان policy یا سرویس محصول نبودند.
3. B روی socket قدیمی echo موفق داشت؛ A فرمان ارسال تازه دریافت کرد، BLOCKED گزارش داد و گیرنده، **نه فقط timeout فرستنده**، عدم افزایش تعداد byte اتصال A را تأیید کرد. شمارنده هر بایت خوانده‌شده از socket پس از handshake را می‌شمارد، نه صرفاً تعداد پیام‌های کامل.
4. A تازه، درحالی‌که guard همچنان نصب بود، initial connect/echo موفق داشت. این یک کنترل ضروری برای reauth-only بودن primitive است، نه اثبات اجازه مقصد/مسیر محصول.
5. audit/idempotent و تست‌های conflict قاعده سالم را حفظ کردند؛ حذف دقیق guard انجام شد و اتصال تازهٔ A و B دوباره echo موفق داشتند.

بازه مشاهده شامل تلاش ارسال و انتظار پاسخ/خطا یا timeout خواندن۲۵۰۰ms و سپس۵۰۰ms انتظار است. اگر خطا زودتر برگردد، این بازه دقیقاً۳ثانیه نیست. صفر در receipt، مجموع delta دو case تکمیل‌شده است؛ هر case جداگانه delta=0 لازم داشت. این اندازه‌گیری محدودِ byte در گیرنده application است، نه packet capture، نه اثبات نبود packet کنترلی/byte روی wire و نه تضمین نامحدود زمانی برای همه flowها. دوباره زنده‌شدن socket مسدودشده پس از Disable آزموده نشد؛ برای کنترل پس از حذف از A تازهٔ موفق استفاده شد.

## چرا commit به‌تنهایی barrier نیست
[مستند رسمی ALE Reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization) می‌گوید پس از تشخیص policy change، اولین packet روی flow قدیمی برای reauthorization به لایه برمی‌گردد. [ALE Stateful Filtering](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering) نیز cache شدن مجوز flow تا تغییر policy را توضیح می‌دهد. این یک رفتار lazy/per-flow است، نه سند fence هم‌زمان همه socketها در لحظه FwpmTransactionCommit0.

آزمون P15 عمداً بعد از خروج installer و audit، ترافیک تازه روی socket قدیمی فرستاد و نتیجه در گیرنده را سنجید. بنابراین synchronous_commit_barrier_tested=false باقی ماند؛ از این دو flow نتیجه «هیچ packet قبلاً مجازشده‌ای در هیچ رقابتی بعد commit عبور نمی‌کند» گرفته نشده است. arrival-interface reauthorization در سند، جای آزمون قطع SSTP، route change یا بررسی IP_NEXTHOP_INTERFACE واقعی را نمی‌گیرد. NET_LUID نیز شناسه interface است؛ از منابع خوانده‌شده ضمانت دائمیِ تعلق آن به یک RAS session خاص به دست نیامد.

## تعارض و پاک‌سازی
سه سناریوی منفی: AppID مورد انتظار از exe معتبرِ fixture دیگر، کلید filter تغییرکرده که مجموعه ناقص می‌ساخت، journal خراب. دو سناریوی اول هم audit و هم remove را رد کردند؛ count=3 شمار سناریوست، نه callهای ردشده. تصویر اصلی فقط با اطلاعات معلوم harness بازگردانده شد. هیچ reset، Force-Allow، حذف بیگانه، تغییر profile/NIC/route/VPN یا دست‌کاری BFE/service انجام نشد.

هفت set سه‌شیئی در پایان با کلیدها و تصویر دقیق خودی absent تأیید شدند. شمار صفر فقط اجرای نهایی را پوشش می‌دهد، نه سابقه‌ای که رسید ندارد. raw WFP بیگانه snapshot کامل نشده؛ enumeration وزن sublayer فقط read-only admission بود. in-use ناشی از ارجاع بیگانه باید transaction را abort کند؛ تزریق آن در این مرحله آزموده نشد.

## سوابق غیرموفق و سلامت رسید
1. sourcee8cdb5ef67dfc13373da2ad07017650e27313360، [run39297090561](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39297090561): چهارcheck، قبل از ایجاد fixture policy متوقف شد. نام تابع Echo با alias PowerShell به Write-Output تداخل داشت. به‌جای ارسال واقعی، اشیای probe روی stdout افتادند؛ نام فایل تصادفی و tag مصنوعی fixture در آن log دیده شدند، نه داده/شناسه/credential کاربر. آن داده‌ها در receipt نبودند و این الگوی خروجی با نام InvokeFlowEcho اصلاح شد. fixture=0، remaining=0، baseline P8 برابر؛ payload_bytes=-1 یعنی آزموده‌نشده.
2. source87289d7bdd818a40a29b26b715869d8985326e19، [run39297426511](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39297426511): چهارcheck، اولین echo قبل policy متوقف شد. ورودی کنترل child به StreamReader صریحِ UTF8 با BOM detection تغییر یافت. این تغییر transport fixture بود، نه شل‌کردن WFP یا assertion. علت encoding بدون dump خام ورودی به‌عنوان نتیجه امنیتی قطعی استنباط نشد. fixture=0، remaining=0، baseline برابر و payload=-1 باقی ماند. receipt و ZIP و هر هشت hash دو اجرای اول حفظ/تأیید شدند.
3. source16adf117afc7fc365690314d5965d7068b7b919a، [run39297958437](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39297958437): log مرحله existing_IPv4 و RuntimeException در خط۵۷ را نشان داد. متغیر script:fresh هم counter بود و هم شیء اتصال تازه؛ شمارنده به object تبدیل شد و increment شکست خورد. validator نوع صحیح count را رد کرد؛ **build receipt/artifact تولید نشد**. کنترل schema حذف/شل نشد؛ متغیرهای counter و client جدا شدند. این اجرا فقط failure-observation جدا دارد، نه native receipt تأییدشده. شمار بررسی‌ها، cleanup و baseline نهایی آن unavailable هستند؛ cleanup_verified=false در observation یعنی تأیید نشده، نه اثبات باقی‌ماندن یا شکست cleanup. از رسید موجود اجرای موفق به گذشته صفر تعمیم داده نشده است. JSON محلی با field نامعتبر هرگز artifact نشد و محتوای object در چت/گزارش بازنشر نشد.

تعدادهای اجراهای ناموفق به۱۶۰check اجرای نهایی اضافه نشده‌اند. کد native گارد برای رفع خطاهای harness ضعیف نشد؛ gateهای kernel/ownership و معیار صفر دریافت دست‌نخورده ماندند.

## مرز تحویل و گام بعد
whole_machine_guard_tested=false؛ active_sstp_tested=false؛ vpn_disconnect_tested=false؛ reboot_tested=false؛ wire_capture_tested=false؛ synchronous_commit_barrier_tested=false؛ user_device_tested=false؛ ready_for_user_apply=false.

هیچ چیزی روی دستگاه کاربر اجرا نشد، بسته Enable تازه تحویل نشد، گزارش قبلی تکراراً درخواست نشد و مخزن قدیمی read-only ماند. اجرای نهایی فقط receipt شمارشی/hash upload کرد، نه raw journal/inventory، tag/nonce/port یا exe؛ استثنای stdout مصنوعی اجرای اول در بالا صریحاً ثبت شد.

گام بعد، یکپارچه‌سازی کنترل جریان قدیمی با محدودیت مقصد/رابط و frontier مشترک است؛ این primitive نباید مستقل یا با حذف gate exe fixture به سیاست کل Windows تبدیل شود. تعلق واقعی SSTP، مسیر خروجی واقعی در برابر local-address interface، lifetime/reuse، bootstrap محدود با حفظ TLS/CRL، IPv4/IPv6 عمومی، DNS/LAN، UDP، boot و قطع/وصل همچنان باید اجرایی و qualified شوند. آزمون موجود قدیمی یک gap را محدوداً پوشش داد؛ جای این موارد را پر نکرد.
