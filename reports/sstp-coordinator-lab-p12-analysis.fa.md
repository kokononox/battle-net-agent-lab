# P12 — هماهنگ‌کنندهٔ بومی مشترکِ guard/rule/profile، فقط آزمایش محدود

## نتیجهٔ qualified
**PASS محدودِ coordinator آزمایشی**؛ نه Enable/Disable کاربر و نه SSTP kill switch.

- source: `46fa0a68c1516b39d9a6e42e9def479608a08452`
- run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39231424822
- checks=124؛ model_pending_cases=20 برای before/after ده transition.
- fault_cases=8؛ fresh_process_recoveries=8؛ partial_enable_disables=2.
- release_conflict_stops=2؛ pre_release_pause_cases=2؛ injected_process_exits=10.
- fixture rules=4؛ remaining=0؛ cleanup_exact=True؛ final_stored_notconfigured=True.
- baseline کامل rule/هفت filter/profile نامرتبط برابر=True؛ foreign label drift=2.
- ZIP SHA256: `863916eea45852000980e7ba0946cd548ffa7135f4c8ae5bf3c06b5b9f8ded78`. digest فایل واقعی، schema/count/scope flags، source/run و hash هشت فایل کد با LF/CRLF checkout مستقل تأیید شدند.

ممیزی نهایی **policy-equal** بود، نه strict/byte-for-byte برابر: دو rule نامرتبط فقط در labelهای نمایشی مجاز قرارداد P8 اختلاف داشتند. تمام fieldهای policy، هر هفت filter و profileها برابر بودند؛ اختلاف نمایشی حذف یا overwrite نشد و count=2 در receipt حفظ شد. receipt نام/مقادیر یا ترکیب دقیق سه label در هر rule را نشان نمی‌دهد و از count آن‌ها استنباط نشده است.

## یک state مشترک، نه سه API پشت سر هم
Coordinator.ps1 schema مستقل P12 دارد: original سه raw rule/هفت filter، شش profile و policy/strict seal تمام ruleهای PersistentStore در یک journal امن P2 است. bits چهار resource، origin/cursor/pending با replay plan ثابت اعتبارسنجی می‌شوند؛ بنابراین profile عوض‌شده دیگر با baseline ثابت نامرتبط P9 اشتباه گرفته نمی‌شود. متدهای mutation legacy P9/P10/P11 یا journalهای آن‌ها پشت هم اجرا نشده‌اند؛ primitives P9/P11 و مدل Enabled-only گارد P10 زیر یک frontier مشترک استفاده شده‌اند.

Enable آزمایشی: guard on → old Allow off → Domain Block → new Allow on → ممیزی کامل تازه زیر guard → guard off.
Disable آزمایشی: guard on → new Allow off → Domain stored original=NotConfigured → old Allow original on → ممیزی کامل تازه زیر guard → guard off.

pending فقط قبل/بعد دقیق یک mutation معلوم را می‌پذیرد. Disable از Enable ناقص وضعیت مشاهده‌شدهٔ معلوم را normalize می‌کند و plan بازگردانی را از همان origin شروع می‌کند؛ نه اینکه Enable را اول کامل کند یا Force-Allow بزند. پس از disable/disabled، Enable دوباره رد می‌شود. journal خراب/گمشده یا backup recovery_required، تغییر policy/ownership/membership و profile ناآشنا هیچ adoption/reset/release خودکار ایجاد نمی‌کند.

full inventory در ورود و recovery، بلافاصله پیش از setter آزادسازی guard و قبل از completion بررسی می‌شود. هر setter write-ahead دارد و خود resource پیش/پس با همهٔ فیلترها مقایسه می‌شود؛ برای profile هر شش تصویر و settled-before/after P11 لازم است. فقط Enabled سه rule یا DefaultOutboundAction همان Domain نوشته می‌شود. سه label خارجی فقط با همان حضور/نوع string/null قرارداد P8 معاف‌اند؛ guard/new owned تماماً strict و field/filterهای دیگر strict هستند. سقف۱MiB قبل از اولین mutation سنجیده می‌شود. Native NotConfigured no-op قبل از هر Block/Enable باید موفق و در journal ثبت شود.

## دقیقاً چه چیزی native آزمایش شد
فقط سه rule fixture از پیش stage شده با GUID/Group معلوم و executable ناموجود یکسان مجازند؛ قانون old در آزمون با نام و برنامهٔ fixture است، نه قاعدهٔ قبلی واقعی runner. guard فقط همان executable را می‌پوشاند، نه کل ماشین. old/new Allow روی مقصدهای مستندسازی IPv4/IPv6 و TCP65534 هستند؛ **new Allow مقید به SSTP نیست**. تنها Domain غیرفعال، با کنترل COM CurrentProfileTypes و Get-NetConnectionProfile و original stored=NotConfigured، تغییر می‌کند. gateهای fixture/inactive نباید برای ساخت محصول حذف شوند.

هشت fault اصلی شامل guard بعد از Hold، old قبل از mutation، profile بعد از Block، new Allow بعد از Enable، قبل و بعد از آزادسازی guard، profile در Disable و قبل از release در Disable هستند. هر هشت با process تازه recovery شدند؛ دو مورد مستقیم از Enable ناقص به Disable رفتند. ده خروج73 شامل این هشت fault و دو pause اضافیِ منفی است؛ دو pause با هشت recovery اصلی خلط نشده‌اند.

دو conflict منفی هنگام pause قبل از release ایجاد شدند: label owned جدید و اضافه‌شدن یک rule. **بعد از restart، ممیزی ورود** آن‌ها را قبل از پیشروی journal رد کرد و guard held ماند. این آزمایش مخصوصاً recovery با conflict را می‌سنجد؛ به‌تنهایی آزمایش raceِ تزریق drift پس از entry audit در همان process نیست. کدِ release ممیزی کامل تازهٔ جدا دارد، اما read/check/set اتمیک نیست. تغییر admin یا policy بعد از ممیزی یا بعد از release، تضمین خودکار re-block ندارد. post-release completion audit نیز ممکن است بعد از خاموش‌شدن guard conflict ببیند؛ این کتابخانه نباید به‌عنوان تضمین کلی «هر خطا حتماً guard held» عرضه شود.

رویدادهای عمدی negative-test فقط پس از تطبیق کامل با تصویر دقیق همان تغییر معلوم undo شدند. canary یک بار در initializer بومی سنجیده شد؛ harness برای caseهای دیگر همان original/capability معلوم را در journal نو نوشت و خود worker قبل از اولین mutation ممیزی کامل لازم را اجرا کرد. این adopt کردن policy جدید یا نادیده‌گرفتن وضعیت واقعی نیست.

## پاک‌سازی و ماندگاری
در تست corrupt/missing journal، مسیر محصول guard را آزاد نکرد. cleanup مستقل CI فقط original/Enabled-variant کاملِ fixtureهای همین اجرا و Domain اصلیِ معلوم در process تست را می‌پذیرد؛ مجوز recovery حدسی محصول نیست. چهارمین rule فقط تست membership بود و با hash/هویت دقیق حذف شد؛ در پایان همهٔ fixtureها حذف و کل baseline P8 برابر شد.

خود coordinator lifecycle ایجاد/حذف stageها را مدیریت نمی‌کند؛ سه asset از قبل وجود دارند و پس از Disable به state اولیه برمی‌گردند. حذف stageها در تست کار harness است و lifecycle محصول هنوز باید journaled شود. گارد و تنظیمات native پس از خروج process می‌مانند و پایان process آن‌ها را خودکار undo نمی‌کند. resident/task/watchdog/expiry/rollback زمان‌دار ساخته نشده است؛ boot آزمایش نشده است.

## سوابق غیرموفق حفظ‌شده
1. source942c0c17739ebb9da1e88fefc114a348a4273910، run39228124773: failed در checks=2 قبل از canary/coordinator activation؛ سه fixture ساخته و همگی حذف شدند، remaining=0 و baseline کامل برابر بود.
2. sourcef04f78fe896e9fec5b34df0ad8055dec0a14d7f7، run39228650676: همان failed با diagnostic در Coordinator.ps1:96 و missing_property_Program. نام عمومی Program به‌اشتباه از raw CIM خوانده شده بود؛ نام خام رسمی AppPath است. accessor اصلاح شد؛ sealing/ownership/release gate حذف نشد. تغییر synthetic filter نیز از property موجود کشف‌شده استفاده کرد، نه فرض alias عمومی.
3. source87e8b17106f884820d6153615d3f990185ef12e7، run39229163269: توسط سقف خودکار job به علت exceeded maximum execution time of15m0s لغو شد؛ عامل آن را دستی cancel نکرد. در log هر هشت recovery دیده شد، ولی native JSON نهایی تولید نشد. artifact محدودِ تأییدشده native_outcome=cancelled و coord_native_unavailable با default counts=0، remaining=-1 دارد. این صفرها/falseها اطلاعات unavailable هستند، نه اثبات عدم mutation، وقوع drift، یا پاک‌سازی. cleanup/final baseline آن اجرا تأیید نشده و PASS نیست.

هر سه receipt و hash هشت فایل منبع هر اجرا حفظ/تأیید شدند. اجرای موفق سقف۲۵دقیقه روی همان نوع standard windows-2025 runner دارد؛ runner بزرگ‌تر یا مجوز گسترده‌تر نگرفت. ممیزی تکراری harness پیش از ایجاد journal fixture حذف شد؛ **ممیزی اجباری worker قبل از اولین mutation و تمام گیت‌های موتور تغییری نکردند**. Native-success script صریحاًexit0 دارد تا exit code تست‌های منفی در نتیجه نشت نکند. یکی از caseها عمداً BeforeMutation شد؛ مدل۲۰before/after همچنان کامل است.

## خارج از qualification و گام بعد
whole_machine_guard_tested=false؛ active_profile_targeted=false؛ sstp_binding_tested=false؛ packet_enforcement_tested=false؛ reboot_tested=false؛ user_device_tested=false؛ ready_for_user_apply=false.

این نتیجه هماهنگی native چند resource را ثابتاً در آزمایش محدود سنجید، نه اجرای خواستهٔ نهایی کاربر. همهٔ Allowهای واقعی، preflightهای firewall/BFE/GPO/merge و ActiveStore rules کامل، default همهٔ profileهای فعال، bootstrap محدود، binding سخت SSTP، دامنه/مقصد قابل‌ویرایش، IPv4/IPv6/DNS/LAN، disconnect/reconnect، اتصال‌های قبلی و boot/no-leak هنوز qualified نشده‌اند. گام بعد باید admission/lifecycle و backend قواعد مجاز واقعاً مقید به هویت SSTP و گیت مؤثر release را تکمیل کند؛ نه صرفاً برداشتن محدودیت‌های CI.

هیچ چیزی روی دستگاه کاربر اعمال نشد، هیچ بستهٔ اجرای تازه/فرمان Enable تحویل نشد و گزارش کاربر تکراراً درخواست نشد. فقط receipt محدود و hash منبع upload شده‌اند؛ raw inventory/journal/policy خصوصی upload نشده است.

## مرجع
نام خام AppPath: https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netapplicationfilter
