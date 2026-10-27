# تراکنش ایزولاسیون موقت — طراحی و مدل آفلاین ۰٫۱

## خروجی این مرحله، نه وعدهٔ اجرای آماده

قرارداد مرحلهٔ quarantine و مدل ترتیب تغییر/بازیابی ساخته و آزموده شده است. **هیچ adapter بومی فایروال، baseline خصوصی واقعی، بستهٔ Apply، task بازیابی یا فرمان قابل‌اجرای Windows تحویل نشده است.** core فقط اشیای حافظه‌ای Python و برچسب عملیات تولید می‌کند؛ فایل، شبکه، subprocess، رجیستری یا API ویندوز ندارد. ready_for_apply، plan_executable و no_leak_certified همواره false هستند. Trueهای Assumptions در fixture صرفاً فرض مدل‌اند، نه شواهد واقعی یا رضایت کاربر.

## چرا مرحلهٔ تازه لازم است؟

رسید ALLOW-REVIEW-01: هر سه پروفایل فعال و outbound Block؛۴۲۶ قاعدهٔ دیده‌شده،۱۰۶Allowخروجی فعال،صفر مطابق predicate محدود حمل SSTP و صفر خطای فیلتر. تمام۱۰۶مورد سرویس غیر از SstpSvc دقیق داشتند؛۱۰۴پورت غیر443دقیق،۱۰۳مقصد غیرIPصریح،۷۸پروتکل غیرTCP و۷۶مسیر غیرsvchostدقیق. دلیل‌ها هم‌پوشان‌اند؛ اینها خطرناک‌بودن یا قابلیت استفادهٔ نصب‌کننده از همهٔ قواعد را اثبات نمی‌کنند. از گزارش شمارشی نمی‌توان backup یا طرح تغییر۱۰۶قاعدهٔ واقعی ساخت. fixture۱۰۶قاعده در تست کاملاً ساختگی است.

Allow صریح می‌تواند default Block را پشت سر بگذارد؛ Block صریح نیز بر Allow متعارض غلبه دارد. بنابراین افزودن Block-all و سپس Allow انتخابی راه‌حل نیست. این قواعد precedence برای outbound نیز برقرارند.[^https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules]

ActiveStore جمع policyهای مؤثر است؛ PersistentStore فقط policy محلی پایدار است. منشأ مؤثر باید با TracePolicyStore/شناسهٔ بومی/فیلترهای کامل بررسی و به شیء محلی قابل‌کنترل نگاشت شود، نه اینکه PolicyStoreSource دلخواه مستقیماً به setter داده شود. مستندات همچنین برخی قواعد AppContainer و محدودیت‌های سرویس را خارج از پوشش Get-NetFirewallRule توصیف می‌کنند؛ این cmdlet به‌تنهایی اثبات inventory کامل WFP نیست.[^https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps]

## دامنهٔ محدودِ نسخهٔ نخست طراحی

فقط baseline فعلی‌ای که **هر دو مشاهدهٔ local/effective تازه** فعال و outbound Block باشند پشتیبانی می‌شود؛ defaults اصلاً تغییر نمی‌کنند. قواعد Block، قواعد inbound و قواعد ازقبل disabled دست‌نخورده می‌مانند. هر Allow مؤثر غیرقابل‌کنترل/managed/نامعلوم مانع ادامه است، نه مجوز تغییر GPO یا دورزدن مدیریت دستگاه.

این مرحله برای رصد تلاش مسدود است و **صفر grant دادهٔ برنامه** دارد. مقصدهای برنامه، فرزندان و سرویس‌های کمکی خودکار مجاز نمی‌شوند. طرح browser/game/installer قبلی و اصل فقط یک پروفایل فعال حفظ می‌شوند؛ mode switch بومی یا full enforcement در این مرحله پیاده نشده است.

## ترتیب پیشنهادیِ وابسته به پیش‌شرط‌ها

1. **inventory خصوصی کامل و تازه:** پروفایل‌ها، منشأ قواعد، همهٔ فیلترها و metadata مرتبط، اتصال local/effective، اشیای Block/disabled، IPsec/WSH/third-party و تغییرات هم‌زمان. unknown یعنی توقف. fingerprint مدل جای backup قابل‌بازخوانی نیست.
2. **بازبینی و رضایت محلی دقیق:** فهرست دقیق اشیای مجاز به تغییر، استثنای حمل، baseline و برنامهٔ بازیابی باید نمایش داده شود. consent قبلی prepare/candidate/audit و دکمهٔ «شروع کن» مجوز setter تازه نیستند.
3. **backup و مسیر recovery مستقل از شبکه:** journal جدا و قفل انحصاری، readback کامل، هویت نشست/عامل، before دقیق و intentهای append-only؛ توانایی recovery محلی باید پیش از کاهش دسترسی آزموده شود. journalهای قدیمی دست‌نخورده‌اند.
4. **حمل SSTP قبل از quarantine:** اگر حمل دقیق قبلاً وجود ندارد، فقط پس از review مقصد/سرویس، شیء متعلق به نشست ابتدا disabled ساخته، readback و سپس enable/بررسی شود. broad443/DNS، تغییر hostname بهIP، TLS bypass و حدس server ممنوع‌اند. اتصال فعلی SSTP، اثبات کارکرد rule دقیق مستقل از Allowهای قبلی نیست.
5. **quarantine صریحِ موردی:** فقط Allow محلیِ بازبینی‌شده و قابل نگاشت، یکی‌یکی Enabled=false؛ نه حذف، نه بازسازی، نه غیرفعال‌سازی همه با یک pipeline. پیش از هر اثر intent پایدار و بررسی before؛ پس از آن readback کامل و checkpoint لازم است. در مدل حمل قبل از این مرحله است؛ اجرای واقعی تا qualification انتقال و bootstrap ممنوع می‌ماند.
6. **راستی‌آزمایی محدودیت:** local/effective دوباره کامل خوانده شوند؛ Allow نامنتظر یا drift توقف است. هیچ نصب‌کننده‌ای در آماده‌سازی اجرا نمی‌شود. تا coverage، flowهای قدیمی، TLS/DNS/DHCP/route، reconnect و recovery بومی آزموده نشده‌اند، از نتیجهٔ مدل READY اجرایی نسازید.
7. **بازیابی جدا و صریح:** ابتدا توقف/بی‌کاری تأییدشدهٔ هدف و helperها، سپس restore دقیق تغییرات همین نشست به ترتیب معکوس، با journal و readback هر اقدام؛ در پایان فقط اشیای حمل ساخته‌شدهٔ خود نشست و با مشخصات دقیق پاک شوند. هیچ شیء foreign حذف/بازسازی نشود.

## ماشین مدل

`compile_model` بعد از فرض‌های مدل، create-disabled/enable حمل و disable تک‌تک Allowهای foreign را به‌صورت اشیای غیرقابل‌اجرا می‌چیند. snapshot ورودی شامل Ruleهای fixture با fingerprint کاملِ ادعایی است؛ فایل Windows backup یا schema عمومی import نیست. digest فقط تغییر محتوا را تشخیص می‌دهد، نه امضا/رضایت/anti-rollback.

`open_model` → `request_intent` → `confirm_intent_checkpoint` → `model_write_precondition` → مشاهدهٔ اثر در حافظه → `acknowledge_observation` → `confirm_result_checkpoint`. پیش از checkpoint معتبر، مرحلهٔ بعدی اجازهٔ مدل ندارد. هیچ تابعی setter ندارد. حتی نتیجهٔ `restricted_model_observation` دارای target_execution_authorized=false است.

در crash پس از intent، اثر ممکن است اعمال شده یا نشده باشد؛ success counter کافی نیست. `recovery_preview` فقط prefixهای reachable همان intentهای ثبت‌شده را می‌پذیرد؛ rollback به قبل از checkpointهای کامل، شیء اضافه/حذف‌شده یا تغییر fingerprint را تعمیر نمی‌کند. before/after مساوی ناشی از مدیر دیگر قابل انتساب قطعی نیست؛ این محدودیت native باید جدا حل یا صریحاً مانع ادامه شود.

برای restore یک تراکنش جدا با digest متصل به وضعیت و inverseها ساخته می‌شود. اگر خود recovery قطع شد، همان journal بازیابی و intent معلق آن resume می‌شود؛ طرح تازه برای undo کردن restore ساخته نمی‌شود. `resume_pending_model` نبود اثر را از اثر مشاهده‌شده جدا می‌کند و قبل از checkpoint نتیجه setter تکراریِ مدل را مجاز نمی‌داند. همهٔ اینها فرض journal معتبر حافظه‌ای است، نه اثبات دوام دیسک/ACL/boot Windows.

## خطا و قطع ارتباط

- شکست backup یا intent: هیچ اقدام بعدیِ مدل.
- شکست پس از اثر: intent حفظ شود؛ نه فرض «هیچ تغییری نشد» و نه cleanup بی‌قید.
- تغییر rule/فیلتر/GPO/adapter یا نبود شواهد: ادامه و اجرای هدف متوقف؛ unknown را به حالت امن اثبات‌شده تعبیر نکنید.
- قطع SSTP: دادهٔ برنامه grant ندارد؛ reconnect/bootstrap هنوز qualification نشده‌اند. timeout هیچ‌وقت Allow عمومی نمی‌سازد.
- rollback خودکار به Allowهای قبلی درحالی‌که هدف/helper فعال است ممنوع است؛ این کار می‌تواند دسترسی را باز کند. recovery نیاز به رضایت جدا و quiescence دارد. نصب انجام‌شده undo نمی‌شود.
- baseline Block همان Block بازگردد؛ بازیابی این نشست معادل «اینترنت عادی Allow» یا restoration baseline تاریخیِ اثبات‌نشده نیست.

بررسی before/readback چند cmdlet اتمیک نیست. مدیر/GPO/نصب‌کنندهٔ elevated و WFP ثالث ممکن است بین دو مشاهده تغییر دهند؛ journal و polling جلوی این race را نمی‌گیرند. فایل hash/ACL نیز محافظت در برابر مدیر مخرب یا rollback کامل tail نیست. این طرح راه فرار از کنترل امنیتی دستگاه ارائه نمی‌کند و حفاظت no-leak ادعا ندارد.

## آزمون و کار بعدی

۱۱ test method جدید: ترتیب journal و consent، رد prerequisite، حفظ Block/disabled، fixture ساختگی۱۰۶Allow، drift،۶۰حالت ابهام اثر در۳۰نقطهٔ نوشتنِ مدل،۱۰گام resume قطع‌شدهٔ recovery، digest و عدم mutation ورودی و مرز بدونIO.۸۶assertionحمل و۲۵test methodپروفایل قبلی نیز rerun شدند. مقیاس و سرعت Windows از این آزمون‌ها نتیجه نمی‌شود.

`python qa.py --pwsh <pwsh>` همهٔ آزمون‌های آفلاین را اجرا می‌کند. آزمون native Windows، setter، ACL/journal بازیابی واقعی، packet، اتصال سرد/reconnect و reboot این مرحله **انجام نشده‌اند**. مرحلهٔ اجرایی بعدی توسعهٔ adapter **فقط‌خواندنی و خصوصیِ inventory/منشأ و backup قابل‌بازخوانی با رضایت محلی** است، همراه با بستن موانع حمل و recovery؛ نه تحویل زودهنگام Disable/Apply. فعلاً کاربر اقدام تازه‌ای ندارد و تنظیمات فعلی تغییر نکنند.
