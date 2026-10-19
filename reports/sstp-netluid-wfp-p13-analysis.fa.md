# P13 — آزمون محدودِ شرط NET_LUID و مقصد در WFP

## نتیجه
**PASS محدود آزمایش CI، نه محصول آماده و نه اتصال واقعی SSTP.**

- source: `0f41d3c448b17cecbd54bf4e4fa087c9cfaa886f`
- [اجرای نهایی](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39293369563)
- checks=140؛ پنج fault و پنج recovery در پردازش تازه.
- هفت جفت TCP probe: پنج جفت مثبت/بازگردانی و دو جفت منفیِ رابط/مقصد.
- سه سناریوی تعارض: LUID مورد انتظار اشتباه، مقصد مورد انتظار اشتباه، journal خراب؛ دو سناریوی اول هرکدام audit و remove را رد کردند، پس count سناریو با تعداد callهای ردشده یکی نیست.
- fixture_sets=8؛ cleanup_sets=8؛ remaining_objects=0.
- baseline قواعد PersistentStore/هفت filter و شش profile قرارداد P8 برابر=True؛ اختلاف نمایشی خارجی=0.
- digest ZIP=`f0875b715925e842dfe47927c7fadf357f9f1c1a257758008c10c5d9cea3bb27`؛ digest واقعی ZIP، نام/اندازه فایل، schema، countها، false بودن scopeها، source/run و SHA256 هفت فایل کد با LF/CRLF به‌طور مستقل بررسی شدند.

## آنچه ساخته شد
موتور C++ با هدر رسمی Windows SDK و Win32 API ساخته شد؛ ABI و GUIDهای WFP دست‌نویس نیستند. NET_LUID یک uint64 واقعی است و در JSON رشته باقی می‌ماند تا دقت عددی از دست نرود. تبدیل index→LUID→index و LUID→GUID در برابر GetIfEntry2 بررسی شد. LUID ورود RAS به‌جای NET_LUID استفاده نشده است.

provider، sublayer و سه فیلتر BLOCK پایدار با پنج GUID تصادفی اختصاصی ایجاد می‌شوند. هر فیلتر فقط ALE_APP_ID برنامه آزمایشی با basename تصادفیِ محدودشده را می‌پذیرد؛ AppID از FwpmGetAppIdFromFileName0 می‌آید. مسیر برنامه کنترل دوم متفاوت است. هیچ PERMIT عمومی، تغییر پیش‌فرض پروفایل، rule عمومی Windows Firewall، تغییر VPN، task یا سرویس اختصاصی نصب نمی‌شود.

سه ممنوعیت عبارت‌اند از:
1. ALE_AUTH_CONNECT_V4: app=A و IP_LOCAL_INTERFACE ≠ NET_LUID انتخابی → BLOCK.
2. همان لایه: app=A و IP_REMOTE_ADDRESS ≠ یک IPv4 مجاز → BLOCK.
3. ALE_AUTH_CONNECT_V6: app=A → BLOCK.

هیچ فیلتر Allow برای عبور از Blockهای قبلی Windows نصب نشده؛ مثبت بودن probe وابسته به اجازه موجودِ خود runner است. این‌ها predicateهای بومی یک برنامه‌اند، نه اجازه کل دستگاه و نه سیاست کامل DNS/LAN/SSTP.

## ممیزی و lifecycle
install و remove هر پنج object در یک تراکنش BFE هستند. هر پنج باید یا کاملاً absent یا دقیقاً installed باشند؛ حالت ناقص یا ناشناخته adoption ندارد. قبل/بعد commit و سپس در process تازه، GUIDها، provider/link، marker data، نام/شرح، flags، layer/sublayer، action، context، وزن دقیق و تعداد/نوع/عملگر/مقدار تمام شرط‌ها بررسی می‌شوند؛ شناسه runtime فیلترها غیرصفر و یکتا و effectiveWeight از نوع64bit لازم است. ترتیب شرط‌ها با GUID تطبیق داده می‌شود، نه ترتیب تصادفی خروجی.

اولویت sublayer اکنون0x5a23 است؛ درون write transaction تمام sublayer weightها فقط خوانده می‌شوند و استفاده قبلی از همین اولویت باعث توقف قبل از Add می‌شود. مقدار واقعی بازخوانی باید دقیقاً همان مقدار خواسته‌شده باشد؛ weight دلخواه یا بازه پذیرفته نمی‌شود. filter flags صریحاً PERSISTENT|INDEXED هستند و برابری دقیق flags حفظ شد؛ بیت DISABLED یا پرچم ناشناخته مجاز نشده است.

journal امن P2، ACL ادمین/SYSTEM، operation lock، hash exe بومی و write-ahead phase دارد. نصب‌کننده phase installing و حذف‌کننده removing را پیش از عملیات ثبت می‌کنند. recovery فقط pending معلوم را با پنج object دقیق می‌سنجد؛ primary خراب یا backup recovery_required موجب حذف/آزادسازی حدسی نمی‌شود. این journal امضای ضد مدیر محلی متخاصم ندارد؛ چنین مهاجمی خارج از مدل است.

پنج توقف: قبل از child native، بعد از اولین Add داخل transaction، بعد از commit نصب، بعد از اولین Delete داخل transaction، بعد از commit حذف. چهار native TerminateProcess و یک خروج عمدی worker باکد73 هستند. rollback تراکنش ناتمام و باقی‌ماندن همه objectهای commitشده با process تازه بررسی شد. recovery سپس تا پایان و cleanup دقیق پیش رفت. هر helper پیش از audit/probe بعدی بسته شده بود؛ kernel policy به بازماندن helper متکی نبود.

## آزمون شبکه دقیقاً چه بود
فقط TCP connect تازه روی443 به یک IPv4 عمومی GitHub، بدون HTTP، login، credential یا payload برنامه‌ای. DNS سیستم فقط در setup آزمایش برای پیداکردن مقصد استفاده شد؛ این تست اثبات محدودشدن DNS کاربر نیست. A و B از یک کد کامپایل/کپی شدند اما path متفاوت دارند.

LUID رابط خروجی واقعی runner آزمون مثبت بود. LUID loopback، نه یک ifIndex جعلی، آزمون منفی همان مقصد بود؛ A شکست و B وصل شد. مقصد مجاز192.0.2.44 در plan دوم باعث شکست A هنگام تلاش برای همان IPv4 واقعی شد، درحالی‌که B وصل شد. حذف دقیق policy اتصال A را بازگرداند. هیچ ترافیکی به192.0.2.44 برای اثبات مثبت ارسال نشد.

این runner نشست SSTP ندارد. بنابراین آزمون‌ها **primitive تطبیق NET_LUID و مقصد** را می‌سنجند، نه رابطه با پروفایل holand، نه قطع/وصل SSTP، نه تغییر نام NIC و نه session lifetime. IP_LOCAL_INTERFACE رابط local IP است و الزاماً همان IP_NEXTHOP_INTERFACE نیست؛ از این تست تضمین کلی مسیر استنباط نمی‌شود. IPv6 فقط rule/readback شد، نه packet test؛ اتصال‌های ازقبل‌باز، UDP، DNS، LAN، multi-interface و IPv6 عمومی آزموده نشدند.

## محدودیت ماندگاری مهم
PERSISTENT و بستن process فقط ماندگاری object/اثر در طول همین اجرای Windows را ثابت کردند. reboot/BFE restart آزموده نشده است. **اصلاح مستند در بازبینی P14:** جدول DISABLED در FWPM_FILTER0 از نبود serviceName به‌عنوان علت غیرفعال‌شدن نام می‌برد، ولی بخش Object Lifetimes در سند رسمی [Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) صریحاً می‌گوید persistent object بدون provider، یا با provider فاقد serviceName، هنگام شروع BFE اضافه می‌شود. بنابراین از serviceName خالی نمی‌توان با قطعیت نتیجه گرفت P13 در boot غیرفعال خواهد شد؛ این دو متن رسمی یکدست نیستند و نتیجه زنده‌ای برای داوری نداریم. ادعای کلی قبلی به همین اندازه اصلاح شد؛ نتایج آزمون P13 تغییر نکردند.

**ذخیره پایدار با تضمین اجرای فعال و بدون شکاف از ابتدای boot یکی نیست.** مستند Object Management بین BOOTTIME از شروع TCP/IP تا آماده‌شدن BFE و PERSISTENT از شروع BFE تمایز می‌گذارد. P13 نه boot را آزمود و نه boot-time guard ساخت. هیچ serviceName صوری برای یک سرویس Windows تنظیم نشد و resident اختصاصی نصب نشد. مسیر providerless در P14 برای حذف وابستگی اختیاری به activation provider و کاهش objectها جداگانه آزموده می‌شود، نه برای اثبات اینکه نسخه قبلی حتماً خراب بوده است.

NET_LUID فعلی نیز به‌تنهایی قرارداد عدم reuse یا اثبات دائمی SSTP پس از بازسازی رابط نیست. admission هویت P6 به این primitive متصل نشده و این موتور با coordinator P12 یک state واحد نساخته است. نصب atomic فیلترهای آزمایشی جای guard/release کل سیستم را نمی‌گیرد؛ پیش از commit نصب هیچ guard کلی وجود ندارد.

P8 فقط Windows Firewall rule/filter/profileها را پوشش می‌دهد، نه snapshot کامل objectهای WFP بیگانه. enumeration وزن sublayerها read-only و برای admission اولویت است؛ baseline کامل WFP نیست. حذف فقط objectهای خودی پس از audit سخت‌گیرانه است؛ اگر ارجاع بیگانه موجب in-use شود، transaction باید abort شود، نه حذف بیگانه یا reset عمومی. تزریق چنین filter بیگانه‌ای در این مرحله آزموده نشد.

## سوابق غیرموفق حفظ‌شده
تمام رسیدهای زیر، ZIP digest و هفت hash منبع هر اجرا پیش از تغییر بعدی بررسی/حفظ شدند. این‌ها PASS شمارش نشده‌اند و تعداد بررسی‌شان به بررسی‌های اجرای نهایی اضافه نشده است.

| اجرا | source | نتیجه | checks | fixture/cleanup/remaining | دلیل |
| --- | --- | --- | --- | --- | --- |
| first | `6e5dbbe` | [run39290196696](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39290196696) | 1 | 0/0/0 | کامپایل C2065؛ symbol در این log مشخص نشد |
| second | `113a617` | [run39290459718](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39290459718) | 1 | 0/0/0 | کامپایل C2065 روی GUID_NULL؛ اعلان GUID صفر اصلاح شد |
| third | `a5028af` | [run39290731258](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39290731258) | 11 | 1/1/0 | توقف نصب پیش از commit؛ بازخوانی سخت‌گیرانه |
| fourth | `87c623a` | [run39291068881](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39291068881) | 11 | 1/1/0 | تشخیص توقف در CheckSub؛ بازخوانی سخت‌گیرانه |
| fifth | `4e69961` | [run39291433111](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39291433111) | 11 | 1/1/0 | فیلد sub_weight ناسازگار؛ commit انجام نشد |
| sixth | `8d8c5e3` | [run39291933715](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39291933715) | 8 | 1/0/-1 | آزمون جابه‌جایی audit به پس از commit ناموفق؛ weight=32766 در برابر32767؛ cleanup تأیید نشده |
| seventh | `fb0e60a` | [run39292374088](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39292374088) | 11 | 1/1/0 | اولویت آزاد سخت‌گیرانه پذیرفته شد؛ اختلاف فقط filter_flags در این توقف |
| eighth | `7e22128` | [run39292958908](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39292958908) | 11 | 1/1/0 | پرچم بازخوانی65 در برابر درخواست1؛ INDEXED رسمی صریح شد |

در اجرای ششم نصب commit شد ولی audit وزن32766 در برابر32767 را رد کرد. cleanup هم به همان دلیل متوقف شد: **remaining=-1 یعنی نامعلوم، نه صفر**؛ پاک‌سازی آن runner تأیید نشده است. baseline P8 برابر بود ولی این برابری هیچ اطلاعی درباره پاک‌سازی فیلترهای WFP مستقیم نمی‌دهد. runner آزمایشی بود و دستگاه کاربر نبود. اجراهای بعدی runner جدا داشتند؛ صفر نهایی به عقب برای اجرای ششم تعمیم داده نشده است.

صرفاً انتقال audit به پس از commit مشکل وزن را حل نکرد؛ این فرض رد شد. برابری دقیق پیش/پس commit به کد برگشت. تغییر اولویت همراه gate عدم استفاده قبلی، اختلاف وزن را در اجراهای بعدی رفع کرد؛ علت دقیق وزن قدیمی صرفاً از اختلاف یک‌واحدی به‌عنوان collision اثبات نشده است. diagnostic بعدی مقدار flags65 در برابر1 را نشان داد؛ به‌جای mask کردن اختلاف، INDEXED رسمی از ابتدا درخواست شد و برابری دقیق65 باقی ماند.

## مرز تحویل
whole_machine_guard_tested=false؛ active_sstp_tested=false؛ ipv6_packet_tested=false؛ reboot_tested=false؛ user_device_tested=false؛ ready_for_user_apply=false.

هیچ بسته اجرایی/فرمان Enable روی دستگاه کاربر تحویل یا اجرا نشد؛ گزارش قبلی کاربر دوباره درخواست نشد؛ مخزن قدیمی read-only ماند. فقط receipt محدود upload شد، نه raw inventory/journal، مسیر، مقصد واقعی probe، GUID، NET_LUID یا exe. کد فقط شاخه آزمایشی است و این گزارش در main ثبت می‌شود.

گام بعد: حل activation پایدار پس از BFE/boot بدون resident اختصاصی و تثبیت محدودیت lifetime هویت واقعی SSTP؛ سپس اتصال admission/lifecycle این primitive به journal/frontier مشترک P12 و guard کل سیستم. برداشتن gate محدودبودن به exe آزمایشی مجاز نیست تا policy مؤثر و bootstrap و IPv4/IPv6/DNS/LAN و قطع/وصل/boot qualified شوند.

## منابع API
- [شرط‌های WFP و NET_LUID](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)
- [شرط‌های مجاز هر layer](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer)
- [FWPM_FILTER0؛ flags، persistent، indexed و disabled-on-start](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)
- [FWPM_SUBLAYER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0)
- [تراکنش commit](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0)
