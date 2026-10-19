# P14 — primitive پایدارِ بدون provider/service و مدل پذیرش epoch

## نتیجهٔ محدود
**PASS بومی Windows CI، نه کیل‌سوییچ کل دستگاه و نه بسته آماده کاربر.**

- source: `a57ad1ca30a61d3ef3e67bb148841ef71ba3f001`
- [run39294597263](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39294597263)؛ اجرای اول P14 موفق بود.
- checks=141 در harness؛ epoch_model_cases=20 جداگانه. این دو عدد به‌عنوان۱۶۱ بررسی مستقل جمع نشده‌اند؛ یک check harness کامل‌شدن۲۰case مدل را بررسی می‌کند.
- پنج fault و پنج recovery در process تازه؛ چهار TerminateProcess بومی و یک خروج عمدی PowerShell پیش از native.
- هفت جفت TCP: پنج مثبت/بازگردانی و دو منفی رابط/مقصد. برنامه کنترل در منفی‌ها متصل ماند.
- سه سناریوی conflict: انتظار LUID نادرست، انتظار مقصد نادرست، journal خراب. دو سناریوی اول هرکدام audit و remove را رد کردند؛ سه سناریو با شمار callها اشتباه نشود.
- هشت fixture set؛ هر set چهار object معلوم دارد، نه پنج object P13. cleanup_sets=8؛ remaining_objects=0.
- baseline کامل Windows Firewall P8 برابر=True؛ foreign display changes=0. این snapshot همه WFP خام نیست.
- ZIP SHA256=`1ff726a934e3bdb35af7fe2dd665d18f5757e7c31d33553c4163080eb6b2b65b`؛ digest واقعی ZIP، نام/اندازه فایل، schema، source/run، counts و scope falseها و SHA256 ده فایل کد مستقل با LF/CRLF checkout تأیید شدند.

## تغییر واقعی در موتور
این نسخه مستقلِ مشتق از P13 است؛ journal schema و basename helper/probe آن جداست و P13 را خودکار migrate/adopt/delete نمی‌کند. تنها یک sublayer و سه فیلتر BLOCK پایدار ساخته می‌شوند. providerKey هر چهار object باید دقیقاً NULL باشد؛ provider اصلاً ساخته نمی‌شود و native هیچ API ایجاد/حذف provider ندارد. serviceName، نسبت‌دادن صوری به BFE یا mpssvc، سرویس اختصاصی، task، watcher، timer، expiry و watchdog وجود ندارند.

حذف provider به معنی حذف مالکیت نیست: چهار GUID غیرصفر/یکتا در private journal، marker شانزده‌بایتی مشتق از GUID همان sublayer، label دقیق، مسیر exe آزمایشیِ محدود با نام تصادفی، AppID رسمی از FwpmGetAppIdFromFileName0 و تمام field/conditionها ممیزی می‌شوند. DLL/ABI یا GUID WFP دست‌نویس نیست؛ کد با SDK رسمی کامپایل شد.

پایداربودن sublayer و فیلترها، INDEXED و نبود هر بیت اضافه مانند DISABLED، providerKey=NULL در هر چهار object، weight دقیق، action=BLOCK، layer، context، AppID، تعداد/نوع/عملگر/مقدار تمام شرط‌ها و filterIdهای غیرصفر/یکتا بررسی می‌شوند. flags فیلتر دقیقاً PERSISTENT|INDEXED است، نه mask کردن flags غیرمنتظره. اولویت0x5a23 باید هنگام ورود به write transaction آزاد باشد و قبل/بعد commit عیناً بازخوانی شود. ترتیب conditionها با field GUID تطبیق داده می‌شود.

چهار object در یک تراکنش ساخته/حذف می‌شوند؛ فقط تماماً absent یا تماماً exact-installed پذیرفته‌اند. provider یا asset ناشناخته adopt نمی‌شود. خطای حذف به reset یا حذف policy بیگانه منتهی نمی‌شود؛ ارجاع بیگانه باید موجب abort تراکنش شود، هرچند تزریق آن در این مرحله آزموده نشد.

## آزمون اثر و خروج برنامه
هر helper پیش از audit/probe بعدی بسته شده است. قواعد در session غیر dynamic و به‌صورت persistent ایجاد شدند، بنابراین بعد از پایان process باقی ماندند و probe بعدی را واقعاً مسدود کردند. positive از NET_LUID واقعی رابط خروجی runner و negative از NET_LUID واقعی loopback استفاده کرد، نه ifIndex به‌جای LUID. مقصدِ اشتباه192.0.2.44 فقط در plan منفی بود؛ probe به همان IPv4 عمومی GitHub قبلاً موفق انجام شد. برنامه B مسیر جدا داشت و همان مقصد را موفق آزمایش کرد. پس از حذف دقیق، A دوباره وصل شد.

این فقط TCP connect تازه به443 است، نه HTTP/TLS/SSTP یا packet capture. DNS در setup آزمایش برای یافتن مقصد استفاده شد؛ محدودسازی DNS کاربر از این نتیجه استنباط نشده است. فقط exe آزمایشی زیر policy بود؛ runner و دستگاه کاربر کیل‌سوییچ نشدند. IPv6 برای همان exe deny-only و raw readback شد، نه packet test. سیستم firewall profiles/rules تغییری نکردند.

journal P2 با ACL ادمین/SYSTEM، operation lock، native hash و write-ahead phase حفظ شد. همان پنج نقطه fault P13 برای lifecycle چهارشیئی دوباره آزموده شدند: قبل native، بعد اولین Add داخل transaction، بعد commit نصب، بعد اولین Delete داخل transaction، بعد commit حذف. recovery در process تازه all-none یا all-exact را سنجید؛ ادامه و cleanup دقیق انجام شد. corrupt primary/backup recovery_required باعث توقف Remove شد؛ journal اصلی فقط در harness با bytes معلوم خودش بازگردانده شد. این مجوز بازیابی حدسی محصول نیست. مدیر محلی متخاصم خارج از مدل ACL/hash است.

## اصلاح مهمِ استناد قبلی، نه ادعای boot-test
در بازبینی P14 دو توضیح رسمی Microsoft یکدست نبودند:
- [Object Management / Object Lifetimes](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) می‌گوید هنگام شروع BFE، persistent object بدون provider، یا با provider فاقد serviceName، یا با سرویس مرتبطِ auto-start اضافه می‌شود.
- جدول DISABLED در [FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0) و [FWPM_PROVIDER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0) از نبود serviceName نیز به‌عنوان علت disabled-on-start یاد می‌کند.

بنابراین serviceName خالی به‌تنهایی مدرک قطعی شکست P13 پس از boot نبود. پاراگراف گزارش P13 و هشدار Status متناسب با این تعارض اصلاح شدند؛ نتیجه PASS محدود، تاریخچه شکست‌ها و cleanup نامعلوم اجرای ششم P13 تغییر نکردند. به‌خصوص remaining=-1 تاریخی با صفر P14 جایگزین نشد.

مسیر providerless اکنون به شرط اختیاری سرویس یک provider متکی نیست و Object Management برای آن توضیح صریح دارد. این **رفع وابستگی ساختاری** و تست زنده پس از خروج process است، نه اثبات reboot. BFE restart، توقف سرویس و reboot runner عمداً انجام نشدند؛ برای سبزکردن تست، firewall/BFE کل runner دست‌کاری نشد.

مستند Object Management می‌گوید BOOTTIME از شروع TCP/IP تا پایان آماده‌سازی BFE عمل می‌کند و PERSISTENT هنگام شروع BFE اضافه می‌شود. سه فیلتر این آزمایش BOOTTIME نیستند. فاصله startup، توقف BFE و انتقال boot-time→persistent guard همچنان خارج qualification هستند. از عبارت persistent نمی‌توان no-leak از اولین لحظه boot را نتیجه گرفت.

## مدل epoch — مرز آن دقیقاً کجاست
BindingEpoch.ps1 صرفاً تابع read-only پذیرش مجدد است. profile GUID و scope، RAS correlation، interface GUID، NET_LUID رشته‌ایِ uint64 و boot marker باید دقیقاً مطابق باشند؛ Expected و Observed هر دو باید از gateهای هویت P6 عبور کنند. alias نمایشی سند هویت نیست. فقط observationهای تازه از collector مورداعتماد می‌توانند در آینده ورودی معتبر عملیاتی باشند؛ مدل درستی/تازگی ورودی را امضا یا اثبات نمی‌کند.

بیست case مصنوعی شامل تطابق، alias نامساوی، تغییر تک‌تک شش مولفه epoch، PPP نبودن، صفر/دو SSTP فعال، recheck ناپایدار، observation تهی، فیلد کم/اضافه، LUID عددی یا صفر، GUID نامعتبر و epoch تهی بود. همان LUID با boot/profile/session/interface متفاوت در مدل hold_changed_epoch می‌گیرد؛ نه اینکه صرفاً LUID یکسان اجازه بدهد. مثال uint64 بالاتر از2^53 در رشته نگه داشته شد.

**این مدل collector، monitor یا kernel hook نیست و هنوز به Worker/P12 یا فیلترها متصل نشده است.** مقدار hold هیچ Block جدیدی در kernel روشن نمی‌کند. وقتی controller بسته است، این تابع اجرا نمی‌شود و تغییر هویت را نمی‌بیند. پس۲۰case مصنوعی نه disconnect/reconnect واقعی‌اند و نه اثبات جلوگیری از reuse رابط پس از خروج. static شرط NET_LUID به‌تنهایی اثبات دائمیِ تعلق ترافیک به پروفایل SSTP نیست.

## مرز تحویل و گام بعد
whole_machine_guard_tested=false؛ active_sstp_tested=false؛ ipv6_packet_tested=false؛ reboot_tested=false؛ user_device_tested=false؛ ready_for_user_apply=false. BFE restart نیز آزموده نشده است.

روی دستگاه کاربر هیچ policy اجرا نشد، بسته اجرا/Enable تازه تحویل نشد و گزارش هویت قبلی دوباره درخواست نشد. مخزن قدیمی read-only ماند. فقط receipt محدود upload شد، نه raw journal/inventory، مسیر، IP واقعی probe، GUID/LUID، boot marker، credential یا exe. ادعا نمی‌شود که تمام raw WFP بیگانه snapshot/byte-compare شده است؛ P8 و enumeration read-only وزن sublayerها چنین پوششی ندارند.

گام بعد باید قرارداد اجراییِ بدون resident برای تغییر epoch/boot و تعلق پایدار به SSTP را تعیین و qualify کند، سپس admission و lifecycle چهارشیئی را به frontier مشترک P12 و guard واقعی وصل کند. اگر ابزارهای static برای این هویت کافی نیستند، باید محدودیت صریح گزارش شود، نه اینکه با آزمون مدل جای enforcement واقعی پر شود. تا آن زمان gate محدودبودن به exe آزمایشی حذف نمی‌شود.
