# P5 — journal متصل به قواعد واقعی غیرفعال و ابزار بازرسی فقط‌خواندنی

## نتیجهٔ محدود
**۳۹ بررسی بومی Windows PowerShell5.1 پاس شد؛ باقی‌ماندهٔ قواعد آزمایشی صفر.** این بار adapter مدل فایلی نیست: journal واقعی P2 به cmdletهای واقعی P3 در PersistentStore متصل شد. با این حال همهٔ قواعد ساخته‌شده **غیرفعال** ماندند؛ guard، defaultهای واقعی و Allowهای قبلی تغییر نکردند. **محصول Enable/Disable نهایی هنوز آماده نیست.**

- منبع P5: [17b1cfe0ffdd64b87aac58b772ed2b96dd145f53](https://github.com/kokononox/battle-net-agent-lab/tree/17b1cfe0ffdd64b87aac58b772ed2b96dd145f53/sstp-allowlist-native-journal)
- اجرای موفق: [39202380816](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39202380816)، job۲دقیقه‌و۴ثانیه، windows-2025 استاندارد و timeout پنج دقیقه.
- [رسید محدود](../reports/sstp-allowlist-native-journal-p5-build.json)، artifact12164885218، SHA256 ZIP: `1519d1890a24ddcef604bf8a97b65c5f2aab617c0ae059c80f2d09bd56c6dec4`.
- ZIP دانلود و digest نمایش‌داده‌شده تطبیق داده شد؛ schema، source/run و هش شش منبع NativeJournal/Worker/Test-NativeJournal/Journal/Firewall/Policy با پایان خط checkout ویندوز تأیید شدند. ۸fixture محلی اعتبارسنجی رسید نیز پاس شد.

## چرخهٔ واقعی و رفتار هنگام ابهام
prepared پس از خواندن absence نام؛ create_intent قبل از cmdlet؛ ساخت قاعدهٔ غیرفعال و readback هر هفت filter؛ staged با snapshot و fingerprint ثبت‌شده؛ remove_intent پیش از حذف؛ حذف با fingerprint قبلی و خواندن absence؛ removed.

۵termination واقعی worker با Environment.Exit(73): قبل از ساخت، بعد از ساخت ولی قبل از ثبت snapshot، پس از ثبت snapshot، قبل از حذف و بعد از حذف. چهار مسیر در powershell.exe جدید recovery شدند. برای **یک** حالت مبهم بعد از ساخت بدون snapshot ثبت‌شده، هر دو عمل Stage و Remove عمداً متوقف شدند؛ ambiguous_review_stops=2 مربوط به دو امتناع روی همان یک حالت است، نه دو fault یا دو recovery موفق.

این انتخاب محافظه‌کارانه مهم است: صرفِ نام/GUID یا ظاهر یکسان قاعده، دلیل کافی برای پذیرفتن مالکیت پس از قطع برنامه نیست. موتور قاعدهٔ مبهمِ غیرفعال را حفظ می‌کند و بازبینی می‌خواهد؛ آن را خودکار به journal نمی‌چسباند یا حذف نمی‌کند. پاک‌سازی صریح fixtureهای شناخته‌شدهٔ CI، پس از readback دوباره، جدا از recovery موتور انجام شد؛ این مسیر مجوز حذف کور روی سیستم کاربر نیست.

تست‌های دیگر: تغییر description یکی از قواعد خود تست و توقف حذف با hash قدیمی؛ نام موجود بدون journal؛ journal اصلی خراب با backup معتبر؛ spec معتبر ولی متفاوت؛ تکرار بی‌اثر و قفل کل فراخوانی. baseline خواص منتخب profile stored/effective و خواص rule-level قواعد محلی موجود قبل/بعد برابر بود؛ این ادعای مقایسهٔ همهٔ filterهای دیگر یا کل WFP نیست.

هیچ قاعده‌ای فعال نشد. نوشتن در store فایروال واقعاً انجام شد، ولی اثرگذاری policy شبکه یا no-leak آزمایش نشد. DNS/VPN/hosts/route و دستگاه کاربر تغییر نکردند؛ هیچ resident/service/task ایجاد نشد. snapshotها و journalهای خصوصی upload نشدند. تمام قواعد تست در پایان حذف شدند، از جمله قاعدهٔ مبهمی که صرفاً cleanup صریح fixture آن را بازبینی کرد.

## ابزار گزارش وضعیت جاری دستگاه کاربر
برای خروج از چرخهٔ آزمون‌های بدون SSTP واقعی، بستهٔ **Sstp-Binding-ReadOnly-v1.zip** آماده و به کاربر تحویل می‌شود. این ابزار فقط بازرسی است، نه kill switch یا فرمان Apply.

- منبع: [d0cd360ca68f3d12071d028b8d72da5fb8e180ec](https://github.com/kokononox/battle-net-agent-lab/tree/d0cd360ca68f3d12071d028b8d72da5fb8e180ec/sstp-binding-inspect)
- [39202733508](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39202733508): parser Windows PowerShell5.1 و شش fixture خالص انتخاب پروفایل موفق؛ job۲۷ثانیه. شاخهٔ capture زنده روی دستگاه کاربر یا تونل واقعی در این CI اجرا نشده است.
- [manifest بسته](../reports/sstp-binding-inspector-package.json) شامل هش فایل‌ها؛ SHA256 ZIP: `64b2739efc0b3193ca464574bf2e5511e91112bf9cd9e99ef05f8e62ac73cb17`.
- کاربر ZIP را استخراج، با همان حساب Windows سازنده/استفاده‌کنندهٔ VPN، SSTP را دستی وصل، سپس 01-Inspect.cmd را عادی اجرا و فقط SstpBindingReport.json را ارسال می‌کند. فعلاً elevation درخواست نمی‌شود؛ نبود دسترسی unavailable/null است، نه صفر. اجرای حساب مدیر متفاوت، پروفایل شخصی را عوض می‌کند و خواسته نشده است.
- خروجی whitelist است: نسخهٔ Windows/PowerShell، وضعیت پرس‌وجوها، تعداد/وضعیت پروفایل‌های SSTP با label ناشناس، تطابق ترجیح holand، نوع hostname/IP بدون مقدار، شمارندهٔ رابط‌ها/routeها و Allowهای موجود، خواص firewall profile. نام واقعی VPN، IP/سرور، نام کاربر، رمز و گواهی export نمی‌شوند. هیچ upload خودکار، اتصال VPN یا DNS query وجود ندارد؛ فقط فایل گزارش کنار ابزار نوشته می‌شود و برنامه خارج می‌شود.
- source tracing قواعد ActiveStore فقط در صورت پشتیبانی TracePolicyStore استفاده می‌شود؛ در غیر این صورت شمارندهٔ nonlocal نامعلوم می‌ماند. query ناقص به معنی نبود GPO/Allow نیست.
- alias matching اثبات هویت پروفایل SSTP نیست؛ وجود route پیش‌فرض روی رابط دیگر به‌تنهایی اثبات نشتی نیست. inspector نیز binding_qualified و ready_for_user_apply را false نگه می‌دارد.

## مانع و گام بعد
محیط CI این اجرا SSTP واقعی کاربر را ندارد و عامل از این گفتگو دسترسی مستقیم به Windows کاربر ندارد. گزارش S1 قدیمی، شاهد وضعیت فعلی اتصال نیست. اکنون برای تحلیل اتصال واقعی، گزارش فقط‌خواندنی تازه لازم است؛ هنوز نباید از کاربر اجرای Enable/Disable جدید یا تغییر policy خواست.

علاوه بر دریافت وضعیت واقعی، کد اجرایی guard، تغییرات مؤثر profile/Allowهای قبلی، قرارداد کامل snapshot، unmanaged/GPO، inbound/LAN و اتصال موتور تراکنش به آن‌ها هنوز کامل و qualified نشده‌اند. سپس آزمون packet مستقل، قطع‌وصل، DNS/IPv6 و boot لازم است. P5 به معنی تکمیل کل موتور P4 برای اعمال شبکه نیست. نیاز «بدون برنامهٔ مقیم، بدون انقضا، فقط allowlist از SSTP» حفظ شده است، نه اثبات شده.

ready_for_user_apply=false؛ real_guard_tested=false؛ enforcement_tested=false؛ sstp_binding_tested=false؛ user_device_tested=false.
