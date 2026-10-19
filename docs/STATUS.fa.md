# وضعیت جاری پروژه — مرجع هماهنگی عامل و همکاران

**آخرین به‌روزرسانی: 2026-10-19 06:54 (UTC)**  
**مرحلهٔ فعلی: دامنه نهایی کاربر تأیید شد: Allowlist مقصدها فقط از SSTP همراه کیل‌سوییچ کل Windows؛ اتصال دستی، LAN بسته، بدون resident و انقضا، Enable/Disable اعمال و خروج، config قابل ویرایش. انتخاب A/B دیگر باز نیست. هسته P1 با۳۵fixture و زیرساخت journal در P2 با۳۰بررسی بومی Windows پاس شدند؛ P2 هیچ firewall/DNS تغییری نداد؛ P3 adapter قواعد غیرفعال با۲۹بررسی بومی Windows پاس شد و هر۴قاعده حذف شدند؛ P4 موتور مرجع با adapter صرفاً فایلی با۲۴۳بررسی و۳۸بازیابی فرایند جدید پاس شد؛ P5 journal قواعد واقعیِ غیرفعال با۳۹بررسی پاس شد و باقی‌مانده صفر است؛ گزارش تازهٔ inspector کاربر دریافت شد: یک SSTP فعال ترجیحی، هر۸query موفق،۱۰۰Allow محلی/مؤثر و stored outbound=NotConfigured؛ تکرار گزارش اول/admin لازم نیست؛ P6 با۴۰check SDK/metadata بومی پاس شد و گزارش زندهٔ کاربر identity_chain_observed=true و stable_recheck موفق را نشان داد؛ هویت اتصال جاری از alias-only عبور کرده، اما guard/adapter مؤثر و اعمال واقعی فیلتر SSTP هنوز qualified نشده و backend اجرایی هنوز آماده نیست و ready_for_user_apply=false. P7 قرنطینه Enabled واقعی نوشته شد: اجرای اول هر۸۷check/۱۰recovery و cleanup صفر را تکمیل کرد ولی baseline قوانین نامرتبط برابر نبود و failed ماند؛ اجرای تشخیصی دوم failed با delta added=0/removed=0/modified=2 فقط در Description/DisplayGroup/DisplayName ثبت شد؛ کنترل فقط‌خواندنی P7C در۶۶۰ثانیه/۱۳snapshot همان نوع اختلاف دو قانون در سه فیلد نمایشی را بدون setter بازتولید کرد؛ نخستین مشاهده ثانیه۵۴۰، تبدیل literal→resource-reference؛ منشأ دقیق/قاعده‌های یکسان قبلی اثبات نشده و شرط baseline حذف نشده؛ علت اختلاف اول از شواهد موجود قطعی نیست. guard/defaultهای واقعی و اعمال کاربر هنوز آماده نیستند و ready_for_user_apply=false. تست دو دور provider قبلی PASS محدود CI باقی است. دستگاه کاربر دست‌نخورده و Pause محفوظ است.**

این فایل مرجع وضعیت روز است. README و اسناد قدیمی مسیر تحقیق را نگه می‌دارند، اما تیترهای «آزمایش جاری» یا «گام بعد» در آن‌ها لزوماً وضعیت امروز نیستند. پیشنهادهای همکاران در [سند پیشنهادها](SUGGESTIONS-FROM-OTHER-MODELS.fa.md) قرار می‌گیرد؛ پیشنهاد به‌تنهایی تصمیم، مجوز یا شاهد اجرای موفق نیست.

## هدف و تقسیم نقش
- هدف فعال: بررسی امکان به‌روزرسانی رسمی Retail با Battle.net در حالت **signed out**، همراه با محدودکردن تله‌متری و مشاهدهٔ اثر آن بر عملکرد آپدیت. هنوز تضمین «فقط دانلود آپدیت و هیچ تبادل دیگری» نداریم.
- عامل اجرایی این گفتگو: یکپارچه‌سازی شواهد، بررسی پیشنهادهای مدل‌های همکار، تغییرات کد/مستندات در محدودهٔ مجاز، اجرای آزمون‌های مشخص، تحویل ابزار و نگهداری همین وضعیت. عامل از اینجا دسترسی مستقیم به ویندوز کاربر ندارد.
- همکاران/مدل‌های دیگر: پیشنهاد و نقد مستند؛ ترجیحاً با سؤال مشخص، شاهد/commit، آزمون تمایزبخش، هزینه و معیار توقف. تغییر موازی کد را صریحاً معرفی کنند تا عامل آن را با کار جاری تطبیق دهد.
- کاربر: تصمیم‌گیر دامنه و ریسک آزمایش، اجراکنندهٔ ابزار روی دستگاه خودش و انجام‌دهندهٔ دستی هر Update/Pause. تغییر حقوقی، ورود به حساب یا فعال‌سازی هزینه خودکار نیست.

## الان دقیقاً کجا هستیم؟
| مورد | وضعیت |
| --- | --- |
| تمرکز جاری | Allowlist+SSTP kill switch با اعمال و خروج، بدون resident/انقضا؛ دامنه قطعی ثبت شد. P1 config/plan:۳۵fixture PASS، backend و Apply هنوز آماده نیست |
| بستهٔ ویندوز U1 | ساخته و در Windows runner آزموده شده؛ کاربر اعلام کرد ZIP را دانلود کرده است |
| خودآزمایی روی HP/Windows 11 کاربر | **گزارش ارسالی کاربر PASS**؛ send، WSASend و ورودی منفی EncryptMessage مشاهده شدند؛ خطای اسکریپت صفر |
| آپدیت واقعی تحت مانیتور U1 و بلوک دامنه | **دانلود تا ۳۰٪ به گزارش کاربر**؛ READY/Agent واقعی/hosts در گزارش ثبت شده؛ پایان Paused، تکمیل اثبات نشده |
| اقدام بعدی کاربر | خروجی لازم دریافت شد؛ فرمان/تست دیگری فعلاً لازم نیست. S2 تکرار، backup upload/BAT99/Enable/Disable/Resume نه. WoW بسته، آپدیت Pause و VPN فعلی حفظ شوند |
| دریافت ZIP/ورود GitHub | ZIP ساده BAT قبلاً تحویل شد؛ کاربر فقط۰۶ را موفق گزارش کرد. T1 با artifact آماده است؛ ورود GitHub دوباره درخواست نشود |
| محل کد آزمایشی و گزارش‌های تازه | T1/R1/U2 در شاخه privacy-observation-20261018-a1؛ BATهای ساده در plain-hosts-leave-one-open روی main. کد پژوهشی خودکار merge نمی‌شود |

## شواهد معتبر جدید — مبنای راهنمایی همکاران
### دامنه نهایی Allowlist و هسته P1 — مبنای فعلی
- [نیاز قطعی کاربر](SSTP-ALLOWLIST-REQUIREMENTS.fa.md): Allowlist واقعی، فقط داخل SSTP، kill switch fail-closed کل Windows، LAN بسته، اتصال دستی، فعال/موجود یکتا با holand ترجیحی و توقف در ambiguity. Enable/Disable باید تنظیمات را اعمال و خارج شوند؛ بدون فرایند/سرویس/task دوره‌ای اختصاصی، بدون انقضا و با ماندگاری reboot.
- [P1 config و plan](SSTP-ALLOWLIST-POLICY-P1.fa.md): ۳۵fixture خالص در run39197656262 پاس شد. source7b64da0705c00c8884102b9c3f1ff4e2624199fa؛ هیچ firewall/VPN/hosts/route/DNS تغییر یا query نشد، هیچ resident ساخته نشد. این هسته backend Enable/Disable ندارد و مجوز Apply نیست.
- مبنای نمونه فهرست مجاز level3.blizzard.com است، نه بازکردن نام‌های مسدود BAT۶. DNS/CDN به Refresh صریح نیاز پیدا می‌کند و IP مشترک معادل هویت انحصاری hostname نیست. bootstrap محدود SSTP استثناست، نه Allow عمومی. تعریف «فقط VPN+denylist» دیگر دامنه نهایی نیست و پرسش A/B پاسخ داده شده است.
- [P2 journal](SSTP-ALLOWLIST-JOURNAL-P2.fa.md): run39198636057 با۳۰بررسی بومی پاس شد؛ ACL، قفل، revision، جایگزینی فایل/backup، توقف پس از خرابی و تصمیم‌های خالص restore آزمایش شدند. نه adapter فایروال، guard واقعی، state machine کامل یا enforcement؛ ready_for_user_apply=false.
- [P3 adapter قواعد غیرفعال](SSTP-ALLOWLIST-ADAPTER-P3.fa.md): run39199602299 با۲۹بررسی بومی پاس شد. چهار قالب target/DNS TCP/DNS UDP/transport، readback هفت filter، fingerprint و امتناع از حذف پس از ویرایش خارجی بررسی شدند. remaining_test_rules=0؛ baseline منتخب profile/rule-level برابر. اجرای اول lookup شکست خورد و اصلاح/رسید آن حفظ شد. این تست فقط store/disabled rules است، نه enforcement یا SSTP.
- [P4 تراکنش با مدل فایلی](SSTP-ALLOWLIST-TRANSACTION-P4.fa.md): run39201053220 با۲۴۳بررسی،۳۸termination و۳۸recovery در powershell.exe جدید پاس شد؛ write-ahead intent، readback/frontier، بازگردانی Enable نیمه‌تمام، توقف در corruption/external edit و transaction lock بررسی شدند. adapter_kind=file_model_only؛ نه فایروال، guard واقعی، reboot یا enforcement. دو شکست صفر-check اولیه و اصلاح آرایهٔ JSON حفظ شدند.
- [P5 journal بومی و بستهٔ بازرسی](SSTP-ALLOWLIST-NATIVE-JOURNAL-P5.fa.md): run39202380816 با۳۹بررسی و۵termination؛۴recovery و۲توقف عمدی روی یک حالت مبهمِ ساخت بدون snapshot. همهٔ قواعد غیرفعال و باقی‌مانده صفر؛ baseline منتخب برابر. نه guard/default/enforcement واقعی.
- ابزار فقط‌خواندنی Sstp-Binding-ReadOnly-v1.zip با منبعd0cd360 و تست parser/۶fixture انتخاب در run39202733508 آمادهٔ تحویل است. کاربر SstpBindingReport.json را فرستاد و [تحلیل وضعیت جاری](../reports/sstp-binding-user-inspection-analysis.fa.md) ثبت شد: هر۸query موفق بدون elevation، یک current-user SSTP فعال ترجیحی، یک alias candidate با IPv4 connected،۱۰۰Allow محلی/مؤثر و nonlocal مشاهده‌شده صفر با tracing. stored outbound سه profile=NotConfigured و effective=Allow؛ IPv4/IPv6 default روی candidate دیده نشد و هر دو روی رابط دیگر گزارش شدند، نه اثبات نشتی یا نبود route مقصد خاص. alias identity هنوز qualified نیست. گزارش اول کامل بود و تکرارش/admin لازم نیست؛ ابزار فقط بازرسی بود. اکنون مرحلهٔ متفاوت P6 برای هویت RAS آماده است.
- [P6 هویت RAS/SSTP](../reports/sstp-ras-identity-p6-analysis.fa.md): run39205045945 با۴۰check، مقایسهٔ ABI با SDK x64، roundtrip واقعی IP Helper و enumeration RAS موفق count0. projection زنده SSTP در CI تست نشده؛ اصلاح Pack=4 بعد از شکست ABI اولیه ثبت شد. بستهٔ Sstp-RAS-Identity-ReadOnly-v1.zip با همان سه منبع اصلی آزموده‌شده آمادهٔ تحویل است؛ کاربر با SSTP متصل و همان حساب عادی 01-Inspect-RAS.cmd را اجرا و SstpRasIdentityReport.json را بفرستد. این مرحله GUID/profile→RAS handle→PPP IPv4→interface index/NET_LUID/GUID را می‌سنجد؛ نه alias-only، نه Apply یا no-leak. گزارش تکمیلی دریافت و [تحلیل زندهٔ کاربر](../reports/sstp-ras-identity-user-analysis.fa.md) ثبت شد: identity_chain_observed=true، یک پروفایل/entry/interface یکتا، PPP Up و roundtrip شناسه و stable_recheck موفق؛ بدون خطا. این موفقیت هویت اتصال جاری است، نه qualification packet/reconnect/boot یا مجوز Apply. هیچ تکرار ابزار یا elevation فعلاً لازم نیست و هیچ رمز/نام/IP/GUID صادر نشده است.
- [P7 قرنطینه Allow بومی](../reports/sstp-native-quarantine-p7-analysis.fa.md): source51056e9، run39207924748، نتیجه failed؛ 87check،10termination و10recovery در powershell.exe جدید؛2Restore از Quarantine ناقص؛ remaining=0. اجرای اول run39206606322 به دلیل اختلاف baseline propertyهای قوانین نامرتبط failed بود و پنهان/تبدیل به PASS نشد. معیار baseline حذف نشده؛ getter دقیق و تشخیص bounded diff اضافه شد. نه guard، تغییر defaultهای پروفایل، صد قانون واقعی کاربر، فیلتر SSTP یا packet/reconnect/boot. guard/coordinator نهایی هنوز لازم است؛ گزارش جدیدی از کاربر لازم نیست.
- [کنترل P7C فقط‌خواندنی](../reports/sstp-rule-readonly-control-p7c-analysis.fa.md): source84f308c، run39210801229، completed=true؛۶۶۰ثانیه/۱۳snapshot و۵fixture خالص. بدون setter، همان نوع اختلاف دو قانون در Description/DisplayGroup/DisplayName در ثانیه۵۴۰ دیده شد؛ قبل ثانیه۴۸۰ برابر بود. تبدیل دسته متن literal→resource_reference؛ rule_count=348 ثابت، added/removed=0 و profile baseline منتخب برابر. مستند Microsoft تغییر DisplayName بدون modification object را ممکن می‌داند. علت دقیق، هویت یکسان با قواعد قبلی و عدم تغییر همهٔ فیلترها اثبات نشده؛ دو اجرای P7 همچنان failed و شروط ایمنی حفظ شدند. گام بعد جداسازی audit نمایشی از مقایسهٔ policy/هفت فیلتر با snapshot strict قواعد خود برنامه است؛ classifier هنوز Apply را مجاز نمی‌کند. نه resident محصول، نه تغییر دستگاه کاربر یا گزارش تکراری.
- همزمان کار فنی باقیمانده اتصال موتور مرجع به قرارداد snapshot/adapter مؤثر واقعی، transition guard/readback، مدیریت Allowهای قدیمی/GPO و inbound/LAN، سپس qualification binding/قطع‌وصل/DNS/IPv6/boot است؛ محصول نباید با watchdog دائمی یا زمان انقضا ساخته شود. دستگاه کاربر تغییر نکرده و هیچ فرمان Apply جدیدی تحویل نشده است.

### سابقه معتبر S3U — PASS محدود provider با fixture کنترل CI
- [گزارش و سه رسید](../reports/sstp-ci-control-success-analysis.fa.md): run39195750447 و منبع d62a0e6c548515ed5bd4139eb06983b99249fd37؛ دو دور کامل با همان native code، زمان۷۵ثانیه و guardها. native passed=true؛ نه SSTP/enforcement یا Windows11 کاربر و نه مجوز Apply.
- helper جداگانه دو Allow مخصوص binaryهای runner و چهار host-IP مشاهده‌شدهٔ TCP443 اضافه کرد؛ هر دو قاعده و task helper حذف شدند، remaining_rules=0 و snapshot منتخب قبل/بعد برابر. مسیر انقضای helper فقط مسلح شد و در این اجرا لازم نشد؛ timer_fallback_used=false. هیچ Allow عمومی یا تغییر دستگاه کاربر وجود ندارد.
- خطاهای HTTP/Socket/renewal در diagnostic این اجرا مشاهده نشدند. فیلد ثابت network_exception_added=false در schema قدیمی diagnostic نماینده کل workflow نیست؛ وجود و حذف دو Allow در رسید fixture و کد آشکار است. هیچ IP/path/credential/raw log منتشر نشد.
- این پرسش دامنه بعداً با توضیح نهایی کاربر حل شد: Allowlist مقصدها همراه کیل‌سوییچ فقط از VPN؛ سند نیاز قطعی بالاتر مبناست. این بند سابقه سؤال قبلی است، نه blocker جاری.

### سابقه S3U تشخیصی پیش از اصلاح CI — شاهد اختلال کانال کنترل
- [تحلیل و شمارنده‌های محدود](../reports/sstp-runner-control-analysis.fa.md): run 39194616498، منبع 4a046fbd5459c28e6aa7e1b1c9e40eea98b7331d؛ HTTP/Socket از ثانیه۱۱، exception renewal و لغو worker در ثانیه۸۸ نسبت به cutoff. در فایل‌های بررسی‌شده درخواست cancel از سرور مشاهده نشد؛ این نبودِ مطلق یا انتساب به عامل خاص را ثابت نمی‌کند. مقصد/stacktrace/raw log خصوصی منتشر نشد و نسخه runner نامعلوم است.
- دور اول موفق، دور دوم این بار round_2_driver و لغو؛ S3U همچنان passed=false. چهار PowerShell اصلی، guard و timer بدون تغییر. فقط collector محدود افزوده شد؛ هیچ allow شبکه‌ای یا probe خارجی اضافه نشد. ناشر رسید و diagnostic را موفق ثبت کرد.
- پیش از اجرای دوباره باید fixture CI با کانال کنترل محدود و cleanup دقیق طراحی شود؛ هنوز ساخته/اجرا نشده و سیاست کاربر نیست. اجرای چهارم انجام نشد. BAT۶ و SSTP holand دست‌نخورده و Apply آماده نیست.

### S3U ناتمام — دور اول موفق، دور دوم دو بار لغو؛ انتشار اصلاح شد
- [منبع](https://github.com/kokononox/battle-net-agent-lab/tree/a60fde6c11c437e3b187d1e0cb0b5b8aa5c438f4/sstp-unset-s3u) · [طرح و حدود](SSTP-UNSET-S3U.fa.md). مستقل از S3 سخت‌گیرتر؛ هیچ guard قبلی عوض نشده است. **نتیجه جدید:** [تحلیل و رسیدهای دو اجرا](../reports/sstp-unset-s3u-analysis.fa.md). هر دو فقط یک دور کامل و سپس cancelled در round_2_timer؛ passed=false و Apply ممنوع. [اصلاح محدود](https://github.com/kokononox/battle-net-agent-lab/commit/51fd173698446377d29b1366cb5aa624348eb840) انتشار رسید cancelled را در اجرای تازه عملی کرد. علت لغو از لاگ معلوم نیست؛ اجرای سومِ تغییر فایروال راه نیفتاد. [کنترل فقط‌انتظار S3W](../reports/sstp-wait-control-s3w-analysis.fa.md) اکنون با ۱۸۱ ثانیه انتظار کامل PASS شد؛ لغو عمومی پس از حدود دو دقیقه در این کنترل مشاهده نشد، اما علت لغو S3U اثبات نشده است. پیش از تکرار mutation باید اثر آن بر کانال کنترل runner بررسی شود.
- baseline هر سه profile باید NotConfigured باشد؛ تبدیل baseline به Allow برای PASS انجام نمی‌شود. دو دور روی همان VM، نه دو سیستم مستقل. registry فقط read-only، هفت مسیر profile مشخص و valueهای مستقیمشان با نوع/وجود/محتوا مقایسه می‌شوند، نه تمام registry یا WFP. داده خام فقط در پوشه خصوصی CI و upload فقط receipt محدود است.
- driver موقتاً outbound سه profile را Block و با Exit73 بدون cleanup خارج می‌شود؛ task SYSTEM باید همان propertyها را به NotConfigured برگرداند. CIM stored/effective، COM getter مستقل، hash ویژگی‌های منتخب rules، state دقیق کلیدها، مشاهده mutation در valueهای DefaultOutboundAction، replay و cleanup سنجیده می‌شوند. fallback موفقیت timer محسوب نمی‌شود.
- مستند Microsoft NotConfigured را GPO-only معرفی می‌کند؛ این تست صرفاً qualification رفتار provider همان build است، نه تغییر مستند/اثبات پشتیبانی عمومی Windows11 یا مجوز Apply. version/build/PowerShell در receipt ثبت می‌شوند. هیچ SetValue/DeleteValue/registry-write، policy reset/import، game/VPN/hosts-change یا enforcement واقعی در این آزمون نیست.
- فقط windows-2025 و ubuntu-latest استاندارد؛ larger/paid runner فعال نشده، هزینه صفر تضمین نشده است. دستگاه کاربر تغییر نمی‌کند؛ S2/فرمان/BAT99/toggle/Resume جدید لازم نیست.

### baseline محلی کاربر تأیید شد — NotConfigured در هر سه profile
- [خروجی خلاصه بدون اطلاعات خصوصی](../reports/sstp-user-local-outbound.json). Domain/Private/Public در PersistentStore هر سه DefaultOutboundAction=NotConfigured هستند. این خروجی فقط local stored setting است؛ به‌تنهایی effective action یا خاموش‌بودن firewall را نشان نمی‌دهد. S1 پیش‌تر هر سه firewall enabled و ActiveStore outbound=Allow را ثبت کرده بود.
- اکنون می‌دانیم **gate فعلی S3 baseline دستگاه کاربر را هم رد می‌کند**؛ این به معنی اجرای S3 روی کاربر یا اثبات علت دقیق توقف runner نیست. مقدارهای runner از این خروجی کاربر استنتاج نشوند.
- NotConfigured خودسرانه به Allow تبدیل نشود؛ بازگردانی effective Allow با بازگرداندن دقیق local unset یکی نیست. مستند Microsoft برای Set-NetFirewallProfile و netsh، NotConfigured را GPO-only توصیف می‌کند؛ رفتار provider در آزمون اولیه به‌تنهایی راهکار عمومی/مستند برای Windows کاربر نیست.
- گام بعد طراحی/آزمون اختصاصی round-trip حالت unset با شاهد مقدار stored/effective و حفظ ruleهای نامرتبط است؛ نه حذف guard یا reset/import کل policy. هیچ کد Apply تازه، تغییر دستگاه کاربر یا runner تازه برای این بررسی اجرا نشد. ورودی کاربر کافی است؛ خروجی اضافی فعلاً لازم نیست و Pause حفظ شود.

### نتیجه نهایی این گام S3 — PASS قدیمی جایگزین gate تازه نیست
- [تحلیل دقیق دو نسخه](../reports/sstp-rollback-s3-analysis.fa.md) · [شواهد](../reports/sstp-rollback-s3-analysis.json) · [رسید نخست](../reports/sstp-rollback-s3-first-build.json) · [رسید نسخه سخت‌گیرتر](../reports/sstp-rollback-s3-build.json).
- run39187957739:۱۶fixture و دو سناریوی واقعی محدود پس از abrupt exit موفق؛ SYSTEM timer بدون fallback، حفظ conflict و fixture نامرتبط، replay و cleanup. run39188345339:۱۷fixture پاس، اما full_setup پیش از mutation با s3_no_real_profile_transition_available متوقف؛ live scenario صفر. نسخه اخیر PASS نیست.
- guard جدید براساس مستند Microsoft، baseline محلی غیر Allow/Block را نمی‌پذیرد؛ سه profile و حداقل یک Allow هم می‌خواهد. baseline در receipt نیست؛ نسبت‌دادن قطعی توقف به NotConfigured یا هر حالت مشخص دیگر مجاز نیست. هیچ guard حذف/دور زده نشده و برای PASS تنظیمات runner normalize نشده‌اند.
- ورودی کم‌خطر لازم از کاربر فقط PersistentStore Name/DefaultOutboundAction است؛ S1 ActiveStore را می‌داد. Apply/لانچر S3 کاربری وجود ندارد؛ settings کاربر تغییر نکرده‌اند. S2 تکرار و backup upload/BAT99/toggle/Resume نه؛ Pause حفظ شود.
- اولویت نقد همکاران: تفاوت unset/NotConfigured و مقدار effective، بازیابی مستند و بدون تغییر semantics store محلی، خطای ترکیبی precondition و observability. compare-before-write اتمیک نیست؛ فعلاً enforcement SSTP/Level3 یا صفرtelemetry اثبات نشده است.

### S3 در حال آزمون — تغییر واقعی محدود فقط روی runner موقت
- [منبع](https://github.com/kokononox/battle-net-agent-lab/tree/40fd1b53b13cc03d77f0054dd467667958207474/sstp-rollback-s3) · [طرح/حدود](SSTP-ROLLBACK-S3.fa.md). فقط standard windows-2025 و receipt publisher ubuntu-latest؛ larger/paid runner فعال نشده، هزینه صفر تضمین نشده است.
- دو سناریو: full و partial_conflict. journal پیش از write، snapshot PersistentStore و ActiveStore، task SYSTEM قبل Apply، driver خود ابزار عمداً Environment.Exit(73) بدون cleanup؛ timer باید propertyهای برنامه‌ریزی‌شده را restore کند. فقط fixture ruleهای GUID خود ابزار و default outbound profiles تغییر می‌کنند؛ Allowهای موجود runner disable نمی‌شوند و هیچ Blizzard/game/VPN اجرا نمی‌شود.
- fixtureB با تغییر بیرونی مصنوعی باید conflict بماند، نه overwrite؛ fixtureC نامرتبط باید تغییر بیرونی‌اش را حفظ کند. replay و cleanup task/ruleهای همان تست سنجیده می‌شود؛ fallback controller به معنی موفقیت timer نیست. نخستین run39187957739 با۱۶fixture و دو سناریو موفق شد؛ نسخه تکمیلی در حال آزمون است.
- این compare-before-write است، **CAS اتمیک نیست**؛ race بین read/write و منشأ تغییر هم‌مقدار حل نشده‌اند. fingerprint فقط fixtureهاست، نه تمام ruleهای کاربر؛ GPO/IPsec/WFP/reboot و SSTP/IPv6/DNS/certificate/enforcement آزمون این مرحله نیست. موفقیت runner مجوز Apply روی کاربر نیست.
- هیچ بسته/لانچر S3 برای کاربر ساخته نمی‌شود؛ source هم با guard فقط CI است که attestation امنیتی محسوب نمی‌شود. کاربر S2 را تکرار نکند، backup خصوصی را نگه دارد، Pause و تنظیمات فعلی را حفظ کند.

### S2 واقعی کاربر PASS — بدون Apply، بدون اثبات rollback شبکه
- [تحلیل](../reports/sstp-recovery-s2-user-analysis.fa.md) · [شواهد redacted](../reports/sstp-recovery-s2-user-analysis.json). export غیرخالی، ACL و hash worker تأیید شده؛ task SYSTEM و receipt موفق، LastTaskResult=0 و task خودش حذف شده است. خلاصه profileهای firewall قبل/بعد برابر است، نه تمام rule/filterها.
- firewall_restore_import_tested=false، independent_network_rollback_proven=false و ready_to_apply_isolation=false؛ هیچ network setting، VPN/game process یا Resume توسط ابزار تغییر نکرده است. snapshot/user report موفق به معنی enforcement یا نبود telemetry نیست.
- S2 تکرار نشود؛ backup خصوصی نگه داشته و upload نشود. گام بعد عامل: طراحی/آزمون rollback واقعی مجاز در محیط موقت با journal/failed partial apply و watchdog، بدون overwrite کورکورانه policy/GPO. هنوز ابزار Apply یا restore واقعی ساخته/تحویل نشده؛ هیچ runner تازه برای این تحلیل اجرا نشد. کاربر Pause و تنظیمات فعلی را حفظ کند.

### S2 — native موفق، اما نه rollback واقعی یا isolation
- [راهنما و حدود](SSTP-RECOVERY-S2.fa.md) · [رسید Windows](../reports/sstp-recovery-s2-build.json) · [درخواست نقد همکاران](PEER-REQUEST-SSTP-S2.fa.md).
- منبع `684626bec2cb7e7c610126b46187eb61db508e4b`؛ run `39186827205`. syntax/AST،۱۷ fixture، export policy خصوصی، ACL خصوصی، task زمان‌دار SYSTEM، receipt، LastTaskResult=0 و حذف task خودش پاس شدند. خلاصه profileهای فایروال قبل/بعد برابر بود؛ تمام rules/filters مقایسه نشده‌اند. هیچ policy خصوصی از runner آپلود نشد.
- تلاش‌های اول gate را نگذشتند؛ در دو رسید diagnostic، unexpected_worker_command ثبت شد. whitelist آزمون Join-Path و Set-StrictMode موجود در worker را جا انداخته بود؛ فهرست دقیق اصلاح شد، محدودیت فرمان تغییر شبکه حذف نشد. تلاش اول علت جزئی در receipt نداشت. شکست‌ها موفق جا زده نشدند و بسته پیش از PASS تحویل نشد.
- S2 شبکه را تغییر نمی‌دهد، اما فقط‌خواندنی مطلق نیست: export خصوصی در ProgramData با ACL Admin/SYSTEM و task یکتا برای۴۵ثانیه بعد می‌سازد؛ worker فقط رسید می‌نویسد. backup و task رسید، بازیابی شبکه نیستند. firewall import/enforcement/user-device هنوز تست نشده؛ ready_to_apply=false و independent_network_rollback_proven=false.
- بسته مستقل PowerShell5.1؛ دو PS1 تحویلی CRLF و دقیقاً هم‌هش با بایت‌های آزموده‌شده‌اند. فقط JSON قابل‌اشتراک فرستاده شود، نه wfw یا پوشه خصوصی. هیچ تغییر VPN/game/hosts/firewall rule یا Resume انجام نمی‌شود.
- کاربر احتمال داد کیل‌سوییچ روی دستگاه فعال نشده؛ با نبود group/state مورد انتظار سازگار است، نه نفی هر فیلتر WFP. Enable/Disable/BAT99 لازم نیست. فقط runner استاندارد استفاده شد؛ هزینه صفر تضمین نشده و larger/paid runner فعال نشده است. N2 متوقف و سؤال fingerprint A→B باز است.

### S1 واقعی کاربر — مسیر Level3 روی VPN، نه ایزولاسیون
- [تحلیل و تصمیم](../reports/sstp-preflight-s1-user-analysis.fa.md) · [شواهد redacted](../reports/sstp-preflight-s1-user-analysis.json). raw report و آدرس VPN کاربر عمومی نشده‌اند.
- holand یک تطابق user، Connected/Sstp، interface49/IPv4؛ split_tunneling=true ولی هر دو IP جاری Level3 با مسیر /1 روی49 هستند. flag به‌تنهایی اثبات bypass نیست. یک TCP443 Established سرویس SSTP مطابق DNS سرور، نه binding قطعی پروفایل.
- هر سه پروفایل firewall روشن ولی default outbound=Allow؛۱۲۱ rule فعال شامل۱۰۰Allow و۲۱Block، خلاصه همگیLocal و بدونcap. گروه SSTP Kill Switch قانون خروجی فعال ندارد و state مورد انتظار غایب است؛ دیگر WFP/kill-switchها از این گزارش نفی نمی‌شوند.
- یک default route IPv6 خارج VPN دیده شده؛ ریسک طراحی، نه اثبات leak. query_errors=0،review_blockers=0 اما ready_to_apply=false و rollback_prepared=false. S1 تنظیمی تغییر نداده است.
- گام بعد عامل: طرح Apply کوتاه با snapshot/rollback کامل مستقل محلی/زمان‌دار و gateهای non-mutating، مدیریت قابل‌بازیابی Allowهای فعلی، IPv6، DNS/certificate/reconnect. هنوز Apply ساخته/اجرا نشده؛ هیچ runner تازه در تحلیل گزارش فعال نشد. کاربر Pause را نگه دارد؛ S1 تکرار، BAT99 یا toggle کیل‌سوییچ لازم نیست.

### S1 — دامنه روشن و Kill Switch فعلی بازبینی شد
- کاربر کل Windows و VPN داخلی SSTP با نام holand را تأیید کرد. Connect-rus ارسالی برای پروفایل دیگری است؛ KillSwitch1.2 اولین SSTP متصل را برمی‌گزیند، نه الزاماً holand. exeهای آپلودشده شورتکات تبدیل‌شده بودند و بنا به درخواست کاربر کنار گذاشته شدند.
- Kill Switch فعلی RemoteAccess را به همه مقصدها/برنامه‌ها باز می‌گذارد، DNS و server TCP443 دارد و Allowهای قبلی را خنثی نمی‌کند. بنابراین فقط‌Level3 نیست؛ Disable/Reset کورکورانه توصیه نمی‌شود. فایل state خصوصی خوانده یا منتشر نشده است. مخزن SSTP فقط خوانده شد.
- [شرح و بازبینی](SSTP-ISOLATION-S1.fa.md)؛ [رسید Windows](../reports/sstp-preflight-s1-build.json). S1 فقط نام پروفایل، DNS/route/interface، ActiveStore و خلاصه قوانین فعال، گروه Kill Switch و کاندید SSTP را می‌خواند. هیچ credential/key یا فایل بازی/hosts خواندن گسترده/نوشتن یا upload خودکار ندارد؛ DNS lookup ممکن است درخواست شبکه بسازد.
- syntax/AST و۲۰ fixture مصنوعی روی Windows استاندارد پاس شدند؛ این آزمون VPN واقعی/firewall واقعی/Apply/بازی نیست. گزارش همیشه ready_to_apply_isolation=false است. IP دستی فعلاً لازم نیست؛ از پروفایل و snapshot خوانده می‌شود، نه فهرست دائمی CDN.
- گام بعد تنها دریافت گزارش S1 است. قبل Apply باید Allowهای موجود/GPO، IPv6، SSTP binding/reconnect، DNS/CRL/OCSP و backup/rollback مستقل محلی/زمان‌دار روشن و تست شوند. کل سیستم ممکن است مرورگر/چت را هم قطع کند. کاهش امنیت TLS مجاز نیست.
- همه بندهای قدیمی پایین‌تر تاریخچه‌اند؛ پیشنهاد قدیمی اجرای T1/Resume یا ادامه N2 اقدام جاری نیست. نبود telemetry در مقصد مجاز و fingerprint A→B هنوز اثبات نشده‌اند.

### تغییر جهت صریح کاربر — allowlist واقعی برای SSTP و مسیر آپدیت
- کاربر توضیح داد منظورش ایزولاسیونی است که فقط سرور/مقصدهای آزمون۶ و سرور VPN خودش (SSTP) از اینترنت عبور کنند؛ هدف صرفاً denylist hosts یا ادامه دنبال‌کردن DLLها نیست.
- طرح مفهومی، نه پیکربندی اجراشده: زیرلایه فیزیکی برای tunnel فقط endpoint سرور SSTP؛ درون VPN فقط مقصدهای ضروری آپدیت. چند IP متغیر Level3، DNS bootstrap، سیاست IPv6، route/interface و اعتبارسنجی گواهی باید جدا بررسی شوند. این‌ها هنوز حل/آزموده نشده‌اند؛ خاموش‌کردن TLS/revocation راه‌حل نیست.
- دامنه اکنون روشن است: کل Windows، native SSTP، holand؛ IP/پورت زنده و policy از S1 خوانده می‌شوند. هیچ username/password/certificate private key لازم نیست.
- محدودیت کل سیستم می‌تواند مرورگر/چت و بقیه سرویس‌ها را هم تا rollback قطع کند؛ قبل اجرای هر change باید snapshot سیاست فعال، ruleهای allow موجود/GPO، تونل و مسیرها، backup و recovery محلی قابل اجرا آماده و آزمایش شوند. صرف افزودن rule allow به معنی default-deny واقعی نیست.
- N2 شمارنده API فقط در draft محلی `/data/network-route-observer-n2` ایجاد شد؛ source/workflow آن push نشده و runner/build/native test آن اجرا نشده است. بررسی libcef/route دیگر اقدام بعدی خودکار نیست. هیچ rule، hosts، route، VPN یا فایل بازی تغییر نکرده است.
- این شبکه allowlist هم به‌تنهایی نبود داده شخصی در درخواست‌های مجاز یا fingerprint انتقال A→B را ثابت نمی‌کند. نتیجه۲۶GET Level3 و نامعلوم بودن HTTPSهای دیگر حفظ می‌شود؛ با طرح تازه پاک یا تعمیم داده نشود.

### N1 کاربر — CEF در فرایند صاحب HTTPS، نه اثبات BoringSSL یا محتوا
- [تحلیل](../reports/network-library-inventory-n1-user-analysis.fa.md) · [شواهد ماشینی](../reports/network-library-inventory-n1-user-analysis.json) · [گزارش](../reports/network-library-inventory-n1-user.json).
- اجرای کاربر window_ended بدون error، sampling_errors=0،sample_count=12 وlimit_hit=false؛۹ فرایند verified و۱۳ فایل ماژول PE parsed بدون cap. این گزارش ارسالی کاربر است؛ سابقه «N1 هنوز Windows-tested نیست» پیش از این اجرا تاریخی است، نه وضعیت اجرای جدید.
- سه tuple TCP/443 همگی process_index5 این گزارش:3.125.253.166،2.21.23.89،54.69.78.197. Index/PID به نمونه قبلی قابل تعمیم نیست و تفاوت مقصدها A/B کنترل‌شده نیست.
- همان battle.net.exe امضاشده libcef.dll/chrome_elf.dll،winhttp/wininet/ws2_32/secur32/sspicli را بار کرده است. exportهای CEF حاضر؛ SSL_write/SSL_write_ex استاندارد در exportهای بررسی‌شده libcef نیستند. WSASend/WinHTTP/SSPI import شده‌اند، اما import/presence شاهد call واقعی نیست.
- محتوای HTTPS، hostname، TLS engine واقعی و علت دقیق کور بودن T1.1 همچنان نامعلوم‌اند. BoringSSL فرضیه است، نه یافته. N1 هیچ payload/key/hook ندارد؛ از نتیجه آن نبود hardware upload استنتاج نشود.
- تصمیم بعدی: call-route counter برای Winsock حتی غیرHTTP و APIهای WinHTTP/WinINet/SSPI با caller-module classification، سپس انتخاب نقطه پیش-TLS. N2 در این پاسخ ساخته/اجرا نشده و runner تازه‌ای فعال نشده است؛ قبل تحویل به gate fixture/native و caveat پایداری نیاز دارد. فعلاً Pause؛ N1 یا تست Level3 تکرار نشود.

### N1 — مکمل شناسایی فقط‌خواندنی شبکه، بدون آزمایش دانلود
- source: `1469d04971ebcf069f4911b2c85c3a3c23881f9a` در شاخه پژوهش، مسیر `network-library-inventory-n1/`؛ [راهنمای تحویل](NETWORK-LIBRARY-INVENTORY-N1.fa.md) و [رسید آفلاین](../reports/network-library-inventory-n1-offline-validation.json).
- شواهد قدیمی D2/E2 بازبینی شد: categories محدود setup/Agent داشتند؛ شناسایی actual battle.net.exe صاحب چهار HTTPS نمونه اخیر نیستند. libcef/BoringSSL/OpenSSL برای آن فرایند هنوز تشخیص داده نشده است؛ پیشنهاد به یافته تبدیل نشود.
- N1 از runtime/helperهای اصلی T1.1 استفاده می‌کند، manifest/source همان build موفق را کنترل می‌کند، فایل قبلی را جایگزین یا manifest را بازنویسی نمی‌کند. فایل‌های مکمل SHA مستقل دارند و عضو manifest قدیمی نیستند؛ source ثبت شده است.
- فقط image معتبر Blizzard و هویت PID/creation پیش و پس از snapshot تازه TCP، module enumeration استاندارد Windows، hash و جدول PE import/export روی دیسک. فقط نام ثابت کتابخانه/API، هش، اندازه و دسته مسیر؛ نه مسیر کامل/نام ماژول نامرتبط/command line/payload/key یا dump حافظه.
- بدون hook/injection، درخواست Update/Pause، اجرای/kill/gate فرایند، hosts/firewall/cache/game-file write، TLS downgrade یا upload خودکار. بررسی امضا می‌تواند ارتباط certificate service داشته باشد؛ خود Battle.net باز ممکن است ترافیک خودش را بسازد. وضعیت Pause حفظ شود.
-۲۵ آزمون آفلاین parser/bounds، PE32/PE64، PID reuse، signature rejection، TCP attribution mock، privacy و non-mutation پاس شدند. helperهای native پایه قبلاً در T1.1 تست Windows داشتند؛ **خود N1 جدید هنوز روی Windows اجرا نشده**. هیچ workflow تازه یا runner برای ساخت ZIP راه‌اندازی نشده است.
- presence کتابخانه/export/import به معنی API usage واقعی نیست؛ delay import، static/dynamic resolving و UDP/QUIC پوشش کامل ندارند. نبود symbol یا نبود TCP در حالت Pause، نبود مسیر/ترافیک را ثابت نمی‌کند. این گام فقط انتخاب مسیر مشاهده بعدی است، نه verdict محتوا.
- ZIP مکمل بدون runtime است؛ باید داخل همان root بسته T1.1 که runtime/app دارد استخراج شود. فقط observerهای قبلی بسته شوند؛ Battle.net می‌تواند باز و paused/signed-out بماند. تا گزارش N1، هیچ Resume یا تعویض BAT لازم نیست.

### نتیجه واقعی T1.1 — Level3 بدون نشانه حساسِ تشخیص‌داده‌شده؛ HTTPSهای دیگر نامعلوم
- [تحلیل کامل](../reports/level3-audit-t11-user-analysis.fa.md) · [شواهد](../reports/level3-audit-t11-user-analysis.json) · [گزارش اصلی](../reports/level3-audit-t11-user.json).
- READY=true، observation_ended، error=null؛ reported_progress و reported_paused انتخاب کاربرند. بایت دانلود مستقل نداریم. hosts_changed_by_tool=false و hash برابر؛ پروفایل DNS نرمال‌شده قبل/READY/بعد پاس شد؛ نقص guard قبلی مانع این اجرا نشده است.
-۲۶ request کامل از Agent اصلی با hash قبلی؛ همه GET در plaintext Winsock و مسیر طبقه tpr، بدنه/query صفر. فقط accept/host/range در metadata هدر؛ credential/User-Agent/unknown header و CPU literal/field hints در این subset دیده نشده‌اند. raw مسیر/مقادیر در گزارش نیستند؛ ID encoded/hashشده نفی نشده و دریافت سرور ثابت نیست.
- **چهار مقصد عمومی TCP/443 برای یک battle.net.exe امضاشده (index6) نمونه‌برداری شده ولی input_events همان فرایند صفر است**:52.29.86.120،2.21.23.89،54.149.134.39،192.178.24.142. محتوا/hostname/علتِ فقدان capture نامعلوم؛ هیچ انتساب telemetry یا پاک بودن از IP مجاز نیست. BoringSSL/OpenSSL فرضیه است، نه یافته.
- یک sampler_error، دو attach_failed؛ Agent اصلی attached و بی‌خطای script. capها false و sampler متوقف است، اما پوشش کامل نیست. برچسب parsed_to_end در۱۸۷stream با صادرشدن۲۶request یکی نیست؛ parser می‌تواند Host نامعتبر/پورت پشتیبانی‌نشده را بی‌ردیف رد کند. این محدودیت در تحلیل نگه داشته شد.
- تصمیم: فعلاً همین نمونه Level3 تکرار و BAT تغییر نکند؛ مسیر بعد شناسایی فقط‌خواندنی API/TLS فرایند صاحب HTTPS و پوشش آن است. هیچ runner/build/rule تازه در این پاسخ اجرا نشد. آپدیت Pause؛ completion و fingerprint A→B هنوز حل نشده‌اند.

### گزارش DNS دریافت شد — اصلاح محدود T1.1، نه رفعِ اثبات‌شده روی دستگاه کاربر
- [گزارش کاربر](../reports/t1-dns-user-diagnostic.json) و [تحلیل](../reports/t1-dns-stop-analysis.json):۲۵ ردیف یکتا. هر۲۴ نام blocked دارای hosts_addresses=[0.0.0.0]، resolver_state=resolution_failed و error_code=11004 است. مقصد باز level3.blizzard.com بدون hosts override به2.21.23.18 و2.21.23.82 پاسخ عمومی داده است.
- guard قدیمی فقط sink_only را قبول می‌کرد؛ در این اجرای Windows، پاسخ0.0.0.0 به صورت خطای11004 دیده شده و آن guard وضعیت را تأیید نمی‌کرد. این نقص آمادگی ابزار است؛ نه اثبات ارسال/عدم ارسال داده یا firewall enforcement.
- `profile_gate.py` جدید فقط در win32، برای socket.gaierror دقیق11004، و فقط با entry صریح0.0.0.0 برای همان نام blocked و بدون هر آدرس متعارض/نامعتبر، وضعیت `explicit_hosts_sink_windows_no_data` می‌دهد. مقصدباز همچنان باید public_only باشد. پاسخ عمومی/مختلط نام بسته override نمی‌شود؛ missing entry/11001/11002/timeout/خطای عمومی رد می‌شوند.
- بازپخش گزارش روی فایل hosts موقت و resolver مصنوعی پاس شد؛ واقعیات Windows از گزارش کاربرند، replay اجرای زنده روی دستگاه نیست.۹۹ تست محلی شامل۲۰ regression تازه پاس؛ gateهای native/certificate استاندارد هم success شدند؛ این‌ها fixture/build هستند، نه اجرای اصلاح‌شده روی دستگاه کاربر.
- source T1.1: `7eacb50b04ffe4676ff85a8c37df9f5e03d1a97e`؛ هیچ BAT/hosts/firewall/game/TLS تغییر نکرده و شرط ایمنی حذف نشده است. بسته تازه در پوشه جدا جای اجرای نسخه قدیمی را می‌گیرد؛ manifest حذف یا دستی دستکاری نشود.
- [رسید T1.1](../reports/level3-request-audit-t11-build.json) و [بسته تازه](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39180867922/artifacts/12156645195)؛ SHA256 آرتیفکت `db78a6f82946e35555533ffaf995f6606ec3271ef7aec9b6fa2b64586eed2f5b`، نگهداری۷روز.
- هنوز READY/نمونه محتوایی سیستم کاربر نداریم. اجرای بسته تازه با BAT۰۶ بدون تغییر، همه مشاهده‌گرهای قدیمی/Battle.net/Agent/WoW ابتدا بسته، سپس بازکردن دستی Battle.net پس از درخواست و انتظار READY. Resume/Pause دستی؛ هیچ نصب تازه یا runner بزرگ/پولی اضافه نشده است.

### توقف T1 روی سیستم کاربر — تشخیص لازم، نه حذف guard
- خروجی کاربر به `STOP: bat06_resolution_not_confirmed_do_not_resume` رسیده است؛ قبل از پرسش مسیر بازی/شروع collector/READY. هیچ گزارش محتوایی تازه دریافت نشده است. چاپ خروجی به‌تنهایی اثربخشی یا شکست واقعی BAT را ثابت نمی‌کند.
- guard فعلی از۲۴ نام sink_only (loopback یا unspecified مانند0.0.0.0) و مقصدباز level3.blizzard.com با public_only می‌خواهد. یک resolve ناموفق/timeout یا mixed/public برای نام بسته، یا پاسخ غیرعمومی مقصد باز، می‌تواند مانع شود؛ هنوز معلوم نیست کدام است.0.0.0.0 از قبل پذیرفته می‌شود؛ این مشکل با حدسِ نپذیرفتن0.0 اصلاح نشد.
- عیب‌یاب مکمل در `diagnostics/t1-dns/` فقط خطوط همان۲۵ نام در hosts و `socket.getaddrinfo` همان runtime را می‌خواند؛ snapshot DNS با timeout۲۰ثانیه، نام mismatch و کد عددی خطا را ثبت می‌کند. hook/flushdns/hosts write/firewall/process control/Update/upload ندارد؛ lookup می‌تواند ترافیک DNS ایجاد کند.
- ZIP شامل `Diagnose-Profile.cmd`، `app/diagnose_profile.py` و `README-DNS-fa.md` است؛ باید داخل ریشه بسته T1 موجود که runtime/app دارد استخراج شود. هیچ فایل قبلی جایگزین نمی‌شود؛ نصب Python یا Administrator برای عیب‌یاب لازم نیست.
- کنترل‌های محلی parser/حذف نام‌های نامرتبط/pass-fail/timeout/عدم تغییر فایل موقت و ZIP integrity پاس؛ این عیب‌یاب روی Windows هنوز اجرا نشده است و برایش runner تازه‌ای راه‌اندازی نشده است. نتیجه fixture قبلی T1 با موفقیت guard واقعی کاربر یکی نیست.
- گام بعد: خروجی JSON یا خطوط MISMATCH کاربر، سپس اصلاح مشخص مبتنی بر شاهد؛ نه حذف guard، اجرای BAT دیگر یا Resume برای دورزدن STOP.

### گزارش تازهٔ کاربر — فقط BAT۰۶ دانلود را راه انداخت؛ T1 ساخته شد، هنوز نمونه کاربر نداریم
- کاربر صریحاً نام `06-All-Except-Level3.bat` را داد و گفت تنها همین گزینه دانلود را راه انداخت. در این مکمل، ۲۴ نام شناخته‌شده بسته و فقط `level3.blizzard.com` از آن فهرست خارج است؛ اینترنت به همین یک مقصد محدود نشده است.
- سپس روشن کرد دانلود کامل نشده و عمداً Stop/Pause کرده تا فرصت تست بماند. درصد/بایت جدید و گزارش ماشینی برای این سری BAT هنوز نداریم. نتیجه R1 قبلی (baseline+یکی) با این سری (همه‌جزیکی) مخلوط نشود.
- مسیر فعلی `level3-request-audit-t1/`: attach-only به فرایندهای امضاشده Blizzard؛ همان hook خواندنی، بازسازی محدود HTTP/1 از send/WSASend و ورودی پیش-TLS EncryptMessage، طبقه‌بندی query/header/body و تطبیق محلی رشته CPU. خام در RAM، گزارش metadata؛ بدون raw values/کلید TLS/URL کامل/بدنه یا upload خودکار.
- T1 hosts را apply/restore نمی‌کند و BAT۰۶ پایدار می‌ماند. هیچ lifecycle control یا Update/Pause/Repair خودکار، TLS downgrade یا اجرای WoW وجود ندارد. DNS sink و hash فقط شاهد محدود‌اند، نه firewall enforcement.
- ۷۹ آزمون محلی پاس شد؛ gate بومی Windows با fixture متعلق به ابزار، runtime بسته و امضای pinned رسمی نیز success شد. فقط windows-2025 و ubuntu-latest استاندارد، بدون runner بزرگ/پولی، ورود یا نصب بازی. رسید موفق در گزارش build ثبت شد؛ این gate اثبات آپدیت بازی/ترافیک کاربر نیست.
- صفر بودن بدنه GET، نبود CPU literal یا field hint، اثبات نبود همه داده‌های شخصی نیست؛ User-Agent/query/header/شناسه encoded و پوشش ناقص همچنان مهم‌اند. recv/بایت دانلود اندازه‌گیری نمی‌شود؛ سؤال fingerprint A→B باز است.
- source: `321a2634871223c24e5018c6145c4e18690c682f`؛ [رسید موفق](../reports/level3-request-audit-t1-build.json)؛ [بسته T1](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39179835020/artifacts/12155548669)؛ [راهنما](LEVEL3-REQUEST-AUDIT-T1.fa.md). Artifact SHA256: `6f93d90d14b9b42f945929537dff3308aeaab8cea22c3f439d088122a5a6e231`، نگهداری۷روز؛ billing رایگان تضمین نشده است.
- خودآزمایی native علاوه بر مشاهده send/WSASend/SSPI منفی، بازسازی دو درخواست مصنوعی loopback، تشخیص field/query/credential presence، حذف مقادیر raw از JSON و تفکیک SSPI ناموفق را assert می‌کند. هیچ Blizzard/game در این gate اجرا نمی‌شود؛ setup رسمی فقط برای امضا دانلود می‌شود.
- بازبینی مستقل قدیمی [Level3](../reports/historical-level3-review.fa.md): مجموع۱۳۷ درخواست HTTP/1 قابل‌بازسازی در سه نمونه startup VM (۵۴/۴۹/۳۴)، همه GET، بدنه صفر، بدون query و مسیر tpr؛ این‌ها داده اجرای BAT۰۶ کاربر یا آپدیت کامل WoW نیستند. وجود User-Agent همچنان metadata است؛ نبود داده شخصی ثابت نشده است.
- برای همکاران: این گام بررسی محتوای مسیر گزارش‌شده است، نه دور تازهٔ تغییر block یا تکرار همه نصب‌ها. نقد مفید: framing/concurrency/coverage، طبقه‌بندی field و آزمون تمایزبخش بدون گسترش مجوز.

### H1: یک جفت آزمایش دامنهٔ تله‌متری، فقط هنگام راه‌اندازی
- run: [39167612892](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39167612892).
- در baseline، نام CPU همان VM داخل بدنهٔ `POST /data` به `telemetry-in.battle.net`، در **ورودی EncryptMessage پیش از TLS** دیده شد. موفقیت محلی رمزنگاری، دریافت یا نگهداری سرور را ثابت نمی‌کند.
- با مسدودسازی فقط همان دامنه در hosts ماشین موقت، درخواست‌های بازسازی‌شده به آن دامنه در نمونه از ۹ به صفر رسید و تطبیق رشتهٔ CPU مرجع همان VM دیده نشد. Agent راه افتاد و درخواست‌های سرویس نسخه و CDN همچنان دیده شدند.
- دو VM دارای CPU متفاوت بودند، هرچند source، تصویر runner و مجموعهٔ هش باینری‌های مشاهده‌شده یکسان بود. این یک جفت مشاهدهٔ محدود است، نه برآورد آماری یا اثبات قطع همهٔ تله‌متری.
- در درخواست‌های قابل بازسازی بازوی مسدود Host تازه‌ای نسبت به baseline دیده نشد؛ این نبود fallback پنهان، مسیر IP مستقیم یا دادهٔ کدگذاری‌شده را تضمین نمی‌کند.
- [تحلیل فارسی H1](https://github.com/kokononox/battle-net-agent-lab/blob/27d065c1846b0a7be16fd38980511edffe6d6d04/reports/startup-ab-api-h1-analysis.fa.md) · [شواهد ماشینی](https://github.com/kokononox/battle-net-agent-lab/blob/27d065c1846b0a7be16fd38980511edffe6d6d04/reports/startup-ab-api-h1-analysis.json).

### U1: ابزار محلی آمادهٔ آزمایش، نه نتیجهٔ آپدیت
- source تأییدشده: `a73531277544939348e8c1e77bd4e92121ac2041`؛ run نهایی: [39171328838](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39171328838).
- ۳۵ آزمون ایمنی/بازیابی/گزارش‌ساز، خودآزمایی native با runtime بسته و کنترل امضای واقعی Blizzard پاس شدند. تأیید امضا از روش native قبلاً آزموده‌شدهٔ پروژه با بررسی revocation استفاده می‌کند؛ حفاظت گواهی پایین آورده نشده است.
- خودآزمایی شامل send، WSASend و ورودی منفی EncryptMessage است؛ موفقیت یک جلسهٔ TLS واقعی یا آپدیت را اثبات نمی‌کند. باینری رسمی فقط برای آزمون امضا دانلود شد و در این build اجرا نشد.
- ابزار روی سیستم کاربر **attach-only** است: خودش Battle.net/بازی را launch، kill، suspend، resume یا gate نمی‌کند؛ Update/Pause/Cancel/Repair درخواست نمی‌کند و فایل بازی را تغییر نمی‌دهد.
- گزینهٔ بلوک دامنه فقط پس از تأیید صریح کاربر، hosts را موقتاً تغییر می‌دهد؛ بکاپ خصوصی و بازیابی دارد. در گزارش واقعی تازه، بلوک و بازیابی hosts و اتصال به Agent اصلی ثبت شده‌اند؛ یک Agent دیگر attach_failed و یک sampler_error دارد. خودآزمایی محلیِ ارسالی بررسی و پاس شد، اما فقط fixture مصنوعی را پوشش می‌دهد.
- تزریق مشاهده‌گر می‌تواند پایداری/زمان‌بندی را تغییر دهد؛ اولین درخواست‌ها و APIها/کدگذاری‌های پوشش‌داده‌نشده ممکن است از دست بروند. گزارش، payload/header/query/کلید TLS یا نام واقعی CPU را صادر نمی‌کند و خودکار آپلود نمی‌شود.
- [رسید ساخت موفق](https://github.com/kokononox/battle-net-agent-lab/blob/d5075f8f6e6431dd27744c95006da7641c5586ae/reports/local-observer-u1-build.json) · [راهنمای همان نسخه](https://github.com/kokononox/battle-net-agent-lab/blob/a73531277544939348e8c1e77bd4e92121ac2041/local-retail-monitor/README-fa.md) · [تحویل و سابقهٔ اصلاح خطاهای انتشار](https://github.com/kokononox/battle-net-agent-lab/blob/f43b66b2706c6bd018fc155556dfc12733be48df/docs/LOCAL-PRIVACY-MONITOR-U1-RESULT.fa.md).

### نتیجهٔ خودآزمایی ارسالی کاربر
- [گزارش خودآزمایی محلی](../reports/local-observer-u1-user-selftest.json): passed=true، loopback_only=true، send_observed=true، wsasend_observed=true، sspi_negative_input_observed=true، worker_exited=true، script_errors=0 و error_code=null.
- فایل از کاربر دریافت شده است؛ حاوی هویت دستگاه یا امضای دیجیتال provenance نیست. انتساب به دستگاه بر مبنای گزارش کاربر و جریان این جلسه است، نه مشاهدهٔ زندهٔ عامل.
- این بند فقط نتیجه fixture است. گزارش اجرای اصلی اکنون جداگانه دریافت و در بخش بعد تحلیل شده؛ completion همچنان ثابت نشده است. پاس fixture تضمین نبود تله‌متری یا بی‌خطر بودن ابزارگذاری نیست.

### اولین گزارش واقعی کاربر — دانلود تا ۳۰٪
- [تحلیل و تصمیم جاری](../reports/local-observer-u1-user-30pct-analysis.fa.md) و [گزارش اصلی](../reports/local-observer-u1-user-30pct.json).
- Agent واقعی و READY ثبت شده؛ بلوک دامنه در بررسی‌های DNS برقرار بوده و در پایان hosts دقیقاً بازیابی شده است. دانلود ۳۰٪ گفتهٔ کاربر است؛ final state=reported_paused و نسخهٔ نشانگر جدید به معنی تکمیل بازی نیست.
- در نمونه نام CPU مرجع یا host_hint دامنهٔ telemetry دیده نشده؛ یک sampler_error، یک attach_failed و late_attach مانع ادعای پوشش کامل هستند. هیچ تضمین صفر بودن upload/telemetry نداریم.
- **بلوک پس از خروج ابزار فعال نیست.** اگر تست فعلاً تمام است Battle.net دستی Exit شود. گام بعد با درخواست‌های تازه از U2 به R1 مبتنی بر BAT 3 و بدون hook تغییر کرد؛ نصب فعلی حفظ می‌شود و بازگردانی بکاپ درخواست نشده است.

### U2 — ساخت موفق آزمون زمان‌دار مقصدها، هنوز بدون اجرای کاربر
- درخواست کاربر: مقصدهای دیگر یکی‌یکی و زمان‌بندی‌شده بررسی شوند. baseline ثابت `telemetry-in.battle.net` می‌ماند و هر بار دقیقاً یک نام اضافه مسدود است؛ بلوک مراحل قبل انباشته نمی‌شود.
- baseline، سپس news، OAuth، distribution.version، us.version و دو نام level3. هر مرحله ۱۲۰ ثانیه از READY؛ این زمانِ کلیک Resume نیست. پایان تایمر فقط capture را متوقف می‌کند، نه دانلود را.
- بین مراحل consent و Pause/Exit دستی لازم است؛ تا فرایندها بازند مرحله بعد اجرا نمی‌شود. تغییر hosts روی اتصال باز به‌عنوان قطع تضمینی جا زده نمی‌شود. اگر بازی به‌روز شد، مراحل باقی‌مانده حذف می‌شوند؛ بازی برای تکرار آزمون پاک/rollback نمی‌شود.
- ۵۷ unit/safety/recovery/schema/schedule test روی Linux و gate بومی runtime/امضا در Windows استاندارد پاس شده‌اند. آزمایش hosts زمان‌دار در unit test روی فایل موقت با API مصنوعی است، نه ویندوز کاربر.
- source: `2638dbf695754a52548fdc15f9a3c26f0f664696`؛ [رسید موفق](https://github.com/kokononox/battle-net-agent-lab/blob/7fd84a9672eaaaf0e8dea11429220a0684e66f40/reports/local-observer-u2-build.json)؛ [بسته U2](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39174764328/artifacts/12153936266)؛ [راهنمای اجرا](https://github.com/kokononox/battle-net-agent-lab/blob/2638dbf695754a52548fdc15f9a3c26f0f664696/local-retail-monitor-u2/README-fa.md).
- SHA256 آرتیفکت: `20b77b557a938284140acef7e7fc2fb2713346c5ba4956e6f3aff213c860d125`؛ نگهداری محدود ۷ روز. هیچ runner بزرگ/پولی یا نصب بازی اجرا نشده؛ مصرف billing از ابزار موجود معلوم نیست.
- **این آزمون تشخیص محتوای تله‌متری نیست.** ادامه ممکن است cache/fallback باشد و توقف ممکن است اثر hook/شبکه باشد؛ تست بدون hook پیشنهاد تمایزبخش آینده است. خطای sampler/attach_failed قبلی هنوز علت اثبات‌شده یا رفع تضمین‌شده ندارند.
- بخش تازه ۷ همکار بررسی و در [ارزیابی جداگانه](PEER-REVIEW-H1-U1-SECTION7.fa.md) ثبت شد؛ متن همکار دست‌نخورده است. SelfTest به‌اشتباه معادل hosts/Agent واقعی گرفته نشود؛ hash یک chunk هم همه fingerprintها را رد نمی‌کند.

### R1 — مسیر فعال بر مبنای BAT 3، بدون hook
- [تحویل و تحلیل BATها](DESTINATION-RECON-R1.fa.md). هر دو BAT اصلی فقط خوانده شدند؛ ۲۰ خط block واقعی BAT 3 مبناست و :443 نامعتبر news اصلاح شد. رفتار نسخه اصلاح‌شده را از آزمایش قبلی فرض نمی‌کنیم.
- U2 قبلاً ساخته شد، ولی پیش از اجرای کاربر درخواست تازه آمد؛ **اکنون R1/02–07 همگی دریافت شدند؛ فعلاً تست block تازه نه؛ پایش محتوا گام طراحی بعد است**.
- پروفایل ۰۲ = همان ۲۰ نام اصلاح‌شده. ۰۳ تا ۰۷ = هر بار همان مبنا + فقط یکی از OAuth/distribution.version/us.version/level3.ssl/level3؛ نه انباشته. ۰۱ مرجع telemetry-only برای نیاز احتمالی به مقایسه است.
- Recon هیچ injection/Frida/TLS decryption/payload capture انجام نمی‌دهد؛ فقط فرایند امضاشده/هش و snapshot TCP عمومی. محتوای encrypted packet از IP قابل استنتاج نیست. گزارش‌های۰۲ تا۰۷ دریافت شده‌اند؛ همه reported_progress دارند، اما محتوای ترافیک نامعلوم است. پایش محتوا گام جداگانه بعد است.
- پنجره هر اجرا ۱۲۰ثانیه از READY است؛ تایمر فقط capture را تمام می‌کند، **Update را Pause نمی‌کند**. Pause/Exit/Resume دستی؛ بین تست‌ها Battle.net/Agent/WoW بسته باشند.
- hosts موقت و system-wide با original bytes و checksum؛ entry قبلی یا journal → توقف/بازیابی بدون پاک‌سازی خودکار؛ تغییر خارجی overwrite نمی‌شود. بعد از restore بلوک باقی نمی‌ماند. BATهای ۳/۴ قدیمی برای recovery توصیه نمی‌شوند.
- source: `4f083a8bf2225abfc545df344f2b2784191494e4`؛ [رسید build موفق](../reports/local-destination-recon-r1-build.json)؛ [بسته R1](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39175413357/artifacts/12154092541)؛ [راهنمای کامل](https://github.com/kokononox/battle-net-agent-lab/blob/4f083a8bf2225abfc545df344f2b2784191494e4/local-destination-recon-r1/README-fa.md).
- ۷۳ آزمون local و gateهای unit/package/native/certificate ویندوز success؛ native gate شامل PID identity و TCP table روی اتصال loopback متعلق به ابزار است. تست واقعی آپدیت/hosts کاربر نیست.
- SHA256 آرتیفکت: `869894a760a8a9b316795e80402003c36bcb44ce119df7d88d7df0dc943aa4fa`؛ نگهداری ۷ روز. فقط runner استاندارد؛ هیچ نصب بازی، runner بزرگ/پولی یا ورود حساب اجرا نشده است.
- این denylist است، نه allowlist؛ unknown hosts/IP مستقیم/DoH/UDP/QUIC و cache/fallback باقی می‌مانند. ادامه/توقف غربالگری است؛ نه اثبات تله‌متری یا علت یکتا. سؤال A→B همچنان باز است.

### نتیجه واقعی R1/02 — مبنای اصلاح‌شده، پیشرفت به گزارش کاربر
- [تحلیل](../reports/destination-recon-r1-user02-analysis.fa.md) · [گزارش اصلی](../reports/destination-recon-r1-user02.json).
- هر ۲۰ نام در resolver پس از apply و پیش از restore، loopback_only؛ restore=restored_exactly؛ پس از خروج بلوک ابزار فعال نیست.
- READY=true؛ کاربر reported_progress و reported_paused انتخاب کرده؛ بدون اندازه‌گیری مستقل بایت/درصد. پایان user_q حدود ۷۵٫۱۵ثانیه پس از READY است، نه تمام ۱۲۰ثانیه و نه زمان دقیق Resume.
- sampler_errors=0 و caps false؛ Agent با همان image hash اصلی دیده شده است. هیچ payload/CPU در R1 جمع‌آوری نشده؛ «CPU دیده نشد» نتیجه این گزارش نیست.
- نسخه ابتدا/انتها 12.1.5.70448؛ از قبل marker تغییر کرده بود و completion را ثابت نمی‌کند.
- گام تاریخی بعد از۰۲، پروفایل۰۳ بود؛ اکنون هر۰۳ تا۰۷ هم دریافت شده‌اند. تست بیشتر فعلاً درخواست نمی‌شود؛ extras همزمان/انباشته نشوند و بازی حذف/Repair/rollback نشود.

### نتیجه مجموعه R1/02–07 — بدون توقف گزارش‌شده، نه اثبات حریم خصوصی
- [تحلیل مجموعه و جدول کامل](../reports/destination-recon-r1-series-analysis.fa.md) · [شواهد ماشینی](../reports/destination-recon-r1-series-analysis.json).
- شش trial متمایز، پنج مورد جدید؛۰۲ عیناً فایل قبلی است. همه READY، reported_progress، reported_paused و restore دقیق؛ هر مرحله DNS تمام نام‌های همان پروفایل loopback بوده است.
- همه با Q پس از حدود۷۱ تا۱۰۶ثانیه از READY خاتمه یافته‌اند. sampler_errors به ترتیب۰۲…۰۷: ۰،۶،۱،۲،۰،۴؛ انواع خطا معلوم نیست. صفر خطا هم پوشش کامل نیست.
- Agent اصلی با همان هش در همه دیده شده؛ endpointهای TCP بعضی نمونه‌ها فرق دارد. این اثبات Host/fallback/محتوا نیست. R1 اصلاً CPU/payload جمع نکرده است.
- همه نسخه‌نشانگرها ابتدا و انتها12.1.5.70448؛ completion مستقل نداریم. extraها همزمان آزمایش نشده‌اند و همگی قابل حذف اعلام نمی‌شوند.
- تصمیم با پرسش تازه کاربر اصلاح شد: block/runner/build تازه اجرا نشود. DNS loopback به معنی قطع واقعی اتصال نیست. ابتدا کنترل مثبت و شاهد process-attributed connection/drop برای اعتبارسنجی روش؛ سپس پایش محتوا. هیچ firewall rule تازه اجرا نشده و ابزار محتوای تازه هنوز تحویل نشده است.

### تصمیم نهایی کاربر — BAT ساده با الگوی همه‌جزیکی
- کاربر صریحاً ساختار همان فایل۳، بدون روش دیگر را خواست؛ مسیر portable R2 در حد draft محلی متوقف شد. هیچ build استاندارد/بزرگ/پولی تازه یا firewall rule در این مرحله اجرا نشد.
- [فایل‌ها](../plain-hosts-leave-one-open/) و [تحویل/محدودیت‌ها](PLAIN-HOSTS-LEAVE-ONE-OPEN.fa.md). ۸ BAT مستقل: مبنای۲۰، کنترل۲۵، پنج مکمل۲۴، و۹۹ برای پاک‌کردن همین فهرست/مارکر.
- همان net session، PowerShell inline، echo 0.0.0.0، copy و flushdns؛ بدون Python، helper، monitor، تایمر یا auto Update/Pause. :443 نامعتبر news اصلاح، backup و TEMP یکتا، خطای backup/تغییر همزمان و marker نامتوازن کنترل شد.
- این BATها به‌عمد مطابق روش درخواستی **hosts-only و پایدار** هستند؛ با خروج BAT restore نمی‌شوند. cleanup خطوط0.0.0.0 هم‌نام خارج marker را هم مانند سبک اصلی حذف می‌کند؛ backup باید نگه داشته شود.
- ۲۵نام فقط known list است، نه همه اینترنت. IPv6/DoH/IP مستقیم/نام ناشناخته یا اتصال موجود تضمیناً بسته نیستند. اثربخشی واقعی شبکه هنوز اثبات نشده؛ هیچ تله‌متری/مقصد آپدیت قطعی از این ساخت استنتاج نشود.
- کنترل استاتیک: همه۲۵ در01، مکمل‌های02…06 دقیقاً۲۴ و فقط همان یک نامزد خارج‌اند؛ CRLF/ASCII، طول خط زیر۸۱۹۱ و ZIP integrity بررسی شد. **روی Windows اجرا نشده‌اند**.
- بعد از تست انتخابی کاربر، مشاهده توقف/پیشرفت و روش جدیدِ اعتبارسنجی شبکه قابل بررسی است؛ ابزار محتوای جدید فعلاً تحویل نشده است.

## وضعیت دستگاه و حدود مجوز — گزارش کاربر، نه مشاهدهٔ مستقیم عامل
- Windows 11 Pro؛ بازی در `G:\World of Warcraft`؛ نسخهٔ قدیمیِ پشتیبان روی هارد اکسترنال موجود است.
- آخرین مجموعه R1/02–07: پیش‌شرط‌ها تأیید و در همه reported_progress و reported_paused؛ hosts هر بار بازیابی شده است. نسخه ابتدا/انتها12.1.5.70448؛ این اثبات تکمیل نیست. درصد یا بایت جدید نداریم؛ کاربر در آخرین پیام تأیید کرد دانلود کامل نشده و دستی Pause است. برای T1 تا READY همین حالت حفظ شود.
- در مرحلهٔ اصلی، بازی بسته و آپدیت تا پیام READY در Pause بماند؛ تا پایان مانیتور بازی اجرا نشود. ابزار خودش Update یا Pause نمی‌زند. Cancel/Repair، حذف نصب، restore بکاپ یا اسکن گسترده درخواست نمی‌شود. اگر پیش‌شرط/READY برقرار نشد، آپدیت برای دورزدن خطا شروع نشود.
- رانر بزرگ/پولی فعال نشود. استفادهٔ آزموده‌شده صرفاً برچسب‌های استاندارد Actions بوده است؛ رایگان‌بودن سهمیه تضمین نشده است.
- ورود به حساب بازی، پذیرش خودکار EULA، دست‌کاری حفاظت/ضدتقلب و پایین‌آوردن TLS/certificate validation به آزمایش فعلی اضافه نشده‌اند. اگر Windows Security مانع شد، هشدار بررسی شود؛ خاموش‌کردن حفاظت پیشنهاد نشود.

## سؤال‌های باز و گام بعد
1. آیا U1 روی سیستم کاربر self-test را پاس می‌کند؟ **گزارش کاربر PASS است.** این پاسخ فقط fixture loopback و ورودی منفی SSPI را شامل می‌شود، نه جلسهٔ TLS واقعی یا اتصال به Agent.
2. **پاسخ جزئی دریافت شد:** U1 به Agent واقعی وصل شده و کاربر دانلود تا ۳۰٪ را با بلوک دامنه گزارش کرده است. سؤال تکمیل همچنان باز است؛ اقدام جاری بنا به آخرین درخواست کاربر T1 برای بررسی محتوای حالت BAT۰۶ است؛ build بومی success است؛ اکنون نخستین گزارش T1.1 تحلیل شده، با۲۶ GET Level3 و شکاف HTTPSهای دیگر. توقف/ادامه در هر مرحله، بدون کنترل cache/فایل و اثر hook، اثبات قطعی علت نیست. هیچ completion یا صفر بودن telemetry فعلاً ثابت نیست.
3. آیا دادهٔ سخت‌افزاری از مسیرهای دیگر می‌رود؟ نبود نام CPU در نمونه یا کاهش تعداد اتصال، پاسخ قطعی نیست. ETW/Sysmon/pktmon برای فراداده مفیدند، نه به‌تنهایی اثبات فیلد داخل درخواست.
4. آیا فایل‌های به‌روز‌شده fingerprint اختصاصی مبدأ/دانلودکننده دارند و انتقال A→B برای سرور قابل تشخیص است؟ **هنوز آزمایش نشده**؛ از پاسخ سؤال تله‌متری نتیجه گرفته نشود.

## برای پیشنهادهای بعدی
- ابتدا همین وضعیت و شواهد H1/U1 را بخوانید. سند پیشنهادها بر commit قدیمی `2614b3a` نوشته شده بود؛ همهٔ برداشت‌های آن نتیجهٔ تأییدشده نیستند.
- حلقهٔ نصب Classic روی runner، صرفاً برای رسیدن به پیش‌نیاز، تکرار نشود مگر فرضیه/ورودی واقعاً تازه و دامنهٔ مجاز روشن باشد. فعلاً آزمایش نصب تازه‌ای در صف نیست.
- کد خطای `2513` به‌تنهایی علت GPU یا ناممکن‌بودن مشروع نصب را اثبات نمی‌کند. ورود حساب هم پیش‌شرط اثبات‌شدهٔ عمومی آپدیت نیست؛ آن را به تست signed-out تحمیل نکنید.
- اپدیتر مستقل و تحقیقات پیشین حفظ شده‌اند، اما مسیر فعال فعلی نیستند. پیشنهاد افزایش دامنه به login/in-world، GDPR/خروجی حساب، نصب VM یا بازی جدید، صرفاً پیشنهاد است و خودکار اجرا نمی‌شود.
- هر اجرای تازه باید سؤال، شاهد مورد انتظار، هزینه/ریسک و شرط توقف داشته باشد؛ تکرار نتیجهٔ قبلی به‌تنهایی پیشرفت نیست.

## لاگ کوتاه تصمیم‌ها
| تاریخ UTC | تصمیم | شاهد / محدوده |
| --- | --- | --- |
| 2026-10-18 | U1 دانلود جزئی با بلوک دامنه را ثبت کرد؛ نه completion | گزارش کاربر تا ۳۰٪؛ تحلیل main در dea81a9 |
| 2026-10-18 | خواسته جدید کاربر: آزمون تک‌مقصدی زمان‌دار | U2، baseline ثابت + یک extra، ۱۲۰ثانیه از READY، مرز دستی برای اتصال‌های قدیمی |
| 2026-10-18 | آماده تحویل U2، نه نتیجه کاربر | source 2638dbf؛ build run 39174764328؛ gateها success |
| 2026-10-18 | no-hook در R1 پیاده و اجرای ۰۲ کاربر دریافت شد؛ هنوز A/B هم‌شرط نداریم | آخرین درخواست BAT 3 مبنا شد؛ پیشنهاد به‌تنهایی مجوز یا شاهد اجرا نیست |
| 2026-10-18 | مسیر فعال از U2 زمان‌بندی‌شده به R1 بدون hook تغییر کرد | source 4f083a8؛ run 39175413357؛ ابتدا فقط پروفایل ۰۲ |
| 2026-10-18 | R1/02 دریافت شد؛ مبنای اصلاح‌شده برای ادامه غربالگری پذیرفته شد، نه اثبات privacy/completion | هر۲۰ DNS loopback، Q پس از حدود۷۵ثانیه، reported_progress، restore دقیق؛ بعد فقط OAuth/03 |
| 2026-10-18 | R1/03–07 دریافت شد؛ با تردید کاربر در اثربخشی، اول اعتبارسنجی block واقعی لازم شد | DNS-only اثبات قطع شبکه نیست؛ هیچ rule جدید اجرا نشده؛ سپس پایش محتوا |
| 2026-10-18 | دستور آخر: فقط BAT مستقل همان سبک فایل۳، نه portable/monitor | کنترل25 + پنج مکمل24؛ source/ZIP آماده، Windows execution نشده؛ بلاک پایدار تا پاک‌سازی دستی |

## روش نگهداری این وضعیت
عامل هنگام ادامهٔ همین پروژه، پس از هر نتیجه/تصمیم مهم و دریافت گزارش کاربر، بخش «الان دقیقاً کجا هستیم» و شواهد/مانع/گام بعد را اصلاح و زمان به‌روزرسانی را ثبت می‌کند. پیشنهادهای همکاران بدون حذف یا بازنویسی نظراتشان در سند جدا می‌مانند. این تعهدِ نگهداری در جلسات فعال است، نه اتوماسیون، پایش دائمی یا وعدهٔ فعالیت در غیاب جلسه. فایل وضعیت جای آرشیو کامل تاریخچه یا ادغام خودکار شاخهٔ پژوهش نیست.
