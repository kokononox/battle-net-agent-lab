# اولویت جاری: آزمون ذخیره‌سازی و ثبت اختیاری خروج عادی

مرجع ادامه: [تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [بستهٔ جدید NORMAL-EXIT-REVIEW-01](../analysis/unifiedfw-session-2026-10-27/normal-exit-runner-v01/README.fa.md)، [کتابخانه HF1.2.4](../analysis/unifiedfw-session-2026-10-27/normal-exit-hf124/README.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json).

اینترنت عادی کاربر با SSTP خاموش برگشته؛ آخرین گزارش firewall روشن، inbound مؤثر Block، outbound محلی/مؤثر Allow هر سه profile است. علت Block بعد reboot و original Restore ثابت نشده‌اند؛ reboot تازه درخواست/آزموده نشده، legacy journal untouched است.

راه‌انداز مستقل جدید ابتدا fixture جداگانهٔ ProgramData را برای ACL metadata، file roundtrip، no-overwrite و exclusive lock می‌سنجد و cleanup غیرrecursive دارد. بعد وضعیت واقعی rules/profiles/journal/task را می‌خواند؛ فقط با رضایت تصادفی دستی، رکورد normal-mode جداگانه ایجاد/بازتأیید می‌شود. در failure بعد از write attempt ممکن است رکورد ایجاد شده باشد؛ retry خودکار نکنید. snapshot اتمیک نیست و ACL test impersonation نیست.

۴۷ assertion راه‌انداز و ۷۲ کتابخانه دوباره گذشتند؛ ۷ PS1 و CMD parse و hash/pin payload تأیید شدند. پنج dependency بدون تغییر بایت‌اند. **این بسته هنوز روی Windows اجرا نشده و رکورد واقعی ساخته نشده است.** اجرای فعلی controller ارتقا نمی‌یابد و ژورنال قدیمی بازنویسی نمی‌شود. record هیچ isolation/original-restore/reboot/no-leak/Apply authority ندارد. guard قدیمی برای baseline حل‌نشده همچنان بسته است.

تنها اقدام تازه: ZIP جدید در پوشهٔ جدا، Run-Exit.cmd با admin همان حساب؛ اینترنت/VPN همان حالت فعلی. فقط JSON تشخیصی را برگردانید؛ Enter در prompt لغو می‌کند. تمام Apply/Restore/local-review قدیمی و live isolation reconnect متوقف بمانند.


## نتیجهٔ واقعی Windows — توقف پیش از ثبت

[گزارش امن](../analysis/unifiedfw-session-2026-10-27/normal-exit-runner-v01/evidence/Windows-normal-exit-review-01-result.json): payload، fixture ACL metadata، file roundtrip، no-overwrite، exclusive lock و cleanup موفق؛ hash ژورنال واقعی حفظ شد. بازبینی واقعی با normal_exit_current_profile_not_normal_allow متوقف شد؛ رضایت گرفته نشد و Record درخواست نشد. موفقیت fixture به معنی موفقیت بازبینی واقعی نیست. این خطای مشترک ممکن است مربوط به نام/Outbound/Enabled/AllowLocalFirewallRules باشد؛ مقدار دقیق هنوز معلوم نیست و Block دوباره ثابت نشده است. صفر بودن شمارنده‌های نتیجهٔ ناموفق، تعداد واقعی rules بررسی‌شده را مشخص نمی‌کند. اقدام بعد فقط جدول خواندنی PersistentStore و ActiveStore است؛ تنظیمات برای force-pass تغییر نکنند.


## تازه‌ترین شواهد — ترتیب زمانی تغییر Block

[رسید امن زمان‌بندی](../analysis/unifiedfw-session-2026-10-27/normal-exit-runner-v01/evidence/Windows-profile-change-timeline.json): هر سه profile در ۰۶:۲۹:۰۹ محلی Allow و در ۰۷:۲۳:۰۵ محلی Block شده‌اند؛ رویداد اخیر UTC=04:23:05.1253967 است. نام گزارش runner UTC=04:23:51 و در کد پیش از qualification و review ساخته می‌شود؛ پس review این اجرای مشخص حدود ۴۶ ثانیه پس از رویداد Block آغاز شده است، نه پیش از آن. این نتیجه همهٔ نسخه‌های قدیمی یا علت تغییر را تعیین نمی‌کند.

WmiPrvSE.exe فقط نام میزبان ثبت‌شده است؛ requester معلوم نیست. task شناخته‌شده صفر و process match فعلی صفر، عدم وجود writer گذشته را ثابت نمی‌کند. کاربر reboot یا بازکردن UI قدیمی را در فاصله رد کرده؛ SSTP متصل است. لاگ فعال با ۸۵۹ رکورد Circular است. WMI چهار event خواند ولی ردیف دارای ClientProcessId نداد؛ نبود requester دلیل نبود درخواست نیست. XPathهای قبلی namespace را لحاظ نمی‌کردند و باید با local-name اصلاح شوند؛ «فیلد خالی» قبلی مشکل parser بود.

ممیزی top-level مسیر مستقیم setter در runner/review پیدا نکرد، اما اثبات رفتار پلتفرم نیست. آزمون/تغییر جدیدی روی سیستم درخواست نشود؛ WmiPrvSE را نبندید و Allow را کورکورانه تکرار نکنید. علت تاریخی هنوز حل نشده. live Apply/Restore/reconnect متوقف؛ ادامهٔ آفلاین باید به بنیاد کوچک نصاب Battle.net، reader حداقلی بدون بارگذاری mutatorهای نامرتبط و baseline صریح local/effective متمرکز بماند، نه گسترش بی‌پایان ابزار تشخیصی.


## جدیدترین پیشرفت کد — reader حداقلی مستقل ۰٫۱

[کد و قرارداد](../analysis/unifiedfw-session-2026-10-27/minimal-readonly-v01/README.fa.md): یک module مستقل با تنها entry خواندنی؛ هیچ dependency از runtime قدیمی و هیچ تعریف mutator ندارد. local/effective جدا، NotConfigured بدون coercion، coverage/encoding/exclusion guard و دو مشاهدهٔ برابر با چهار getter در مسیر موفق. Block مشاهدهٔ معتبر است نه normal mode یا protection. همهٔ authorityها false؛ snapshot اتمیک نیست.

۵۴ assertion آفلاین با Windows getter mock گذشت؛ ۷۲ library و ۴۷ runner قبلی دوباره pass شدند. payload تحویل قبلی byte-unchanged است. ماژول جدید روی Windows آزموده نشده، worker-integrated یا deployed نیست. هیچ اقدام کاربری درخواست نمی‌شود؛ اینترنت/SSTP فعلی همان‌طور بماند و Apply/Restore/reconnect/Allow قدیمی تکرار نشود. مرحلهٔ بعد ادغام آفلاین قرارداد خواندن در preflight و آزمون reset-free recovery هستهٔ کوچک نصاب Battle.net است؛ این reader به‌تنهایی ابزار ایزولاسیون یا حل cold-start نیست.


## جدیدترین توسعه — هستهٔ کوچک، ادغام و recovery callback ۰٫۱

[کد، آزمون و مرزها](../analysis/unifiedfw-session-2026-10-27/installer-core-v01/README.fa.md): ورودی عمومی فقط‌خواندنی به reader واقعی با hash pin وصل شد. reader بدون تغییر بایت است. منطق private بازیابی profile_outbound_only با Save/ReadProfiles/WriteOutbound حافظه‌ای آزموده شد؛ هیچ native writer یا journal دیسکی این مسیر ساخته نشده است و draft execution_authorized=false مجوز اجرا نیست.

۷۸ assertion جدید pass: اتصال کامل getter-mock، pin mismatch، schema/baseline guards، ۸ خطای Save، ۳ خطای write، ۳ crash پس از write، resume بدون duplicate write، readback/drift/final-sweep و restored-stamp checks، baseline Block بدون Allow، عدم وابستگی به ترتیب property/row. ۵۴ reader و ۷۲ library و ۴۷ runner قبلی نیز rerun شدند؛ Windows و persistence واقعی آزموده نشده‌اند. full regression تاریخی rerun نشده و payload قبلی unchanged است.

profile-stage completed یا سازگاری draft، preflight کامل/ایزولاسیون نیست؛ pending components در خروجی آشکار و ready_for_apply/no_leak_certified=false است. کاربر اقدام ندارد، سیستمش تغییر نکرده است. مرحلهٔ بعد authorization و journal جدید محافظت‌شده با failure tests پیش از native write است؛ old NotConfigured journal یا normal-mode receipt هیچ bypass مجوزی نمی‌گیرند.


## جدیدترین توسعه — رضایت محدود و ژورنال مستقل ۰٫۱

[کد و قرارداد](../analysis/unifiedfw-session-2026-10-27/session-journal-v01/README.fa.md): رضایت دقیق challenge برای prepare_profile_journal_only با session/baseline binding، مهلت ۱۲۰ ثانیه، بازخوانی پیش/پس write؛ scope عمداً authorizes_firewall_change=false است، نه consent اجرای ایزولاسیون. JSON consent_validated=true به‌تنهایی capability یا اثبات مستقل انسان نیست. public entry نوشتن هنوز غیرفعال است؛ تنها export capabilities است.

adapter جدید Windows storage در root مستقل InstallerSessions ساخته شد؛ ACL هنگام ایجاد admin/SYSTEM و guard مسیر/owner/DACL دارد، اما API/ACL واقعی Windows آن آزموده نشده است. checkpointهای CreateNew شماره‌دار با lock انحصاری، Flush، checksum، hash-chain، schema/phase/flag checks و readback جایگزین overwrite می‌شوند. فایل مبهم پس از failure حفظ و write_attempted از موفقیت جدا می‌شود. hash-chain نه WORM/HMAC است، نه تضمین کشف tail rollback یا power-loss کامل.

۷۳ assertion جدید با فایل واقعی Linux و metadata ACL mock گذشت؛ recovery core با checkpoint واقعی و profile writer حافظه‌ای تا ۱۱ رکورد آزموده شد. ۷۸ core، ۵۴ reader، ۷۲ HF124 و ۴۷ runner rerun و parse چهار فایل گذشت. core/reader و payload کاربر unchanged اند. هیچ native firewall writer، migration ژورنال قدیمی، deployment یا no-leak/Apply authority نداریم.

کاربر اقدام تازه ندارد؛ مرحلهٔ بعد fixture جداگانهٔ storage-only روی Windows برای همین adapter است، بدون تماس با ژورنال قدیمی یا تغییر شبکه. consent واقعی policy/SSTP و recovery native هنوز pending هستند؛ علت Block تاریخی حل نشده است.


## جدیدترین تحویل — UFW-JOURNAL-STORAGE-01، فقط fixture ذخیره‌سازی

[بسته، source و راهنمای اجرا](../analysis/unifiedfw-session-2026-10-27/journal-storage-test-v01/README.fa.md): سه module بدون تغییر بایت بسته‌بندی شدند. fixture جدید فقط در root جداگانهٔ ProgramData با دادهٔ ساختگی، ACL root/session/record/lock، CreateNew، stale head، exclusive lock، chain، ۱۱ checkpoint با recovery حافظه‌ای، baseline change و فساد/partial record را بررسی می‌کند. هیچ real profile query، consent/store واقعی، legacy journal یا تغییر network/rule/task/VPN اجرا نمی‌کند. پاک‌سازی غیرrecursive و مشروط به validation تمام ساختار است.

۳۶ assertion بسته و ۷۳ ژورنال و parse پنج PS file/CMD و payload hash گذشتند؛ **Windows واقعی هنوز pending است**. simulation Linux native/ACL flagهای Windows را false نگه می‌دارد. اقدام کاربر فقط ZIP تازه در پوشهٔ جدا و Run-Test.cmd با admin همان حساب؛ SSTP/شبکه همان وضعیت. فقط JSON تشخیصی حتی failure برگردد. cleanup failure را با حذف/تکرار خودسرانه دنبال نکنید. engine Apply/Restore، consent نشست واقعی و همهٔ authorityهای ایزولاسیون همچنان غیرفعال‌اند؛ علت تاریخی Block حل نشده است.


## آخرین نتیجه و اصلاح — UFW-JOURNAL-STORAGE-011

[تحویل اصلاحی و receipt](../analysis/unifiedfw-session-2026-10-27/journal-storage-test-v011/README.fa.md): v01 روی Windows، ACL و roundtrip/lock/no-overwrite/stale-head را پاس کرد و cleanup موفق بود، ولی memory-profile recovery با ufw_core_profile_coverage متوقف شد؛ full qualification پاس نشده است. falseهای مراحل بعد و count=0 را به معنی اجرای آن مراحل/نبود رکورد نگیرید.

whole-array JSON clone در WinPS5.1 می‌تواند nested array بدهد. shim این قرارداد روی PS7 دقیقاً خطای v01 را بازتولید کرد و یک‌خط اصلاح row-wise clone در v011 کل fixture را عبور داد. سه module تولیدی و guard سه profile unchanged اند؛ ۳۶ fixture، ۷۳ journal و ۱۰ compatibility assertion گذشتند. **اجرای واقعی Windows نسخهٔ اصلاحی هنوز pending است.**

کاربر فقط ZIP v011 در پوشهٔ جدا با admin همان حساب و بدون تغییر شبکه/SSTP اجرا کند؛ JSON جدید UFW-JOURNAL-STORAGE-011-*.json حتی failure برگردد. هیچ Apply/Restore/real session store، profile query یا legacy access درخواست نشده است.


## تازه‌ترین نتیجهٔ واقعی — STORAGE-011 روی Windows کامل پاس شد

[receipt واقعیِ بدون اطلاعات شخصی](../analysis/unifiedfw-session-2026-10-27/journal-storage-test-v011/evidence/Windows-storage-011-passed-result.json): completed=true در runner و fixture، Windows PS5.1 x64، payload verified، ACL root/session/record/lock، roundtrip، CreateNew/no-overwrite، stale head، exclusive lock، append chain، baseline-change و checksum/partial refusal همه true؛ recovery حافظه‌ای با ۱۱ checkpoint واقعی فایل و cleanup موفق است. اصلاح row-wise JSON clone در همین اجرای Windows تأیید شد.

این فقط **qualification fixture ذخیره‌سازی همین اجرا** است، نه original Restore/Apply/WFP/reboot/SSTP/fingerprint/no-leak. consent انسانی واقعی، نوشتن نشست واقعی در root تولیدی و recovery بومی هنوز انجام نشده‌اند. profile query/legacy access/firewall/VPN/DNS changes همگی requested=false و ready_for_apply/no_leak_certified=false اند. علت Block تاریخی همچنان مجهول است.

کاربر اقدام ندارد و این آزمون موفق تکرار نشود؛ شبکه/SSTP همان حالت بماند. مرحلهٔ بعد runner کنترل‌شدهٔ preparation-only با fresh real profile read و رضایت محدود ثبت ژورنال مستقل است، نه consent برای تغییر فایروال. وجود baseline صریح Block به معنی ایزولاسیون سالم یا اجازهٔ تبدیل به Allow نیست؛ تمام guardهای policy/SSTP/native recovery پابرجا می‌مانند.


## گام بعد آماده شد — UFW-PREPARE-SESSION-01

راه‌انداز محدود [source و بسته](../analysis/unifiedfw-session-2026-10-27/prepare-session-v01/package/UFW-PREPARE-SESSION-01/) خواندن واقعی profileها را به review و consent مخصوص ثبت preparation متصل می‌کند. سه ماژول تولیدی همان بایت‌های milestone قبلی‌اند و native firewall writer وجود ندارد. ۶۰ بررسی راه‌انداز، با getter/prompt شبیه‌سازی‌شده و فایل واقعی Linux، و ۷۳ بررسی ژورنال دوباره پاس شدند؛ پنج PS file و bootstrap/manifest/ZIP کنترل شدند. این آمار، اجرای واقعی WinPS5.1 راه‌انداز یا consent انسانی نیست. آزمون STORAGE-011 قبلاً روی Windows کامل پاس شد و دوباره لازم نیست.

کاربر فقط بستهٔ تازه را در پوشهٔ جدا با همان حساب و admin اجرا می‌کند؛ شبکه و SSTP بدون تغییر. baseline فعلی Block در هر سه profile فقط برای preparation قابل ثبت است، نه normal-mode یا isolation qualification. prompt دقیق `PREPARE JOURNAL <ID> <nonce>` حداکثر دو دقیقه و تنها برای ثبت فایل معتبر است؛ Enter خالی/پاسخ متفاوت بدون نوشتن ژورنال نشست لغو می‌کند و گزارش تشخیصی می‌سازد. عبارت تأیید و فایل محافظت‌شده هرگز ارسال نشوند؛ فقط JSON تازهٔ sanitized. موفقیت سه preflight/۱۲ getter call، یک prepared checkpoint مستقل و authorizes_firewall_change=false دارد. تغییر baseline/انقضا/ACL نامعتبر متوقف می‌کند. پس از attempted write ممکن است رکورد باقی مانده باشد؛ تکرار/حذف خودکار مجاز نیست.

root جدید CommonApplicationData/UnifiedFW-InstallerSessions-01 از ژورنال قدیمی مستقل است؛ legacy read/migration، Apply/Restore، Block→Allow، rule/task/VPN/route/DNS changes انجام نمی‌شود. native recovery، policy/rules/SSTP integration، cold-start/reconnect، reboot، fingerprint و no-leak همچنان حل/تأیید نشده‌اند. هدف همان نصاب کوچک بتل‌نت است؛ این مرحله تنها مبنای بازیابی مستقل آن را ثبت می‌کند، نه محصول نهایی.

وضعیت جاری برای جلوگیری از برداشت اشتباه: آخرین گفتهٔ کاربر SSTP connected، بدون reboot بعد از Allow قبلی؛ آخرین خروجی profileها Block محلی/موثر هر سه بود. علت برگشت Block مجهول است. موفقیت اینترنت بدون VPN پس از Allow یک رخداد تاریخی است نه اثبات وضعیت فعلی؛ normal-exit review بعد از Block آغاز شده و WmiPrvSE.exe فقط host است نه انتساب requester. هیچ آزمون زندهٔ Apply/Restore/reconnect درخواست نشده است.


## نتیجهٔ واقعی Windows — PREPARE-SESSION-01 موفق شد

[receipt پاک‌سازی‌شده](../analysis/unifiedfw-session-2026-10-27/prepare-session-v01/evidence/Windows-preparation-01-passed-result.json): Windows PS5.1.26100.6899 x64، payload verified، review_shown/consent_received/journal_preparation_recorded=true، code=ufw_journal_prepared_no_firewall_authority و write_status=prepared_and_revalidated_no_firewall_authority. سه preflight موفق با چهار getter در هرکدام (۱۲ query)؛ در هر سه، Domain/Private/Public local/effective outbound=Block، firewall enabled=True، effective localrules=True و local localrules=NotConfigured بدون تفاوت مشاهده شده‌اند. این یک نتیجهٔ actual Windows است، نه مدل Linux.

بسته واقعاً profile reader/core preflight و ثبت نشست مستقل preparation را طی کرده؛ مرحلهٔ ذخیره‌سازی و بازخوانی داخلی و postwrite observation پاس شده‌اند. receipt هیچ challenge/session ID/private path ندارد. VPN در این runner query نمی‌شود؛ وضعیت SSTP از گفتهٔ قبلی کاربر است نه این receipt. legacy access/firewall/VPN/DNS changes requested=false، normal_mode_restored/original_restore_verified/ready_for_apply/no_leak_certified=false. بدون packet capture یا تله‌متری مستقل، این فیلدها ادعای اثبات جامع نبود هرگونه ترافیک/تغییر نیستند.

موفقیت فقط preparation همین اجراست؛ بازکردن همان رکورد در process مستقل، reboot، native recovery، rule/SSTP binding و Apply هنوز تست نشده‌اند. baseline Block باید به عنوان Block نگه داشته شود، نه تبدیل بی‌اجازه به Allow یا ادعای اینترنت عادی. علت Block قبلی همچنان مجهول است. آزمون موفق را تکرار نکنید، journal را حذف/بازسازی نکنید و شبکه/SSTP را همان وضعیت نگه دارید.

گام بعد محدود: ساخت و آزمون validator مستقل read-only برای بازخوانی نشست جدید و مقایسه با profile تازه؛ ACL root/session/record/lock، chain/checkpoint/receipt و baseline بررسی شود. اگر چند session باشد انتخاب خودکار آخرین ممنوع؛ بدون فایل خصوصی در چت، بدون write/migration/Apply/Restore یا اعطای authority. این validator هنوز تحویل/اجرا نشده و کاربر فعلاً اقدام ندارد.


## گام تازه — بازخوان مستقل read-only آمادهٔ اجرای Windows

[بسته و source بازخوان](../analysis/unifiedfw-session-2026-10-27/reopen-session-v01/package/UFW-REOPEN-SESSION-01/) فقط root مستقل جدید و **تک‌نشست موجود** را باز می‌کند؛ root/lock/record گم‌شده را نمی‌سازد، چند نشست را خودکار انتخاب نمی‌کند و journal را repair/migrate نمی‌کند. operation.lock فقط Open/Read/FileShare.None؛ فقط یک prepared checkpoint و lock خالی مجازند. ACL، schema، receipt، baseline، checksum/chain بررسی می‌شوند. دو preflight واقعی جدید (۸ getter در موفقیت) باید با baseline یکسان باشند؛ سپس رکورد و تک‌نشست دوباره بررسی می‌شوند. گزارش، ID/path/hash/nonce ندارد. تنها خروجی جدید، JSON تشخیصی کنار بسته است؛ محتوا/ساختار journal write نمی‌شود. metadata دسترسی فایل‌سیستم ممکن است تغییر کند.

۳۸۸ assertion در ۲۴ سناریوی پایه، PS5.1 top-level JSON-array contract shim، child process تازهٔ Linux، کنترل byte/inventory، parse و boundary پاس شده؛ ۷۳ assertion ژورنال هم rerun شد. سه module قبلی بدون تغییر بایت هستند. این آمار اجرای Windows/ACL/getter واقعی بستهٔ جدید نیست؛ getterها و platform guards در مدل جایگزین شده‌اند. receipt قبلی actual Windows preparation و storage در evidence حفظ شده است.

اقدام کاربر: در پوشهٔ محلی تازه، Run-Reopen.cmd با همان حساب و admin؛ شبکه/SSTP بدون تغییر؛ prompt/consent جدید ندارد؛ فقط JSON تازه حتی در شکست ارسال شود. preparation را تکرار نکند، فایل‌های خصوصی/عکس نفرستد، journal را حذف/اصلاح نکند و تنظیمات را برای pass تغییر ندهد. old Apply/Restore، reboot یا reconnect درخواست نشده است.

موفقیت بازخوان فقط سازگاری رکورد prepared با مشاهدات همان اجراست؛ baseline Block همان Block می‌ماند. external anchor برای اثبات قطعی هویت نشست تاریخی وجود ندارد، خواندن اتمیک یا دفاع در برابر admin مخرب نیست؛ reboot/power-loss/native recovery/rule/SSTP/cold-start/reconnect/no-leak/fingerprint همچنان qualification ندارند. ready_for_apply=false؛ هدف نصاب محدود بتل‌نت باقی است، نه اضافه‌کردن اختیار Apply با خواندن یک receipt. اجرای Windows این بسته هنوز pending است.


## نتیجهٔ واقعی Windows — بازخوان مستقل REOPEN-SESSION-01 پاس شد

[receipt واقعی بدون شناسه/مسیر خصوصی](../analysis/unifiedfw-session-2026-10-27/reopen-session-v01/evidence/Windows-reopen-01-passed-result.json): Windows PS5.1.26100.6899 x64، payload verified، completed=true و code=ufw_reopen_prepared_matches_current_no_authority. یک نشست با یک prepared checkpoint معتبر؛ قفل موجود فقط‌خواندنی گرفته و آزاد شد. دو preflight تازه و هشت getter، هر دو با baseline ذخیره‌شده برابرند: Domain/Private/Public local/effective outbound=Block، enabled=True، effective localrules=True و local localrules=NotConfigured. hash بایت‌های رکورد و selection تک‌نشست در بازبینی پایانی بدون تغییر بودند.

این اجرای مستقلِ واقعی مسیر بازخوان/اعتبارسنجی موجود و profile comparison را تأیید می‌کند؛ journal write/repair، legacy access، firewall/VPN/DNS changes requested=false و normal_mode_restored/original_restore_verified/reboot_qualified/ready_for_apply/no_leak_certified=false. VPN query نشده؛ SSTP connected هنوز از گفتهٔ قبلی کاربر است. هیچ anchor بیرونی برای اثبات هویت تاریخی ضد‌دستکاری، مشاهدهٔ اتمیک، packet capture یا آزمون reboot/native recovery وجود ندارد. موفقیت را به آن‌ها تعمیم ندهید.

prepare/reopen plumbing فعلاً پاس شده و نباید دوباره از کاربر آزمون موفق یا ارسال فایل خصوصی خواست. کاربر فعلاً اقدام ندارد؛ journal و شبکه/SSTP همان وضعیت بماند. مرحلهٔ بعد باید به هدف اصلی برگردد: پلن حداقلی و قابل بازبینی برای ایزولاسیون نصاب بتل‌نت، با executable/destinations و SSTP transport/binding صریح، گیت‌های اجرا و recovery محدود. این receipt صرفاً baseline را فراهم می‌کند؛ native writer/Apply/Restore/rules/reconnect هنوز مجاز یا qualified نیستند. علت Block تاریخی همچنان مجهول است و Block هرگز بی‌اجازه به Allow تفسیر نشود.


## تصمیم صریح دامنهٔ مجوز — همهٔ برنامه‌های سیستم

کاربر گزینهٔ «همهٔ برنامه‌های سیستم بتوانند به مقصدهای وایت‌لیست وصل شوند» را انتخاب کرد، نه محدودکردن به executableهای نصاب. دلیل: مقصدها بعداً قابل حذف/اضافه باشند؛ مرورگر بتواند سایت مجاز را باز کند و برنامه‌های دیگر هم به مقصدهای مجاز دسترسی داشته باشند. هدف اولیهٔ بتل‌نت نباید به یک executable allowlist اجباری تبدیل شود. این تصمیم مربوط به دامنهٔ مجوز است، نه اجازهٔ Apply روی سیستم.

[قرارداد کامل دامنه و محدودیت نام‌دامنه/IP](UNIFIED-FIREWALL-WHITELIST-SCOPE.fa.md) ثبت شد. دامنهٔ داده whole_system/Any-program باقی می‌ماند؛ executable-path gate برای نصاب ساخته نشود. مسیر داده فقط SSTP معتبر، حمل خود SSTP جدا و محدود؛ افزودن/حذف مقصد با نسل تازه و بدون Apply خودکار. این انتخاب مجوز تغییر فایروال نیست، سایت دقیق روی IP مشترک و fingerprint با IP whitelist تضمین نمی‌شوند؛ دامنهٔ اجرایی/DNS refresh و native gates هنوز باقی‌اند. کد یا تست جدید در این ثبت تصمیم ایجاد نشده است.


## اصلاح دامنه و شروع کد برنامه‌محور

کاربر انتخاب قبلی all-programs را صریحاً اصلاح کرد: وقتی مود مرورگر فعال است، فقط مرورگر و اجزای مشخص‌شدهٔ مجاز آن اجازهٔ ارتباط دارند و بقیهٔ برنامه‌ها حتی به همان مقصدهای مجاز مسدودند. هر مجوز ترکیب برنامه+مقصد+پورت روی SSTP معتبر است، نه اینترنت آزاد برای برنامه. مودهای browser/game/installer روی یک موتور با یک مود فعال در هر لحظه؛ ابتدا نصاب بتل‌نت تکمیل شود. افزودن/حذف مقصد همچنان لازم است ولی به معنی جهانی‌شدن مجوز نیست.

## کد و شواهد مرحله

[شرح و قرارداد سازندهٔ پلن](../analysis/unifiedfw-session-2026-10-27/app-profile-plan-v01/README.fa.md) و [source](../analysis/unifiedfw-session-2026-10-27/app-profile-plan-v01/source/app_profile_plan.py). compiler خالص Python فقط grantهای پروفایل فعال را جدا برای هر برنامه با template disabled و token binding تازهٔ SSTP تولید می‌کند. cross-product برنامه‌ها×مقصدها، union مودهای غیرفعال، child/service permission خودکار و input approval پذیرفته نمی‌شوند. path/hash ورودی اثبات فایل واقعی و digest/generation مجوز اجرا نیستند. خام پلن واقعی حاوی اطلاعات خصوصی خواهد بود و نباید خودکار ارسال یا commit شود.

۲۵ test method و ۱۰۰۰ predicate case مستقل آفلاین پاس شدند؛ ۸۶ assertion سازندهٔ exact SSTP transport قبلی هم دوباره، بدون تغییر source، پاس شد. predicate مدل native/WFP نیست. recorder، program identity reader واقعی، DNS/site enforcement، mode-switch executor و Apply در این مرحله ساخته نشده‌اند. Windows API/هویت برنامه/SSTP/flow revocation/reboot/reconnect واقعی با این مدل qualification نمی‌شوند. ready_for_apply=false و no_leak_certified=false.

## گیت‌ها و ادامه

هویت native برنامه و file replacement/reparse/ACL، رضایت دقیق محتوا و Apply، baseline تازه، foreign Allow و effective policy، approval و service filter حمل SSTP، DNS/certificate/underlay bootstrap، تعلیق داده در disconnect، جمع‌کردن scopeدار مجوزهای مود قبلی و اتصال‌های برقرار، native journal/recovery و packet/reboot/reconnect هنوز لازم‌اند. blanket Block-all rule با default Block+Allow انتخابی یکسان نیست؛ قواعد Allow قبلی با default Block خودبه‌خود حذف نمی‌شوند. hash/selection فقط draft است و برای گشودن این گیت‌ها کافی نیست.

مرحلهٔ بعد local program-and-destination review برای نصاب و سپس composition با baseline/transport است؛ نه تکرار آزمون عمومی یا old Apply. کاربر فعلاً اقدام ندارد، journal محافظت‌شده و شبکه/SSTP همان وضعیت بماند. بستهٔ Windows یا تغییر واقعی شبکه در این milestone تحویل/اجرا نشده است.

