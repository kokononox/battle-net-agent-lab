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
