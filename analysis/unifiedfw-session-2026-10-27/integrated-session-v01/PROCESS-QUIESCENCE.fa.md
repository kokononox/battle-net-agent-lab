# بررسی مستقل وضعیت فعلی فرایندها، متصل به بازیابی

`ProcessQuiescence.ps1` گزارش جداگانه یا مجوز واردکردنی نمی‌سازد. بررسی فرایندها به همان backend و storage نشست متصل است؛ هیچ فرایندی terminate/launch و هیچ قاعده‌ای خارج از intentهای قبلی تغییر نمی‌کند. این بخش جای رضایت خروج، guard actor/audit یا بررسی واقعی baseline را نمی‌گیرد.

## شواهد گذشته، سپس دو مشاهدهٔ فعلی

`Get-UfwRecoveryLineage` از arm و lifecycle evidence خصوصی همان journal استفاده می‌کند. capture کامل با audit restore تأییدشده، بدون interruption/parse error و code صریحِ غیرجزئی لازم است؛ completed=true قدیمی به‌تنهایی کافی نیست. root انتخاب‌شده با actor مطابق و همهٔ فرزندان مشاهده‌شده باید exit مطابق داشته باشند. PID reuse نامطمئن، parent/exit نامطابق، orphan و هشدار integrity رد می‌شوند. مسیر همهٔ EXEهای انتخاب‌شده، حتی آنهایی که در رخدادها شروع نشده‌اند، در مجموعهٔ بررسی فعلی باقی می‌ماند.

`Read-UfwWindowsProcessCensus` از Win32_Process و Get-Process استفاده می‌کند و مجموعهٔ PIDهای دو enumerator باید برابر باشد. برای تمام فرایندهای غیرکرنل، PID، parent PID، مسیر قابل‌خواندن و CreationDate معتبر لازم است. فقط PIDهای ۰/۴ با نام و parent مشخصِ Idle/System استثنای کرنل‌اند؛ فرایند محافظت‌شدهٔ دیگر با مسیر نامعلوم نادیده گرفته نمی‌شود. null، خطای دسترسی، اختلاف enumeratorها یا نوع ناشناخته به معنی عدم احراز است؛ نه خروجی خالیِ موفق.

`Get-UfwIndependentProcessQuiet` دو census کامل با هویت PID/path/CreationDate/parent یکسان می‌خواهد. وجود هر مسیر انتخاب‌شده/فرزند شناخته‌شده یا هر PID/parent PID شناخته‌شده مانع است؛ حتی PID بازیافت‌شدهٔ احتمالاً بی‌ربط محافظه‌کارانه رد می‌شود. تغییر actor/boot یا journal head، reboot، شاهد ناقص یا زمان مشاهده بیش از ۱۵ثانیه نیز رد می‌شود. این مهلت معیار تازگیِ نتیجه است، نه تضمین قطع اجباری cmdlet گیرکرده؛ CIM timeout و رفتار provider روی Windows هنوز qualification می‌خواهند.

خوانندهٔ بومی پیاده شده، اما روی Windows واقعی این اتصال اجرا نشده است. در سیستم دارای فرایند محافظت‌شده یا churn، ممکن است بررسی محافظه‌کارانه مکرراً رد شود؛ سرعت یا کاربردپذیری آن هنوز تأیید نشده است. این رفتار نباید با skip کردن دسترسی‌ها یا PIDهای ناشناخته «رفع» شود.

## اتصال به guard بازگردانی

`New-UfwQuiescenceBackendGuard` یک callback خصوصی برای همان `New-UfwLocalBackendContext` می‌سازد:

1. guard مستقل موجود باید ابتدا اجازه بدهد؛ audit-clean/actor/رضایت خروج با این لایه حذف یا جایگزین نمی‌شوند.
2. در recovery، restore، immediately_before_restore و finish، بررسی شاهد و فرایندهای فعلی دوباره اجرا می‌شود.
3. guard مستقلِ پوشش helper/service نیز باید پاسخ bool واقعی بدهد. نبود callback، false یا رشتهٔ «true» پذیرفته نیست.
4. guard موجود پس از این بررسی‌ها دوباره خوانده می‌شود. unknown phase رد می‌شود؛ backup/forward همان guard موجود را حفظ می‌کنند.

بازیابی backend پس از آخرین inverse، پیش از بررسی baseline و نوشتن restored، اکنون finish guard را نیز اجرا می‌کند. ردشدن این مرحله اجازهٔ checkpoint موفق نمی‌دهد؛ ممکن است inverseها انجام شده باشند، اما دفتر همچنان برای بررسی و بازیابی باز می‌ماند. بازیابی از دفتر بسته نیز همچنان baseline واقعی را بازخوانی می‌کند.

در آزمون integration، همین backend پس از registry reopen با witness واقعی و collector واقعی اجرا می‌شود؛ تغییر سیاست و providers Windows fixture هستند. guard ردشده هیچ inverse نمی‌زند؛ guard finish ردشده closed موفق نمی‌سازد. برای مسیر موفق داخلی، helper coverage و رضایت/اثرهای بومی صریحاً فرضی‌اند و مدرک production نیستند.

## مرز مهم: فرایندِ دیده‌نشده با سرویس/IPC یکسان نیست

دو census و exitهای ثبت‌شده **انتساب کامل فرایندها، سرویس جدید، broker موجود، scheduled helper، IPC یا رخدادهای پس از پایان capture را ثابت نمی‌کنند**. نتیجهٔ process observer فقط `process_quiet_observed` است و `quiescence_authorized` آن همیشه false می‌ماند. guard پوشش مستقل نباید از همین count یا یک approval JSON مقدار true بسازد. در این گام پیاده‌سازی یا شاهد بومیِ معتبرِ پوشش helper/service فراهم نشده است؛ با جای‌خالی true هم پر نمی‌شود.

پس این guard به backend متصل و منطق خوانندهٔ بومی پیاده شده است، اما native restore-ready و `ready_for_apply` هنوز false هستند. مشاهده‌های user-space اتمیک یا محافظ اجرای مجدد نیستند؛ این ابزار sandbox علیه مدیر، kernel یا IPC نیست. هدف بعدی اتصال ایمن helper/exit-consent به recovery/UI با دامنهٔ روشن، بررسی عملکرد و یک اعتبارسنجی هدفمند Windows است؛ نه درخواست ZIP یا diagnostic دستی تازه از کاربر.

نتایج aggregate فقط در `evidence/process-quiescence-tests.json` و `evidence/QA-SUMMARY.json` منتشر می‌شوند؛ paths/PIDs/actor/boot خصوصی و snapshot کاربر منتشر نمی‌شوند.

## ادامه: رضایت خروج و audit-clean واقعی

[رضایت خروج](EXIT-REVIEW.fa.md) اکنون در callback بازیابی همان backend به این guard ترکیب شده است. سه mask اصلی از arm v02 می‌آیند و واقعاً بازخوانی می‌شوند؛ نبود pending کافی نیست. این اتصال پوشش helper/service یا qualification Windows را جعل نمی‌کند.
