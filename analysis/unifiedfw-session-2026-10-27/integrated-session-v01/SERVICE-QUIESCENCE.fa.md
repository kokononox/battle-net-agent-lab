# تطبیق سرویس‌ها با فرایندهای زنده در همان مسیر بازیابی

## دامنهٔ دقیق این گام

`source/ServiceQuiescence.ps1` یک لایهٔ فقط‌خواندنیِ **لازم ولی ناکافی** اضافه می‌کند. هدف، ردکردن سرویس/PID نامعلوم یا فعالیت شناخته‌شدهٔ باقی‌مانده پیش از بازگرداندن Allowهای ذخیره‌شده است؛ نه اعلام پوشش کامل helper/service/IPC. این گام هیچ سرویس یا فرایندی را start/stop/kill نمی‌کند، مجوز شبکه نمی‌سازد و بستهٔ آزمون تازه‌ای از کاربر نمی‌خواهد.

## خواننده و اعتبار مشاهده

- خوانندهٔ بومی `Read-UfwWindowsServiceCensus` از Win32_Service و Get-Service می‌خواند؛ نام‌های سرویس و وضعیت‌های دو enumerator باید متناظر باشند. هر دو با ErrorAction Stop اجرا می‌شوند؛ CIM مهلت عملیاتی ۱۰ثانیه دارد. این دو خواندن اتمیک نیستند و اثباتِ عدم حذف هم‌زمانِ یک مورد از هر دو منبع هم نیستند.
- برای هر ردیف، نام یکتا، PID با نوع عددی معتبر، state/start mode مشخص و command/account/type قابل‌خواندن لازم است. دادهٔ خالی، دسترسی ناموفق، تکرار، state ناشناخته، سرویس متوقف با PID غیرصفر یا سرویس فعال/درحال‌گذار با PID صفر رد می‌شود. «نامعلوم» مساوی «بی‌خطر» نیست.
- command به‌صورت متن خصوصیِ خام مقایسه می‌شود؛ هرگز اجرا، expand یا با حدس به یک EXE نسبت داده نمی‌شود. ServiceDll و محتوای DLLهای svchost از این متن نتیجه گرفته نمی‌شوند.
- دو دور متوالی سرویس و process census، با مجموعه و هویت یکسان لازم‌اند. هر PID فعال سرویس باید در census معتبرِ همان دور یک فرایند غیرکرنل داشته باشد. سرویس مشترک با چند نام و یک PID مجاز است، اما حذف یا تغییر هر نام یا state موجب رد تطبیق می‌شود.
- همان شاهد خصوصی نشست و lineage قبلی مصرف می‌شود. وجود PID، parent PID یا مسیرِ شناخته‌شدهٔ برنامه/فرزند مانع است؛ حتی اگر منشأ ایجاد آن در رخدادها SCM بوده باشد. actor، boot، binding و journal head باید ثابت بمانند؛ کل مشاهده حداکثر ۱۵ثانیه اعتبار زمانی دارد. این معیار تازگی است، نه تضمین پایان اجباری provider گیرکرده.

خروجی فقط شمار دورها، code و booleanهای aggregate دارد. مسیر، فرمان، account، PID یا snapshot در گزارش عمومی صادر نمی‌شوند. `service_process_links_quiet=true` فقط موفقیت این تطبیق محدود است؛ `complete_helper_service_IPC_coverage` و `quiescence_authorized` همیشه false می‌مانند.

## اتصال بدون مسیر موازی بازیابی

`New-UfwServiceObservationGuard` در recovery/restore/immediately_before_restore/finish، پیش و پس از callback مستقل پوشش، مشاهدهٔ تازه می‌گیرد. callback مستقل همچنان اجباری و پاسخ آن فقط bool واقعی پذیرفته است. مشاهدهٔ سرویس جای این callback نیست؛ نبود پیاده‌سازی production آن با true پیش‌فرض پر نشده است. phase نامعلوم رد می‌شود؛ phaseهای forward فقط guard مستقل را حفظ می‌کنند.

`New-UfwServiceReviewedPolicyRecovery` این ترکیب را به همان `New-UfwReviewedPolicyRecovery` می‌دهد: audit-first، همان handle بازگشایی‌شدهٔ registry، بررسی پیش از نمایش رضایت خروج، رضایت موقت در حافظه، کنترل فرایندها و backend قبلیِ inverseهای ذخیره‌شده حفظ می‌شوند. موتور بازیابی جدید یا دکمهٔ Allow عمومی ساخته نشده است. factory جدید مسیر داخلیِ قابل‌ترکیب است، نه entrypoint بومیِ آمادهٔ استفاده؛ factory قدیمی نیز بدون تغییر باقی مانده و خودکار جایگزین نشده است.

در fixture، مسیر recovery-only هماهنگ‌کننده واقعاً اجرا می‌شود. رد سرویس/پوشش قبل از prompt هیچ inverse نمی‌زند؛ تغییر پس از اولین inverse ادامه را متوقف می‌کند و دفتر pending می‌ماند؛ رد finish حتی پس از انجام inverseها اجازهٔ closed موفق نمی‌دهد. callback پوشش مستقل، UI، فرایندها، سرویس‌ها و اثرهای Windows در این آزمون‌ها صریحاً ساختگی‌اند؛ journal و backend/reconciler واقعی‌اند.

## مانع باقی‌مانده، نه وعدهٔ پنهان

این تطبیق **انتسابِ سرویس‌های ناشناخته یا شروع‌شده پس از capture، سرویس متوقفِ قابل‌اجرای مجدد، broker از قبل موجود، COM/RPC/IPC، scheduled task، service DLL، driver یا اجرای مجدد هم‌زمان را حل نمی‌کند**. سرویس متوقفی که command آن به EXE انتخاب‌شده اشاره دارد نیز دلیل ایمن‌بودن شروع آینده نیست. مشاهده‌های user-space sandbox یا مانع اجرای مجدد نیستند.

بنابراین callback مستقلِ پوشش کامل هنوز در production پیاده نشده است. خوانندهٔ بومی این گام روی Windows واقعی qualification نشده؛ سخت‌گیری روی visibility و تکرار چندبارهٔ census ممکن است هزینهٔ عملکردی یا رد مکرر داشته باشد. performance، native Apply و نصب کامل Battle.net تأیید نمی‌شوند و `ready_for_apply=false` باقی می‌ماند. نتیجهٔ لازمِ این گام نباید به مجوز کافی تبدیل شود.

آزمون‌ها و نتایج aggregate: `tests/Test-ServiceQuiescence.ps1`، `evidence/service-quiescence-tests.json` و `evidence/QA-SUMMARY.json`.
