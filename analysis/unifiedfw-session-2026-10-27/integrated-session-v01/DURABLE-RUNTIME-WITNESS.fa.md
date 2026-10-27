# شاهد پایدارِ احتمال اجرا و شواهد محدود فرایندها

این بخش ادامهٔ همان جریان یکپارچه است، نه ابزار تشخیصی یا بستهٔ Windows جدید. `RuntimeWitness.ps1` از storage، lock، hash chain، backend parser و registry موجود استفاده می‌کند. فایل approval یا دفتر موازی ساخته نمی‌شود؛ dependencyهای collector و محافظت فایل قبلی تغییر نکرده‌اند.

## پیش از پنجرهٔ اجرای دستی

caller خصوصی، پس از ساخت context انتخاب ثابت و داشتن همان storage نشست، `Connect-UfwRuntimeWitness` را با boot observer مستقل bind می‌کند. Connect اختیار سیاست یا اجرای فایل نمی‌دهد و خود record جدیدی نمی‌نویسد. فقط همین storage با baseline و view binding مطابق پذیرفته می‌شود.

Window wrapper پیش از امکان بازشدن UI، `runtime_arm` را به همان زنجیره append و با همان parser بازخوانی می‌کند. همهٔ policy intentها باید result معتبر داشته باشند و restore شروع نشده باشد. رکورد شامل actor، head انتخاب محافظت‌شده، برنامه‌های انتخاب‌شده با هویت فایل/هش قبلی، binding سیاست و boot marker است؛ شناسهٔ نشست از envelope موجود می‌آید. فایل انتخاب‌شده و actor دوباره بررسی می‌شوند. پس از disk IO نیز guard موجود پیش از Window اجرا می‌شود.

factory بومی `New-UfwWindowsRuntimeOps` بدون شاهد armشده، lock زنده و arm مطابق در journal، پنجرهٔ READY را باز نمی‌کند. مسیرهای fixture قدیمی هنوز می‌توانند callback فرضی داشته باشند؛ آنها بومی/qualified نیستند. source جدید باید در همان module خصوصی بار شود؛ launcher عمومی هنوز وجود ندارد.

قطع بین flush/readback و UI یا exception خود UI، وضعیت «ممکن است اجرا شده باشد» باقی می‌گذارد. خطای نوشتن/هویت/head/boot پیش از arm موفق، به UI اجازه نمی‌دهد؛ فایل ناقص یا arm نامطمئن نیز پاک یا اصلاح خودکار نمی‌شود. نمایش UI، launch یا kill برنامه توسط ابزار نیست.

## پس از collector

پس از نتیجهٔ collector، `runtime_evidence` به همان arm bind می‌شود: نتیجهٔ capture و audit restore، parse-error count و رخدادهای محدود 4688/4689 و هشدارهای integrity. این projection شامل PID/path/parent/actor/record است؛ مقصد، پورت، DNS، command line و payload شبکه در آن نیست. رخدادهای فرایندهای دیگر در پنجره نیز ممکن است در شاهد خصوصی باشند؛ این داده فقط روی رایانهٔ کاربر می‌ماند و در گزارش عمومی یا مخزن منتشر نمی‌شود.

حد این projection برابر ۸۱۹۲رخداد و ۲MiB متن JSON است؛ record اصلی و زنجیره همان سقف‌های storage قبلی را دارند. JSON، checksum، شناسه/ترتیب recordها، نوع فیلدها و نسبت arm/evidence کنترل می‌شوند. تکرار arm/evidence، evidence قبل از arm، arm قبل از کامل‌شدن سیاست و append پس از restore رد می‌شوند. شکست ثبت evidence اجازهٔ نتیجه‌سازی موفق نمی‌دهد؛ arm قبلی همچنان مانده است.

این projection **انتساب کامل helper/service یا تاریخچهٔ پیوستهٔ پس از crash نیست**. هنوز intervalهای زمانی/لاگ بعدی و census مستقل لازم‌اند؛ فقدان exit یا دادهٔ capture به معنی هرگز اجرا نشدن نیست. رسید موفق capture هم quiet بودن فعلی را ثابت نمی‌کند.

## بازخوانی در بازیابی

registry همان نشست را reopen می‌کند و backend همان ترتیب recordها را اعتبارسنجی می‌کند. `Read-UfwRuntimeRecoveryWitness` با actor مطابق، برنامه‌های ذخیره‌شده را با validator اصلی candidate بررسی می‌کند؛ به بازکردن EXE فعلی، picker، DNS، مشاهدهٔ VPN یا نوشتن audit نیاز ندارد. boot marker جاری از callback مستقل می‌آید؛ helper بومی فقط Win32_OperatingSystem را می‌خواند و نام ماشین/LastBootUpTime را به hash تبدیل می‌کند. این همبستگی boot است، نه measured boot یا ضد rollback.

خروجی خصوصی میان نبود arm، arm بدون capture و evidence موجود تفاوت می‌گذارد. نبود arm نیز محافظه‌کارانه `may_have_run=true` می‌دهد. boot متفاوت/نامعلوم، authority جدید نمی‌سازد. `quiescence_authorized` در همهٔ این خروجی‌ها false است. dispatcher بازیابی، actor شاهد را پیش و پس از callback سیاست هم بررسی می‌کند؛ witness هرگز جای guard مستقل، audit-clean، رضایت خروج یا fresh baseline verification را نمی‌گیرد.

restore یا closed شدن از وجود evidence نتیجه نمی‌شود. backend در fixture تنها با guard مستقل فرضی می‌تواند بازیابی را ادامه دهد؛ این مجوز native نیست. ژورنال امضا/WORM نیست و محافظت کامل در برابر مدیر یا حذف tail ادعا نمی‌شود.

## وضعیت و ادامه

آزمون `Test-RuntimeWitness.ps1` با collector واقعی، journal فایل واقعی و registry واقعیِ Linux اجرا می‌شود؛ اثرهای Windows fixture هستند. خطای arm پیش از UI، قطع پنجره، arm-only، reboot، head کهنه، record خراب، actor متفاوت، پاسخ موفقِ فرضی بدون terminal معتبر و guard بازیابی پوشش دارند. شمارش و نتیجهٔ معتبر در `evidence/QA-SUMMARY.json` و `evidence/runtime-witness-tests.json` است.

قدم باقی: probe مستقل محافظه‌کارانهٔ فرایند/فرزندان و حدود service/IPC، اتصال guard بومی و رضایت خروج به recovery/UI، بررسی عملکرد و سپس یک اعتبارسنجی هدفمند Windows. ثبت پایدار پیاده شده، اما native recovery safety و `ready_for_apply` هنوز false هستند. هیچ grant، ZIP اجرایی، snapshot خصوصی یا آزمون دستی تازه از کاربر درخواست نشده است.

## اتصال بعدی

[بررسی مستقل فرایندها](PROCESS-QUIESCENCE.fa.md) اکنون همین witness را در guard backend می‌خواند. نبود پوشش مستقل helper/service همچنان restore را مسدود می‌کند؛ census به مجوز قابل‌ذخیره تبدیل نمی‌شود.
