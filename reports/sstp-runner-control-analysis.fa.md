# S3U — شاهد اختلال ارتباط کنترلی runner و لغو محلی worker

## نتیجهٔ اجرایی
اجرای تشخیصی `39194616498` با منبع `4a046fbd5459c28e6aa7e1b1c9e40eea98b7331d` در validate لغو شد و ناشر موفق بود. دور اول کامل و موفق ثبت شد، ولی آخرین stage این بار `round_2_driver` است، نه `round_2_timer` دو اجرای قبل. وضعیت نهایی تغییر/بازیابی دور دوم اثبات نشده؛ passed=false و ready_for_user_apply=false باقی است. هیچ شرطی حذف یا gateی دور زده نشد.

## شاهد تشخیصی، نه متن لاگ
جمع‌کننده فقط نشانه‌های ثابت را از دو فایل Runner/Worker در یک پوشه diagnostic خواند. files_unreadable=0 و scan_complete=true طبق حدود جمع‌کننده؛ این به معنی پوشش همه لاگ‌های سیستم نیست. نسخهٔ runner قابل استخراج نبود (`runner_version=null`). زمان‌ها نسبت به cutoff مرحلهٔ آماده‌سازی هستند، نه نسبت به شروع کل job یا شروع Block.

- ۱۹ تطبیق HttpRequestException و ۱۱ تطبیق SocketException در بازه ثانیه ۱۱ تا۸۸؛ شمارش تطبیق‌ها معادل شمار درخواست مستقل یا تعداد اتصال منحصربه‌فرد نیست.
- یک `Catch exception during renew runner job...` در ثانیه۸۸.
- یک `Send job cancellation message to worker...` و یک `Cancellation/Shutdown message received.` در ثانیه۸۸.
- در فایل‌ها و بازه بررسی‌شده تطبیقی برای درخواست لغو دریافتی از سرور، پایان retry renewal، job-invalid، shutdown یا NullReferenceException ثبت نشد. صفر تطبیق اثبات نبودن رویداد در کل سیستم یا نفی دخالت انسانی نیست.

این ترکیب، همراه با موفقیت کنترل S3W بدون تغییر شبکه، شاهد مشخص اختلال ارتباط HTTP/Socket و تمدید job در مسیر کنترل runner هنگام این آزمایش است. سازگار است با اینکه Block آزمایشی، کانال اجرای خود آزمایش را مختل کرده باشد. مقصد دقیق، پیام کامل خطای شبکه، lease و علت ریشه‌ای پایین‌دستی از این گزارش محدود معلوم نیست. صرف «The operation was canceled» دیگر تنها شاهد ما نیست؛ با این حال ادعای علت قطعی یا انتساب به کاربر مجاز نیست.

کد عمومی runner مسیرهای cancellation دریافتی و اتمام/شکست کار renewal را جدا می‌کند و در هر دو می‌تواند پیام لغو به worker بفرستد. این منبع برای تفسیر نشانه‌هاست؛ برابر بودن نسخهٔ نصب‌شده با ref عمومی اثبات نشده است.

## محدودهٔ تغییر
فقط مرحلهٔ پیدا کردن مسیر diagnostic (بدون چاپ مسیر)، استخراج شمارنده‌های ثابت و اعتبارسنجی schema به workflow افزوده شد. Core.ps1، Timer.ps1، Driver.ps1 و Run-CI.ps1 هیچ تغییری نسبت به اجرای قبلی نکردند؛ هش هر چهار فایل رسید با منبع CRLF تطبیق داده شد. هیچ allow شبکه‌ای، probe خارجی، تغییر زمان تایمر، تغییر baseline یا registry-write مستقیم اضافه نشد. ۹ fixture محلی شامل رد فیلد اضافی/هویت خراب، scope، زمان نامعتبر، حذف اطلاعات تزریقی و حالت فقدان لاگ پاس شد؛ اینها آزمون مصنوعی جمع‌کننده‌اند، نه PASS شبکه.

هیچ متن raw diagnostic، خطا/stacktrace، URL یا path، header، cookie، token، policy یا registry در artifact یا مخزن قرار نگرفت. خواندن لاگ‌ها فقط در runner موقت و خروجی whitelist شمارنده‌ها بود. انتشار با source_commit و run_id جاری تطبیق داده شد. از windows-2025 و ubuntu-latest استاندارد استفاده شد؛ larger/paid runner فعال نشد و هزینه صفر تضمین نشده است.

## تصمیم بعدی و معیار توقف
تکرار همین mutation بدون حفاظت/جداسازی کانال کنترل مفید نیست؛ اجرای چهارم انجام نشد. پیش از تکرار، fixture مخصوص CI باید کنترل runner را حفظ کند، بدون بازکردن عمومی شبکه یا ادعای معادل‌بودن با سیاست کاربر. یک طرح قابل بررسی: استثنای موقت و اختصاصی فقط برای binaryهای احرازشده Runner.Listener/Runner.Worker و مقصدهای HTTPS معتبر موردنیازشان، با journal/cleanup و تطبیق rules پس از حذف استثنا؛ در نبود تشخیص قابل‌اعتماد، توقف نه Allow وسیع. این صرفاً طرح است، هنوز ساخته/آزموده نشده و جزو سیاست دستگاه کاربر نیست. این استثنا فقط صلاحیت‌سنجی provider rollback را ممکن می‌کند؛ enforcement محصول را اثبات نمی‌کند.

BAT۶ و SSTP holand دست‌نخورده‌اند؛ هدف همان ایزولاسیون کل Windows روی مبنای فهرست فعلی است. بررسی مقصدها از صفر شروع نمی‌شود. روی سیستم کاربر هیچ تغییر یا Apply صورت نگرفته؛ Pause و تنظیمات فعلی حفظ شوند. BAT99 و toggle کیل‌سوییچ لازم نیست.

## منابع
- [اجرای تشخیصی](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39194616498)
- [رسید native](sstp-unset-s3u-cancelled-39194616498.json)
- [شمارنده‌های تشخیصی](sstp-runner-signals-39194616498.json)
- [کد workflow و جمع‌کننده](https://github.com/kokononox/battle-net-agent-lab/commit/4a046fbd5459c28e6aa7e1b1c9e40eea98b7331d)
- [رسید منتشرشده خودکار](https://github.com/kokononox/battle-net-agent-lab/blob/e2a7c7c77f9bf9722083b28772cf6e0c64a5d379/reports/sstp-control-diagnostic.json)
- [کنترل فقط‌انتظار](sstp-wait-control-s3w-analysis.fa.md)
- [GitHub: workflow cancellation](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation)
- [کد عمومی JobDispatcher](https://github.com/actions/runner/blob/9abfe11d2abd9de09d3a8d933d7ed701ea0518a3/src/Runner.Listener/JobDispatcher.cs)
- [کد عمومی Worker](https://github.com/actions/runner/blob/9abfe11d2abd9de09d3a8d933d7ed701ea0518a3/src/Runner.Worker/Worker.cs)
