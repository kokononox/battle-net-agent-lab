# تحویل U1 — مانیتور محلی فقط‌مشاهده، آمادهٔ self-test کاربر

## نتیجهٔ تأییدشده
- source: `a73531277544939348e8c1e77bd4e92121ac2041`
- receipt: `d5075f8f6e6431dd27744c95006da7641c5586ae`
- run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39171328838
- artifact: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39171328838/artifacts/12152851621
- SHA256 بستهٔ artifact: `d699bb8072e45f19897a0145dab1c1d05325a97203284ccf55d607dae09e09bb`
- ساخت، نصب وابستگی‌های هش‌پین‌شده، ۳۵ آزمون ایمنی/بازیابی/گزارش‌ساز، اجرای native خودآزمایی با runtime بسته و آزمون امضای ناشر همگی موفق شدند. شش کنترل مستقل ساختار گزارش نیز محلی پاس شدند.
- خودآزمایی native شامل send، WSASend و ورودی منفی EncryptMessage است؛ جلسهٔ معتبر TLS یا آپدیت واقعی را اثبات نمی‌کند.
- باینری رسمی آغازگر فقط برای تأیید هش و امضای Blizzard دانلود شد و اجرا نشد. هم Python معتبر با ناشر غیرBlizzard و هم آغازگر معتبر Blizzard درست تشخیص داده شدند.
- فقط windows-2025 و ubuntu-latest استاندارد؛ هیچ رانر بزرگ/پولی فعال نشد. سهمیهٔ Actions تابع حساب است.

## وضعیت واقعی کاربر
هنوز به سیستم کاربر دسترسی نشده، بازی آپدیت نشده و سازگاری روی HP / Windows 11 او ثابت نشده است. گام کاربر فعلاً فقط دانلود artifact، Extract کامل و اجرای SelfTest-Only.cmd با Administrator است. پیام SELFTEST PASS و فایل selftest-to-share-....json باید بررسی شوند؛ فعلاً Update را Resume نکند و Start-Monitor.cmd را هم اجرا نکند.

پس از تأیید self-test محلی، مرحلهٔ اصلی مطابق README انجام می‌شود: بازی و Battle.net ابتدا بسته، خودکارآپدیت خاموش، بکاپ موجود، مسیر G:\World of Warcraft، بلوک موقت فقط دامنه با تأیید صریح BLOCK، بازکردن دستی Battle.net، ماندن signed out و Pause تا READY. خود ابزار هیچ Update/Pause/Cancel/Repair یا فرایند کنترل‌کنندهٔ Battle.net اجرا نمی‌کند. README بسته جزئیات و محدودیت‌ها را دارد.

## اصلاح‌های انتشار — برای تکرارنکردن خطا
- گزارش‌ساز در U1b کلید اشتباه ترکیبی `standard_runner_only certificate_gate` داشت؛ این خطای کد ما بود، نه خرابی ویندوز کاربر. builder و validator اکنون از قرارداد آزموده‌شده استفاده می‌کنند و schema به local-observer-build-2 تغییر کرد.
- امضای PowerShell در کنترل اولیهٔ runtime شکست خورد؛ علت زیرین آن در گزارش قدیمی ثبت نشده بود، بنابراین کندی/خرابی Windows یا نامعتبر بودن امضای Python را نتیجه نگیرید.
- نسخهٔ نهایی از همان پیاده‌سازی native `scripts/authenticode_native.cs` پروژه استفاده می‌کند: WinVerifyTrust با revocationChecks=1 و providerFlags=0x2080؛ ناشر از همان signer تأییدشده خوانده می‌شود. هیچ cache-only/no-revocation fallback یا تغییر certificate store/TLS verification اضافه نشد.
- خودآزمایی تکرارپذیر است و نام گزارش منحصر‌به‌فرد دارد. بازگردانی hosts مستقل از خواندن نسخهٔ بازی/ساخت گزارش انجام می‌شود. قفل تک‌نمونه از بازگردانی ناخواستهٔ hosts حین مشاهدهٔ فعال جلوگیری می‌کند. بازیابی در برابر تغییر هم‌زمان ابزار دیگر، fail-closed است و بکاپ را نگه می‌دارد.

## محدودیت مهم
این ابزار attach-only است و ممکن است نخستین درخواست‌ها را از دست بدهد؛ تزریق مشاهده‌گر می‌تواند پایداری/زمان‌بندی را تغییر دهد. شمارهٔ نسخه و پاسخ کاربر Finished، اثبات تکمیل یا صحت همهٔ فایل‌ها نیستند. نبود رشتهٔ CPU، نبود همهٔ تله‌متری را ثابت نمی‌کند. اثر انگشت فایل بازی/انتقال A به B هنوز آزمایش نشده. هیچ قالب گزارش نباید server_receipt_proven یا zero_telemetry_guaranteed یا whole_update_completion_proven را true کند.

بسته‌های قبلیِ بدون گواه انتشار موفق به کاربر داده نشوند. فقط artifact همین run نهایی قابل پیشنهاد برای self-test محلی است؛ عمر artifact هفت روز از زمان ساخت است.
