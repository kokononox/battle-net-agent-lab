# نتیجهٔ registry-only روی Popen عادی: b4

## هویت اجرا

- source: bd72035e2a2f03765b9bf147de84dda91fe0ed0a
- run: 40443309512
- evidence: 947196379c532d88f06c52bfb3d3134096828587
- Windows 2025 تازهٔ GitHub-hosted، attempt اول، شاخهٔ تحقیق. نصب dependency، آزمون‌ها، observation و sanitization همگی success بودند.

## کنترل بومی و پیشروی نصاب

fixtureهای x64/x86 هر دو با exit صفر و registry errors/limits صفر پاس شدند: readA/readW/RegGetValueW/writeW، منفی size-only و frameهای دقیق تصویر fixture در readW/writeW همگی موفق بودند. کنترل‌ها پیش از target انجام شدند.

با hook رجیستری‌تنها روی بوت‌استرپ، اتصال به هدفِ ۳۲بیتی آماده بود؛ هویت تصویر پیش و پس تأیید شد، همهٔ ۱۱ API مورد انتظار نصب بودند و errors/limits هدف صفر بود. همان SHA pin پیشین برقرار بود. helper زبان continued و Agent.exe مشاهده شد. به خود Agent attach نشد و startup عادی در این نمونه با این observer پیش رفت.

## شواهد جدید رجیستری، پیش از ورود به حساب

کلید ثابت: HKCU\Software\Blizzard Entertainment\Blizzard Error، نام مقدار UserUUID. baseline قبل از هدف absent بود و پس از پاک‌سازی هدف present با قالب معتبر UUIDv4 بود. observer کلید هدف را تغییر نداده است.

در خود فرایند بوت‌استرپِ pinشده، دو callback موفق RegSetValueExW و شش callback موفق RegQueryValueExW ثبت شد. تمام این هشت رکورد status=0، type=REG_SZ و valid_uuid=true داشتند و Backtracer.ACCURATE در هر کدام frameهای متعلق به محدودهٔ تصویر تأییدشده ثبت کرد. شمار callback را نباید تعداد مستقل نوشتن/خواندن دانست؛ wrapperهای API تو در تو dedup نشده‌اند.

در بعضی رکوردها returnAddress مستقیم بیرون تصویر هدف بود، ولی stack دقیق frame داخلی داشت. anchor مستقیم write در RVA 0x1f38f2 و read در RVA 0x1f37bf ثبت شد. RVA آدرس نسبی داخل باینری عمومیِ pinشده است، نه آدرس مطلق یا شناسهٔ کاربر. Process.mainModule در رکوردها با تصویر تأییدشده متفاوت بود؛ محدودکردن scope به تصویر تأییدشده همچنان لازم بود، حتی در این روش Popen. علت داخلی این تفاوت ثابت نشده است.

این شواهد، حضور عملیِ read/write مقدار دارای قالب UUID و frameهای واقعی هدف را تأیید می‌کند؛ دیگر صرفاً آزمون مصنوعی یا حدس از نام فایل نیست. مقدار واقعی و هش آن منتشر نشده است.

## مرز دقیق نتیجه

- از valid_uuid=true، برابری بایت‌به‌بایت مقدار تمام read/writeها نتیجه نمی‌شود؛ این مقایسه در b4 انجام نشده است.
- baseline absent→present و write موفق، ذخیرهٔ مقدار در این بازه را نشان می‌دهند؛ اولین نویسندهٔ مطلق یا تابع مولد UUID ثابت نشده، چون Agent instrument نشده و attach پس از launch است.
- نام Blizzard Error به‌تنهایی اثبات crash-only بودن کاربرد نیست؛ این فعالیت در startup عادیِ بدون درخواست crash مشاهده شده است.
- شبکه hook نشده، plaintext یا capture ندارد و UUID با host_id شبکه مقایسه نشده است. این اجرا به‌تنهایی نه ارسال را اثبات می‌کند نه عدم آن را. شواهد مستقلِ ارسال پیشین a11 محفوظ‌اند و UUIDهای دو run به هم پیوند داده نشده‌اند.
- frame روی stack، جریان کامل داده یا assignment به provider تلمتری را ثابت نمی‌کند. provider_assignment_causality_proven=false و process_birth_coverage=false باقی‌اند.
- per-install uniqueness، HWID دائمی، انتساب حساب/شخص، reboot/reinstall، ذخیره‌سازی سرور یا نشان‌گذاری فایل‌های WoW از این داده ثابت نمی‌شوند.

هیچ login، Install، دانلود بازی، remote access، تغییر TLS یا child gating درخواست نشد. token گیت‌هاب به محیط فرزند منتقل نشد. فایل خام مشاهده، UUID/هش UUID، مسیر، PID/session ID، باینری یا capture منتشر نشده است. سؤال دوم در صف است.

## محدودترشدن مسئله و گام بعدی

b2 بدون Frida، b3 با attach حداقلی و اکنون b4 با registry-only روی Popen عادی به Agent رسیدند. این داده hook رجیستری‌تنها را در این روش/نسخه عامل ضروریِ توقف startup نشان نمی‌دهد؛ علت دقیق شکست مسیر قبلی هنوز بین wire hook، spawn و child gating جدا نشده و مقایسه روی یک ماشین نبوده است.

گام بعدی، مشاهدهٔ جداگانهٔ Agent با identity/pin و افزودن شبکه به‌صورت مرحله‌ای روی مسیر موفق است تا read رجیستری به پیام همان run پیوند بخورد. پوشش دیرهنگام نباید پوشش کامل آغاز فرایند نامیده شود. در زمان ثبت این نتیجه، b4 تمام شده و مرحلهٔ شبکه/Agent هنوز اجرا نشده است.
