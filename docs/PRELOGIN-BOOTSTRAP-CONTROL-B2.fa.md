# نتیجهٔ کنترل بدون Frida: b2

## هویت اجرا

- source: 18d4ca655c1e9897d5f4fb6306ce9a90f93e24d8
- run: 40433984524
- evidence: 7bdf0848f8acd817107336d31e2765fb1d972116
- محیط: Windows 2025 تازهٔ GitHub-hosted، attempt اول، شاخهٔ research/prelogin-telemetry-wow-data-provenance.
- preflight، آزمون‌های ایمنی و کنترل، observation و sanitization همگی success.

## آنچه واقعاً مشاهده شد

bootstrap با SHA پیشین برابر و Authenticode مورد قبول observer اجرا شد. بدون نصب/import Frida یا درخواست تزریق، راه‌اندازی عادی Popen توانست مرحلهٔ زبان را ادامه دهد و Agent.exe در snapshotهای محدود مشاهده شد. این «تکمیل نصب لانچر» یا «ورود به حساب» نیست.

۳۰ sample و دو snapshot GUI نگه داشته شد. در هر دو snapshot، window_station_visible و input_desktop_accessible true بود؛ فرایندهای بررسی‌شده هم‌session بودند و فرایند متفاوت/نامشخص ثبت نشد. در اولی یک فرایند و سه پنجرهٔ متعلق به فرایندهای محدود، با یک پنجرهٔ visible؛ در پایانی دو فرایند و شش پنجره، با یک visible ثبت شد. probe_errors=0 و enumeration_truncated=false بود. این شمارها همهٔ پنجره‌ها/دسکتاپ‌های سیستم را پوشش نمی‌دهند.

continue مرحلهٔ زبان برگشت موفق داشت؛ outcome_uncertain=false. پیش از cleanup، root در ۳۱ فراخوانی poll در حال اجرا بود و exit مشاهده نشد؛ شمار poll با تعداد sample اصلی یکسان نیست، چون snapshot پیش از cleanup هم poll می‌کند. هیچ Install، login، دانلود بازی یا remote access درخواست نشد. متن UI، مسیر، PID/session ID، UUID و capture خام صادر نشدند.

## تفاوت با a12d

a12d با Frida spawn و hookهای registry/wire فقط bootstrap را مشاهده کرد و helper زبان no_targets ماند. این کنترل عادی توانست به Agent برسد. بنابراین ادعای کلیِ «محیط GitHub اصولاً قادر به اجرای این نصاب نیست» با این شاهد سازگار نیست؛ اختلاف روش اجرا/ردیابی اکنون مسئلهٔ قابل آزمایش بعدی است.

علت قطعی به Frida نسبت داده نمی‌شود: دو run روی یک ماشین نبوده‌اند، stdio/launch mechanism متفاوت است و آزمایش تک‌متغیره انجام نشده است. نتیجهٔ درست «اختلاف مسیرهای مشاهده‌شده» است، نه «اثبات ضد-Frida بودن نصاب» یا «اثبات bug مشخص».

## مرز سؤال اول

این کنترل هیچ plaintext شبکه یا packet capture جمع نکرده و network_payload_observed=false است. به‌تنهایی نه ارسال hardware را اثبات می‌کند نه عدم آن را. شواهد مثبت a11 حفظ می‌شوند؛ زنجیرهٔ جدید frameهای Agent و provider assignment هنوز تکمیل نشده است. یکتایی نصب، reboot/reinstall، انتساب حساب، ذخیره‌سازی سرور و نشان‌گذاری WoW همچنان اثبات‌نشده‌اند؛ سؤال دوم شروع نشده است.

## گام بعدی، هنوز اجرا نشده

مسیر راه‌اندازی موفق Popen حفظ شود و instrumentation مرحله‌به‌مرحله افزوده شود: ابتدا attach حداقلی بدون hook و با هویت تصویر تأییدشده؛ سپس registry-only؛ در آخر wire hook. attach پس از launch پوشش ابتدای عمر فرایند ندارد و برای ادعای «همهٔ داده‌های قبل از ورود» کافی نیست؛ صرفاً کنترل تشخیصی است. هر مرحله باید با pin/امضا، گزارش محدود و بدون Install/login اجرا شود. در زمان ثبت این نتیجه، اجرای b2 تمام شده و مرحلهٔ بعدی هنوز راه نیفتاده است.
