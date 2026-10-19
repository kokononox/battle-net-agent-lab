# P7C — بازتولید اختلاف برچسب‌ها بدون mutation فایروال

## نتیجه
کنترل فقط‌خواندنی کامل شد و همان نوع اختلاف P7 را بدون اجرای هیچ setter فایروال از طرف کد ما نشان داد: 2 قانون، فقط Description/DisplayGroup/DisplayName. این نتیجه نشان می‌دهد اختلاف برچسب‌ها به‌تنهایی شاهد تغییر دسترسی شبکه نیست؛ نه تأیید کل کیل‌سوییچ و نه اثبات منشأ دقیق اختلاف اجرای قبلی.

- منبع: `84f308c2567f7612a733f551769da0f5da2dc675`
- اجرا: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39210801229 ؛ job موفق در۱۱دقیقه۱۹ثانیه.
- مشاهدهٔ واقعی: 660ثانیه، 13snapshot و 5fixture خالص comparator. completed=true یعنی اندازه‌گیری کامل، نه enforce شدن کیل‌سوییچ.
- digest ZIP: `96d490da8552b2338aaeb710e2dddb504963ac5038444c89052676b33d87ca2a`. source/run و هر دو hash منبع مستقلاً با نسخه اجراشده (LF/CRLF checkout) تطبیق داده شدند.

## آنچه دیده شد
تعداد قواعد PersistentStore در هر۱۳خواندن برابر348 بود؛ هیچ قانون افزوده/حذف نشد و baseline منتخب پروفایل‌ها در همهٔ نمونه‌ها برابر ماند. نخستین اختلاف در sequence=10 و ثانیه540 دیده شد؛ خواندن قبلی در ثانیه۴۸۰ برابر بود. زمان دقیق تغییر معلوم نیست، فقط بین این دو خواندن مشاهده شده است.

هر سه فیلد Description/DisplayGroup/DisplayName در دو قانون از دستهٔ literal به resource_reference رفتند. دستهٔ دوم در کد صرفاً یعنی متن با @ آغاز شده است؛ نه بررسی اعتبار resource و نه اثبات مکانیزم localization. در diff property-level نامی از Enabled/Action/Group یا دیگر propertyهای policy نیامد. هفت فیلتر قوانین نامرتبط در این کنترل خوانده نشدند؛ پس عدم تغییر تمام enforcement نتیجه گرفته نمی‌شود.

## مستند رسمی و حدود نتیجه
[مستند Microsoft برای Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps) تصریح می‌کند DisplayName محلی‌شده و locale-dependent است و حتی بدون modification خود object می‌تواند در بعضی شرایط تغییر کند؛ برای اسکریپت Name توصیه شده است. Description هم localized user-facing و DisplayGroup حاصل source stringِ Group معرفی می‌شود. این مستند با ماهیت نمایشی مشاهده سازگار است، اما فرآیند/علت دقیق تغییر در runner را مشخص نمی‌کند.

کنترل در VM تازهٔ Windows-2025 و بدون واردکردن ماژول mutation اجرا شد: فقط Get-NetFirewallRule/Get-NetFirewallProfile، پردازش محلی، انتظار و نوشتن receipt محدود. سرویس‌ها و agentهای خود runner همچنان فعال بودند. اثر خواندن provider، فعالیت بیرونی و localization از هم جدا نشده‌اند. چون هویت قواعد صادر نشد و ماشین‌ها متفاوت‌اند، یکسان بودن دقیق دو rule قبلی با این دو rule قابل اثبات نیست.

## تصمیم ایمنی و گام بعد
هیچ criterion در P7 برای گرفتن PASS حذف نشد؛ دو اجرای قبلی همچنان failed ثبت می‌شوند. گام بعد، جداکردن audit نمایشی از مقایسهٔ policy پایدار/هفت فیلتر واقعی است. تبدیل برچسب نباید با تغییر Enabled، آدرس، پورت، برنامه، سرویس یا interface یکسان تعبیر شود. snapshot کامل مالکیت و قواعد خود برنامه باید strict بماند و هیچ تغییر ناشناختهٔ policy/GPO/فیلتر نباید «فقط نمایشی» محسوب شود. classifier جدید هنوز در Apply محصول ادغام یا qualified نشده است.

guard/coordinator، adapter پیش‌فرض پروفایل‌ها، binding عملی SSTP، DNS/IPv6/LAN، packet، قطع‌وصل VPN و reboot هنوز qualified نشده‌اند؛ ready_for_user_apply=false. دستگاه کاربر تغییر نکرد؛ فایل اجرایی تازه‌ای برای کاربر ارائه نشد و گزارش تکراری لازم نیست. انتظار۱۱دقیقه‌ای فقط برای CI است؛ محصول نهایی همچنان بدون resident/task/expiry است.

## صحت تحلیل و حریم خصوصی
مبدأ یک build JSON تودرتو است، نه۱۷رکورد آماری؛ profiler اولیه آن را نادرست تخت کرد و هشدار duplicate/null حاصل grain اشتباه بود. آن خروجی مبنای تحلیل نشد. داده به۱۳رویداد خواندن با sequence یکتا استخراج و دوباره profile شد: duplicate صفر و null صفر. تکرار elapsed_seconds در دو خواندن فوری و ثابت‌بودن شمارش‌ها و profile-equality معتبرند و حذف نشدند. run_id شناسهٔ رشته‌ای است، نه مقدار تحلیلی.

وجود اختلاف از دو مسیر مستقل (boolean شمارش‌ها و جمع مستقیم سه شمارش از raw) تأیید شد. union هویت‌ها فقط در حافظه PowerShell محاسبه شد؛ چون هویت صادر نشده، dedup مستقل آن عدد ممکن نیست و عدد۲ همان شمارش collector است. نام قانون، مقدار متن، مسیر برنامه، IP/GUID/SID یا snapshot خصوصی upload نشد؛ فقط receipt محدود و hash منبع منتشر شد. این یک تصمیم تشخیصی categorical است، نه تحلیل روند آماری یا شاهد عبور بسته؛ نمودار جداگانه‌ای ساخته نشد.
