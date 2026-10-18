# A/B شروع اجرا با یک دامنه مسدود — c1

دو job مستقل windows-2025 روی VMهای تازه: baseline بدون تغییر hosts و block_telemetry فقط برای telemetry-in.battle.net با هر دو نگاشت 127.0.0.1 و ::1. فایل‌های BAT کاربر اجرا نمی‌شوند. این آزمایش هیچ تغییری در کامپیوتر/بازی کاربر نمی‌دهد. آزمایش ورود یا آپدیت کامل بازی نیست و یک اجرا در هر arm برای تعمیم آماری کافی نیست.

## کنترل‌ها
- source commit مشترک، attempt=1، push message یک‌بارمصرف، contents:read فقط در مشاهده؛ publisher تمیز جدا با contents:write.
- bootstrap با SHA256 ثابت de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf و سپس Authenticode/ناشر Blizzard. اگر دانلود رسمی امروز با pin متفاوت باشد، قبل اجرا متوقف می‌شود؛ pin بی‌صدا به‌روز نمی‌شود. سایر دانلودهای child از این طریق pin نشده‌اند؛ هش فایل Agent کاندید در گزارش جداست و هویت executable همه processها را ثابت نمی‌کند.
- نسخه image و build ویندوز ثبت می‌شوند؛ دو VM مستقل تفاوت شبکه/زمان/backend دارند. endpointهای خام IP ممکن است متغیر باشند؛ نام‌های مستقیم SNI/Host از DNS candidate جدا می‌شوند.
- پیش از مداخله، resolver سیستم باید فقط IP عمومی برای دامنه بدهد. بعد از تغییر hosts در arm مسدود، flush با API ویندوز و تأیید resolver فقط loopback الزامی است؛ در غیر این صورت bootstrap آغاز نمی‌شود. این تأیید رفتار resolver سیستم است، نه تضمین استفاده کلاینت از آن؛ IP مستقیم/روش resolver دیگر می‌تواند عبور کند و باید در capture جست‌وجو شود.
- فایل hosts حداکثر ۱ MiB، بدون reparse و بدون نگاشت قبلی target. bytes اصلی فقط در حافظه نگه‌داری می‌شوند. در پایان فقط اگر محتوا هنوز دقیقاً نسخه نوشته‌شده خود آزمایش باشد، bytes اصلی بازگردانده می‌شوند. هیچ backup کاربر پاک یا بازنویسی نمی‌شود. عدم restoration در receipt صریح است؛ VM در هر حالت دور ریخته می‌شود.

## مشاهده
همان capture/parser b1، ۱۲۰ ثانیه مشاهده startup، فقط Continue صفحه زبان؛ بدون Install، legal acceptance، حساب یا بازی. PowerShell DNS cache probes که در b1 timeout شدند تکرار نمی‌شوند؛ نام‌ها از packet DNS و SNI/Host می‌آیند. raw capture/header/body/key صادر نمی‌شود. max job ده دقیقه برای هر arm، سقف سخت حجم شبکه فرزندان وجود ندارد. محدودیت‌های fragmentation/ECH/TCP prefix/offload/truncation باقی است.

## معیار تحلیل
اول precondition و pin، build/image و سلامتی capture هر دو arm بررسی شود. سپس bootstrap/Agent مشاهده‌شده و نتیجه language helper، نام‌های SNI/Host عمومی target، IPهای مرتبط و نام‌های مقصد تازه مقایسه شوند. نبود مشاهده، تضمین نبود درخواست/عدم ارسال سخت‌افزار یا نبود fallback نیست. مشاهده Agent به معنی کلاینت آماده بازی یا آپدیت موفق نیست. packet/flow counts تعداد درخواست یا مصرف واقعی شبکه نیست. آزمون منشاء فایل A→B هنوز مستقل و باز است.
