# BATهای مستقل — همه فهرست بسته، جز یک نامزد

آخرین درخواست کاربر، همان ساختار BAT۳ با net session، PowerShell inline، echo0.0.0.0 و flushdns است؛ بدون Python/runtime/monitor/timer. فایل‌ها در [پوشه اصلی](../plain-hosts-leave-one-open/) قرار دارند.

| فایل | block | نامزد خارج از block در فهرست۲۵تایی |
| --- | --- | --- |
| 00-BAT3-Base.bat | ۲۰نام مبنا | پنج نامزد، فقط مرجع |
| 01-Block-All-25.bat | هر۲۵ | هیچ |
| 02-All-Except-OAuth.bat | ۲۴ | oauth.battle.net |
| 03-All-Except-Distribution.bat | ۲۴ | distribution.version.battle.net |
| 04-All-Except-US-Version.bat | ۲۴ | us.version.battle.net |
| 05-All-Except-Level3-TLS.bat | ۲۴ | level3.ssl.blizzard.com |
| 06-All-Except-Level3.bat | ۲۴ | level3.blizzard.com |
| 99-Unblock-This-List.bat | پاک‌کردن marker و خطوط0.0.0.0 همین فهرست | restore کامل hosts نیست |

نسخه‌ها مستقل‌اند، نه انباشته. block پس از خروج باقی می‌ماند و کاربر با BAT دیگر/۹۹ تغییرش می‌دهد. hosts برای همه برنامه‌های ویندوز است. هیچ Update/Pause/بستن فرایند/تغییر فایل بازی از این اسکریپت‌ها انجام نمی‌شود.

نام news بدون :443 تولید شده است. backup و TEMP هر بار GUID مستقل دارند، backup failure کنترل و پیش از copy مقایسه شده که hosts نسبت به backup تغییری نکرده باشد. marker خراب/نامتوازن باعث توقف می‌شود. cleanup مانند سبک فایل۳ شامل خطوط0.0.0.0 همین نام‌ها بیرون marker هم هست؛ backup را نگه دارند. www.google.com نه block می‌شود، نه cleanup.

ساخت بدون هیچ runner/Windows execution انجام شد؛ بررسی واقعی اجرا روی Windows هنوز نداریم. کنترل استاتیک فهرست‌ها، CRLF، ASCII، حد طول خط CMD و سلامت ZIP انجام شد. [MANIFEST](../plain-hosts-leave-one-open/MANIFEST.json) شامل SHA256 هر BAT است. این بررسی جای آزمون syntax/رفتار Windows نیست.

روش hosts-only، نه allowlist/firewall؛ تمام اینترنت/IP/IPv6/DoH/نام ناشناخته/اتصال قبلی را تضمیناً کنترل نمی‌کند. «همه» در نام01 یعنی همین۲۵نام. اگر کنترل01 هم دریافت واقعی دانلود را متوقف نکند، روش یا فهرست قدرت تمایز کافی ندارد. هیچ یک‌نامزد کافی نبودن هم می‌تواند به نیاز همزمان سرویس نسخه+CDN مربوط باشد.

ZIP تحویلی: BattleNet-BAT-Leave-One-Open.zip؛ SHA256: `aedb45010ae5dff6b7a61788aa41c563ebce4a82112fa475d096da2212ec4c82`. ZIP شامل۸BAT، README و MANIFEST است؛ helper/runtime ندارد. ابزار محتوای درخواست/TLS تازه تحویل نشده و سؤال hardware upload/fingerprint همچنان باز است.
