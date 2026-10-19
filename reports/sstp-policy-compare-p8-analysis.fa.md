# P8 — مقایسهٔ کامل policy، هفت فیلتر و audit نمایشی

## نتیجه
کتابخانهٔ فقط‌خواندنی جدید با 224check در Windows-2025 پاس شد. این بار baseline صرفاً propertyهای خود rule نیست: همهٔ 348rule موجود در PersistentStore و هفت نوع فیلتر مربوط snapshot و با هویت دقیق join شدند. این موفقیتِ inventory/comparison است، نه Enable/Disable یا تست کیل‌سوییچ و عبور بسته.

- منبع نهایی: `0ad3799844791324fed3a7594b3aaa5fd9ea5ca7`
- اجرا: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39213797768 ؛ success در۱دقیقه۱۱ثانیه.
- 152تغییر مصنوعیِ property در حافظه، هر هفت نوع filter، سه مورد برچسب متعلق به برنامه و هفت مورد فیلتر ناقص بررسی شدند.
- 42تطبیق واقعی AssociatedNetFirewallRule روی شش rule با فاصلهٔ یکنواخت، join bulk هفت نوع فیلتر را تأیید کرد. InstanceID/Name، یک‌به‌یک بودن، پوشش کامل، duplicate/orphan/missing برای همهٔ ruleها کنترل شدند؛ association جداگانه برای هر rule انجام نشد و ادعا نمی‌شود.
- دو inventory واقعی در همین اجرای کوتاه policy_equal بودند؛ display change مشاهده‌شده=0. این اجرا منتظر بازتولید drift دقیقه۹ نبود؛ شاهد آن همان کنترل P7C است.
- ZIP SHA256: `8768973781ba4397312d1780a95827e11d6bcbdc2140e9a5a66ec5c784538419`. digest واقعی artifact، source/run و هر سه hash منبع با کد دقیق اجراشده (LF/CRLF checkout) مستقلاً تطبیق داده شدند. receipt schema/نوع/شمارش/flags با validator سخت‌گیر بررسی شد؛ شمارش نهایی رابطهٔ 152+۷۲=224 را دارد.

## قرارداد مقایسه
snapshot کامل نگه داشته می‌شود؛ مقداری حذف یا بازنویسی نمی‌شود. برای rule خارجی فقط مقدار string/nullِ سه فیلد شناخته‌شدهٔ Description/DisplayGroup/DisplayName، با حضور همان فیلد در دو طرف، audit نمایشی است. حذف خود فیلد یا تغییر نوع، حتی برای این labelها، policy conflict می‌شود. raw Group، Enabled، Action، InstanceID و تمام propertyهای دیگر، شامل فیلد جدید ناشناختهٔ آینده، strict هستند.

برای OwnedRuleNames صریح، حتی سه label هم strict و تغییرشان stop_policy_change است؛ ownership از prefix یا متن نمایشی حدس زده نمی‌شود. ownership ناموجود/تکراری/ناهمسان رد می‌شود. هیچ فیلدی از address،port،application،service،interface،interface_type یا security معاف نیست. ترتیب آرایه‌ها حفظ می‌شود تا reorder ناشناخته مخفی نشود.

پروفایل‌های Domain/Private/Public در PersistentStore و ActiveStore با همهٔ CIM propertyهای قابل تبدیل snapshot می‌شوند، نه فقط DefaultOutboundAction. مجموعهٔ ruleهای افزوده/حذف‌شده، هر تغییر فیلتر یا property پروفایل و هویت/schema ناقص باعث stop/خطای ایمن است. خروجی فقط unchanged/display_only/stop_policy_change و شمارش/نام فیلدهاست؛ هیچ نام rule، مقدار، آدرس یا مسیر خصوصی صادر نمی‌شود.

## شواهد تست و تغییر نسخه
اولین منبع `bbe671f4b8c294050fc45dbf2e2a302da7c6fed5` در https://github.com/kokononox/battle-net-agent-lab/actions/runs/39213456004 با 222check پاس شد. بازبینی بعدی نشان داد معافیت label باید حضور فیلد و نوع string/null را هم شرط کند؛ دو تست منفی حذف/تغییر نوع اضافه شد و نسخهٔ نهایی دوباره روی Windows پاس شد. نسخهٔ اولیه با وجود موفقیت تست قبلی، منبع نهایی توصیه‌شده نیست.

تغییرهای منفی در حافظه روی یک rule واقعی، هفت filter آن و یک profile انجام شدند؛ نه روی policy ویندوز. بنابراین این تست هر property از نمونهٔ این کلاس‌ها را exercise می‌کند، نه تغییر واقعی هر یک از۳۴۸rule. field جدید/حذف‌شده، فیلتر ناقص، rule اضافه/حذف/تکراری، ownership غلط و reorder خود مجموعهٔ ruleها هم بررسی شدند. هیچ setter یا ماژول mutation وارد نشد و هیچ fixture rule ساخته نشد. baseline و snapshot خصوصی در artifact نیستند.

تفکیک نمایشی، بر پایهٔ [کنترل P7C](sstp-rule-readonly-control-p7c-analysis.fa.md) و [مستند Microsoft](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps) است؛ نه حذف بی‌شاهد فیلد مزاحم برای گرفتن PASS. audit اختلاف نمایشی نگه داشته می‌شود. دو failed receipt قدیمی P7 و comparator/journal قدیمی دست‌کاری یا به PASS تبدیل نشدند.

## محدودیت و گام بعد
این کتابخانه هنوز به Quarantine/journal/Enable/Disable متصل نشده است. caller باید decision را اعمال کند؛ نتیجهٔ stop در comparator به‌خودی‌خود فایروال یا بسته‌ای را مسدود نمی‌کند. گام بعد اتصال کنترل‌شدهٔ این قرارداد به snapshot/transaction واقعی با حفظ مالکیت و recovery است، سپس guard و profile-default adapter.

خواندن ruleها، هفت filter و profileها اتمیک نیست؛ برابر بودن دو inventory عدم تغییر گذرا یا مقابله با admin هم‌زمان را ثابت نمی‌کند. ActiveStore همهٔ ruleها و GPO اینجا inventory نشده‌اند؛ فقط profileهای ActiveStore خوانده شده‌اند. بنابراین این inventory به‌تنهایی gate کافی برای اعمال محصول نیست.

guard پایدار، SSTP binding عملی، DNS/IPv6/LAN، packet، reconnect و reboot همچنان qualified نشده‌اند. هیچ تنظیمی روی دستگاه کاربر عوض نشده و فایل اجرای جدیدی به کاربر داده نمی‌شود؛ گزارش جدیدی از او لازم نیست. ready_for_user_apply=false. هیچ resident/task/expiry محصول اضافه نشده است.
