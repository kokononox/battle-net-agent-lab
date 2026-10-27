# ساختار آماده‌سازی WoW Retail بدون حساب — c3

## دامنه و نتیجه

در اجرای Windows 2025 بدون حساب، bootstrap پین‌شده و Agent امضاشده متعلق به آزمایش استفاده شدند. پس از handshake محلی، دقیقاً یک GET /game و یک POST /install برای wow انجام شد. پاسخ آماده‌سازی HTTP 201 با ۱۴۵۸ بایت بود؛ نصب نهایی، درخواست دانلود محتوای بازی، اجرای بازی و پذیرش شرایط انجام نشد.

کد منبع: `f383066038eacc944e5333553d6f2d29277434a6`

اجرای `40452004350`؛ مراحل آزمون، مشاهده و اعتبارسنجی همگی success. ۴۴ آزمون محلی نیز بدون PYTHONPATH در چیدمان مشابه checkout گذشت.

## یافته‌های مستقیم

- authentication.error = 0 و min_spec.error = 0 فقط در پاسخ آماده‌سازی.
- game_dir.error = 800 و language.error = 704. معنا/نام رسمی این دو کد هنوز تأیید نشده است.
- game_dir شامل default، dirname، game_dir، required_space، required_space_info، error و warning است. رشته‌های مسیر منتشر نشدند.
- required_space = 52,000,000,000 بایت؛ فقط مقدار اعلام‌شده Agent در این فرم، نه اندازه اثبات‌شده انتقال، نصب کامل یا محتوای قابل‌بازی. این مشاهده ادعای کاربر درباره پوشه حدود ۱۳۰ گیگابایت را رد نمی‌کند.
- language دارای list، speech و text است؛ هرکدام آرایه ۱۱ رشته‌ای. اجتماع کدهای شناخته‌شده در بخش language: deDE، enUS، esES، esMX، frFR، itIT، koKR، ptBR، ruRU، zhCN، zhTW. تعداد رشته‌های ناشناخته در بخش زبان صفر بود. این خلاصه به‌تنهایی برابری سه آرایه یا موفقیت انتخاب هر زبان را ثابت نمی‌کند.
- یک عضو خارج از فهرست مجاز در ساختار داخلی required_space_info وجود داشت؛ نام و مقدارش منتشر نشده است. بنابراین بازسازی کامل آن ساختار ادعا نمی‌شود.
- eula فقط دو عضو error (عدد) و eula (بولی) دارد. مقادیر error=0 و eula=true مشاهده شد؛ متن یا URL قرارداد در این بخش نبود.

## تصحیح برداشت از EULA

برچسب eula_review_pending یک قاعده احتیاطی تحلیلگر ماست که با حضور بخش EULA فعال می‌شود؛ خطای اعلام‌شده سرور یا اثبات مطالبه پذیرش جدید نیست. معنای دقیق eula=true در این پروتکل تأیید نشده و نمی‌توان آن را معادل پذیرش کاربر، اجازه نصب، یا الزام به پذیرش تازه دانست. ابزار هیچ مقدار رضایت/پذیرشی ارسال نکرده است.

## بررسی تطبیقی کد عمومی، نه اجرای آن

نسخه ثابت barncastle/Battle.Net-Installer در ProductModel از GameDir، Language، SelectedAssetLocale و SelectedLocale استفاده می‌کند، اما پیش‌فرض Finalized=true، AccountCountry=USA و GeoIpCountry=US هم دارد. این پیش‌فرض‌ها در آزمایش ما کپی یا اجرا نشدند. این پیاده‌سازی کامیونیتی سند رسمی پروتکل نیست و موفقیت آن روی این build را اثبات نمی‌کند.

همان پروژه در InstallProductTask برای شروع دانلود درخواست به UpdateEndpoint می‌فرستد؛ این درخواست در c3 انجام نشده است. Program نیز مرحله POST محصول را بعد از آماده‌سازی دارد. تا تأثیر این مراحل و رضایت احتمالی روشن نباشد، نباید صرفاً با کپی مدل عمومی نصب را نهایی کرد.

## مرز استنتاج

آماده‌سازی بدون حساب دوباره مشاهده شد، نه دانلود موفق بدون حساب. هیچ ابزارگذاری محتوای شبکه در این مرحله وجود نداشت؛ ارسال سخت‌افزار در فاز دانلود، رسید سرور، منشأ فایل‌های بازی و نشان‌گذاری آن‌ها اثبات نشده‌اند. شواهد قبلی ارسال پیش از لاگین جدا باقی می‌مانند.

گام فنی بعدی: تعیین درخواست غیرنهایی برای انتخاب زبان شناخته‌شده و یک مسیر خالیِ متعلق به محیط آزمایش، با کنترل پاسخ و بدون کپی کشورهای پیش‌فرض یا رضایت ضمنی. اگر بتوانیم عدم نهایی‌سازی را مستند/کنترل کنیم، تغییر کدهای ۸۰۰ و ۷۰۴ آزموده می‌شود؛ موفقیت آن نیز هنوز شاهد انتقال بازی نیست.

## منابع ثابت

- https://github.com/kokononox/battle-net-agent-lab/blob/4cdebe678764e541c858888f3c31c8a77b439845/reports/prelogin-retail-prepare-ci.json
- https://github.com/kokononox/battle-net-agent-lab/blob/4cdebe678764e541c858888f3c31c8a77b439845/reports/prelogin-retail-prepare-runtime.json
- https://github.com/barncastle/Battle.Net-Installer/blob/3aa2d98d866b393197da0b75d7381b7fff495ad9/BNetInstaller/Models/ProductModel.cs
- https://github.com/barncastle/Battle.Net-Installer/blob/3aa2d98d866b393197da0b75d7381b7fff495ad9/BNetInstaller/Operations/InstallProductTask.cs
- https://github.com/barncastle/Battle.Net-Installer/blob/3aa2d98d866b393197da0b75d7381b7fff495ad9/BNetInstaller/Program.cs
