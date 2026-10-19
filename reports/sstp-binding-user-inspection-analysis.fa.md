# نتیجهٔ گزارش فقط‌خواندنی SSTP دستگاه کاربر

## منبع و حدود
فایل ارسالی کاربر SstpBindingReport.json، schema=sstp-binding-inspect-1، زمان گزارش 2026-10-19T05:10:11.6799878Z، SHA256 فایل `e46ac8b20aa3b262793a2d7ce7b3e7a908578c70b2e3f9bb1cce5d1ecdaf6996`. این یک snapshot تشخیصی تجمیع‌شده است، نه trace بسته یا اثبات مستقل وضعیت kernel. فایل خام دستگاه به مخزن اضافه نشده است؛ فقط یافته‌های لازم ثبت می‌شوند.

## یافته‌های مستقیم
- هر هشت query گزارش current-user/all-users VPN، رابط‌ها، routeها، profileهای stored/effective و قواعد local/effective موفق است. ابزار elevated=false بوده؛ برای همین بازرسیِ انجام‌شده اجرای دوباره با حساب مدیر لازم نیست. این به معنی امکان نوشتن policy بدون elevation نیست.
- یک پروفایل SSTP در current_user فعال گزارش شده؛ selected_active و preferred_name_match=true یعنی با holandِ منطق بازرسی تطابق دارد. سرور در دستهٔ hostname_or_unrecognized است؛ این فیلد به‌تنهایی اثبات نام DNS معتبر نیست و مقدار سرور صادر نشده است.
- یک interface با alias متناظر گزارش شده؛ IPv4 آن connected و IPv6 آن disconnected است. تطابق alias هنوز پیوند قطعی RAS/profile/interface یا qualification فیلتر packet نیست.
- روی همین candidate هیچ route پیش‌فرض IPv4/IPv6 گزارش نشده، روی رابط‌های دیگر برای هر خانواده یک default route وجود دارد. این گزارش routeهای مقصد خاص، prefixهای جایگزین یا مسیر واقعی packet را اندازه نگرفته است. نه نرسیدن مقصدهای خاص به VPN ثابت است، نه نشتی IPv6 یا bypass واقعی.
- هر سه firewall profile روشن‌اند. مقدار ذخیره‌شدهٔ default outbound هر سه **NotConfigured** و مقدار مؤثرشان **Allow** است؛ default inbound مؤثر Block و merge قواعد محلی True گزارش شده است. snapshot بازگردانی باید مقدار stored را حفظ کند، نه اینکه برای Disable سه profile را به Allow تحمیل کند.
- ۱۰۰ outbound Allow فعال محلی و ۱۰۰ outbound Allow مؤثر گزارش شده است. با source tracing روشن، nonlocal فعالِ outbound Allow قابل مشاهده صفر است. این فقط همین مجموعهٔ قابل مشاهده است؛ نبود همهٔ GPOها، محدودیت‌های profile، WFP/فایروال ثالث یا تغییرات آینده را ثابت نمی‌کند.
- فیلدهای network_policy_changed، dns_queried، enforcement_tested و ready_for_user_apply همگی false هستند. این اجرای ابزار صرفاً inspection است و policy تازه‌ای اعمال نشده است.

## تصمیم اجرایی
1. مانع فعلی «پروفایل SSTP پیدا نمی‌شود» یا «گزارش را حتماً باید admin خواند» نیست. هیچ تکرار همین inspection یا تغییر تنظیمات از کاربر لازم نیست.
2. default outbound Block به‌تنهایی با وجود ۱۰۰ Allow موجود، policy مقصد-محدود مورد نظر را ایجاد نمی‌کند. هر Allow باید در snapshot کامل ثبت و در transition واقعی حساب‌شده مدیریت شود؛ پس از Disable صرفاً تغییرات خود ابزار و مقدار stored اولیه برگردد. مجوز پاک‌کردن کل قواعد یا reset عمومی وجود ندارد.
3. IPv6 و مسیرهای بیرون تونل باید صریحاً در policy واقعی پوشش داده شوند؛ default routeِ گزارش‌شده شاهد الزام طراحی است، نه مدرک نشتی اتفاق‌افتاده.
4. گام فنی بعد، پیوند معتبر اتصال RAS/SSTP انتخاب‌شده به رابط واقعی و قرارداد snapshot/guard برای تغییرات مؤثر است؛ صرف alias کافی نیست. سپس qualification packet، قطع‌وصل، DNS، IPv6 و boot لازم است. backend مؤثر هنوز کامل نیست و گزارش آماری این کار را جایگزین نمی‌کند.

## وضعیت
نیاز کاربر ثابت است: allowlist فقط از SSTP، LAN بسته، اتصال دستی، بدون برنامهٔ مقیم و انقضا، اعمال و خروج، restore اختصاصی. آمادهٔ Apply نیستیم؛ نه این گزارش و نه تست‌های P1–P5 مجوز Enable جدید نیستند. گزارش تازه دریافت و تحلیل شد؛ بندهای «منتظر گزارش inspector» در سابقه، دیگر blocker جاری نیستند.

روش اعتبارسنجی: JSON به‌صورت یک observation تو‌در‌تو خوانده و schema، وضعیت queryها، انتخاب پروفایل، مجموعهٔ سه profile، شمارنده‌های اعلام‌شده و flags کنترل شدند. profiler جدولی برای این ساختار تو‌در‌تو مناسب نبود؛ از شمارش row یا استنباط دادهٔ گمشده استفاده نشد. شمارنده‌های دستگاه تجمیعی‌اند و از فایل نمی‌توان مستقل از خود گزارش ۱۰۰ rule را دوباره enumerate کرد. نمودار برای این تشخیص هویت/پالیسی اطلاعات معناداری اضافه نمی‌کند.
