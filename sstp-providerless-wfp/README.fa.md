# P14 — primitive محدود WFP بدون provider/service و مدل epoch هویت

صرفاً CI و فقط exe آزمایشی؛ برای دستگاه کاربر یا کل سیستم آماده نیست.

نسخه مستقلِ مشتق از P13: یک sublayer پایدار و سه فیلتر پایدار/INDEXED با providerKey=NULL. provider اصلاً ایجاد نمی‌شود و serviceName، سرویس اختصاصی، task، timer، watchdog یا expiry وجود ندارد. marker و GUID تصادفی، برنامه محدود، ممیزی دقیق و ژورنال اختصاصی حفظ می‌شوند؛ نبودن provider مجوز adopt/delete ناشناخته نیست.

همان هفت جفت TCP، پنج fault/recovery تازه، سه سناریوی تعارض و پاک‌سازی دقیق بازآزمایی می‌شوند. audit باید providerKey خالی در sublayer و همه فیلترها و flags دقیقِ بدون DISABLED را تأیید کند. تنها ۴object معلوم در یک تراکنش ساخته/حذف می‌شوند؛ metadata شرط‌ها از journal تغییر حدسی نمی‌کند.

اسناد رسمی Object Management و جدول DISABLED در FWPM_FILTER0 درباره provider بدون serviceName یکدست نیستند. از این تعارض نباید نتیجه گرفت P13 در boot قطعاً غیرفعال می‌شد. در مسیر providerless، Object Management صریحاً بارگذاری persistent object بدون provider هنگام شروع BFE را بیان می‌کند. با این حال تست زنده BFE restart/boot انجام نمی‌شود و بازه قبل از آماده‌شدن BFE نیز پوشش‌داده‌شده تلقی نمی‌شود. PERSISTENT با BOOTTIME یکسان نیست.

BindingEpoch.ps1 فقط مدل read-only پذیرش مجدد است: boot marker، GUID و scope پروفایل، RAS correlation، GUID رابط و NET_LUID رشته‌ای باید مطابق باشند و observationهای P6 qualified باشند. بیست fixture شامل reuse همان LUID با profile/session/interface/boot متفاوت است. collector بومی یا monitor نیست، به Worker/kernel وصل نشده و نمی‌تواند پس از خروج controller تغییر را بفهمد. این مدل از reuse شناسه به تضمین امنیتی شبانه‌روزی نتیجه‌گیری نمی‌کند.

SSTP واقعی، boot/restart BFE، فاصله boot، UDP/DNS/LAN، IPv6 packet، اتصال‌های قبلی، guard کل دستگاه و integration با P12 هنوز بیرون qualification هستند. توقف/راه‌اندازی سرویس‌های Windows یا reboot runner برای سبزکردن آزمون مجاز نیست. فقط receipt شمارشی و hash کد upload می‌شود؛ raw journal/شناسه/مسیر/IP واقعی/boot marker خصوصی upload نمی‌شوند. Disable تنها objectهای دقیق خودی را حذف می‌کند، نه reset/Force-Allow.
