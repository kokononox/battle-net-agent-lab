# ادامهٔ جلسهٔ Unified Firewall

اول [تحویل جامع](../../docs/SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md) و [وضعیت جاری](../../docs/UNIFIED-FIREWALL-CURRENT.json) را بخوانید.

- `source-overlay/`: تغییرات متنی نسبت به سورس پایهٔ immutable؛ [قرارداد بازسازی](SOURCE-OVERLAY.json). runtime نیست؛ manifestهای release داخل overlay تاریخیِ HF1.1 و برای کاندید فعلی نامعتبرند. این پوشه را روی برنامهٔ آزمایش جایگزین نکنید.
- `windows-receipts/`: رسیدهای پالایش‌شدهٔ drift، بازیابی و مقایسهٔ خواندنی (شکست و موفقیت جدا).
- `qa/`: آزمون‌های محلی با scope صریح؛ قبولی Linux برابر qualification ویندوز نیست.
- `diagnostics/hf121/`: سورس همان ابزار فقط‌خواندنیِ نمونه‌ای؛ دستور اجرای تازه نیست. مسیرهای مطلق مدل‌تست‌ها متعلق به محیط ساخت‌اند؛ برای بازتولید آزمون باید پارامتر Root/مسیرها به checkout محلی تنظیم شوند.
- `reconnect-design-v01/`: kernel تصمیم با ۶۷ بررسی؛ بدون native observer/executor و بدون دخالت در guardian.
- `ARTIFACT-INDEX.json`: هش بسته‌های تحویلی و وضعیت تاریخی/غیرقابل‌نصب؛ ZIP و runtime منتشر نشده‌اند.

این سینک raw chat، dump، pcap، اطلاعات ورود، آدرس سرور VPN، نام/مسیر شخصی، ژورنال محافظت‌شده یا backup خصوصی را منتشر نمی‌کند. اصلِ هدف: ابزار کوچک Battle.net؛ جلوگیری کامل از فینگرپرینت هنوز تأیید نشده است.
