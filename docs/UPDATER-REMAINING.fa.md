# اقدامات باقی‌مانده پس از ۰٫۲۶

## پیشرفت واقعی
بندهای عمومی ترجیحات کپی تاریخی، بدون حذف optional یا قاطی‌کردن زبان متن/صدا، به نامزد hash-verified وصل شد. حذف تگ خصوصی فقط پس از اثبات غیبت نامش در هر دو manifest ممکن است. bitmap نامزدها مستقل برای تک‌تک رکوردها بررسی شد؛ نامزد تغییر نکرد. ۷۰۶ Linux و ۳۶۴ Windows پاس‌اند. [تحویل](UPDATER-SESSION-0.26.fa.md).

## ترتیب باقی‌مانده
1. **مرحلهٔ اول هنوز باز است:** قواعد کامل feature/variant/dependency، ترجیحات واقعاً تازه و نسل فعال همساز. اتصال candidate و تگ تاریخی oracle رسمی یا live capture نیست. برای نسل فعال ابتدا قرارداد bounded/versioned شامل مسیر/حجم/حریم خصوصی و معیار مستقل سازگاری طراحی شود؛ نه حدس offset و نه بزرگ‌ترین filename. هیچ خواندن تازه shmem/LRU یا اجرای کاربر در این مرحله خواسته نشده است.
2. اثبات reuse محلی، required set معتبر و حجم دقیق شبکه؛ unknown صفر نیست.
3. qualification انتقال واقعی محدود، resume/recovery با budget و approval مستقل.
4. writer تراکنشی CASC، rollback و activation؛ ابتدا کپی مستقل و آزمون شکست/قطع عملیات. writer نصب واقعی هنوز پیاده نشده است.
5. آزمون نسخه‌های متفاوت و نسخهٔ آینده، stop برای قالب ناشناخته؛ سپس UI، بسته‌بندی و انتشار.

فعلاً اقدام کاربر لازم نیست. admin/ACL، update/repair رسمی، broad upload و game write درخواست یا مجاز نشده‌اند. required_set_selected=false، active_generation_proven=false، required_network_download_bytes=null، installation_ready=false و apply_authorized=false. تست‌های Windows پوشهٔ موقت‌اند و qualification تولید/نصب واقعی محسوب نمی‌شوند. کش‌ها حفظ و دوباره دانلود نشوند؛ workflow مستقل Agent تغییر نکند.
