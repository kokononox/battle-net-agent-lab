# اقدامات باقی‌مانده پس از ۰٫۲۵

## پیشرفت ثبت‌شده
ترجیحات text/speech از کپی تاریخی با حفظ بندها و حذف qualifier خصوصی خوانده شد؛ reader محدود ویندوز برای دو متادیتا فایل پیاده و روی پوشه‌های مصنوعی تست شد. ۶۷۴ Linux و ۳۳۲ Windows پاس‌اند. این‌ها reader و تست‌اند، نه اپدیتر قابل نصب. [تحویل](UPDATER-SESSION-0.25.fa.md).

## ترتیب باقی‌مانده
1. **مرحلهٔ اول هنوز کامل نیست:** قواعد کامل انتخاب feature/variant/dependency، ترجیحات واقعاً تازه و اثبات نسل فعال همساز. ProductConfig و تگ تاریخی به‌تنهایی کافی نیستند. reader فعلی shmem/LRU/index/archive نمی‌خواند؛ offset جامعه یا بزرگ‌ترین filename oracle نیست. ابتدا قرارداد format/consistency/privacy و تست bounded طراحی شود؛ سپس در صورت ضرورت اقدام مشخص کاربر خواسته شود.
2. ساخت required set معتبر، شواهد reuse معتبر و حجم دانلود دقیق؛ عدد نامعلوم صفر فرض نشود.
3. انتقال واقعی محدود و recovery/resume بدون عبور از budget/approval و بدون حذف خودکار lock.
4. نوشتن تراکنشی CASC، rollback و activation؛ ابتدا کپی مستقل با آزمون شکست/قطع برق و کنترل فضای کافی. هیچ writer واقعی هنوز پیاده نشده است.
5. آزمون چندنسخه و نسخهٔ آینده با discovery تازه و stop برای قالب ناشناخته؛ سپس UI، بسته‌بندی و انتشار.

فعلاً از کاربر فایل/اجازه/اجرای تازه‌ای لازم نیست. required_set_selected=false، active_generation_proven=false، required_network_download_bytes=null، installation_ready=false و apply_authorized=false. تست ویندوز روی پوشهٔ موقت مجوز بازی زنده یا qualification کامل backend نیست. نه update/repair رسمی، نه admin/ACL change و نه broad upload تقاضا شود.
