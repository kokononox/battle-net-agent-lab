# اقدامات باقی‌مانده پس از ۰٫۲۷

## پیشرفت ثبت‌شده
قرارداد pure برای دو دور copied metadata/control و دقیقاً ۱۶ ایندکس ارجاع‌شده ساخته شد؛ header/checksum/هندسهٔ شناخته‌شده بررسی و fallback بزرگ‌ترین نام رد می‌شود. اختلاف دورها، pending/reset یا قالب ناشناخته توقف می‌دهد. دادهٔ fixture کاملاً مصنوعی است. ۷۴۶ Linux و ۴۰۴ Windows پاس‌اند. [تحویل](UPDATER-SESSION-0.27.fa.md).

## ترتیب باقی‌مانده
1. **مرحلهٔ اول هنوز باز است:** انتخاب کامل feature/variant/dependency، ترجیحات واقعاً تازه و نسل فعال همساز. برای نسل فعال اکنون قرارداد منفی و معیارهای مشخص داریم، نه detector زنده: معنای control/extension، اتصال store/root/file-ID، capture محدود بومی و شاهد مستقل استفادهٔ client باید اعتبارسنجی شوند. برابری دو دور snapshot یا محافظت ABA نیست؛ offset حدسی یا بیشترین filename کافی نیست. [معیارها](../updater-core/research/GENERATION-LIVE-PROOF-REQUIREMENTS.json).
2. اثبات reuse محلی، required set معتبر و حجم دقیق دانلود؛ unknown صفر نیست.
3. qualification انتقال واقعی محدود، resume/recovery با budget و approval مستقل.
4. writer تراکنشی CASC، rollback و activation؛ ابتدا کپی مستقل و آزمون قطع عملیات/شکست. writer نصب واقعی هنوز پیاده نشده است.
5. آزمون چندنسخه و نسخهٔ آینده با discovery تازه و stop برای قالب ناشناخته؛ سپس UI، بسته‌بندی و انتشار.

فعلاً اقدام کاربر لازم نیست. این مرحله هیچ فایل تازه‌ای از کنترل یا ایندکس کاربر نخواند؛ سقف API قرارداد مجوز بازی زنده نیست. نه admin/ACL، نه update/repair رسمی، نه broad upload و نه game write تقاضا شود. required_set_selected=false، active_generation_proven=false، required_network_download_bytes=null، installation_ready=false و apply_authorized=false. تست Windows qualification تولید/نصب واقعی نیست. کش‌ها حفظ و workflow مستقل Agent دست‌نخورده بماند.
