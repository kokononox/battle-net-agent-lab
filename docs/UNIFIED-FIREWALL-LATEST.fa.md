# اولویت جاری: بازیابی و ثبت خروج عادی، نه Apply

مرجع ادامه: [تحویل جامع](SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md)، [کتابخانهٔ رکورد خروج HF1.2.4](../analysis/unifiedfw-session-2026-10-27/normal-exit-hf124/README.fa.md)، [اصلاح بازیابی HF1.2.3](../analysis/unifiedfw-session-2026-10-27/recovery-hf123/README.fa.md) و [وضعیت ماشین‌خوان](UNIFIED-FIREWALL-CURRENT.json).

اینترنت عادی کاربر بعد از خروج صریح به Allow برگشته؛ firewall روشن و ورودی مؤثر Block بوده است. علت Block پس از reboot و صحت بازیابی اصلی ثابت نشده‌اند. ژورنال قدیمی untouched است.

HF1.2.4 کتابخانهٔ Review/Record جداگانه ساخته: consent دقیق و digest تازه، نبود واقعی owned rules، برابری foreign before images، local/effective Allow، نبود task شناخته‌شده، قفل operation و CreateNew محافظت‌شده با checksum/readback و revalidation. ژورنال قدیمی به Allow تبدیل/بازنویسی نمی‌شود. رکورد original_restore_verified/authorizes_isolation/reboot_qualified/ready_for_apply=false دارد. وجودش مجوز Apply نیست و guard HF1.2.3 بدون تغییر است.

۷۲ assertion اختصاصی، ۴۶ suite PS، ۵۳۱ Python pass+۲ skip و ۱۰۲ parse گذشتند؛ native Windows ACL/identity و اجرای واقعی ثبت آزموده نشده‌اند. wrapper/فایل IO در مدل Linux آزموده شده؛ worker auto-load/runner بسته و migration جدید هنوز نداریم. کاربر اقدام تازه ندارد؛ همهٔ Apply/Restore/local-review و live reconnect متوقف بمانند. مرحلهٔ بعد runner کنترل‌شده و qualification ACL/حفظ legacy در Windows است، نه ارتقای خودکار controller.
