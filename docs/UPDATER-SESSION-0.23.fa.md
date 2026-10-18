# تحویل ممیزی ابهام انتخاب — ۰٫۲۳

ادامهٔ [۰٫۲۲](UPDATER-SESSION-0.22.fa.md). اولویت کاربر قطعی‌کردن قواعد انتخاب همراه با نسخه و نسل فعال است؛ مرحلهٔ اول کامل نشده و هیچ reader هویت تازه‌ای به‌جای آن اعلام تکمیل نمی‌شود. محصول reusable است و 12.1.5.70448 فقط snapshot تاریخی pinned.

## انجام‌شده
policy_ambiguity.py و policy_ambiguity_review.py دادهٔ کپی‌شدهٔ دارای زنجیرهٔ اصالت را می‌خوانند؛ target/profile/hash، بانک‌ها و bitmap قبلی کنترل می‌شود. چهار cell متقابلاً جدا برای هر feature/candidate، سطرهای بدون tag هر dimension و نمونه‌های دارای ordinal+هویت کامل تولید می‌شوند. عددها با روش مستقل per-ordinal و عضویت تک‌تک نمونه‌ها کنترل شده‌اند؛ استقلال محاسبه با استقلال policy فرق دارد.

گروه‌های label تکراری Install فقط با slash/casefold و به‌عنوان متادیتای opaque ثبت می‌شوند؛ نه اعتبارسنجی مسیر سیستم و نه انتخاب variant. سقف نمایش ۱۶ گروه و ۸ سطر هر گروه و دو نمونهٔ هر cell است؛ omittedها ثبت‌اند. بررسی CKeyهای Install انتخاب‌شده هم هیچ EKey را اولویت نمی‌دهد. تمام candidateها بدون تغییر ماندند؛ هیچ قاعدهٔ لازم/اضافی‌بودن برای Alternate/Talebound/HighRes نتیجه نشده است.

گزارش واقعی به target/profile/hash متصل است؛ profile عمومی Windows/x86_64/EU و text/speech=enUS تازهٔ نصب نیست. هیچ payload بازی، decoded بزرگ، بانک، مسیر نصب، log خصوصی یا credential در بسته/مخزن منتقل نمی‌شود.

## آزمون واقعی
۲۷ تست تازه شامل mask/padding، crossfoot، نمونه‌ها، type/schema، group/row limits، عدم انتخاب variant و integration اصالت/عدم تغییر برنامه. Linux ۶۲۲ تست، Windows/Python 3.12.10 برابر ۲۶۰، صفر failure/error/skip. شمار پلتفرم‌ها جمع نشود. source 6247126ad714d46767a78eb7c0b4f6556849fe9c و receipt 3caeda38c1aabef0338080b35b4fb06d4b7b2fc1. ZIP استخراج و CRC/hash و regression کنترل می‌شود.

## مانع واقعی و گام بعد
سؤال‌های شاهد مستقل اکنون دقیق‌اند؛ اما الگوریتم/خروجی انتخاب مستقل از کلاینت رسمی در ورودی‌های موجود نداریم. تطبیق نمونه، label یک feature، bitmap خودمان، نبودن فایل در download log یا defaults استخراج‌کننده مدرک policy کامل نیست. مرجع باید scope دقیق target/profile/manifest، inclusion/exclusion/unknown و variant/feature/dependency/patch را پوشش دهد؛ یک build/profile برای همهٔ نسخه‌های آینده کافی نیست.

اگر مرجع مستند مستقل یا plan از قبل موجود و پالایش‌شده در دسترس باشد، ابتدا applicability آن بررسی شود. فعلاً کاربر نباید آپدیت/repair رسمی اجرا، log گسترده جمع یا فایل‌های بزرگ تصادفی ارسال کند. probe زنده‌ای در این بسته ارائه نشده؛ هر capture بعدی نیازمند دامنهٔ دقیقِ clone/action/network/write/bytes/privacy و تأیید جداست. دسترسی Windows/فضای کپی کاربر مجوز اجرای update رسمی نیست. freshness ترجیحات و نسل فعال همچنان بازند؛ متادیتای Active=1 یا نام بزرگ‌تر idx جای آن نیست.

installation_ready/apply_authorized/required_set_selected=false و required_network_download_bytes=null. مراحل حجم/reuse، انتقال واقعی و recovery عملیاتی، writer/rollback/activation، Windows E2E و UI پس از این موانع‌اند. هیچ دسترسی بازی/CDN، admin، scan، repair، permission change یا تغییر workflow مستقل Agent انجام نشده. کش/متادیتای پروژه حفظ شوند؛ دوباره دانلود نشوند.

[گزارش ممیزی](../updater-core/reports/POLICY-AMBIGUITY-to-share.json) · [رسید Windows](../updater-core/reports/WINDOWS-POLICY-AUDIT-CI-to-share.json) · [قرارداد مرجع](../updater-core/research/POLICY-REFERENCE-PROTOCOL.md) · [باقی‌مانده](UPDATER-REMAINING.fa.md)
