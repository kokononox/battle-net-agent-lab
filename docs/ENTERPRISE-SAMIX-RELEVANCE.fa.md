# ارزیابی کاربرد Enterprise samix برای پروژه

کاربر فعال‌کردن https://github.com/enterprises/samix را اعلام کرد. این سند ادعای تأیید plan، موجودی سهمیه، عضویت organization یا دسترسی runner همین مخزن نیست؛ ابزارهای GitHub فعلی مدیریت Enterprise/Actions runner را ارائه نمی‌کنند.

## نتیجه فعلی
برای decode آفلاین نمونه‌های E2 قابلیت Enterprise لازم نیست؛ آزمایش‌های محدود Windows روی runner موجود انجام شده‌اند. در این جلسه هیچ runner پولی جدید، انتقال مخزن یا تغییر sharing/permissions فعال نشده است.

## کاربرد احتمالی بعدی
طبق مستند GitHub، larger runners می‌توانند CPU/RAM/disk بیشتر، static egress IP، runner groups و قابلیت networking اضافه داشته باشند. این‌ها در صورت نیاز به محیط Windows بزرگ برای fixture نصب/آپدیت کامل و آزمایش‌های تکرارپذیر مفیدند؛ نوع/ظرفیت واقعی و سیاست دسترسی باید بررسی شود. ثابت‌کردن egress IP، IP مقصد CDN را ثابت نمی‌کند و telemetry را حذف/محتوای TLS را قابل‌خواندن نمی‌کند.

Enterprise به‌تنهایی این مسائل را حل نمی‌کند: decode بدنه باینری، تشخیص hardware fields، اثبات عدم ارسال روی همه مسیرها، یا اثرانگشت فایل‌های منتقل‌شده A→B. سیاست شبکه هنوز باید طراحی/آزمون شود.

## شرط استفاده
- سازمان/runner group و دسترسی همین repository تأیید شود؛ فعال‌سازی Enterprise خودکار این دسترسی را ثابت نمی‌کند.
- نیاز مشخص منابع (RAM/disk/OS/ساعت اجرا) و retention/disposal تعیین شود.
- هزینه و سقف روشن شود. GitHub می‌گوید larger runnerها در private/public repositories همواره per-minute محاسبه می‌شوند و included minutes شامل آن‌ها نیست؛ free entitlement فرض نشود.
- بدون تأیید روشن هزینه، larger runner هزینه‌دار راه‌اندازی/مصرف نشود. برای این جلسه نیازی به این هزینه نداریم.

منابع رسمی بررسی‌شده:
- https://docs.github.com/en/enterprise-cloud@latest/actions/concepts/runners/larger-runners
- https://docs.github.com/en/enterprise-cloud@latest/actions/reference/runners/larger-runners
- https://docs.github.com/enterprise-cloud@latest/admin/configuring-settings/configuring-private-networking-for-hosted-compute-products/configuring-private-networking-for-github-hosted-runners-in-your-enterprise
