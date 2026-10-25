# بازیابی گزارش در صورت BlobNotFound

این مسیر فقط خواندن گزارش همان run/job مجاز است؛ policy رانر، شرایط بازیابی یا مجوز شبکهٔ هدف را تغییر نمی‌دهد.

1. هویت source commit و run را از API/صفحهٔ همان اجرای مجاز ثبت کنید. نام/source/schema دلخواه نسازید.
2. ابتدا artifact و raw job log را با ابزار رسمی بخوانید. اگر raw BlobNotFound شد، نبود blob را به معنی نبود شواهد اجرای برنامه تعبیر نکنید.
3. در مرورگر احرازشدهٔ GitHub، صفحهٔ همان job را باز کنید. از عنصر check-step مربوط به مرحلهٔ مشاهده، مقدار موجود data-job-step-backscroll-url را بخوانید. URL را حدس نزنید یا برای job دیگری استفاده نکنید. در G29، این مقدار زیر همان repo/run/job بود.
4. درخواست فقط‌خواندنی همان URL را در همان مرورگر با Accept: application/json، X-Requested-With: XMLHttpRequest و GitHub-Verified-Fetch: true اجرا کنید. این headerهای ثابت، credential نیستند. cookie، token یا header احراز هویت را استخراج/چاپ/منتشر نکنید. fetch پیش‌فرض بدون headerهای viewer ممکن است400 برگرداند؛ این لزوماً نبود log نیست.
5. پاسخ را خصوصی در فایل بگذارید. ساختار lines و اعضای id/line را بررسی کنید؛ تعداد و اندازه را محدود نگه دارید (حداکثر4096خط و8MiB). فقط lineها را به متن تبدیل کنید.
6. CollectReport.extract باید آخرین manifest کامل را با ترتیب/تعداد بخش‌ها، اندازه، SHA-256، source commit، run و schema/فیلدهای مجاز تأیید کند. صرف قابل‌خواندن‌شدن prefix فشرده، شاهد کامل نیست. تا تطبیق همهٔ شروط، نتیجه را verified اعلام نکنید.
7. فقط JSON پاک‌سازی‌شدهٔ تأییدشده و provenance بدون header/URL امضاشده منتشر شود. log خام یا response مرورگر artifact کاربر نیست.
8. در source تعمیرشده، Reporter یک core-g29.json مستقل می‌سازد و همان capsule کوتاه را پیش و پس از گزارش بلند چاپ می‌کند. Core manifest/source/run/hash خودش را دارد. اگر فقط core قابل‌دریافت باشد، آن را critical receipt بنامید، نه گزارش کامل. hash گزارش کامل داخل core جای دریافت و اعتبارسنجی خود گزارش کامل را نمی‌گیرد.

## آنچه این تعمیر تضمین نمی‌کند
وجود backscroll در همهٔ وضعیت‌های GitHub، upload خودکار artifact در حالت quarantine، موفقیت بازیابی firewall یا آمادگی کامل فرم login تضمین نمی‌شود. این مسیر در همان G29 پیشین آزمایش و گزارش پایانی از آن بازیابی و تطبیق شد؛ نصب جدیدی برای امتحان آن اجرا نشد. در CI، job جمع‌آوری همچنان فقط token محدود actions:read خودش را دارد؛ cookie ورود مرورگر به CI منتقل نمی‌شود.
