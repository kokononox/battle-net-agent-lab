# مبنای ادامه پس از تطبیق تاریخچه

## هدف و اجزای قابل استفاده

هدف فعلی یک پروفایل برنامه‌محور فعال است: فایل‌های صریحاً انتخاب‌شده، مقصد/پورت تأییدشده و SSTP تازه‌بررسی‌شده؛ سایر برنامه‌ها حتی برای همان مقصدها مجوز ندارند. انتخاب EXE مجوز مقصدهای ناشناخته نیست؛ رصد فقط پیشنهاد می‌سازد. فرزند و سرویس خودکار مجاز نمی‌شوند. پروفایل اول نصاب Battle.net است.

RC 0.9.10 دورریختنی نیست: UI، ویرایش سیاست و تجربهٔ recovery آن ورودی قابل استفاده‌اند. program=Any مربوط به دامنهٔ قدیمیِ مقصد-محور بود؛ انتخاب بعدی کاربر آن دامنه را تغییر داد. نه خود RC و نه هستهٔ فعلی بدون یکپارچه‌سازی و بررسی بومی، محصول آماده محسوب نمی‌شوند.

## درس‌های الزام‌آور از اجرای واقعی قبلی

- اصلاحات HF1/HF1.1 و رسیدهای موفق Windows حفظ می‌شوند؛ آزمون موفق قبلی صرفاً برای تولید گزارش جدید تکرار نمی‌شود.
- Apply واقعی HF1.1 در arming با drift متوقف شد؛ recovery محدود همان نشست چهار owned غیرفعال را حذف و صد قاعده و سه پروفایل را بازگرداند. استثنای InterfaceAlias فقط حذف owned غیرفعالِ دقیقاً تأییدشده بود؛ مجوز enable یا relax عمومی نیست.
- مشاهدهٔ بعدی journal=restored همراه با پروفایل واقعی Block، دلیل ممنوعیت موفقیت صرفاً از روی journal است. تغییر صریح به normal Allow، بازگردانی دقیق baseline پیشین نیست. عامل تغییر مجدد Block اثبات نشده است.
- ترتیب transport قبل از quarantine، fresh per-object mutation/readback، حفظ guard و cleanup قابل‌بررسی باید بمانند. بهینه‌سازی با نمونه‌های محدود مجوز حذف بررسی کامل نیست.
- خطاهای quoting، PowerShell و ابزارهای آزمایشی از خطای خود محصول تفکیک می‌شوند؛ هزینهٔ رفع آنها دوباره به کاربر منتقل نمی‌شود.

مراجع پروژه: `docs/SESSION-UNIFIED-FIREWALL-2026-10-27.fa.md`، `windows-receipts/hf11-scoped-recovery.json`، `windows-receipts/hf121-parity-passed.json` و `normal-exit-runner-v01/evidence/Windows-profile-change-timeline.json` در همین شاخه؛ مسیرهای سه مورد آخر نسبت به پوشهٔ session هستند. فایل گفتگو، snapshot و مشخصات خصوصی در مخزن قرار نمی‌گیرند.

## نقطهٔ کد فعلی

همان coordinator، mixed backend، journal و collector قبلی ادامه می‌یابند. اتصال candidate ثابت و recovery-first تکمیل شده است؛ audit قبل از policy بازمی‌گردد، terminal policy معتبر لازم است و پس از callback سیاست، actor و مقدار واقعی audit نیز دوباره بررسی می‌شوند. true بازگشتیِ callback یا نبود pending به‌تنهایی موفقیت نیست. همهٔ این آزمون‌ها داخلی‌اند؛ اثر بومی Windows اجرا نشده است.

## ترتیب ادامه تا یک جریان قابل استفاده

1. ثبت پایدارِ actor/انتخاب هدف و شواهد محدود helper در همان journal پیاده شد؛ [شرح و محدودیت](DURABLE-RUNTIME-WITNESS.fa.md). این witness سابقهٔ کامل سرویس/فرایند نیست و اختیار restore نمی‌دهد.
2. probe مستقل و محافظه‌کارانهٔ quiescence؛ خطای دسترسی یا شواهد ناقص اجازهٔ بازگرداندن Allow نمی‌دهد. نبود فرایند در reader قدیمیِ skip-errors یا exitهای audit به‌تنهایی کافی نیست. وضعیت IPC/service attribution باید صریحاً محدود بماند.
3. اتصال actor/audit/exit-consent به recovery بومی و همان ورودی/UI؛ pending قبل از picker و بررسی VPN دیده شود. recovery به EXE/VPN فعلی وابسته نشود.
4. سنجش و اصلاح هزینهٔ reader/lease برای تعداد قواعد واقعی، بدون تضعیف guard؛ سپس یک اعتبارسنجی هدفمند Windows برای جریان واحد.

نسخهٔ اول فقط SSTP ازقبل‌وصل‌شده است. reconnect/cold-start/reboot و نصب کامل Battle.net هنوز تأیید نشده‌اند. تا تکمیل موارد بالا `ready_for_apply=false` است؛ grant برنامه، ZIP عمومی Apply یا درخواست diagnostic دستی تازه نداریم. موفقیت‌های storage/prepare/reopen/candidate/inventory ویندوز محفوظ‌اند، اما جای qualification این اتصال اجرایی را نمی‌گیرند.
