# تحویل آزمون فقط ذخیره‌سازی Windows — ۰٫۱

[راهنمای بسته](package/UFW-JOURNAL-STORAGE-01/README-FA.md) و [مشخصات ZIP](PACKAGE-SUMMARY.json).

سه module دقیقاً byte-identical با session-journal-v01 هستند. fixture مستقل هیچ real profile query، consent prompt، native real session store، legacy journal، rule/task/VPN/DNS/route را فراخوانی نمی‌کند. فقط توابع داده و فایل ژورنال و callback recovery حافظه‌ای استفاده می‌شوند. root جداگانهٔ disposable ProgramData با سه session ساختگی دارد؛ cleanup کل ساختار را پیش از هر حذف validate می‌کند و recursive نیست.

۳۶ assertion بسته و پاک‌سازی با فایل واقعی Linux و ۷۳ assertion ژورنال rerun شدند؛ پنج PS1/PSM1 و CMD parse و hash/pin payload تأیید شدند. Windows واقعی این بسته هنوز اجرا نشده است. مدل Linux نمی‌تواند root/file/lock ACL Windows را پاس‌شده اعلام کند؛ native flag و ACL flagها در simulation false می‌مانند و runner به native Windows flag نیاز دارد.

اقدام تازهٔ مجاز: فقط این ZIP جدید در پوشهٔ جدا، Run-Test.cmd با admin همان حساب، اینترنت/SSTP همان وضعیت؛ هیچ Apply/Restore/قطع‌و‌وصل یا تغییر Allow. فقط JSON جدید UFW-JOURNAL-STORAGE-01-*.json حتی failure برگردد؛ در cleanup failure تکرار/حذف خودکار نشود. هیچ فایل protected/backup/raw screen لازم نیست.

این milestone نه deployment engine است، نه consent برای ایجاد نشست واقعی، نه no-leak/reboot/original Restore qualification. نتیجهٔ واقعی Windows باید بعداً دریافت شود؛ علت Block تاریخی همچنان نامعلوم است.
