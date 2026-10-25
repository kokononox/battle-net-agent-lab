# G45 — آزمون محدود سه دریافت مستقل

نتیجهٔ ثبت‌شده: هر سه درخواست واقعی404؛ هیچ payload تأیید نشد. این پوشه نه installer است، نه broker آنلاین آمادهٔ محصول و نه مجوز runtime.

plan.review-only.json سه شیء کوچک ثابت از G44 را با hash در pins.py پین می‌کند. source code فعلی پس از اجرای واقعی فقط به‌صورت آفلاین سخت‌گیرانه‌تر شد؛ نسخهٔ اولیه و تفاوتِ provenance در reports/sample-download-g45 ثبت شده‌اند. هیچ درخواست واقعی برای تست نسخهٔ نهایی تکرار نشد.

fetch_samples.py فقط Linux/POSIX پژوهشی، HTTPS با TLS عادی، URL ثابت، GET بدون query/body/cookie/auth و بدون proxy/redirect/retry را پشتیبانی می‌کند. session.started قبل از شبکه با CreateNew ساخته می‌شود. هر attempt سهمش را پیشاپیش مصرف می‌کند. داده فقط در فایل خصوصی0600 با suffix .bin ذخیره می‌شود و هیچ execution/load مسیر ندارد. خروجی بازاجرای محلی fetch-evidence.local.json است تا گزارش ثبت‌شدهٔ قبلی overwrite نشود. محدودیت‌های mode/owner محلی معادل backend Windows G40 نیستند.

برای اجرای آزمون‌های کاملاً آفلاین از ریشهٔ repo:

```bash
python analysis-tools/sample-download-g45/test_contract.py
```

اجرای آنلاین مجدد در این پوشه انجام نشود: سه attempt جلسهٔ ثبت‌شده مصرف شده‌اند؛ ساخت session پژوهشی تازه تصمیم صریح دیگری است. marker محلی ضد replay سراسری یا محصول نهایی نیست. کلون تازه marker همان ماشین را ندارد و نبود marker مجوز تکرار خودکار پژوهش نیست.

codec.py نسخهٔ خالص و بدون تغییر G44/G43 است. fixture آزمون BLTE مصنوعی است و با payload واقعی Battle.net اشتباه نشود. next-index-plan.unexecuted.json صرفاً metadata آینده است؛ این کد آن را اجرا یا به allowlist اضافه نمی‌کند. نتیجه و محدودیت‌ها در RESULT.fa.md آمده‌اند.
