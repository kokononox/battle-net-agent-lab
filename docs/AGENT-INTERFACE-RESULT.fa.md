# نتیجهٔ واقعی رابط Agent بدون حساب

## نتیجهٔ تأییدشده

روی Windows hosted تازه، Agent امضاشدهٔ Blizzard راه افتاد. دقیقاً یک `GET /agent` محلی پاسخ HTTP 200، JSON object به طول 331 بایت و فیلد authorization رشته‌ای غیرخالی برگرداند. ورود حساب انجام نشد؛ مقدار توکن و پاسخ خام صادر نشدند.

- source آزمایش: `1f8c3803ec96e1e60d673a4d53bbc10357282343`
- run: `39098949663`؛ attempt: `1`
- [رسید ثابت](https://github.com/kokononox/battle-net-agent-lab/blob/90e4b8ea5dcda8a27daa8557e481053762f25521/reports/agent-interface-latest.json)
- [کد اجراشده](https://github.com/kokononox/battle-net-agent-lab/blob/1f8c3803ec96e1e60d673a4d53bbc10357282343/agent-interface-lab/probe.py)
- [اجرای Actions](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39098949663)

رسید از نظر schema، source commit، run identity، تعداد یک درخواست و پرچم‌های scope با کد همان اجرا دوباره تطبیق داده شد. status=`handshake_token_observed`؛ امضا/ناشر فایل، مسیر فرایند و مالک listener تأیید شدند. listener به loopback bind بود.

این شاهد دریافت توکن ارتباط محلی بدون ورود حساب در همین مسیر/نسخه/محیط است. از آن، اعتبار token برای درخواست بعدی، نصب کامل Battle.net، موفقیت آپدیت بازی، سیاست Retail یا انتخاب معماری وابسته به Agent نتیجه گرفته نمی‌شود. `game_update_without_login_proven=false` و `retail_policy_proven=false` باقی ماندند. هیچ install/update/repair endpoint درخواست نشد.

## گام بعدِ مشخص

در [سورس community بررسی‌شده](https://github.com/Ghostopheles/bnet-toolbox/blob/d4956d9aa3eaa858b1d2606093298c066ec8a2b7/bnet_toolbox/tools.py)، تابع `get_install_summary` از `GET /game` با authorization محلی برای مشاهدهٔ فهرست نصب‌ها استفاده می‌کند. این شاهد سورس است؛ هنوز در Agent این آزمایش اجرا نشده. گام بعدی مناسب، آزمایش همین یک درخواست مشاهده‌ای در VM بدون حساب/بازی و صدور فقط status/type/count، با token صرفاً در حافظهٔ همان اجراست. خطای 401/403 به درخواست حساب یا دورزدن احراز هویت تبدیل نمی‌شود.

port scan، اطلاعات hardware، پیش‌فرض کشور، product initialization و فرمان‌های install/update/repair همان منبع به آزمایش ما منتقل نشده‌اند. private بودن رابط و کنترل side effect همچنان باید در نظر گرفته شود.

پس از اثبات رابط مشاهده، محصول/branch و build دقیق برای آزمایش واقعی انتخاب و حجم معتبر دانلود، حجم نصب، staging و baseline قدیمی قابل‌استفاده مشخص می‌شوند. نصب تازهٔ Classic جاری، آزمایش آپدیت نسخه‌به‌نسخه نیست. هیچ Classic برای دانلود انتخاب یا مجاز نشده است. موفقیت Classic هم شاهد کامل سیاست Retail نخواهد بود.

## فضا و دامنه

فضای آزاد گزارش فقط volume شامل `RUNNER_TEMP` است؛ نه همهٔ دیسک‌ها و نه الزاماً volume نصب Agent. این عدد تضمین فضای runner بعدی یا جا شدن بازی نیست. [مشخصات عمومی GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) جای سنجش مقصد واقعی و نیاز build دقیق را نمی‌گیرد. صفحهٔ رسمی Classic Era در بررسی عمومی فقط loading برگرداند؛ حجم فعلی آن تأیید نشد و عدد تاریخی جایگزین نشد.

فایل نصب کاربر باز نشد، بازی دانلود نشد، token/log/binary آپلود نشد و کپی نصب 130 گیگی لازم نبود. خود راه‌انداز و Agent در VM موقت شبکه و نوشتن state داشته‌اند؛ سقف سخت شبکهٔ فرزند ادعا نمی‌شود. فعلاً برای تحقیق رابط مشاهده، اقدام یا اطلاعات ورود کاربر لازم نیست.
