# نتیجهٔ بازکردن پیام واقعی StartAgent پیش از ورود

تاریخ: 2026-10-24. این گام تحلیل آفلاین شواهد موجود است؛ اجرای تازهٔ نصاب/ویندوز، dispatch workflow، تغییر CA/TLS یا ورود به حساب انجام نشده است.

## نتیجهٔ اصلی

**ادامهٔ تازه:** [ممیزی سایر پیام‌ها و شناسهٔ مشترک context](PRELOGIN-EVENTS-CONTEXT.fa.md): payloadهای Agent/TACT بیشتری باز شدند و یک UUID مشترک در پیام‌های Setup/Agent مشاهده شد؛ نوع و ماندگاری آن هنوز اثبات نشده است.

مشخصات سیستم در این شاهد فقط یک رشتهٔ CPU نیست. بدنهٔ خروجی رویداد `Blizzard.Telemetry.Distribution.Agent.StartAgent` در `POST /data` به `telemetry-in.battle.net` با تعریف Protobuf همان تصویر Agent باز شد. فیلدهای واقعی CPU، حافظه، مشخصات گرافیک، معماری و نسخهٔ OS در پیام حضور دارند. این نتیجه از **محتوای ثبت‌شدهٔ درخواست قبل از TLS** است، نه صرف وجود تعریف فیلدها در باینری یا لاگ محلی سخت‌افزار.

## زنجیرهٔ انتساب نسخه و محتوا

1. SHA-256 تصویر `Battle.net/Agent/Agent.9824/Agent.exe` در ZIP ارسالی با تصویر Agent صاحب درخواست H1 برابر است: `b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5`.
2. تعریف معتبر `Startup.proto` با package `Blizzard.Telemetry.Distribution.Agent` از offset بایتی `5307144` همان تصویر استخراج شد؛ طول `2774` بایت و SHA-256 آن `62dd014b30182602254cacc1d1a47b49e6a301b95963a107b1b3d1341ac936eb` است.
3. بدنهٔ multipart درخواست شمارهٔ `77` با اندیس صفر به بخش‌ها تفکیک شد. بخش شمارهٔ `4` با اندیس صفر، برچسب رویداد `StartAgent` دارد.
4. payload با کلاس پویای Protobuf ساخته‌شده از تعریف همان تصویر باز شد. در payload StartAgent هیچ فیلد ناشناخته‌ای نسبت به تعریف استخراج‌شده باقی نماند؛ این حکم شامل envelope/context و بقیهٔ پیام‌ها نیست.
5. CPU در مسیر شماره‌فیلد `4 → 1011 → 10` با پیمایش wire مستقل نیز کنترل شد؛ متن cpu_brand پس از حذف فاصله‌های انتهایی با CPU مرجع VM برابر است.

## فیلدهای واقعاً حاضر در پیام

| دسته | نام دقیق فیلدهای حاضر | آنچه می‌توان گفت |
| --- | --- | --- |
| CPU | hardware.cpu_arch، cpu_num_cores، cpu_speed، cpu_vendor، cpu_brand، cpu_hypervisor_vendor | معماری، تعداد گزارش‌شده، مقدار سرعت، سازنده/مدل و سازندهٔ hypervisor در بدنه هستند؛ واحد سرعت یا معنای منطقی/فیزیکی count از اسم فیلد حدس زده نمی‌شود |
| حافظه | hardware.memory | مقدار فیلد حافظه در پیام هست؛ مقدار آن با total_physical_memory_bytes مرجع OS دقیقاً برابر نیست |
| گرافیک | hardware.num_gpus؛ gpu_1 و gpu_2 شامل name، vendor_id، device_id، shared_memory، video_memory، system_memory، integrated | دو ورودی گرافیکی در این پیام ثبت شده‌اند؛ این الزاماً به معنی دو کارت فیزیکی نیست |
| سیستم‌عامل | real_os_version، os_arch | نسخهٔ واقعی گزارش‌شده و معماری OS حضور دارند |
| پیکربندی | region، igr، ipv6_support، wmi_enabled، database_type، download_limit، backfill_limit، crash_report_disabled | فیلدها واقعاً serialize شده‌اند؛ حضور boolean مساوی True بودن آن نیست |
| وضعیت Agent | running_agents.agent_count، phx_count، other_count، unknown_count، total_count، other_process_list | فیلدهای شمارنده حضور دارند. other_process_list در این نمونه رشتهٔ خالی است؛ از آن ارسال نام برنامه‌های دیگر نتیجه نمی‌گیریم |

فهرست دقیق مسیر، شماره و نوع فیلدهای حاضر در `reports/prelogin-startup-schema-audit.json` ذخیره شد. مقدار خام مشخصات دستگاه، شناسه‌های context، پیام خام و باینری در این commit منتشر نمی‌شود.

### کنترل ناسازگاری مقادیر مرجع

نام CPU تطبیق دارد، اما `hardware.cpu_num_cores` با `reference.logical_processors` و `hardware.memory` با `reference.total_physical_memory_bytes` برابر نیستند. عدد فیلد cores در پیام 1 و مرجع logical processors برابر 2 است. حافظهٔ پیام 8589934592 و مرجع OS برابر 8584425472 بایت است. این اختلاف‌ها در نتیجه پنهان نشده‌اند؛ بدون شاهد مستقل نمی‌گوییم علت حتماً physical/logical یا installed/usable memory است. وجود مشخصات در payload قطعی است، اما معنای دقیق اندازه‌گیری این فیلدها نیازمند بررسی پیاده‌سازی است. این مقادیر مربوط به VM آزمایش GitHub است، نه سخت‌افزار کاربر.

## سایر پیام‌ها و سؤال انحصاری‌بودن مقصد

در بدنه‌های همان نمونه، برچسب رویدادهای Bootstrapper شامل SessionGenerate، SessionUpdate، SelfPatch و InstallReport و رویدادهای Agent/TACT مثل VersionFetch و DownloadPerformance نیز دیده شدند. خواندن برچسب envelope به معنی schema-decode محتوای آن رویدادها نیست؛ نتیجهٔ ماشینی برای آن‌ها `payload_decoding=not_attempted` ثبت می‌کند.

از وجود پیام StartAgent در یک مقصد نمی‌توان انحصار همهٔ ارسال‌های مشخصات به آن مقصد را ثابت کرد. ingest.gdp.blizzard.com در capture کاربر هنوز محتوای قابل‌خواندن ندارد. OpenSSL/BoringSSL، HTTP/2، QUIC، فرایندهای خارج از پوشش و شناسه‌های context نیازمند بررسی جدا هستند. دادهٔ BIOS/شماره‌سریال در این StartAgent به‌عنوان فیلد تأییدشده گزارش نشده؛ نبود آن در این پیام، نبودش در همهٔ رویدادها یا مسیرها نیست.

## بازتولید و آزمون

نیازمندی: Python و کتابخانهٔ `google.protobuf`. ابزار باینری را فقط به‌عنوان bytes می‌خواند و هرگز آن را اجرا نمی‌کند. فقط تصویری که هش آن دقیقاً با تصویر صاحب درخواست برابر باشد مجاز به تفسیر پیام است. ورودی‌های حجیم، بدنهٔ ناقص، مرزهای نامعتبر wire/MIME و تعریف مبهم/تکراری رد می‌شوند.

```sh
python analysis-tools/prelogin-audit/decode_startup.py Agent.exe baseline-api.json result.json
python -m unittest discover -s analysis-tools/prelogin-audit -p 'test_*.py' -v
```

هشت آزمون تازهٔ مصنوعی محلی پاس شدند: تطبیق schema/حذف مقادیر خام، رد هش نابرابر، رد بدنهٔ ناقص، علامت‌زدن فیلد ناشناخته، رد تعریف مفقود/تکراری، مرزهای wire، مرزهای MIME و حفظ اختلاف مرجع. کنترل مستقل شماره‌فیلدها با پیمایش wire جداگانه نیز پاس شد. این‌ها اجرای تازهٔ ویندوز و پوشش کامل شبکه نیستند.

## منابع ثابت

- [ورودی خام H1](https://github.com/kokononox/battle-net-agent-lab/blob/27d065c1846b0a7be16fd38980511edffe6d6d04/reports/startup-ab-api-h1-baseline-api.json)
- [شرح دامنه و محدودیت H1](https://github.com/kokononox/battle-net-agent-lab/blob/27d065c1846b0a7be16fd38980511edffe6d6d04/reports/startup-ab-api-h1-analysis.fa.md)
- [نقطهٔ مشاهدهٔ EncryptMessage](https://github.com/kokononox/battle-net-agent-lab/blob/ac62d58f9b61f190f4a8279e185366bd27d1c377/privacy-ab-api/birth_hook.js)
- تصویر Agent از ضمیمهٔ خصوصی کاربر بررسی شد؛ این سند اجازهٔ انتشار ZIP یا capture خام نیست.

## ادامهٔ تحقیق

تفسیر schema-backed بقیهٔ پیام‌ها و context، سپس تکمیل پوشش APIهای فرایندهای صاحب اتصال. موفقیت EncryptMessage هنوز تأیید دریافت کاربردی یا ذخیره‌سازی سرور نیست. سؤال دوم و ابزار بررسی فایل‌های WoW همچنان در صف است.
