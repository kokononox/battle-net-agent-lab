# نتیجهٔ اتصال حداقلی بدون hook: b3

## هویت اجرا

- source: 017b1312c2356e3ebe529125fbb45b43a9d0d12e
- run: 40441779071
- evidence: eb71038f9f92ec8ba38d8eac9d1510b34b18ae5e
- محیط: Windows 2025 تازهٔ GitHub-hosted، شاخهٔ تحقیق و attempt اول.
- نصب dependency ثابت Frida 17.24.2، آزمون‌ها، observation و sanitization همگی success.

## نتیجهٔ واقعی

هر دو fixture بومی C++ در x64/x86 با Popen عادی اجرا شدند؛ اتصال، پیام readiness، بیت‌بودن و تأیید هویت تصویر پیش و پس از اتصال موفق بود. exit هر دو صفر و message_errors هر دو صفر بود. به همین دلیل گیت اجازهٔ شروع هدف را داد.

bootstrap با همان SHA pin اجرا شد و اتصال حداقلی فقط به آن موفق بود: target_attach.status=ready، pointer_bits=32، identity پیش/پس تأیید و message_errors=0. تنها اسکریپت، پیام readiness ثابت بود؛ registry/network hook، Frida spawn یا child gating در این آزمایش درخواست نشد. خود attach همچنان بارگذاری کد ابزار در فرایند است؛ این مرحله برخلاف b2 «بدون تزریق» نیست.

پس از اتصال، helper زبان ادامهٔ موفق داشت و outcome_uncertain=false بود. snapshotهای محدود هم battle.net-setup.exe و هم agent.exe را مشاهده کردند. به خود Agent attach نشده است؛ بنابراین «Agent مشاهده شد» نباید «Agent instrument شد» خوانده شود. تکمیل نصب، ورود حساب یا تلمتری این اجرا اثبات نشده است.

۳۰ sample و دو snapshot GUI نگه داشته شد. در هر دو snapshot، window station قابل‌مشاهده و input desktop قابل‌دسترسی بود؛ فرایندهای بررسی‌شده هم‌session، probe_errors=0 و enumeration_truncated=false بودند. بوت‌استرپ در ۳۱ poll پیش از cleanup در حال اجرا بود. شمار poll با sample اصلی یکسان نیست، چون snapshot قبل از cleanup نیز poll دارد.

## چیزی که اکنون محدودتر شده است

کنترل b2 بدون Frida به Agent رسید؛ b3 با Popen عادی + attach حداقلی به bootstrap نیز به Agent رسید. پس در این نمونه، attach سادهٔ Frida مانع پیشروی نشده است. این داده با ادعای مطلقِ «با هر حضور Frida، این bootstrap پیش نمی‌رود» سازگار نیست.

علت شکست a12d هنوز مشخص نشده: آن مسیر Frida spawn، child gating و ترکیب hookهای رجیستری/شبکه داشت. این کنترل مجموعهٔ آن متغیرها را جدا نکرده و روی همان ماشین نبوده است؛ ضد-Frida بودن یا نبودن همهٔ نسخه‌ها، bug دقیق یا اثر هر hook ثابت نشده است.

## مرز شواهد

این مرحله شبکهٔ plaintext یا capture ندارد؛ network_payload_observed=false. پیش از login، Install یا دانلود بازی هیچ اقدامی درخواست نشد. خودِ launch ممکن است ترافیک عادی داشته باشد؛ این گزارش ادعای نبود ترافیک ندارد. UUID/هش UUID، متن UI، مسیر، PID/session ID، باینری یا capture خام منتشر نشده است.

اتصال پس از Popen است و process_birth_coverage=false؛ در نتیجه داده‌های ابتدای فرایند پوشش ندارند. readiness اتصال تنها همان لحظه را نشان می‌دهد، نه تضمین پوشش پیوسته تا cleanup. هیچ ادعای provider assignment، یکتایی نصب، reboot/reinstall، ذخیره‌سازی سرور یا نشان‌گذاری فایل WoW اضافه نشده است. شواهد a11 محفوظ و سؤال دوم همچنان در صف است.

## گام بعدی، هنوز اجرا نشده

روی همین الگوی Popen موفق، registry-only اضافه شود؛ wire hook و child gating همچنان خاموش بمانند. هدف آن مرحله ابتدا سنجش ادامهٔ startup و مشاهدهٔ کلید ثابت UserUUID است؛ نه ادعای ارسال آن روی شبکه. برای خواندن Agent یا اتصال دادهٔ رجیستری به payload شبکه، مشاهدهٔ جداگانه با identity/pin و گیت بومی لازم است. در زمان ثبت، b3 پایان یافته و مرحلهٔ registry-only هنوز شروع نشده است.
