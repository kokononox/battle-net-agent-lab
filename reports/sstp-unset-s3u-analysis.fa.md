# S3U — دو اجرای ناقص؛ انتشار رسید اصلاح شد، Apply ممنوع

## نتیجه و تصمیم
- اجرای اول `39190167936` با منبع `a60fde6c11c437e3b187d1e0cb0b5b8aa5c438f4` و اجرای تازه `39192387719` با منبع `51fd173698446377d29b1366cb5aa624348eb840` هر دو در `round_2_timer` لغو شدند. هر رسید تنها یک دور کامل دارد؛ `passed=false` و `ready_for_user_apply=false` باقی ماندند. این دو دور اول روی دو runner جدا جای شرط دو دور کامل روی همان VM را نمی‌گیرند.
- دور اول هر اجرا: سه baseline محلی NotConfigured، مشاهده سه Block، خروج driver با 73، تایمر SYSTEM با سه write، تطبیق stored/CIM/COM و مقدار/نوع/وجود valueها در هفت مسیر محدود registry، تطبیق ویژگی‌های منتخب rules، replay بدون write، TaskResult=0 و حذف task ثبت شده است. تعداد DefaultOutboundAction در مسیرهای بررسی‌شده ۰→۳→۰؛ این شاهد تمام registry یا WFP یا تمام ویژگی‌های rules نیست.
- وضعیت نهایی دور دوم و اجرای cleanup آن از رسید ناقص اثبات نمی‌شود. موفقیت دور اول به دور دوم یا دستگاه کاربر تعمیم داده نشود. Windows Server runner، build 26100، PowerShell 5.1.26100.33438 است؛ نه آزمون Windows11 کاربر و نه اثبات پشتیبانی مستند NotConfigured.

## علت لغو: هنوز نامعلوم
آرشیو لاگ هر دو اجرا خوانده شد. پیام موجود فقط `The operation was canceled.` است؛ خطای assertion یا عامل لغو در این لاگ‌ها ثبت نشده. نسبت‌دادن آن به کاربر، قطع شبکه، timeout یا نقص provider مجاز نیست. timeout تعریف‌شده job هشت دقیقه است؛ این به‌تنهایی علت لغو زودتر را مشخص نمی‌کند.

لاگ مرحله‌ای اجرای تازه، UTC:
- round_1_baseline: 02:57:52
- round_1_driver: 02:57:56
- round_1_timer: 02:58:01
- round_1_exact_state: 02:59:13
- round_2_baseline: 02:59:15
- round_2_driver: 02:59:16
- round_2_timer: 02:59:20
- cancellation: 02:59:38

## اصلاح محدود و شاهد آن
- شرط publish از فقط `needs.validate.result == 'success'` به `always() && needs.validate.result != 'skipped'` تغییر کرد. در اجرای تازه validate لغو شد ولی publish موفق بود و رسید را در شاخه آزمایشی ثبت کرد. این موفقیت انتشار است، نه PASS آزمون فایروال. انتشار در هر نوع force-cancel تضمین نشده؛ artifact مسیر پشتیبان است.
- checkout ناشر به source commit مقید شد؛ source_commit و run_id رسید قبل از commit با اجرای جاری تطبیق داده می‌شوند.
- فقط پیام‌های stage ثابت و timestamp به کنترل‌کننده اضافه شد؛ هیچ journal، path خصوصی، rule، policy یا registry خام به لاگ اضافه نشد.
- Core.ps1، Timer.ps1 و Driver.ps1، guardهای قبلی و assertionهای native بدون تغییر ماندند. تلاش جدید با commit-message یک‌بارمصرف s3u2 بود، نه Re-run با دورزدن gate.
- ۱۰ fixture محلی پایتون برای اعتبارسنج رسید و حالت‌های ردشدنی پاس شد؛ این آزمون مصنوعی و جدا از ۱۳ fixture native ثبت‌شده در رسید است و PASS runtime محسوب نمی‌شود.
- هش فایل artifact اجرای اول با digest صفحه GitHub یکسان بود. هش چهار فایل native هر دو رسید با محتوای همان source با line ending ویندوز CRLF تطبیق داده شد. لاگ خام، policy، registry و credential در مخزن منتشر نشده‌اند.

## معیار توقف و گام بعد
اجرای سومِ تغییر فایروال انجام نشد. پیش از تکرار، آزمون تشخیصی فقط‌انتظار با مدت مشابه و بدون تغییر firewall/network لازم است تا فرضیه محیط اجرا از رفتار آزمایش جدا شود؛ هنوز آماده یا اجرا نشده و نتیجه‌ای ندارد. اگر نیاز به شاهد runner بیشتری باشد، فقط diagnostic محدود و بدون اطلاعات خصوصی جمع شود. guardها حذف نشوند و baseline برای PASS تغییر نکند.

دستگاه کاربر تغییر نکرده؛ Apply آماده نیست. آپدیت Pause، WoW بسته و VPN فعلی حفظ شوند. BAT99، Enable/Disable کیل‌سوییچ و Resume لازم نیست. فقط runnerهای استاندارد windows-2025 و ubuntu-latest استفاده شدند؛ هزینه صفر تضمین نشده و larger/paid runner فعال نشده است.

## منابع
- [اجرای اول](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39190167936)
- [اجرای تازه](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39192387719)
- [رسید اول](sstp-unset-s3u-cancelled-39190167936.json)
- [رسید تازه](sstp-unset-s3u-cancelled-39192387719.json)
- [اصلاح کد و workflow](https://github.com/kokononox/battle-net-agent-lab/commit/51fd173698446377d29b1366cb5aa624348eb840)
- [انتشار خودکار رسید تازه](https://github.com/kokononox/battle-net-agent-lab/blob/af4ec6e9d18b67dd429b1d36f8ac6f3d3d181a37/reports/sstp-unset-s3u-build.json)
