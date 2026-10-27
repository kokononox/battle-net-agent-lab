# تشخیص فقط‌خواندنی علت رد Allowها

این بسته ادامهٔ توقف `ufw_runtime_unreviewed_allow_rules_no_launch` است. هیچ نصبی را اجرا نمی‌کند؛ فایروال، audit، DNS و VPN را تغییر نمی‌دهد؛ candidate، baseline و Security log را باز نمی‌کند. فقط از ActiveStore پروفایل‌ها و قواعد را می‌خواند و شمارش دسته‌های عدم‌تطبیق را برمی‌گرداند. **این ابزار نه مجوز اجرای نصب‌کننده است و نه بررسی کامل امنیت/نشت.**

## اجرا

1. ZIP را کامل در پوشهٔ محلی جدید و غیرپیوندی استخراج کنید.
2. با همان حساب Windows، `Run-Review.cmd` را با Run as administrator اجرا کنید. نیازی به انتخاب candidate یا اجرای نصب‌کننده نیست.
3. فقط فایل تازهٔ `UFW-ALLOW-REVIEW-01-*.json` کنار ابزار را برگردانید؛ حتی در خطا. screenshot، transcript، نام قواعد، مسیرها یا dump فایروال را ارسال نکنید.
4. هیچ قاعده‌ای را حذف/غیرفعال نکنید و VPN را تغییر ندهید. بسته READY ندارد و نتیجهٔ بدون mismatch نیز اجازهٔ اجرا یا Apply نیست.

## تفسیر شمارش‌ها

فقط قواعد Enabled=True، Direction=Outbound، Action=Allow بررسی می‌شوند؛ سایر قواعد در شمارش کل هستند، اما در mismatchها نیستند. معیار قبول **همان predicate نسخهٔ RUNTIME-CAPTURE-01** است، نه معیار امنیتی جدید: SstpSvc دقیق، svchost با مسیر دقیق SystemDirectory، TCP/6، فقط remote port443 و یک تا هشت IP صریح که فیلتر endpoint قبلی بپذیرد؛ بدون dynamic keyword.

| کلید | معنای عدم‌تطبیق |
| --- | --- |
| service_not_exact_sstpsvc | سرویس با SstpSvc دقیق برابر نیست |
| application_not_exact_system_svchost | مسیر با svchost اصلی دقیقاً تطبیق ندارد؛ معادل‌بودن مسیرهایی مثل متغیر محیطی بررسی نمی‌شود |
| protocol_not_tcp | پروتکل TCP یا مقدار6 نیست |
| remote_port_not_exact_443 | پورت مقصد دقیقاً یک مقدار443 نیست |
| remote_address_not_literal_ip | مقصدی مثل Any، subnet، range، keyword یا متن غیر-IP وجود دارد |
| remote_address_count_outside_1_to_8 | تعداد مقصدها خارج از محدودهٔ قبلی است |
| remote_address_excluded_by_runtime_predicate | دست‌کم یک IP طبق معیار قبلی حذف می‌شود، مانند loopback/link-local/multicast |
| dynamic_remote_keywords | قاعده مقصد dynamic keyword دارد |
| *_filter_cardinality | تعداد فیلترهای خوانده‌شده دقیقاً یک نیست |

یک قاعده ممکن است چند دلیل داشته باشد؛ **جمع reason_counts برابر تعداد قواعد ردشده نیست.** شکست خواندن فیلتر جدا با filter_reads_indeterminate ثبت می‌شود و نتیجه incomplete است؛ آن را به‌عنوان mismatch قطعی یا قاعدهٔ امن حساب نمی‌کنیم. تطبیق دقیق نیز اثبات هویت سرور VPN یا امنیت rule نیست.

این مشاهدهٔ چند دستور مستقل، اتمیک نیست و ممکن است قواعد هم‌زمان تغییر کنند. نام/ID/شرح قواعد، مسیر برنامه، IP، keyword و متن exception در گزارش ذخیره نمی‌شود؛ فقط شمارش ثابت و وضعیت‌ها ذخیره می‌شوند. خروجی تنها نوشتهٔ ابزار است؛ هیچ private backup یا journal ساخته نمی‌شود. bootstrap فقط همان سه فایل PowerShell داخل بسته را پس از بررسی هش Unblock می‌کند؛ RemoteSigned فقط برای process جاری است، بدون Bypass یا تغییر دائمی execution policy.

## اعتبارسنجی

منطق دسته‌بندی با predicate اصلی در۵۱۲ ترکیب و۱۸ حالت endpoint مقایسه شده و aggregation، خطای خواندن، عدم انتشار هویت و مسیر بدون اختیار اجرا آزموده شده‌اند. Windows PowerShell5.1 و cmdletهای بومی فایروال این نسخه هنوز در محیط توسعه اجرا نشده‌اند؛ آزمون‌های مدل روی Linux/PowerShell7 اجرا شده‌اند. شمارش نهایی آزمون‌ها در evidence/model-tests.json و اطلاعات بسته در PACKAGE-SUMMARY.json خارج ZIP است. هیچ آزمونی نشت‌ناپذیری سیستم را اثبات نمی‌کند.
