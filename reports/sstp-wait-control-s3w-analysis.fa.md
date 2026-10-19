# کنترل انتظار S3W — بدون تغییر شبکه

## نتیجهٔ ثبت‌شده
[اجرای 39193218810](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39193218810) روی standard windows-2025 با منبع `b13c46dd805e4db36dc2b060b8028222b1c32602` موفق شد. رسید: native_outcome=success، چهار فاصله انتظار کامل، elapsed_seconds=181، completed=true. مدت کل job در UI حدود ۳دقیقه و۱۰ثانیه بود. [رسید محدود](sstp-wait-control-s3w-39193218810.json).

Workflow فقط انتظار، پیام heartbeat ثابت، نوشتن JSON محدود و upload artifact دارد. checkout، credential، فرمان firewall/hosts/route/VPN یا دسترسی به دستگاه کاربر ندارد. پنج fixture محلی برای نویسنده رسید بررسی شد؛ جدا از شاهد واقعی انتظار است. digest ZIP دریافت‌شده با مقدار صفحه GitHub برابر بود: `e29c516bd9eaea53a29aaf6486769db5bfae510b5086e59635231abefc24f136`. source_commit و run_id نیز با اجرا برابرند. raw log، policy، registry و مشخصات سرور VPN منتشر نشدند.

## استنتاج مجاز و محدودیت
- در این اجرای کنترل، لغو عمومی/اجباری پس از حدود دو دقیقه مشاهده نشد. این شاهد با فرض سقف عمومی دو دقیقه‌ای برای همه jobها سازگار نیست.
- این نتیجه علت دو cancellation قبلی S3U را اثبات نمی‌کند. زمان، runner، checkout، workload و وضعیت فایروال با آن اجراها یکسان نیستند؛ A/B هم‌زمان یا تشخیص علت قطعی نیست.
- اثر موقت default-outbound Block بر ارتباط runner با GitHub یک فرضیه قابل بررسی است، نه نتیجه ثبت‌شده. خرابی provider، دخالت انسانی یا سیاست لغو خاص نیز از این شاهد اثبات یا کاملاً رد نمی‌شوند.
- S3U همچنان دو دور کامل روی همان VM ندارد. passed=false و ready_for_user_apply=false باقی‌اند؛ موفقیت انتظار به منزله موفقیت rollback، SSTP، enforcement یا Windows11 کاربر نیست.

## تمرکز بعدی، بدون گسترش دامنه
BAT۶ مبنای موجود است: در hosts، از فهرست ۲۵ نام، ۲۴ نام بسته و level3.blizzard.com بسته نشده؛ allowlist کل اینترنت نیست. بازآزمایی اکتشافی همه مقصدها لازم نیست. دامنه قبلی ایزولاسیون کل Windows و VPN داخلی SSTP با نام holand است، نه صرفاً یک برنامه. هیچ تغییر در BAT۶ یا اتصال کاربر داده نشد.

پیش از mutation دوباره، طراحی آزمایش باید از جهت زنده‌ماندن کانال کنترل CI بررسی شود. اگر استثنای شبکه‌ای فقط برای CI لازم باشد باید صریح، محدود، جدا از سیاست کاربر و با محدودیت اثبات آن مستند شود؛ موفقیت آن نباید اثبات ایزولاسیون کاربر معرفی شود. هیچ allow وسیع، تغییر baseline برای PASS یا حذف guard مجاز نیست. اجرای سومِ تغییر فایروال در این گام انجام نشد.

هدف بعدی همچنان طراحی fail-closed سازگار با holand روی مبنای BAT۶ است؛ شواهد S1 درباره Allowهای موجود و مسیر IPv6 باید در طرح لحاظ شوند. snapshot قبلی دسترسی زنده به دستگاه نیست و مرور زمان با حدس جبران نشود. فرمان تازه، Resume، BAT99 یا toggle کیل‌سوییچ برای کاربر لازم نیست؛ Pause و تنظیمات فعلی حفظ شوند.

تنها یک runner استاندارد Windows برای این کنترل استفاده شد؛ larger/paid runner فعال نشد و رایگان‌بودن سهمیه تضمین نشده است.

## مراجع
- [Workflow کنترل](https://github.com/kokononox/battle-net-agent-lab/blob/b13c46dd805e4db36dc2b060b8028222b1c32602/.github/workflows/sstp-wait-control-s3w.yml)
- [نتایج دو اجرای ناقص S3U](sstp-unset-s3u-analysis.fa.md)
- [دامنه SSTP ثبت‌شده](../docs/SSTP-ISOLATION-S1.fa.md)
- [شاهد S1 کاربر](sstp-preflight-s1-user-analysis.fa.md)
- [BAT۶](../plain-hosts-leave-one-open/06-All-Except-Level3.bat)
