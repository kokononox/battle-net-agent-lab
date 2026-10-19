# P12 — هماهنگ‌کنندهٔ بومی یکپارچه، فقط fixture و Domain غیرفعال
کتابخانهٔ qualification داخلی؛ **نه SSTP allowlist، نه Enable/Disable کاربر**. محدودیت fixture/Domain غیرفعال نباید برای تحویل محصول حذف شود.

## دامنهٔ تغییر
سه قانون از قبل stage شده، با یک Group و GUID معلوم: guard غیرفعال Block، old فعال Allow و new غیرفعال Allow. همه باید به همان executable ناموجودِ fixture مقید باشند؛ نام‌ها و Group دقیق آزمایش الزام می‌شود. فقط Enabled آن‌ها نوشته می‌شود. DefaultOutboundAction تنها Domain غیرفعال در PersistentStore، از stored=NotConfigured به Block و بالعکس، هدف است. COM و Get-NetConnectionProfile غیرفعال بودن Domain را کنترل می‌کنند. profile فعال/کل سیستم هدف نیست و هیچ قاعدهٔ قدیمی واقعی قرنطینه نمی‌شود.

## یک journal و یک frontier
برخلاف چسباندن سه API با سه journal مستقل، این موتور schema جدید P12، original سه raw rule/هفت filter، original هر شش profile و policy/strict seal همهٔ ruleها را در **یک journal P2** نگه می‌دارد. از primitives و comparatorهای P9/P11 استفاده می‌کند، نه mutation entrypointهای legacy P9/P10/P11. guard با همان native Enabled-only اصل P10 مدیریت می‌شود، نه با reset یا تایمر.

bits چهار resource (guard، old، profile، new) و origin/cursor/pending با replay یک plan ثابت اعتبارسنجی می‌شوند. baseline خارجی فقط سه label string/null حاضر P8 را معاف می‌کند؛ guard/new owned تماماً strict هستند. policyهای دیگر/هفت filter/unknown fields و profileها تحت مقایسه‌اند. ظرفیت۱MiB قبل از اولین mutation بررسی می‌شود. canary native NotConfigured→NotConfigured قبل از هر Block/Enable لازم است و موفقیتش در همین journal ثبت می‌شود.

Enable: guard on → old off → Domain Block → new on → ممیزی کامل تازه زیر guard → guard off.
Disable: guard on → new off → Domain original NotConfigured → old original on → ممیزی کامل تازه زیر guard → guard off.

Disable از Enable ناقص هم پشتیبانی می‌شود؛ ابتدا pending فقط exact-before/afterِ یک mutation را حل می‌کند، سپس plan بازگردانی از وضعیت معلوم جاری شروع می‌شود. پس از شروع Disable، Enable دوباره مجاز نیست. before/after setter با write-ahead و readback کامل resource همراه است. full inventory در ورود/recovery، بلافاصله پیش از آزادسازی guard و پیش از completion بررسی می‌شود. در طول عمل، تغییر resource نامرتبط ممکن است فقط در checkpoint بعدی تشخیص داده شود؛ guard تا گیت آزادسازی برقرار است.

یک journal خراب/گمشده، تغییر policy/ownership/membership یا profile نامعلوم هیچ reset/Force-Allow/adoption یا release خودکار ایجاد نمی‌کند. پایان کار یا خروج process گارد را خودکار برنمی‌دارد. read/check/set اتمیک نیست و قفل جلوی admin مستقل را نمی‌گیرد؛ full audit قبل از release، اثبات نبود race یا تغییر گذرا نیست. conflict تازه بعد از release هم تضمین خودکار re-block ندارد؛ resident/watchdog عمداً وجود ندارد.

## آزمون
۲۰ مدل before/after برای ده transition plan، هشت قطع process با recovery تازه شامل دو Disable مستقیم از Enable ناقص، دو conflict قبل از release (owned label و rule اضافه)، corrupt/missing journal در حالی guard held، idempotency/lock/capacity و full-frontier drift بررسی می‌شوند. دو pause اضافی برای آزمون گیت و journal خرابی هستند؛ بنابراین شمار خروج‌های73 عمداً۱۰ است، نه۸. هشت recovery اصلی با آن دو pause منفی یکی شمرده نمی‌شوند.

قواعد واقعی CI فقط executable ناموجود، مقصدهای مستندسازی و port65534 دارند؛ guard هم فقط همان executable را می‌پوشاند. Allow جدید **fixture است، نه قاعدهٔ مقید به SSTP**. no-op capability یک بار در Initialize بومی تأیید می‌شود؛ fixture harness برای caseهای بعد همان original و canary معلوم را بعد از ممیزی تازه به journal جدید می‌برد، نه اینکه policy جدید را adopt کند. journal خراب از مسیر محصول آزاد نمی‌شود؛ cleanup مستقل CI فقط تصاویر کامل شناخته‌شدهٔ همین fixtureها/Domain را برمی‌گرداند و بعد P8 همهٔ rule/filter/profileهای نامرتبط را می‌سنجد. این cleanup در فرآیند تست original معتبر دارد و مجوز recovery حدسی محصول نیست.

فقط receipt محدود و hash هشت فایل کد upload می‌شود؛ journal، raw inventory، نام شبکه/برنامهٔ خصوصی یا policy واقعی کاربر upload نمی‌شود. هیچ شبکهٔ probe، DNS، SSTP یا packet در این P12 تست نمی‌شود.

## مرز با محصول
هدف این مرحله هماهنگی native تحت یک frontier است، نه اجرای خواستهٔ نهایی کاربر. guard سراسری، default همهٔ profileهای فعال، همهٔ Allowهای واقعی، bootstrap محدود، binding سخت SSTP، GPO/effective rules، IPv4/IPv6/DNS/LAN، disconnect/reconnect/boot و no-leak هنوز qualified نیستند. لازم است coordinator واقعی با preflightها و backend مناسب SSTP طراحی/تست شود؛ صرف حذف gateهای CI محصول نمی‌سازد. ready_for_user_apply=false؛ دستگاه کاربر تغییر نمی‌کند؛ هیچ فایل اجرای کاربر تحویل نمی‌شود.
