# آماده‌سازی واقعی QEMU و رسانهٔ رسمی Windows، بدون بوت مهمان

## دامنه

روی runner لینوکس موقت GitHub، attempt اول، شاخهٔ تحقیق و commit دقیق d3 انجام می‌شود. این مرحله سیستم‌عامل مهمان را بوت/نصب نمی‌کند، EULA نصب را نمی‌پذیرد و Battle.net را اجرا نمی‌کند. هیچ ورود حساب، reboot میزبان، تغییر TLS یا permission دستگاه KVM ندارد.

## پاک‌سازی محدود میزبان موقت

فقط ریشه‌های ثابت ابزارهای غیرلازم runner حذف می‌شوند و فقط تا رسیدن به headroom دست‌کم 32 GiB:

- `/usr/local/lib/android`
- `/usr/share/dotnet`
- `/usr/local/.ghcup`
- `/opt/ghc`
- `/usr/share/swift`
- `/opt/hostedtoolcache/CodeQL`
- `/usr/local/share/powershell`

اگر مسیر symlink باشد، resolve آن تغییر کند، یا با workspace هم‌پوشانی داشته باشد، حذف نمی‌شود. این پاک‌سازی روی سیستم شخصی یا runner ماندگار نیست. مسیر دلخواه ورودی، خانهٔ کاربر، فایل مخزن، Python و credential حذف نمی‌شوند. اگر فضا کافی نشود، مرحله متوقف می‌شود؛ به پاک‌سازی عمومی یا تغییر آستانهٔ پنهانی متوسل نمی‌شود.

## ابزار و رسانه

QEMU، qemu-utils، OVMF، xorriso و wimtools از مخزن استاندارد Ubuntu با بررسی معمول بسته‌ها نصب می‌شوند. خروجی خام apt و ابزارها فقط log موقت محلی است و artifact نمی‌شود.

منبع تصویر، لینک عمومی منتشرشده توسط [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025) است. لینک انگلیسی ISO در صفحه `linkid=2345730` دارد؛ HEAD عمومی به فایل Microsoft CDN زیر منتهی شد:

```text
26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso
Expected bytes: 8152356864
```

تنها HTTPS با اعتبارسنجی معمول گواهی و redirect به دامنهٔ Microsoft پذیرفته می‌شود؛ اندازهٔ فایل دقیقاً کنترل و SHA-256 کل دانلود محاسبه می‌شود. این hash **محاسبهٔ خود آزمایش** است، نه ادعای انتشار checksum توسط مایکروسافت. هیچ فرم ثبت‌نامی با مشخصات حدسی پر نمی‌شود و account یا activation ساخته نمی‌شود. استفادهٔ مجاز از Evaluation جایگزین مجوز تولیدی نیست؛ این مرحله صرفاً دریافت/بررسی رسانه است و پذیرش EULA نصب انجام نمی‌شود.

install.wim فقط در پوشهٔ موقت استخراج، XML متادیتای محدود آن خوانده و سپس نسخهٔ اضافی WIM حذف می‌شود. یک index یکتای `ServerStandardEval` با `INSTALLATIONTYPE=Server` و `ARCH=9` انتخاب می‌شود؛ Server Core را Desktop Experience فرض نمی‌کنیم. نام‌های آزاد و raw XML صادر نمی‌شوند.

## دیسک و QEMU

دیسک تازهٔ 64 GiB با فرمت qcow2 ساخته می‌شود؛ actual allocated bytes جدا گزارش می‌شود. QEMU با KVM، CPU میزبان، 2 vCPU و 4 GiB RAM، دیسک تازه و CD-ROM رسمی را attach می‌کند، اما با `-S` **پیش از اجرای CPU مهمان متوقف می‌ماند**. از QMP محلی query-kvm، query-status و query-block بررسی می‌شوند؛ سپس QEMU بسته می‌شود. رابط شبکه یا port forwarding در این مرحله وجود ندارد.

بنابراین وضعیت موفق فقط `prepared_paused_no_windows_boot` است. صفحهٔ Setup، بوت Windows، نصب، reboot مهمان یا ماندگاری UserUUID از آن نتیجه نمی‌شود.

## فایل‌ها و تکرارپذیری

ISO، WIM، qcow2، socket و log خام در پوشهٔ موقت همان job هستند؛ نه commit و نه artifact می‌شوند و پس از اتمام آماده‌سازی حذف می‌شوند. آماده‌شدن آن‌ها در این job به معنی باقی‌ماندن دیسک برای job بعد نیست. workflow نصب آینده باید همین آماده‌سازی را بازتولید کند و نصب/آزمون reboot را داخل **همان job**، با دیسک ثابت همان مهمان انجام دهد. hash و index ثبت‌شده امکان pinکردن رسانه در مرحلهٔ بعد را فراهم می‌کنند.

۳۰ آزمون قرارداد شامل انتخاب نسخه، XML غیرمجاز، symlink/هم‌پوشانی cleanup، headroom، منع رسانهٔ دیگر و منع ادعای بوت/reboot/ارسال هدف است. خروجی عمومی فقط whitelist از provenance، عددها و booleanهاست.

### اصلاح d2
اجرای d1 بعد از آزادسازی 41996992512 بایت (حدود 39.1 GiB) فقط به حد قراردادی 40 GiB نرسید و پیش از apt/download متوقف شد. حد آماده‌سازی به 32 GiB اصلاح شد: ISO حدود 7.6 GiB، WIM استخراج‌شده حداکثر در حد ISO، دیسک خالی sparse و ابزارها. این حد تأیید ظرفیت برای نصب ویندوز نیست؛ مرحلهٔ نصب به سنجش مستقل فضا نیاز دارد. مسیرهای مجاز حذف و ممانعت از دسترسی به workspace تغییر نکرده‌اند.

### اصلاح d3
در d2 کل ISO با اندازهٔ مورد انتظار دانلود شد و SHA256 برابر `7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51` ثبت شد؛ این هش محاسبهٔ آزمایشگاه است، نه چک‌سام منتشرشدهٔ مایکروسافت. مرحلهٔ metadata با خطای کلی متوقف شد، پس تعیین علت دقیق از آن خروجی ممکن نیست. در d3 استخراج تک‌فایل install.wim با 7z (پشتیبانی UDF، تطبیق نام غیرحساس به حروف) جایگزین شد؛ اندازهٔ خروجی محدود و خطاهای استخراج/XML command از parser جدا شدند. هش ISO به نمونهٔ d2 پین شد. هیچ تغییر TLS یا انتشار لاگ خامی انجام نمی‌شود.

### d4: تشخیص شکست مسیر CI
نبود گزارش متناظر d3 نتیجهٔ اجرای آن نیست. d4 یک رسید آغاز با source/run، outcome محدود آزمون/prepare/sanitize و انتشار حتی در صورت failure اضافه می‌کند. timeout مرحلهٔ prepare برابر 22 دقیقه و کمتر از timeout job است تا فرصت ثبت نتیجه بماند. هیچ محیط، exception متن‌آزاد یا لاگ خصوصی منتشر نمی‌شود. مجوز write فقط در jobهای انتشار با checkout معتبر و guard commit است؛ prepare همچنان read-only و بدون credential باقی می‌ماند.

### d5: تشخیص استثنای خارج از خروجی معتبر
d4، run 40158164765، source debea6e3d644a0fc169810bea3d9f74c5be22dfe: tests success، preparation failure، sanitization failure. در نتیجه وجود خروجی معتبر آماده‌سازی تأیید نشد و علت دقیق هنوز معلوم نیست. wrapper جدید فقط stage/type/reason از enum ثابت و شمارهٔ خط کد را گزارش می‌کند؛ متن exception، traceback و محیط منتشر نمی‌شوند. در استثنا، خروجی ناقص دور ریخته و fallback صریح stopped ساخته می‌شود، نه موفقیت مصنوعی.
