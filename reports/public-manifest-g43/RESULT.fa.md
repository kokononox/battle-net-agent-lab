# G43 — manifest عمومی واقعی پیدا و بدون اجرای نصاب بررسی شد

## نتیجه
برای ProductCode=bna کشف‌شده در bootstrap رسمی G42، دو درخواست ثابت HTTPS به سرویس رسمی موفق شدند:

```
https://us.version.battle.net/bna/versions
https://us.version.battle.net/bna/cdns
```

نسخهٔ snapshot ردیف عمومی us برابر2.53.6.17952 و BuildId=17952 بود. انتخاب us یک انتخاب ثابت پژوهشی بود، نه خواندن منطقه یا اطلاعات سیستم کاربر. سرویس، ردیف‌های عمومی سایر مناطق را هم برگرداند؛ همه به‌صورت داده حفظ شدند. v2 fallback در کد هست اما در این اجرای موفق فراخوانی نشد.

از ردیف cdns، مقصد HTTPS با نام us.cdn.blizzard.com به‌صورت صریح انتخاب شد. این نام خارج از گیت تاریخی دو میزبان است؛ فقط در فرآیند پژوهشی استفاده شد و به محصول یا firewall اضافه نشد. HTTP به HTTPS روی همان hostname به‌طور فرضی تبدیل نشد؛ HTTPS این سرور در metadata رسمی اعلام شده بود و در دریافت واقعی هم با TLS معمول معتبر پاسخ200 داد. queryهای maxhosts/fallback از رشتهٔ Servers کپی یا ارسال نشدند.

## زنجیرهٔ محتوای قابل بازتولید
| شیء | اندازهٔ دریافت‌شده | بررسی انجام‌شده |
| --- | --- | --- |
| versions |1129بایت |PSV معتبر، snapshot SHA-256 |
| cdns |1441بایت |PSV معتبر، snapshot SHA-256 |
| BuildConfig |853بایت |MD5 محتوای خام برابر کلید نسخه، snapshot SHA-256 |
| CDNConfig |4226بایت |MD5 محتوای خام برابر کلید نسخه، snapshot SHA-256 |
| ProductConfig |38805بایت |MD5 محتوای خام برابر کلید نسخه، JSON فقط به‌عنوان داده |
| encoding |62245بایت encoded؛62068بایت decoded |BLTE EKey، checksum هر chunk، CKey محتوای decoded، SHA-256 و اندازه‌ها |
| install |123288بایت encoded؛125951بایت decoded |همان بررسی‌های BLTE؛ سپس parse کامل IN |
| download |21256بایت encoded؛23418بایت decoded |همان بررسی‌های BLTE؛ سپس parse کامل DL |

BuildConfig اعلام می‌کند build-uid=bna و build-product=Phoenix. کلیدهای دو‌تایی encoding/install/download و اندازه‌های encoded/decoded بدون جابه‌جا فرض‌کردن معنای آن‌ها استفاده شدند. برای EKey در BLTE دارای chunk table، hash header+table و برای chunkless کل فایل encoded بررسی می‌شود؛ علاوه بر آن chunkها و CKey decoded بررسی شدند. SHA-256 بایت واقعی هر دریافت هم جداگانه ثبت شده است. MD5 محتوایی و HTTPS، جای امضای مستقل publisher بر کل manifest را نمی‌گیرند؛ امضای bootstrap از G42 به payloadهای این فهرست تعمیم داده نشده است.

## فهرست‌های واقعی، نه حدس از نام دامنه
- IN دارای1157ردیف نصب با نام فایل، CKey و اندازهٔ decoded است.
- DL دارای954ردیف با EKey، اندازهٔ encoded، اولویت و tagهاست.
- tagهای Windows، OSX، زبان‌ها و Volatile وجود دارند و maskهای کامل حفظ شده‌اند.

این اعداد مربوط به دو نوع فهرست متفاوت‌اند و «تعداد فایل‌های لازم برای Windows» نیستند. هنوز platform/language/tag policy اعمال نشده است. encoding با صحت بایتی و signature=EN دریافت و decode شده، ولی جدول نگاشت CKey↔EKey آن هنوز parse/join نشده است. بنابراین1157نام نصب را خودکار به954آدرس دانلود نگاشت نکرده‌ایم. همهٔ URLهای payload، اندازهٔ نهایی مجموعه، منابع archive/range، root/patch و وابستگی Agent هنوز اثبات نشده‌اند. manifestهای bna کل زنجیرهٔ نصاب و محصول agent را پوشش نمی‌دهند.

هشت درخواست واقعی صرفاً metadata عمومی بودند؛ هیچ entry از فهرست دانلود، فایل اجرایی، Agent، بازی، login یا telemetry دریافت/اجرا نشد. در ProductConfig دستورهای نصب/حذف وجود دارد، اما هیچ‌کدام evaluate یا اجرا نشده‌اند. نام فایل‌های manifest نیز به filesystem نصب نوشته نشده است.

## خروجی‌های ثبت‌شده
- discovery.json و configs.json: پاسخ‌های عمومی و parse نسخه/CDN/config.
- manifest-objects.json: آدرس دقیق سه manifest، اندازه، EKey/CKey، SHA-256 و نتیجهٔ بررسی‌ها.
- install-manifest.json و download-manifest.json: فهرست کاملِ parseشدهٔ snapshot؛ نه برنامهٔ دانلود تأییدشده.
- public-fixtures.json: بایت‌های هشت پاسخ عمومی به‌صورت base64، بدون capture کاربر، installer یا payload؛ تست‌ها کاملاً آفلاین قابل بازتولیدند.
- metadata-pins.review-only.json: هشت pin پژوهشی با approval_state=pending_runtime_review. قالب عمداً catalog معتبر G37 نیست و promotion خودکار ندارد.
- runtime-catalog-unchanged.json: catalog خالی G37 و hash آن؛ خود فایل اصلی تغییر نکرد.
- offline-tests.txt: پانزده آزمون موفق با socket و opener شبکه ممنوع.

## کنترل‌های آزموده‌شده
آزمون‌ها hash/اندازهٔ fixtureها و lineage پاسخ‌ها، PSV/schema، کلید هر سه config، صحت BLTE و decode، parse کامل IN/DL، رد truncation/trailing/corruption، EKey نادرست، mode ناشناخته یا encrypted/recursive، zlib expansion، نام نصب نامطمئن، URL دارای query/credential/HTTP/مقصد telemetry، هدرهای ثابت و رد redirect را پوشش می‌دهند. همهٔ پانزده آزمون محلی و آفلاین‌اند؛ هیچ CI بومی یا نصب جدید در G43 ادعا نمی‌شود.

## حدود حریم خصوصی و ایمنی
درخواست‌ها توسط کد پژوهشی ثابت بازسازی شدند؛ ورودی نصاب relay نشد. query، Cookie، Authorization، بدنه، device/client_id یا UUID کاربر وجود نداشت. Host و User-Agent ثابت و داده‌های پروتکلی معمول HTTPS/TCP همچنان ارسال می‌شوند؛ سرور IP و fingerprint شبکه/TLS محیط آزمایش را می‌بیند. این پروژه وعدهٔ «دانلود بدون هیچ بیت خروجی» یا ناشناس‌سازی مطلق نمی‌دهد.

فهرست hostnameهای metadata، دستور یا مجوز نیست. به لینک‌های ناشناختهٔ config، telemetry، HTTP یا URLهای دارای query رجوع نشده است. Allowlist فایروال، CA، TLS/revocation، Windows task، main و Unified Firewall Desktop0.9.10 تغییر نکردند. نصاب همچنان دستی و مسئولیت نصب با کاربر است؛ این ابزار به installer خودکار تبدیل نشده است. تعداد resourceهای واقعی approved در broker هنوز صفر است.

پاسخ‌های نسخه زنده‌اند و می‌توانند عوض شوند. این نتیجه دربارهٔ snapshot ثبت‌شده است، نه تضمین «همیشه آخرین نسخه». parserهای پژوهشی فقط حالت‌های صریحاً پیاده‌شده را قبول می‌کنند؛ پشتیبانی عمومی همهٔ TACTها یا اعتبارسنجی کامل مسیرهای نصب Windows نیستند.

## قدم بعد
جدول encoding به‌صورت آفلاین parse و صحت pageها بررسی شود؛ سپس CKey فایل‌های نصب به EKey و اندازهٔ encoded نگاشت شود. معنای tagهای محصول، انتخاب Windows و زبان، و فایل‌های مشترک باید صریح و قابل آزمون باشد، نه union/intersection حدسی. بعد از آن فقط چند resource ضروریِ محتوایی می‌توانند برای بررسی محدودِ دانلود و pin بایتی نامزد شوند؛ هیچ HTTPS ناشناخته یا نام دامنهٔ عمومی مجوز خودکار نمی‌گیرد.

## منابع قالب و شواهد
دادهٔ نسخه و CDN از سرویس رسمی و config/manifest از CDN اعلام‌شده در همان داده دریافت شدند. راهنمای قالب ثالث صرفاً برای پیاده‌سازی parser استفاده شد، نه اعتماد یا مجوز شبکه:
- https://us.version.battle.net/bna/versions
- https://us.version.battle.net/bna/cdns
- https://wowdev.wiki/TACT
- https://gist.github.com/jleclanche/91f2f5c0f2042a81db1c61464ae6d459
