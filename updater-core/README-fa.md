# پیکربندی محصول متصل به نسخه — ۰٫۲۴

پیشرفت روی خودِ مرحلهٔ اول: ProductConfig دقیق snapshot تاریخی 12.1.5.70448 از دو آرشیو عمومی GitHub پیدا شد. فایل‌ها ۱۵٬۷۶۴ بایت و byte-for-byte یکسان‌اند؛ MD5 آن‌ها 53020d32e1a25648c8e1eafd5771935f است و با ProductConfig سطر EU در همان versions ذخیره‌شده تطبیق دارد. SHA256 هر دو 0909c89b6e5808a26791197dd722364d4b94d4b01ac64437b81bcde37d5c7519 است. این تطبیق هویت محتوایی است، نه امضای ناشر یا اثبات مستقل‌بودن دو آرشیو.

product_policy_facts.py ورودی byte محدود می‌گیرد: ابتدا SHA256 کل versions با target pinned، سپس Region/Version/BuildId/BuildConfig/CDNConfig و کلید ProductConfig همان سطر کنترل می‌شوند. JSON تکرار کلید را نمی‌پذیرد. محصول/چیدمان WoW Retail و نگاشت platform/architecture صریح باید شناخته‌شده باشد؛ زبان پشتیبانی‌نشده و alias چرخه‌ای یا مبهم رد می‌شود. نسخهٔ آینده در تست استفاده شده؛ کلید یا نسخهٔ تاریخی داخل منطق hardcode نیست. checkpoint قدیمی تفسیر تازه نمی‌شود؛ گزارش حقایق جدید جداگانه به bytes جدول و کلید config وصل است و مجوز اجرا به checkpoint اضافه نمی‌کند.

نگاشت enGB→enUS و زبان‌های دیگر به‌عنوان fact ثبت می‌شود، نه تغییر بی‌خبر ترجیحات. text/speech جدا می‌مانند و تغییر canonical نسبت به candidate، نیاز به بازبینی/replan را علامت می‌زند. تگ‌های platform.win و architecture خوانده می‌شوند. extra_tags فقط با منشأ all/platform/region/locale گزارش می‌شود؛ نبود declaration به معنای disabled بودن نیست. zhCN جای CN فرض نمی‌شود. install/uninstall/delete/registry/binary paths داخل config صرفاً دادهٔ inert هستند و هرگز اجرا/تفسیر نمی‌شوند.

اتصال به review_existing_candidate دوباره هویت target، بانک‌ها و metadata را کنترل کرده و روی متادیتای موجود اجرا شده است؛ candidate دست‌نخورده ماند. هیچ transport تازه، درخواست CDN، reader زنده، installer یا writer افزوده نشده است.

۲۶ تست جدید (۲۵ synthetic و یک fixture عمومی)، مجموع ۶۴۸ Linux و ۲۸۶ Windows/Python 3.12.10 با صفر failure/error/skip پاس‌اند؛ شمار پلتفرم‌ها جمع نشود. source و receipt در QA.json و reports/WINDOWS-PRODUCT-FACTS-CI-to-share.json ثبت شده‌اند.

**مرحلهٔ اول هنوز کامل نیست:** ProductConfig الگوریتم کامل feature/variant/dependency نیست؛ ترجیحات تازه و نسل فعال نصب هم اثبات نشده‌اند. required_set_selected=false، required_network_download_bytes=null و installation_ready/apply_authorized=false باقی‌اند. فعلاً از کاربر فایل، permission یا اجرای تازه‌ای لازم نیست.

[شواهد و نتیجهٔ منابع مستقل](research/PRODUCT-CONFIG-AND-SOURCES.md) · [حقایق متصل به candidate](reports/PRODUCT-CONFIG-FACTS-to-share.json) · [مقایسهٔ مدل‌ها](reports/INDEPENDENT-POLICY-SOURCES-to-share.json)

## سابقهٔ ۰٫۲۳

# ممیزی ابهام قواعد انتخاب — ۰٫۲۳

**مرحلهٔ اول هنوز باز است.** این بسته ابزار اثبات قواعد Battle.net یا اپدیتر قابل نصب نیست. هیچ ابزار جمع‌آوری زنده‌ای برای اجرا روی سیستم کاربر در این مرحله ارائه نشده است.

policy_ambiguity.py و policy_ambiguity_review.py فقط متادیتای کپی‌شدهٔ قبلاً بررسی‌شده و برنامهٔ نامزد را می‌خوانند. اصالت target/profile/hash، بانک‌ها و manifestها دوباره کنترل می‌شود. برای هر tag ویژگی چهار گروه متقابلاً جدا از عضویت candidate/tag، و دو نمونهٔ ابتدایی هر گروه غیرخالی ثبت می‌شود. شمار همهٔ رکوردها و membership نمونه‌ها با حلقهٔ مستقل per-ordinal کنترل شده؛ این استقلال محاسباتی است، نه شاهد مستقل قواعد vendor.

گروه‌های label تکراری Install و چندنمایشی بودن CKeyهای Install انتخاب‌شده هم بدون انتخاب variant/EKey بررسی می‌شوند. labelها متادیتای opaque هستند، نه مجوز استفاده به‌عنوان مسیر ویندوز. خروجی نمونه‌ها محدود و omittedها صریح‌اند؛ matching نمونه‌ها کامل‌بودن policy را ثابت نمی‌کند. گروه‌های tag مختلف ممکن است هم‌پوشان باشند و قابل جمع نیستند. untagged بودن هم به‌عنوان معنای انتخاب حدس زده نمی‌شود.

ممیزی هدف تاریخی 12.1.5.70448 با پروفایل عمومی Windows/x86_64/EU و enUS برای text/speech انجام شده؛ این پروفایل تازهٔ نصب کاربر نیست. candidateهای قبلی بدون تغییر ماندند. گزارش reports/POLICY-AMBIGUITY-to-share.json و قرارداد شاهد لازم research/POLICY-REFERENCE-PROTOCOL.md است. required_set_selected=false، active_generation_proven=false، required_network_download_bytes=null و installation_ready/apply_authorized=false باقی‌اند.

۲۷ تست تازه، مجموع ۶۲۲ تست Linux و ۲۶۰ تست واقعی Windows/Python 3.12.10 با صفر failure/error/skip پاس شدند؛ شمار پلتفرم‌ها جمع نشود. رسید در QA.json و reports/WINDOWS-POLICY-AUDIT-CI-to-share.json ثبت شده است. آزمون‌ها به هیچ بازی/CDN متصل نمی‌شوند. این ممیزی مجوز اجرای کلاینت رسمی، آپدیت، repair، scan، admin یا جمع‌آوری log/account نیست.

## سابقهٔ مرحلهٔ ۰٫۲۲

# بستن scope ناموفق و شروع صریح با سابقهٔ حفظ‌شده — ۰٫۲۲

این بسته سورس و تست پژوهشی است، نه اپدیتر قابل نصب. اجرای آن روی پوشهٔ بازی درخواست نشده است.

## تغییر تازه
درخواست pending که هنوز در journal مرحلهٔ داده commit نشده، اکنون می‌تواند فقط با تأیید صریح بازنشسته شود. SHA تمام قطعات قبلی تازه بررسی می‌شود؛ رسید تغییرناپذیر با نام ثابت نوشته و سپس marker بازنشستگی منتشر می‌شود. اگر داده commit شده ولی ledger عقب مانده، ابتدا reconciliation مرحلهٔ ۰٫۲۱ لازم است؛ این مسیر آن را دور نمی‌زند.

ادامه با دو API جدا برای صدور grant تازه و ساخت ledger جانشین است؛ هرکدام تأیید صریح می‌خواهد و هیچ‌کدام fetch یا step را خودکار اجرا نمی‌کند. nonce تازه از استفادهٔ مجدد هویت قبلی جلوگیری می‌کند؛ SHA سابقه در grant جدید pinned است. بودجهٔ مصرف‌شده پس داده نمی‌شود: شمار scope جدید جداست و شمار lifetime شامل تمام scopeهای قبلی می‌ماند. حذف/دستکاری رسید یا سابقه و grant قدیمی پذیرفته نیست.

سقف سابقه ۱۶ scope قبلی و هر رسید حداکثر ۲۵۶ KiB است. receipt موجود فقط در صورت برابری دقیق برای تکمیل صریحِ قطع قبل از marker پذیرفته می‌شود؛ lock رهاشده حذف نمی‌شود. این سابقهٔ مشارکتی امضاشده یا مقاوم در برابر مهاجم/rollback کامل نیست. فایل orphan اسکن، پذیرفته یا پاک نمی‌شود.

۳۳ تست تازه شامل چرخه و restore در دو process تازه، fault قبل/بعد انتشار، بودجهٔ انباشته، خراب‌شدن prefix/receipt، حذف سابقه، hardlink، سقف سابقه و سازگاری v1 است. ۵۹۵ تست Linux و ۲۳۳ تست واقعی Windows/Python 3.12.10 با صفر failure/error/skip پاس شدند. شمار پلتفرم‌ها نباید با هم جمع شوند. نتیجه و source commit در QA.json و reports/WINDOWS-SCOPE-CI-to-share.json ثبت شده است. هیچ دسترسی بازی، CDN بازی، admin، repair یا تغییر ACL انجام نشده؛ installation_ready=false و apply_authorized=false است.

مرز کامل: research/SCOPE-RETIREMENT-SAFETY.md. منطق محصول همچنان برای نسخه‌های بعدی است؛ 70448 فقط snapshot تاریخی pinned است.

## سابقهٔ مرحلهٔ ۰٫۲۱

# بازیابی محلیِ commit نیمه‌تمام — ۰٫۲۱

این بسته همچنان سورس و تست پژوهشی است، نه اپدیتر آمادهٔ نصب. هیچ ابزار آن برای اجرا روی نصب بازی درخواست نشده است.

## تغییر جدید
TransferController.reconcile_pending اکنون می‌تواند فقط با تأیید صریح، یک Range رزروشده را که در journal مرحلهٔ داده ثبت شده ولی تأیید ledger آن قطع شده، محلی بررسی و ثبت کند. هیچ fetch، retry، اعطای بودجهٔ تازه، تعویض target یا ادامهٔ خودکار انجام نمی‌شود.

همهٔ lockهای stage هنگام بررسی نگه داشته می‌شوند. journal قبلی از حذف دقیق همان یک segment و بازگرداندن وضعیت پیشین بازسازی می‌شود و SHA باید دقیقاً با ledger قبلی برابر باشد. journalهای دیگر، entityهای آرشیو مشترک و SHA همهٔ قطعات تازه کنترل می‌شوند. اگر شیء کامل شده، EKey/CKey و chunk checksum کامل هم دوباره بررسی می‌شوند؛ برای شیء ناقص full_object_verified=false می‌ماند. شمار رزرو درخواست و body تغییر نمی‌کند؛ پس از نتیجه، ادامه به restore صریح و همان Rangeهای باقی‌مانده نیاز دارد.

اگر داده در journal ثبت نشده، pending حفظ می‌شود و شبکه تکرار نمی‌شود. orphan، قطعهٔ اضافه، prefix خراب، source/target/baseline متفاوت، entity متعارض و lock رهاشده پذیرفته/پاک نمی‌شوند. توقف سخت داخل critical section ممکن است lock باقی بگذارد؛ بازیابی خودکار آن وجود ندارد. canonical نبودن journal قبلی می‌تواند باعث توقف امن شود. این قابلیت بازیابی عمومی هر قطع شبکه/برق نیست.

۲۶ تست جدید شامل بازیابی در process تازه، فایل ناقص و کامل، قطعهٔ دوم، منبع مشترک، فساد محتوا، fault قبل/بعد انتشار ledger و ثابت‌ماندن بودجه‌اند. ۵۶۲ تست Linux و ۲۰۰ تست واقعی Windows/Python 3.12.10 بدون failure/error/skip پاس شدند؛ ۲۶ تست جدید روی هر دو backend اجرا شده‌اند. اعداد دو پلتفرم قابل جمع به‌عنوان آزمون مستقل نیستند. رسید source dfb11f5e894e807e6559213fc4d484cf6a334b0d در reports/WINDOWS-RECONCILE-CI-to-share.json ثبت شد. installation_ready=false و apply_authorized=false تغییر نکرده‌اند؛ هیچ CDN بازی، admin، تغییر ACL یا نصب زنده استفاده نشده است.

## سابقهٔ مرحلهٔ ۰٫۲۰


این بسته سورس و تست پژوهشی است، نه اپدیتر آمادهٔ نصب. اجرای آن روی نصب بازی لازم نیست. دامنهٔ محصول همچنان مستقل از یک جفت نسخهٔ ثابت است.

## انجام‌شدهٔ ۰٫۲۰
- transfer_controller.py برای tuple حداکثر ۶۴ stage شناخته‌شده، با grant صریح به checkpoint/object/source و وضعیت اولیهٔ journal متصل می‌شود. برنامه در سقف حداکثر ۴۰۹۶ Range و ۴ GiB بایت body در هر grant کنترل می‌شود؛ این‌ها محدودیت عددی‌اند، نه آزمون واقعی تمام سقف یا مجوز دانلود این حجم.
- هر درخواست پیش از fetch در transfer.json رزرو و flush می‌شود؛ مصرف scope در restore صفر نمی‌شود. هیچ retry/redirect/اسکن/اعطای apply یا تغییر هدف خودکار وجود ندارد. ذخیرهٔ grant اجازهٔ شبکه نیست؛ restore به approved=True تازه نیاز دارد.
- بین Rangeهای commitشده، restore در process تازه آزموده شده است. قطع مبهم پس از reservation یا append ولی پیش از commit ledger عمداً pending باقی می‌گذارد و خودکار ادامه نمی‌دهد؛ بازیابی مجاز این حالت هنوز پیاده/qualify نشده است. هیچ pending/lock/orphan خودکار حذف یا پذیرفته نمی‌شود.
- strong ETag و total برای URL آرشیو مشترک بین اشیاء هم ثابت می‌مانند. قبل از resume، prefixهای موجود SHA-check می‌شوند؛ کامل‌شدن هر شیء و finish همهٔ محتوا را با verifier جریانی تازه می‌سنجند. baseline ورودی caller با pinned baseline برابر می‌شود؛ این به‌خودی‌خود اثبات freshness نصب زنده نیست.
- stream_http.py به کنترلر وصل است: Range دقیق، If-Range، status 206، URL، Content-Range/Length، ETag و total قبل از خواندن بدنه کنترل می‌شوند. هدر تکراری، Transfer-Encoding، فشرده‌سازی پاسخ، short body و تغییر entity توقف می‌دهند. read حداکثر ۶۴ KiB است؛ probe اضافهٔ EOF و retry نیست. شمارش body/reservation تضمین بایت فیزیکی TCP/TLS نیست.

## شواهد آزمون
۵۳ تست کنترلر/HTTP مصنوعی در هر دو backend اجرا شدند، از جمله چندشیء، Rangeهای فایل بزرگ‌تر از ۱ MiB، ادامه در process تازه، faultهای reservation/append، لغو، بودجه، تغییر baseline/target/source و entity مشترک. HTTP در این تست‌ها mock است؛ هیچ CDN بازی یا شبکهٔ localhost استفاده نشده است.

۵۳۶ تست Linux پاس شدند. اجرای واقعی Windows/Python 3.12.10 شامل ۱۷۴ تست با صفر failure/error/skip بود: ۷۳ portable، ۳۸ native stage، ۱۰ native admission و ۵۳ transfer. اعداد دو پلتفرم قابل جمع به‌عنوان تست مستقل نیستند. source d9f7c14e3c40e4bf3432dd7e7b5505773384c208؛ receipt 9ab5f617da43cfa5836cf7e527283844d0bece23. بسته بعد از تولید، استخراج، hash/CRC و تست می‌شود.

## مرز توقف
این نتیجه qualification تولیدی شبکه، قطع برق، native CASC writer/rollback/activation، سیاست رسمی انتخاب، نسل فعال نصب یا reuse محتوای نصب نیست. حجم ضروری دانلود null، installation_ready=false و apply_authorized=false باقی‌اند. هیچ دانلود تازهٔ بازی یا دسترسی به نصب اصلی، admin یا تغییر ACL انجام نشد. workflow مستقل Agent تغییر نکرده است.

کاربر Windows و فضای کپی آزمایشی دارد؛ فعلاً نیاز به کپی بازی نیست. برای policy یک جست‌وجوی عمومی هدفمند انجام شد: wowdev Alternate را censored content و مقدار 0x4000 توصیف می‌کند؛ این معنای Talebound یا policy انتخاب Agent را اثبات نمی‌کند. TACTSharp ابزار استخراج است و README آن اولویت tag را در TODO دارد؛ جای oracle نصب رسمی قرار نگرفت. گزارش research/POLICY-EVIDENCE-0.20.md مرز شواهد را ثبت می‌کند.

## سابقهٔ مرحلهٔ ۰٫۱۹


این بسته کد، تست و رسید پژوهشی است، نه اپدیتر آمادهٔ نصب. اجرای آن روی Windows یا پوشهٔ بازی لازم نیست. فایل‌های decoded بزرگ، بانک‌های SQLite و payload نمونهٔ بازی در این ZIP نیستند.

## تغییرات ۰٫۱۸: staging بومی Windows، بدون دسترسی به بازی
WindowsStore و WindowsStreamStage اکنون I/O بومی Windows را برای پوشهٔ scratch تازه و متعلق به برنامه پیاده‌سازی می‌کنند. مسیر ثابت محلی، هویت handle پوشه و والدها، رد reparse/offline/recall و hardlink، منع write/delete هنگام خواندن، فایل lock انحصاری، FlushFileBuffers و انتشار journal با MoveFileExW استفاده شده‌اند. هیچ اسکن پوشه، نصب بازی، درخواست CDN، admin یا تغییر ACL در این backend نیست. حفاظت در برابر پردازش مهاجم یا قطع برق واقعی ادعا نمی‌شود.

آزمون نخست Windows یک خطای واقعی یافت: handle صرفاً FILE_READ_ATTRIBUTES جلوی rename خود ریشه را نمی‌گرفت. درخواست FILE_LIST_DIRECTORY هم اضافه شد تا share checking اعمال شود؛ این درخواست به معنی enumerate کردن پوشه نیست. پس از اصلاح، اجرای واقعی Windows/Python 3.12.10 هر ۱۱۱ تست را با صفر failure/error/skip گذراند: ۷۳ parser/انتخاب و ۳۸ تست native scratch. رسید شکست نخست و موفقیت بعدی جدا نگه داشته شده‌اند. source commit نهایی 531f95f8ccae807d078efd2876c00f86fd54d0dd است.

۴۷۹ تست Linux هم پاس شدند؛ ۳۸ تست native آنجا اجرا یا به‌عنوان skip شمارش نشده‌اند. شمار Linux و Windows را به‌عنوان تست‌های مستقل جمع نکنید. تست native شامل restore/verify فایل مصنوعی بیش از ۶ MiB در پردازش تازه، hardlink/junction، guard پوشه و handle خواندن، تغییر محتوا/هدف/منبع، lock و قطع شبیه‌سازی‌شده است. آزمایش‌های synthetic هیچ محتوای بازی را مصرف نمی‌کنند.

### تغییرات ۰٫۱۹: پذیرش محدود ورودی staging بومی
stream_staged_reuse.py اکنون فقط دو نوع دقیق StreamStage و WindowsStreamStage را می‌پذیرد؛ object جعلی و subclass ناشناخته قبل از هر خواندن receipt رد می‌شوند. URI بانک read-only با Path.as_uri ساخته می‌شود تا مسیر Windows درست encode شود. انتخاب‌شدن full EKey، اندازهٔ encoded، full CKey و اندازهٔ decoded در بانک‌های pinned کنترل می‌شوند؛ سپس verify همهٔ segmentها و هویت BLTE را از نو می‌سنجد. metadata restore به‌تنهایی proof نیست.

ده آزمون synthetic SQL/Windows اضافه شدند: پذیرش سالم و restore، خرابی payload، تغییر target/catalogue، شیء انتخاب‌نشده، عدم اعطای apply از receipt، guard بسته، subclass ناشناخته و CKey نادرست حتی با hash receipt سازگار. اجرای واقعی جدید: ۱۲۱ تست Windows بدون failure/error/skip (۷۳ portable، ۳۸ native stage و ۱۰ native admission)، source 0da8bfdbec54f742f53f627e364997efd99b67cd. ۴۸۳ تست Linux پاس شدند. این اعداد روی پلتفرم‌ها قابل‌جمع به‌عنوان آزمون مستقل نیستند.

این اتصال فقط eligible_as_verified_staging_input می‌دهد، نه installed reuse، required set، اعتبار نسل فعال یا مجوز نصب. کنترلر انتقال شبکهٔ بزرگ/چندشیء، سیاست انتخاب رسمی، CASC writer/rollback/activation و UI نهایی آماده نیستند. native_windows_staging_backend_qualified=false به معنای عدم qualification تولیدی باقی است؛ installation_ready=false و apply_authorized=false تغییر نکرده‌اند.

کاربر وجود Windows و فضای کپی آزمایشی را تأیید کرده است؛ فعلاً کپی‌کردن بازی یا اجرای ابزار روی آن لازم نیست. workflow مستقل Agent دست‌نخورده است.

## سابقهٔ تغییرات ۰٫۱۷: پیشرفت مستقل از ابهام سیاست انتخاب
stream_blte.py یک عبور N/Z را با بلوک خواندن حداکثر ۶۴ KiB، checksum هر chunk، EKey و CKey و SHA encoded/decoded انجام می‌دهد. فایل decoded تولید نمی‌کند و کل payload را در RAM جمع نمی‌کند. header/table تا ۶۵۵۳۶ chunk محدود است؛ حد عددی parser برابر encoded حداکثر ۴ GiB و decoded حداکثر ۳۲ GiB است، نه تضمین آزمون همهٔ این اندازه‌ها و نه مجوز خواندن/دانلود. حالت E/F/ناشناخته بدون fallback رد می‌شود. نوع StreamObjectSpec جدید است؛ سقف و مجوز کلاس‌ها و ابزارهای قبلی بزرگ نشده‌اند.

stream_stage.py دادهٔ از قبل تأمین‌شده را در قطعات immutable حداکثر ۱ MiB و journal فاقد payload ذخیره می‌کند؛ هویت baseline/target/source، ترتیب قطعات، Range، ETag و اندازهٔ archive ثابت‌اند. restore فقط journal و هندسه را می‌سنجد و سلامت محتوا را ادعا نمی‌کند. verify همهٔ SHAهای قطعات و کل هویت محتوا را از نو و جریانی کنترل می‌کند. lock رهاشده شکسته نمی‌شود؛ orphanها پذیرفته/حذف نمی‌شوند. تست قطع شبیه‌سازی‌شده قبل/بعد journal وجود دارد، نه qualification قطع برق واقعی.

stream_staged_reuse.py هویت کامل این ورودی را به برنامهٔ نامزد و فهرست مقصد متصل می‌کند، بدون بازگرداندن raw/decoded payload و بدون مجوز نصب. transport جدیدی برای شبکه راه نیفتاده و هیچ scope قدیمی باز نشده است. اتصال فعلی append به ArchiveResponse تأمین‌شدهٔ caller است؛ کنترلر دانلود بزرگ/چندشیء و بازاعتباردهی سیاست هنوز تکمیل نشده‌اند.

### اجرای واقعی بدون شبکه
هر سه فایل متادیتای موجود پروژه با verifier جدید دوباره بررسی شدند: مجموع 251510113 بایت encoded، بزرگ‌ترین فایل 188062372 بایت. decoded SHA دقیقاً با رسید تأییدشدهٔ قبلی منطبق بود؛ فایل decoded تازه‌ای صادر نشد. نمونهٔ قبلی ۵۲ بایتی کشِ پروژه در staging جدید بازپخش و کامل کنترل شد. ETag این بازپخش marker محلی است، نه مشاهدهٔ تازهٔ CDN. هیچ نصب زنده یا payload آرشیو کاربر خوانده نشد.

### آزمون و مرز پلتفرم در مرحلهٔ ۰٫۱۷
مرحلهٔ قبلی ۴۷۶ تست Linux و ۷۳ تست parser/انتخاب Windows داشت. verifier فایل مصنوعی encoded بیش از ۶ MiB را در پردازش تازه کنترل کرد؛ decoded مصنوعی ۲۰ MiB با peak تخصیص Python هنگام verifier کمتر از ۲ MiB آزموده شد. این سنجش شامل fixture از پیش ساخته‌شده نیست و سقف RSS کل پردازش نیست. staging آن مرحله POSIX بود؛ افزودن backend بومی scratch در ۰٫۱۸ جای qualification نصب‌کننده را نمی‌گیرد.

## سابقهٔ تغییرات ۰٫۱۶: قواعد نوع‌دار انتخاب
selection_policy.py پروفایل عمومی را به ابعاد platform/architecture/region و localeهای جدا برای speech/text تبدیل می‌کند. هیچ بُعد اصلی optional نیست؛ نبود یا تغییر نوع tag، ناسازگاری schema دو manifest، تزریق عبارت در پروفایل، کلید اضافه و نوع ناشناخته متوقف می‌شوند. زبان speech به‌صورت تصادفی با همهٔ زبان‌های text ضرب نمی‌شود. قرارداد ورودی اجازهٔ اعطای apply یا ادعای freshness نمی‌دهد.

این ماژول اکنون ابزار بررسی فقط‌خواندنیِ برنامهٔ نامزد است، نه سیاست رسمی Agent و نه نصب‌کننده. هر دو بانک و تمام متادیتای مصرف‌شده به هدف/هش/اندازهٔ موجود متصل و دوباره کنترل می‌شوند. خروجی قبلی تغییر نکرد: ۳۹ Install و ۱۵۷۸۰۲۲ Download با bitmap کاملاً یکسان، با عبارت صریح بدون علامت optional.

ابهام واقعی: در Download انتخاب‌شده ۱۰۰۲۸ عضو Alternate و یک عضو Talebound وجود دارند؛ عضو HighRes انتخاب‌شده صفر است. این برچسب‌ها با نوع 16384 ثبت‌اند؛ معنای دقیق و ترجیح نصب آن‌ها qualify نشده و از شمارش نمی‌توان لازم/اضافی‌بودن را استنتاج کرد. امکان هم‌پوشانی وجود دارد؛ اعداد قابل‌جمع به‌عنوان اشیای یکتا نیستند. هیچ‌کدام حذف یا دانلود نشدند.

منبع عمومی wowdev انواع tag را وابسته به محصول و bitmap مشترک Install/Download توصیف می‌کند، نه الگوریتم رسمی و کامل Agent. خواندن آن مجوز flip کردن vendor_selection_policy_qualified به true نیست:
https://wowdev.wiki/TACT#Install_manifest
https://wowdev.wiki/TACT#Tags

گزارش reports/SELECTION-POLICY-to-share.json چهار شکاف را صریح نگه می‌دارد: سیاست مستقل Agent، ترجیحات زنده، وابستگی/variant/patch و معنای featureها. promotion_to_required_set_permitted=false و installation_ready=false باقی است. این مرحله هیچ درخواست CDN بازی، نوشتن نصب، خواندن payload محلی، admin یا تغییر permission نداشت.

در تاریخچهٔ ۰٫۱۶، ۲۸ تست جدید، زبان‌های جدا و چندگانه، بعد اجباری، تغییر نوع/schema، ورودی دستکاری‌شده و ثابت‌ماندن فایل‌های برنامهٔ موجود را پوشش می‌دهند. این آزمون‌ها جای تأیید بومی Windows یا سیاست واقعی نصب نیستند.

برای بررسیِ کش و برنامهٔ موجودِ متعلق به پروژه (نه پوشهٔ بازی):
```sh
python selection_policy.py --binding-workspace BINDING --objects-workspace OBJECTS --candidate-workspace PLAN --profile-json PUBLIC_PROFILE.json --output NEW_REPORT.json
```
خروجی موجود بازنویسی نمی‌شود؛ هیچ شبکه‌ای در این ابزار نیست. پروفایل فقط platform، architecture، region، text_locales و speech_locales می‌پذیرد.

## سابقهٔ تغییرات ۰٫۱۵
reuse_candidates.py تمام ۱۶ ایندکس V7 ارسالی و ۲۶۲۴۵۳۰ مرجع را به ۱۵۷۸۰۲۲ شیء نامزد مقصد متصل کرد. هویت ZIP، هر عضو، checksumهای ایندکس و بانک برنامه دوباره کنترل شدند. فقط بدنهٔ همین ۱۶ عضو خوانده شد؛ نه بدنهٔ shmem/LRU و نه payload آرشیوهای بازی. هش کل ZIP از بایت‌های ظرف فشرده محاسبه شد.

- ۱۵۳۱۱۶۶ شیء دارای prefix، اندازه و نشانی احتمالی داخل حدود اندازه‌های گزارش تاریخی‌اند؛ این «اعتبار محتوای موجود» نیست.
- ۱۰۳۰۰۱۳ شیء بیش از یک نشانی سازگار دارند؛ هیچ نشانی خودسرانه برگزیده نشد.
- ۴۶۸۵۶ شیء در این کپی ایندکس مرجع ندارند؛ مفقودبودن آن‌ها اثبات نشده است.
- اعتبار reuse نصب، صرفه‌جویی تأییدشده و تعداد اشیای مفقود اثبات‌شده صفر است؛ حجم دانلود لازم هنوز نامعلوم است.

بانک متعلق به پروژه یک خطای integrity_check ناشی از چیدمان ستون‌های WITHOUT ROWID در SQLite 3.40.0 داشت؛ با مثال مصنوعی بازتولید شد. چیدمان اصلاح شد و تمام ۲۶۲۴۵۳۰ ردیف با digest ترتیبی یکسان پیش و پس از اصلاح حفظ شدند. integrity_check نهایی ok است. این مسئله تشخیص خرابی بازی نیست. نسخهٔ ناقص اصلی برای سابقه باقی ماند؛ ZIP، نصب یا ایندکس کاربر تغییر نکرد.

staged_reuse.py برای پذیرش ورودی کش خود برنامه، هویت مقصد، اندازه و SHA بانک‌ها، عضویت EKey در برنامه و پیوند کامل EKey/CKey در فهرست را کنترل می‌کند؛ سپس خود بایت‌های staging را زیر قفل همکاری‌کننده دوباره با BLTE، checksum و هر دو کلید می‌سنجد. نمونهٔ واقعی ۵۲ بایتیِ قبلاً دریافت‌شده این مسیر را بدون شبکه گذراند. این فقط تأیید یک ورودی staging است، نه اثبات reuse نصب یا محاسبهٔ صرفه‌جویی کل بازی. گزارش قدیمی به‌تنهایی مجوز نمی‌دهد. این prototype هنوز محدود به POSIX و شیء encoded حداکثر ۴ MiB و اعتبارسنجی در حافظه است.

آزمون تطبیقیِ ترتیب بیت برای هر ۲۵۶ مقدار بایت و هر ۸ موقعیت با فرمول پیاده‌سازی مستقل TACTSharp اضافه شد؛ این شاهد ترتیب بیت است، نه oracle سیاست انتخاب Agent. منبع pinned:
https://github.com/wowdev/TACTSharp/blob/67fd53ac852ca297e9bf95bb41d1a97da202eba4/TACTSharp/InstallInstance.cs

در این مرحله درخواست جدید CDN بازی، خواندن نصب زنده، نوشتن بازی یا تغییر permission انجام نشد. گزارش‌های REUSE-CANDIDATES و STAGED-CACHE-REUSE داخل reports هستند. بانک ۴۱۱۸۴۰۵۱۲ بایتی نامزدها بیرون ZIP در پوشهٔ مستقل پروژه نگه‌داری شده است؛ دانلود/اجرای بسته روی رایانهٔ کاربر لازم نیست.

## سابقهٔ اجرای ۰٫۱۴ با تأیید کاربر
فقط سه فایل Install، Download و Encoding مقصد pinned دریافت شدند؛ سه درخواست، دقیقاً 251510113 بایت بدنهٔ کاربردی (حدود 239.86 MiB)، بدون retry یا redirect. Content-Length دقیق پیش از بدنه کنترل شد. BLTE، EKey، CKey و readback decoded هر سه با descriptorهای config مطابق هدف تأیید شدند. سقف شامل header و سربار شبکه نیست. game asset، اسکن/نوشتن نصب، repair، admin و تغییر permission همگی صفر بودند.

هدف 12.1.5.70448 snapshot تاریخیِ آزمایش است؛ هیچ ادعایی دربارهٔ جدیدترین نسخهٔ امروز نداریم. دریافت سه فایل، انتشار جاری را دوباره resolve نکرد. معماری resolver و برنامه‌ریز نسخه‌مستقل است؛ target یک اجرای نیمه‌تمام خودکار عوض نمی‌شود.

## فهرست مقصد بازسازی شد
- ۲۷۴ رکورد Install، ۳۱ tag و ۲۸۸۱۶۲۸ رکورد Download.
- تمام رکوردهای Download به Encoding و Content Link متصل‌اند و اندازهٔ encoded تعارض ندارد؛ تمام variantهای Install مسیر Encoding/Download دارند.
- به‌صورت مستقل، union عضویت tagها برای هر گروه CKey از Install با رکورد Download متناظر تطبیق شد: ۱۸۰ CKey یکتا، ۳۱ tag و ۵۵۸۰ مقایسهٔ عضویت؛ بدون اختلاف.
- این کنترل‌ها ساختار و روابط را تأیید می‌کنند، نه همهٔ جزئیات سیاست proprietary Agent یا سلامت نصب کاربر.

## برنامهٔ آزمایشی انتخاب
candidate_plan.py ورودی‌ها را با اندازه، CKey و SHA-256 و بانک منبع با SHA دوباره می‌سنجد. ابتدا فیلتر bitmap، سپس یک پیاده‌سازی مستقلِ per-bit اجرا می‌شود. خروجی آزمایشی پروفایل عمومی تاریخی Windows / x86_64 / EU / enUS و speech/text، شامل ۳۹ مسیر Install و ۱۵۷۸۰۲۲ شیء Download است. تعداد اشیای انتخاب‌شده تعداد فایل مفقود، فایل تغییرکرده یا دانلود ضروری نیست.

همهٔ مسیرهای انتخاب‌شده از Windows path gate گذشتند. مسیرهای متادیتا فقط رشته‌اند؛ هیچ‌کدام باز یا اجرا نشد. اتصال هر Install انتخاب‌شده به Download انتخاب‌شده و اندازه‌های Encoding نیز کنترل شد. دادهٔ qualifier خصوصی در گزارش صادر نشده؛ فیلتر از زیرمجموعهٔ عمومی پروفایل تاریخی استفاده کرد، نه ترجیحات زندهٔ نصب. current target با فایل‌های نسخهٔ قدیمی جایگزین نشد.

محدودیت مهم: سازگاری دو فیلتر و دو manifest یک oracle مستقل برای سیاست واقعی نصب نیست. vendor_policy_qualified و required_set_selected همچنان false هستند. قالب، tag یا حالت انتخاب ناشناخته را نباید خودکار پذیرفت. freshness، نسل فعال و reuse نیز اثبات نشده‌اند؛ required_network_download_bytes عمداً null است.

## کد و آزمون
- recover_approved_metadata.py: مجوز دقیق به URL و descriptor متصل است؛ ledger انحصاری قبل از هر درخواست، یک تلاش برای هر URL، توقف در اولین شکست و بدون اجرای خودکار مرحلهٔ محتوایی.
- candidate_plan.py: ساخت SQLite آزمایشیِ انتخاب، کنترل ورودی و روابط، رد تعارض و تغییر، کنترل صحت و عدم بازنویسی خروجی قبلی. metadata-only و آفلاین.
- tag_crosscheck.py: کنترل عضویت tag بر اساس CKey و variant، بدون ادعای سیاست نصب.
- هستهٔ ۰٫۱۲ انتقال واقعیِ دو process برای نمونهٔ ۵۲ بایتی و بازپخش آفلاین staging را قبلاً تأیید کرده بود؛ در این مرحله هیچ Range نمونه‌ای دوباره درخواست نشد. staging فایل‌محور هنوز prototype محدود POSIX است، نه backend نصب Windows.

۴۷۶ تست Linux پاس شدند: ۴۷۱ مصنوعی و پنج fixture کوچک متادیتای واقعی. یک fixture Install همین مقصد به suite اضافه شد. آزمون چند نسخه، تغییر هدف، دستکاری ورودی/بانک، تعارض tag، نگاشت ناقص و reference bitmap نیز وجود دارد. دریافت سه فایل و پردازش فهرست واقعی جدا از شمارش mockها در reports ثبت‌اند. ZIP پس از استخراج نیز دوباره تست می‌شود.

```sh
python -m unittest discover -v
```

## وضعیت مجوز و نگه‌داری
APPROVED-METADATA-RECOVERY.json اجرای مصرف‌شده و بسته‌شده را ثبت می‌کند؛ مجوز تکرار نیست. تلاش دوبارهٔ runner با این رکورد پیش از شبکه رد شد. پیشنهاد قبلی فقط برای سابقه در reports/HISTORICAL-METADATA-RECOVERY-PROPOSAL.json مانده است.

متادیتای کامل و بانک مقصد فعلاً در پوشهٔ مستقل پروژه metadata-recovery-0.14 نگه داشته شدند و برنامهٔ آزمایشی در target-candidate-0.14 است؛ داخل ZIP کوچک نیستند. CACHE-RETENTION-to-share.json هویت cache را ثبت می‌کند. هیچ فایل نصب کاربر کپی یا تغییر نکرد.

## ترتیب باقی‌مانده
۱. تکمیل qualification سیاست انتخاب و پروفایل زنده؛ candidate فعلی نباید مجوز apply بگیرد.
۲. تشخیص نسل فعال و reuse تازه؛ prefix یا گزارش تاریخی به‌تنهایی اعتبار استفادهٔ مجدد نمی‌دهد. تنها پس از این دو مرحله حجم دانلود معتبر محاسبه می‌شود.
۳. یکپارچه‌سازی شبکه و staging مقیاس‌پذیر، verifier جریانی و آزمون بومی Windows.
۴. نویسندهٔ تراکنشی CASC، rollback و activation روی کپی جداگانهٔ آزمایشی.
۵. UI، بستهٔ Windows و end-to-end چند baseline/target.

این مرحله نیاز به اجرای ابزار تازه یا ارسال فایل از طرف کاربر نداشت. هیچ مجوزی برای مرحلهٔ نصب یا اسکن زنده ایجاد نشده است.
