# G68 — 33 از 34 مسیر CDN عمومی‌اند؛ بایت‌های ناشناختهٔ HTTP همگی TLS بودند

## نتیجهٔ مرتبط با سؤال اصلی
از 34 رکورد بازسازی‌شدهٔ درخواست CDN، کل path در 33 رکورد دقیقاً با مرجع مستقلِ عمومیِ ساخته‌شده پیش از مشاهده تطابق داشت. فقط یک رکورد مسیرِ هنوز نامعلوم دارد. شباهت به hash یا عضویت چند token ملاک نبود: کل مسیر، fanout و نبود query مقایسه شد. این شاهد منشأ عمومی مسیرهای انتخاب اشیای دانلود است، نه حکم عمومیِ نبود fingerprint.

همهٔ 5116 بایتی که parser HTTP در non_HTTP1_or_midstream نگه می‌داشت، با parser مجزای جریان به رکوردهای کامل TLS طبقه‌بندی شد. بایت opaque/ناقص یا باقی‌مانده در حسابداری جدید نبود. این نتیجه شکاف «قالب این بایت‌ها چیست؟» را رفع می‌کند؛ محتوا را به‌خودی‌خود بی‌خطر نمی‌کند و mapping یک‌به‌یک ciphertext به plaintext SSPI را اثبات نمی‌کند.

## شناسنامه
Run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/40286805955
Source commit: 2a1d104de3778f58b675899a9de15757107c31be
Artifact SHA256: c13feb8982ce0c92a8364a6110c1186ecdd77ed7da04ec92713818e83a2622b8
Digest نمایش‌داده‌شدهٔ گیت‌هاب، run_id و source_commit با فایل دریافتی تطبیق دارند. runtime.json، control.json و manifest.json شواهد پالایش‌شده‌اند.

## مرجع مستقل مسیر
پیش از ثبت/اجرای مشاهده‌گر، 12 GET ثابت برای metadata عمومی agent و bna، مجموع 80275 بایت بدنه، دریافت شد. هیچ path نصاب ورودی این دریافت نبود. versions/cdns از us.version.battle.net و metadata محتوامحور از HTTPS us.cdn.blizzard.com اعلام‌شده در cdns گرفته شدند. این کاربرد پژوهشی همان منبع G43 است؛ به firewall/allowlist runtime اضافه نشد.

Build/CDN/ProductConfigها با MD5 بایت خام و کلیدِ نسخه، و DownloadManifestها با اندازه، BLTE EKey/chunk و CKey decoded و parse کامل DL کنترل شدند. از این داده‌ها 1241 مسیر دقیق در public-download-reference.json ساخته و با SHA256 پین شد. snapshot بایت‌های 12 دریافت در public-reference-fixtures.json، receiptها در catalog و روش ساخت در build_public_reference.py حفظ است. workflow fetcher را اجرا نکرد؛ فقط snapshot مستقل را خواند. scriptها و fixtureها در analysis-tools/two-host-live-g68 هستند. MD5 و پین محلی جای امضای مستقل ناشر را نمی‌گیرند.

33 تطابق شامل configهای عمومی agent/bna، indexهای آرشیو، file index، manifestهای encoding/install/download/size/patch-index و شیء دانلود یا آرشیو معرفی‌شدهٔ عمومی بودند. وجود path در مرجع، وجود فایل در CDN یا صحت payload دریافت‌شده را برای همهٔ اشیا جداگانه اثبات نمی‌کند؛ فقط منشأ عمومی خود مسیر را نشان می‌دهد. دادهٔ مرجع یک snapshot مشخص برای US و دو محصول است، نه کل تاریخچه/همهٔ مناطق.

## یک مسیر نامعلوم و Range
رکورد نامنطبق GET، بدون query و بدنه است؛ User-Agent آن ساختار agent/نسخهٔ عمومی دارد. path دارای بخش‌های طبقه‌بندی‌نشده و یک token شبیه hash است. مقدار خام صادر نشده؛ آن را صرفاً به‌خاطر شکل hash بی‌خطر نمی‌نامیم، و عدم عضویت در snapshot محدود هم اثبات fingerprint نیست. هیچ GET جدیدی با path مشاهده‌شده برای جست‌وجوی معنای آن ساخته نشد.

13 رکورد دارای Range بودند: در 8 مورد حدود عددی داخل اندازهٔ عمومی شیء بود؛ 5 مورد اندازهٔ قابل‌اعمال مستقل نداشتند. Rangeها با رکورد archive، الگوی chunk لازم یا نبود کانال شناسه در مقدار Range تطبیق معنایی کامل نشده‌اند. bounds معتبر، نبود fingerprint در مقدار را ثابت نمی‌کند. مقدار خام Range صادر نشده است.

## حسابداریِ محدودهٔ مشاهده‌شده
9494 بایت ورودی پذیرفته‌شدهٔ API به IPهای منتخب ثبت شد. 4378 بایت HTTP candidate و 5116 بایت رکورد کامل TLS بود؛ جمع مستقل دقیقاً با hook_counts و accepted_write_transport_audit برابر است. buffered_unclassified_bytes=0، accounting_reconciles=true و cap_hit=false بود. نوع‌های رکورد در runtime.json حفظ‌اند.

HTTP candidate به‌تنهایی تأیید privacy نیست؛ parser جداگانه 34 رکورد CDN را بازسازی کرد. SSPI هم 12 رویداد outgoing و 40 incoming با status موفق ثبت کرد؛ این دو لایه نباید به‌عنوان درخواست‌های یکتای بیشتر جمع شوند. عدد 9494 کل ترافیک سیستم یا packet capture مستقل نیست. TLS handshake نیز می‌تواند اطلاعات پروتکلی/fingerprint TLS داشته باشد؛ طبقه‌بندی آن نفی این اطلاعات نیست.

در هر شش snapshot، unobserved_live_process_owner_rows=0 بود. ردیف‌های خارج از PIDهای مشاهده‌شده TIME_WAIT/PID صفر بودند. نمونه‌برداری متناوب است و جریان کوتاه، API دیگر، process خارج از hook یا ارسال پس از بازه را رد نمی‌کند. closesocket فقط برای جداکردن چرخهٔ reuse در parser به‌صورت خواندنی مشاهده شد؛ return value/buffer برنامه تغییر نکرد.

## کیفیت و کنترل‌ها
70 تست محلی گذشتند، شامل رد query/suffix/fanout/encoding متفاوت، عدم افشای مقادیر، bounds Range، بازتولید مسیرهای DL از بایت‌های اعتبارسنجی‌شدهٔ metadata، fragmentation هر مرز بایت TLS، جریان ناقص، socket reuse و حسابداری مستقل. parse/test ویندوز و ده کنترل بومی x86/x64 نیز موفق بودند.

46 ردیف API با grain مشخص نگه داشته شد؛ 18 ردیف خلاصهٔ پالایش‌شده تکراری‌اند و حذف نشدند. این تکرارها شمار درخواست یکتای رسیده به سرور نیستند. برابری ظاهری ردیف پالایش‌شده هم برابری raw را تضمین نمی‌کند.

مشاهده 120.5 ثانیه، error=null، cache آنلاین/آفلاین معتبر، firewall_verified=true و cleanup=true بود. حفاظ‌های شبکه/گواهی/شناسایی process/UI با G67، به‌جز تغییر نام مرحله، بدون تغییرند. مقصد runtime جدیدی اضافه نشد، بررسی ابطال خاموش نشد، ورود/نصب بازی انجام نشد، main و نسخهٔ 0.9.10 دست‌نخورده‌اند.

## مرز نتیجه و گام بعد
دو ابهام G67 دربارهٔ seqn و User-Agent قبلاً با equality مستقل حل شدند. این مرحله منشأ عمومی بیشتر مسیرهای CDN و قالب بایت‌های خارج از parser HTTP را روشن کرد. هنوز حکم «فقط دانلود، بدون fingerprint» صادر نمی‌شود و ابزار فیلتر معناییِ آمادهٔ استفاده نشده است.

گام بعد باید فقط روی منشأ همان یک مسیر، معنای Rangeهای باقی‌مانده و سپس پوشش همهٔ مسیرهای ارسال در بازهٔ کامل دانلود متمرکز باشد. توسعهٔ کور allowlist، تکرار آزمون TLS یا فرض بی‌خطر بودن مقدارِ شبیه hash پاسخ این شکاف‌ها نیست.
