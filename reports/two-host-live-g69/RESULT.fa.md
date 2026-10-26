# G69 — 12 از 13 Range به مرز عمومی دقیق متصل شدند؛ مسیر نامعلوم هنوز حل نشده است

## پاسخ به خواستهٔ حریم خصوصی
در اجرای ادامه‌دهنده، از 13 رکورد دارای Range، 12 مورد دقیقاً بخش‌های عمومیِ مستقل و مشخص را انتخاب کردند: 7 مورد کل یک metadata عمومی و 5 مورد رکورد کامل archive یا اجتماع رکوردهای کاملِ پیوسته بودند. برای این مقادیر، شاهد قوی‌تر از «صرفاً داخل اندازهٔ فایل بودن» داریم.

یک Range دیگر روی path کاملاً عمومی و دارای EKey در DL/EN است؛ از offset صفر شروع می‌شود و داخل اندازهٔ عمومی است، اما مرز دقیقش به مرجع ساختاری مستقل متصل نشده است. این مورد لزوماً مشکوک نیست و نبودِ تطابق مرجع به معنی fingerprint نیست؛ هنوز برای حکم کامل کافی نیست.

همان مسیرِ غیرمنطبق G68 هم دوباره دیده شد. شکل path، fanout و prefix عمومی سازگار است، ولی leaf key در مجموعهٔ کلیدهای عمومی بررسی‌شده پیدا نشد. این مسیر GET و بدون query/body و Range است. پس این مسیر و Range نامعلوم، دو مورد جدا هستند. هیچ‌کدام خودکار مجاز یا بی‌خطر اعلام نشده‌اند. هنوز حکم «فقط دانلود، بدون fingerprint» صادر نمی‌شود.

## شناسنامهٔ نتیجهٔ اصلی
Run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/40289840845
Source commit: e762f8ef0fb70ccc75e08f15c980fdb327a81ac5
Artifact SHA256: 3e86ad8bff3c829c0caada1c3b6c03b6f920d016662dbcd4c9b85697ff5d1cb7
Digest صفحهٔ گیت‌هاب، run_id و source_commit با artifact دریافتی تطبیق داده شدند. runtime.json و control.json مربوط به همین اجرای ادامه‌دهنده‌اند. manifest.json جمع‌بندی محاسبات و کنترل مستقل است.

## مرجع مستقل و روش Range
پیش از اجرای installer، 11 GET ثابت اضافی فقط برای metadata عمومی انجام شد؛ 262244 بایت بدنه دریافت شد. encoding/install/size/patch-indexهای دو محصول از کلیدها و اندازه‌های BuildConfig معتبر گرفته و EKey/chunk/CKey کنترل شدند؛ DownloadManifestها از fixture مستقل قبلی بازاستفاده شدند. هیچ archive body یا برنامهٔ اجرایی دریافت نشد.

سه index عمومی archiveهای Agent از CDNConfig گرفته شد. parser محدود G46، hash کلید footer، checksum footer، TOC، تمام blockها، ترتیب کلید، اندازه/offset و padding را کنترل کرد. رکوردهای Range از offset و اندازهٔ همین indexها ساخته شدند. اجتماع چند رکورد فقط وقتی پذیرفته شد که ابتدا/انتها دقیق و همهٔ رکوردها کامل و بدون gap باشند؛ slice یا عبور از gap full match نیست.

برای ده metadata BLTE، کل شیء، هدر حداقلی، هدر+جدول chunk و chunkهای کامل از دادهٔ عمومی مستقل مرجع شدند. این ساختارها از Range ورودی installer استخراج یا یاد گرفته نشده‌اند. تطابق انتخاب یک بخش عمومی، ضرورت/علت انتخاب یا نبود تمام کانال‌های covert در زمان‌بندی/تعداد/ترتیب را اثبات نمی‌کند.

مرجع EN و configهای منطقه‌ای نیز بررسی شدند؛ تعداد pathهای مستقل همچنان 1241 ماند. تشخیص تکمیلی leaf فقط با کلیدهای عمومی BuildConfig/versions/EN انجام شد؛ هیچ private key، raw path یا Range مشاهده‌شده منتشر نشد. CKey هم به‌طور حدسی EKey فرض نشد. مجموعهٔ مرجع یک snapshot محدود است، نه همهٔ تاریخچه/مناطق/محصولات.

## نتایج جزئیِ دو مورد باقی‌مانده
- مسیر نامعلوم: canonical_hash_path_shape=true، canonical_fanout_matches_key=true، prefix_in_public_reference=true، suffix_class=none و key_public_origins=[]؛ semantic_endpoint_confirmed=false. شکل صحیح hash، منشأ عمومی یا نبود شناسهٔ دستگاه را ثابت نمی‌کند.
- Range نامعلوم: path کاملاً منطبق با DL و EN محصول agent، offset_is_zero=true و range_inside_public_object_size_if_checkable=true؛ exact_public_boundary_match=false با status=no_independent_range_reference. این عدم تطابق ناشی از فقدان مرجع ساختاری در matcher این شیء است، نه اثبات خراب/غیرعمومی‌بودن خود فایل. مقدار خام Range ذخیره نشده؛ از true بودن bounds نمی‌توان equality کل فایل را پس از اجرا نتیجه گرفت.

## اجرای نخست و اصلاح محدودِ مانع ابزار
اجرای اول https://github.com/kokononox/battle-net-agent-lab/actions/runs/40289287822 با source be3c7d9bc0f0a92b75bb375dd82d0130c3dd39c2 پیش از رسیدن به مسیر هدف با late_process_image_failed متوقف شد؛ cleanup=true بود. بخش کوتاه‌شده 27 رکورد path منطبق و 9 Range دقیق از 10 Range داشت. نبود مسیر نامنطبق در آن بخش به معنی حل آن نبود. initial-runtime.json و initial-control.json حفظ شده‌اند.

برای یک اجرای ادامه‌دهنده، guard فقط در یک حالت اجازهٔ صرف‌نظرکردن از تلاش attach گرفت: QueryFullProcessImageNameW شکست بخورد و WaitForSingleObject روی همان handle بازشده، با timeout صفر، دقیقاً WAIT_OBJECT_0 بدهد؛ یعنی آن process object قطعاً خاتمه یافته است. OpenProcess اکنون SYNCHRONIZE را هم لازم دارد. TIMEOUT/WAIT_FAILED/unknown، شکست بازکردن handle، process زنده و تغییر path/hash همچنان fail-closed هستند. سایر کنترل‌های شبکه/گواهی/UI تغییر نکردند.

78 آزمون کشف شدند؛ در Linux آزمون native Windows skip و 77 آزمون دیگر موفق بودند. در مرحلهٔ pre-mutation ویندوز، آزمون controlled owned child زنده/خاتمه‌یافته نیز اجرا می‌شود و گام آزمون با موفقیت گذشت. کنترل‌های بومی x86/x64 هم موفق بودند. در اجرای target ادامه‌دهنده، شمار late_candidate_proven_terminated_before_attach=0 بود؛ بنابراین ادعا نمی‌شود علت خطای اجرای اول ثابت شده یا شاخهٔ skip روی target واقعی تمرین شده است. فقط منطق fail-closed و proof termination با کنترل مصنوعی سنجیده شدند. اجرای ادامه‌دهنده موفق شد، اما رفع ریشه‌ای خطای قبل به این اصلاح نسبت داده نمی‌شود.

## پوشش و ایمنی
همچنان 33 از 34 رکورد CDN با کل path مستقل منطبق‌اند. 46 ردیفِ خلاصهٔ API حفظ شدند؛ 17 ردیف پالایش‌شده تکراری‌اند و حذف نشدند. اینها تعداد درخواست یکتای رسیده به سرور نیستند.

حسابداری ارسال پذیرفته‌شدهٔ API در محدودهٔ hook دقیقاً با مجموع HTTP candidate و رکوردهای کامل TLS برابر است؛ opaque/ناقص باقی نماند و cap پر نشد. این پوششِ کل سیستم یا نگاشت یک‌به‌یک ciphertext به plaintext نیست. در شش snapshot مالک زندهٔ خارج از مشاهده دیده نشد، اما نمونه‌برداری پیوسته نیست.

مشاهدهٔ اجرای ادامه‌دهنده 120.6 ثانیه، error=null، cache آنلاین/آفلاین معتبر، firewall_verified=true و cleanup=true بود. دو مقصد runtime قبلی و استثنای قبلی مدیریت CI حفظ شدند. دریافت پژوهشی us.cdn.blizzard.com از runtime جداست و به allowlist اضافه نشد. CA/TLS/ابطال تضعیف نشدند، main و 0.9.10 تغییر نکردند. ورود، Install، نصب بازی یا کل دانلود اجرا نشد.

## گام بعدِ لازم، بدون اجرای خودکار بیشتر
برای مسیر نامعلوم باید منشأ تولید/دریافت leaf key در خود Agent و context درخواست/پاسخ به‌صورت محدود و پالایش‌شده ردیابی شود؛ تکرار همین تطبیق با همان snapshot، شاهد تازه ایجاد نمی‌کند. برای Range نامعلوم باید equality با کل اندازهٔ عمومی یا مرزهای BLTE همان شیء مستقل سنجیده شود، بدون اینکه مقدار مشاهده‌شده به allowlist تبدیل شود. سپس پوشش کل بازهٔ دانلود هنوز لازم است. در این نوبت اجرای بیشتری خودکار شروع نشده است.

## محل بازتولید و مراجع
کد/fixtureها: analysis-tools/two-host-live-g69 در همین شاخه. snapshot بایت‌های عمومی و receiptها پین شده‌اند؛ script پژوهشی اجراشده با مسیرهای sandbox در extended-reference-acquisition.provenance.txt حفظ است و workflow آن را اجرا نمی‌کند. parserهای EN و index از G44 و G46 دوباره استفاده شدند.
مستند جامعهٔ توسعه‌دهندگان برای قالب، نه تضمین رسمی ناشر: https://wowdev.wiki/TACT
مرجع قبلی pathها و بایت‌ها: reports/two-host-live-g68/RESULT.fa.md
