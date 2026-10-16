# قرارداد واقعی bind ایندکس Agent 9824: گذر از V7 به V8

> مرحلهٔ بعد تکمیل شد: [چرخهٔ V8 با گیت اجباری bind و resume](../retail-v8-cycle/README-fa.md). ۹ توقف سخت/بازیابی، جلوگیری از publication در خطای نگاشت و primitive اصلی range بررسی شدند؛ suite فعلی ۶۰۱ آزمون است. اعداد و دامنهٔ اثبات این گزارش تاریخی‌اند؛ full Agent object I/O و Windows همچنان اثبات‌نشده‌اند.

## نتیجهٔ اساسی

**نمونهٔ جدید V8 را توابع اصلیِ جداشدهٔ bind/parser خود Agent پذیرفتند؛ این بار validator اصلی دیگر mock نیست.** هر ۱۶ ایندکس نمونهٔ مشتق‌شده از چرخهٔ واقعی Retail، شامل ۱۸ رکورد، پذیرفته شد. جست‌وجوی اصلی Agent کلید کامل ۱۶بایتی source و target را پیدا کرد؛ سپس spanهای انتخاب‌شده با پیاده‌سازی مستقل Python و EKey/CKey بازخوانی شدند. archive جدید فقط ۸۵۶ بایت و عین archive مرحلهٔ قبل است؛ نه نصب WoW، نه full download.

**اصلاح مهمِ برداشت از مرحلهٔ قبل:** ایندکس‌های V7 چرخهٔ قبلی با CascLib تأیید شده بودند، نه با bind واقعی Agent 9824. parser این Agent revision کمتر از ۸ را رد می‌کند و عرض‌های ۸/۸/۱۶ می‌خواهد. ایندکس V7 واقعیِ باکت هدف به همان binder داده شد و status=5 گرفت. این آزمایش نشان می‌دهد داده‌خوانی موفق CascLib به‌تنهایی گواه پذیرش همان ایندکس توسط Agent نیست. رسیدهای قبلی حذف یا بازنویسی نشدند؛ دامنهٔ ادعایشان محدود است.

## چه چیزی واقعاً اجرا شد؟

۱۰ قطعه‌تابع اصلی، مجموع **۳۴۴۲ بایت کد دست‌نخورده** و **۳۱۲ بایت جدول پرش اصلی**، با آدرس‌های اصلی در ELF محدود Linux i386 قرار گرفتند. SHA256 کل PE ثابت و سپس بایت‌های هر fragment داخل ELF کنترل شد.

| تابع | بازهٔ VA، انتها خارج از بازه | نقش |
|---|---|---|
| equal | 0x70349f–0x7034c4 | برابری کلید کامل ۱۶بایتی |
| cleanup | 0x7214f2–0x72152d | پاک‌سازی واقعی فیلدهای bind |
| hashlittle2 | 0x722fc0–0x7233be | checksum هدر و زنجیرهٔ primary |
| hashlittle | 0x72345c–0x723848 | checksum رکوردهای tail |
| map/parse | 0x72b8f9–0x72b9bf | مسیر نگاشت و parser |
| inner bind | 0x72b9bf–0x72ba22 | reset، اندازه، bind و cleanup خطا |
| parser | 0x72cd8d–0x72cf38 | هدر و فراخوانی primary/tail |
| primary | 0x72cf38–0x72d004 | رکوردهای ۳۲بایتی |
| tail | 0x72d004–0x72d0c9 | صفحات ۱۰۲۴بایتی و slotهای ۴۰بایتی |
| search | 0x72d46c–0x72d52f | binary search با کلید کامل و بازهٔ duplicateها |

۸ مقصد مرزی مشخص‌اند: length/map/unmap/log/error-conversion/memcmp شبیه‌سازی شده‌اند؛ دو مسیر mode=2 و ساخت فایل خالی عمداً trap هستند. تعداد ۲۹ call مستقیم بررسی شد. indirect call مربوط به آزادسازی mode=2 در cleanup وجود دارد ولی wrapper فقط mode=1 می‌سازد و به آن نمی‌رسد. جدول‌های hash جدا از کد استخراج و همهٔ مقصدهای آن‌ها داخل تابع مربوط کنترل شدند.

**اجرا نشده:** wrapper بیرونی 0x72b84f با Windows SEH/Sleep و retry، کل Agent.exe، Windows API، نگاشت واقعی فایل یا اشتراک حافظه، قفل‌های Agent، durable publication و activation بازی. driver ورودیِ غیرخالی حداکثر ۱MiB و باکت ۰ تا ۱۵ می‌پذیرد و اندازه‌های خطرناک را پیشاپیش محدود می‌کند؛ این fuzz عمومیِ همهٔ PE نیست. دادهٔ ورودی با mprotect فقط‌خواندنی است؛ canaryهای دو سوی شیء و صفرشدن فیلدهای cleanup کنترل می‌شوند. ELF بدون dynamic linker، بدون segment هم‌زمان writable/executable و با NX stack است.

## قرارداد مشاهده‌شده و سیاست سخت‌گیرانهٔ خودمان

- guarded header: طول ۱۶ و hash اصلی؛ payload شامل revision=8، bucket، flags=0، عرض‌های size=8/offset=8/key=16، segmentbits=30 و maxoffset ثابت پژوهشی است.
- primary از offset=32 آغاز می‌شود: guard هشت‌بایتی و رکوردهای key16 + دو qword، جمعاً ۳۲ بایت. checksum به‌صورت hashlittle2 زنجیره‌ای روی هر رکورد است.
- tail از مرز ۴۰۹۶ آغاز می‌شود و parser دست‌کم ۰x۷۸۰۰ بایت فضا می‌خواهد. هر صفحه ۲۵ slot با stride=40 دارد؛ checksum صفر، پایان tail است. slot غیرصفر با hashlittle روی ۳۳ بایت و OR 0x80000000 کنترل می‌شود.
- در نمونهٔ کوچک، هر ایندکس ۱۳۱۰۷۲ بایت است؛ فرمول rounding در initializer 0x72c9e8 جداگانه در disassembly بررسی شد، **خود initializer اجرا نشد**.
- parser اصلی آینده‌نگرتر/آزادتر از سیاست ماست: revision>=8، flags غیرصفر با warning، برخی فیلدها و دادهٔ پس از terminator را می‌پذیرد؛ مرتب‌بودن، یکتایی و باقیماندهٔ اندازهٔ primary را اثبات نمی‌کند. `strict_read` فقط پروفایل دقیق V8، رکوردهای مرتب و یکتا، بدون remainder و tail/padding صفر را می‌پذیرد. این تفاوت‌ها تست دارند.

**دو qword فعلاً opaque هستند.** در fixture خودمان qword0 را offset مطلق archive صفر و qword1 را طول span گذاشته‌ایم. جست‌وجوی اصلی دقیقاً همان ۱۶ بایت را برگرداند و reader مستقل ما طبق این سیاست داده را خواند؛ اما مسیر کامل تفسیر value و خواندن آبجکت توسط خود Agent در این مرحله اجرا/اثبات نشده است. این را با اثبات «Agent بازی را از این archive خواند» اشتباه نکنید. search این harness فقط primary را جست‌وجو می‌کند؛ tail از نظر checksum بررسی می‌شود، نه مسیر merge/lookup کامل Agent.

## آزمایش واقعیِ محدود

- کلید source: `914fcad4f4fcf4abb0ba52b197bb066f`، offset=480، span=188.
- کلید target: `faedca88d0a0ab30dae5519239582d31`، offset=668، span=188.
- CKey هدف مستقل از Encoding: `3d42bf2e42127f313b0ec64cb440cde9`.
- CKey source مشتق از نمونه است، نه مقدار موردانتظار مستقل: `98ad7b81687304aa0e99cf326200adfe`.
- هر دو خروجی decoded برابر ۳۳۹۴۰ بایت بودند؛ full EKey، checksumهای span و CKey دوباره بررسی شدند.
- ۱۶ رکورد prefix، source و target: مجموع ۱۸ رکورد و ۱۶ ایندکس پذیرفته‌شده. prefix با seed مصنوعیِ صریح پژوهشی مرحلهٔ قبل است، نه هویت نصب کاربر.
- دادهٔ ۸۵۶بایتی SHA256: `0bc16095b26bc8d1e0c8d3aaba86502e9938f932ccf093e0c135531f1f2861b1`.
- فایل‌ها فقط در خروجی تازه ساخته شدند. hash/identity فایل‌های owned store قبلی ثابت ماند. بازی، Lab، fixture اصلی، ZIP پرتابل و Release تغییر نکردند. هیچ دانلود یا اسکن دوبارهٔ آرشیو انجام نشد.

## آزمون و بازتولید

**۵۶۳ آزمون، صفر failure/error/skip**: ۵۲۰ قبلی + ۴۳ جدید. ماتریس جداگانهٔ **۱۴۲۴ بردار** با اجرای بایت‌های اصلی و مدل مطابق بود: ۴۸۰ جست‌وجو، ۶۴۰ mutation تک‌بیتی محدود، ۲۴۰ truncation، ۴۸ خطای mapping و ۱۶ tail با ۲۶ slot روی دو صفحه. هر ۱۶ باکت و حداکثر ۱۰۲۴ رکورد primary پوشش داده شد. کلیدهای دارای ۹ بایت آغازین یکسان ولی انتهای متفاوت نیز درست تفکیک شدند.

رسیدها: `FRAGMENT-BUILD-RECEIPT.json`، `MATRIX-SUMMARY.json`، `REAL-EXPERIMENT.json`، `TEST-RESULTS.json` و `ALL-TESTS.log`. باینری PE، ELF و raw fragment منتشر نمی‌شوند؛ ساخت محلی نیازمند PE با digest دقیق همان رسید است.

از ریشهٔ `downloader/patch_audit_lab`، روی محیط Linux دارای پشتیبانی ELF i386 و GNU as/ld:

```bash
PYTHONPATH=. python research/bind-contract-9824/native/build.py \
  --agent /path/to/pinned/Agent.9824.exe --out-new /new/native-output
PYTHONPATH=. python research/bind-contract-9824/run_experiments.py \
  --oracle /new/native-output/bind_contract_oracle \
  --prior-owned-cycle /path/to/completed/owned-cycle \
  --out-new /new/experiment-output
BIND_CONTRACT_ORACLE=/new/native-output/bind_contract_oracle \
  python -B -m unittest discover -s tests -p test_bind_contract.py -v
```

برای suite کامل، همان متغیرهای native/fixture مراحل قبلی را نیز تنظیم کنید؛ خروجی بدون skip در `ALL-TESTS.log` ثبت است. مسیرهای خروجی باید تازه باشند؛ این ابزار مهاجرت V7 یا writer نصب نیست.

## اثر عملی و گام بعد

یک مانع واقعی شناسایی و در آزمایش محدود برطرف شد: قالبی داریم که bind اصلی همین Agent آن را می‌پذیرد، نه صرفاً قالب قابل‌خواندن با CascLib. **هنوز آپدیتر آمادهٔ اجرا روی بازی نداریم.** گام بعد دنبال‌کردن قرارداد دو qword و مسیر read/merge کامل، سپس اتصال گیت V8 واقعی به چرخهٔ publication/resume پژوهشی، و در نهایت آزمایش Windows روی کپی جداست. صرف return صفر reader همچنان گواه bind/readback نیست؛ نتیجهٔ مرحلهٔ sequence visibility معتبر باقی است.
