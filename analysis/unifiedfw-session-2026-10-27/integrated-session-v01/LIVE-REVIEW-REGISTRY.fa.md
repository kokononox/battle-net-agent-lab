# اتصال بازبینی زنده و قفل سراسری — توسعهٔ داخلی

این مرحله ادامهٔ همان coordinator و backend حمل/quarantine است، نه ابزار تشخیصی تازه. هیچ ZIP، آزمون دستی یا فایل خصوصی جدیدی از کاربر لازم نیست. **نسخهٔ Windows آمادهٔ Apply یا نصب کامل نیست؛ تمام gateهای native همچنان unqualified هستند.**

## پیاده‌سازی جدید

### `LiveReview.ps1`

- factory خصوصی `New-UfwWindowsLiveReviewIO` از `Read-SstpReviewCandidate` موجود و بدون تغییر و reader هویت EXE قبلی استفاده می‌کند. caller باید helperهای pinشده را داخل همان module خصوصی بار کند؛ این فایل launcher عمومی نیست. نشست Windows باید ازقبل‌متصل، current_user، SSTP با split tunneling خاموش باشد. RAS/PPP IPv4/شناسهٔ NIC دو بار بررسی می‌شود؛ پشتیبانی IPv6-only ادعا نشده است.
- observer قبلی فقط cache محلی DNS و اتصال Established موجود را می‌خواند؛ خودش dial، درخواست DNS، credential یا تغییر VPN ندارد. host باید فقط SstpSvc را میزبانی کند و دقیقاً یک tuple پایدار با سرور تنظیم‌شده تطبیق یابد. این **هم‌بستگی اتصال است، نه احراز هویت مستقل TLS یا kernel service-tag attribution**. امضای svchost در مسیر ایجاد قاعده، جداگانه و مانند مرحلهٔ قبلی بررسی می‌شود؛ آن بررسی ممکن است به trust-network سیستم وابسته باشد.
- selection فایل، هویت فایل و مقصد زمان اجرا یکی نیستند. برنامه‌های انتخاب‌شده بازخوانی هویت می‌شوند، اما trusted/executed/granted نمی‌شوند. مقصدهای برنامه هنوز خالی و فقط پیشنهاد خصوصی زمان اجرا هستند؛ child/service خودکار مجاز نیست.
- actor + برنامه‌ها + RAS/flow/host + view دقیق تغییرات در حافظه bind می‌شوند. spec حمل فقط digest این مشاهده را نگه می‌دارد؛ فایل journal یا hash مجوز قابل‌انتقال نیست. رضایت draft قدیمی به رضایت تغییر فایروال ارتقا داده نمی‌شود.
- نمای کنسولی محلی برنامه‌ها/هش، profile/server/endpoint و قبلِ کامل قواعد/فیلترهای quarantine را نشان می‌دهد؛ هیچ raw view یا screenshot ارسال/منتشر نمی‌شود. challenge تصادفی باید همان‌جا تایپ شود. پس از آن اتصال، فایل‌ها و baseline سیاست دوباره خوانده می‌شوند. این UI کنسولی هنوز روی Windows اجرا/ارزیابی نشده و به یک پنجرهٔ نهایی یکپارچه تبدیل نشده است.
- رضایت موقت حداکثر ۱۸۰ ثانیه با ساعت monotonic اعتبار دارد. rollback ساعت، پایان مهلت، تغییر actor/file/RAS/flow/host یا شکست observer آن را برای همان invocation غیرقابل‌بازگشت باطل می‌کند. زمان خواندن observer هم از مهلت کسر می‌شود. این بررسی دوره‌ای/قبل از اثر است، نه قطع‌کنندهٔ اتمیک kernel یا تضمین بدون فاصلهٔ زمانی.
- `New-UfwLiveCoordinatorBindings` adapterهای Inspect/Review/Refresh همان coordinator را می‌دهد. context باید **پس از قفل/scan و gateها، در مرحلهٔ Inspect** ساخته شود؛ نه قبل از بررسی recovery. شناسهٔ نشست در حافظه رزرو و journal فقط در Backup، با همان شناسه ساخته شود؛ cancel نباید پوشهٔ خالی بسازد.
- `New-UfwLiveBackendGuard` guard موجود actor/audit/quiescence/exit را حفظ می‌کند و فقط برای backup/forward تازگی زنده را اضافه می‌کند. restore، immediately_before_restore، recovery و finish به SSTP، EXE یا lease زنده وابسته نیستند؛ همچنان اجازهٔ مستقل موجود را لازم دارند. phase ناشناخته رد می‌شود. برای رصد، `Test-UfwLiveLease` باید علاوه بر guard فایروال موجود در `RuntimeBridge` bind شود؛ native capture UI هنوز نهایی نشده است.

### `SessionRegistry.ps1`

- `global.lock` در ریشهٔ خصوصی قبلی با FileShareNone باز می‌شود، نه truncate. زیرپوشه‌های session فقط پس از قفل خوانده می‌شوند؛ قفل هر نشست نیز قبل از readback گرفته می‌شود. helperهای ACL/path/reparse قبلی بدون تغییر استفاده شده‌اند.
- scanner فقط نام‌های دقیق ریشهٔ خودش را می‌پذیرد، تا ۴۰۹۶ نشست؛ نه inventory/candidate/audit store قبلی و نه مسیر انتخاب‌شدهٔ کاربر. هر journal علاوه بر hash chain و head، با **همان parser عملیات backend** اعتبارسنجی می‌شود؛ حتی نشست ظاهراً بسته. terminal جعلی با intent باز عبور نمی‌کند.
- یک pending معتبر با head/sequence/bytes بازخوانده‌شده در دسترس recovery قرار می‌گیرد و نشست جدید را مسدود می‌کند. چند pending، journal ناقص/خالی، قفل اشغال، ACL/reparse نامعتبر یا فایل نامنتظر رد می‌شود. حذف، overwrite، تعمیر خودکار، بستن اجباری قفل یا حدس ترتیب بازیابی نداریم.
- empty allocation پس از crash محافظه‌کارانه مسدود می‌ماند؛ پاک‌سازی آن به review محلیِ هنوز طراحی‌نشده نیاز دارد. scan موفق فقط یک تخصیص جدید را اجازه می‌دهد. نشست‌های بسته خودکار prune نمی‌شوند؛ رسیدن به سقف مانع شروع است، نه مجوز حذف.
- bindings قفل/Pending/Unlock به coordinator موجود وصل می‌شوند. caller باید storage جدیدش را پیش از رهاکردن global lock ببندد؛ handle pending را registry می‌بندد. pending handle اختیار restore نیست: guard مستقل، baseline/prefix reconciliation و readback واقعی همچنان لازم‌اند.

## شواهد و محدودیت

`qa.py` اکنون suite تازه را همراه suiteهای قبلی اجرا می‌کند. آزمون‌ها فایل و قفل واقعی Linux، callbackهای واقعی module و همان coordinator/backend را دارند؛ providers و اثرهای Windows فرضی‌اند. سه جریان assembled شامل موفقیت، cancel بدون journal خالی و قطع هنگام capture با restore مستقل از lease هستند. suiteهای mixed/runtime قبلی نیز دوباره اجرا می‌شوند. شمارش نهایی در `evidence/QA-SUMMARY.json` است.

تست قفل بین دو handle روی Linux، آزمون Windows ACL/share/power-loss یا APIهای RAS نیست. هیچ SSTP تازهٔ کاربر مشاهده نشده است. hash chain امضای مستقل/WORM/ضد حذف tail نیست؛ تهدید مدیر مخرب یا IPC sandbox را پوشش نمی‌دهد.

## مانع‌های باقیمانده، بدون ادعای پیشرفت کاذب

ورودی بومی واحد هنوز باید recovery را پیش از مشاهدهٔ شبکه راه بیندازد؛ audit pending، actor مجاز، خاتمهٔ target/helper و رضایت خروج را مستقل و واقعی bind کند. UI candidate/audit/capture نهایی باید همان انتخاب بررسی‌شده را بگیرد و guard زنده را در رصد حفظ کند. سرعت reader کامل دو store در هر اثر باید برای ۱۰۶ قاعده بررسی شود؛ lease کوتاه جای benchmark نیست و ممکن است امن متوقف کند. سپس اعتبارسنجی هدفمند Windows برای همین جریان واحد لازم است، نه زنجیرهٔ بسته‌های تشخیصی جداگانه.

هنوز صفر grant دادهٔ برنامه، بدون اجرای خودکار، بدون cold-start/reconnect/reboot/underlay-switch و بدون تضمین no-leak/fingerprint. نصب کامل Battle.net هدف بعدی است، نه قابلیت تکمیل‌شدهٔ این commit.
