# پلن پروفایل برنامه‌محور — ۰٫۱

## وضعیت واقعی

سازندهٔ خالص `source/app_profile_plan.py` پیاده شد؛ فایل اجرایی Windows، native firewall adapter یا recorder ساخته نشده است. این کد ورودی ساختاریافته را به draft غیرقابل‌اجرای برنامه/مقصد/پورت تبدیل می‌کند؛ هیچ فایل کاربر، شبکه، DNS، ژورنال یا فایروالی را نمی‌خواند/تغییر نمی‌دهد. فایل‌های source/test و شواهد داخل این milestone برای توسعه‌اند؛ از کاربر اجرای آزمون دیگری خواسته نمی‌شود.

انتخاب نهایی کاربر **جایگزین تصمیم قبلی all-program** است: کل سیستم تحت محدودیت، ولی فقط برنامه‌ها و grantهای یک پروفایل فعال اجازهٔ داده دارند. پروفایل‌های browser/game/installer روی یک موتور مشترک‌اند؛ ابتدا نصاب تکمیل می‌شود. مرورگر در مثال یک پروفایل است، نه مجوز جهانی برای همهٔ برنامه‌ها به مقصدهای مرورگر.

## قرارداد ورودی

- schema=`ufw-app-profiles-01`، generation عدد صحیح مثبت، active_profile_id یک ID، profiles آرایهٔ ۱ تا ۸ پروفایل.
- پروفایل: id، kind از browser/game/installer، programs و grants. idها lowercase محدودند و تکرار/فیلد ناشناخته رد می‌شود.
- هر program: id، path محلی مطلق و normalize‌شدهٔ Windows با پسوند exe، sha256 ادعایی ۶۴ hex lowercase. حداکثر ۱۶ program صریح؛ duplicate path case-insensitive رد می‌شود. path/hash فقط دادهٔ draft است، نه اثبات فایل واقعی/امضا/اعتماد. reparse/hardlink/WOW64/ACL/file replacement و identity بومی هنوز پیاده نشده‌اند. shared hostهای شناخته‌شده svchost/rundll32/dllhost در این نسخه رد می‌شوند؛ این denylist کامل امنیتی نیست، سرویس مشترک طراحی service-scoped می‌خواهد.
- هر grant: program_id موجود، IP دقیق، protocol فقط TCP یا UDP، یک port صحیح ۱ تا ۶۵۵۳۵. حداکثر ۲۵۶ grant در هر پروفایل؛ wildcard/Any/CIDR/range/hostname در این نسخه پذیرفته نمی‌شود. private IP فقط وقتی صریح وارد شود قابل draft است، نه exemption کل LAN. loopback/linklocal/multicast/unspecified/mapped/scoped IP و IPv4 مبهم رد می‌شوند. IPهای مستندات فقط fixture هستند.
- هر program باید grant صریح داشته باشد. grantها edge مستقل‌اند: مقصدهای helper خودکار به browser/installer داده نمی‌شوند؛ cross-product برنامه‌ها×مقصدها تولید نمی‌شود.

## خروجی

فقط پروفایل انتخاب‌شده application_templates تولید می‌کند؛ inactiveها union نمی‌شوند. template شامل path و hash ادعایی برنامه، IP/پورت/پروتکل دقیق و token غیرقابل‌اجرا برای binding تازهٔ معتبر SSTP است. initial_enabled=false؛ interface_alias=Any یا alias/index کارت فیزیکی برای داده نداریم. path-filter طراحی‌شده در بهترین حالت هر instance همان فایل را شامل می‌شود، نه صرفاً tab/window/parent PID؛ این نسخه per-process native enforcement ندارد.

input_valid یعنی صرفاً شکل draft پذیرفته شده، نه approval. application_identity_verified/endpoint_approval_verified/baseline_verified_by_this_compiler/plan_executable/ready_for_apply همواره false هستند. ورودی approved=true، auto_allow_children، execution_authorized یا interface_alias پذیرفته نمی‌شود. capture خام هم ورودی approval نیست. خطا خروجی صفر-template و code ثابت، بدون raw exception/path می‌دهد.

canonical digest به تمام تنظیمات مرتب‌شده، پروفایل فعال و generation وابسته است؛ تغییر هرکدام digest را عوض می‌کند. digest امضا، consent، freshness یا external identity anchor نیست؛ generation ورودی نیز خودبه‌خود ضد rollback نیست. raw plan شامل مسیر/هش/IP واقعی خواهد بود و برای اشتراک/commit مناسب نیست؛ summarize_profile_plan برای خروجی همین compiler فقط شمارنده و blocker عمومی می‌دهد، نه validation یک report دلخواه.

## افزودن/حذف و تعویض مود

در مدل، هر بار از config جدید پلن تازه ساخته می‌شود؛ پلن قبلی inplace تغییر نمی‌کند. switching=one active profile، نه ادغام پروفایل‌ها. هستهٔ apply باید در آینده دقیقاً نسل/پروفایل مورد بازبینی را validate و مجوزهای قدیمی را journaled و scopeدار جمع کند؛ صرف تغییر config هیچ اتصال یا قاعدهٔ واقعی را نمی‌بندد.

ترتیب نیازهای اجرایی (هنوز اجرا/پیاده نشده):
1. تأیید baseline تازه و رضایت محدودِ محتوای دقیق؛ preparation consent قبلی رضایت Apply نیست.
2. ثبت intent و تعلیق/بازخوانی قواعد دادهٔ پروفایل قدیمی؛ بدون انتقال permissive هم‌زمان دو مود.
3. inventory و بازبینی local/effective/GPO/foreign Allow و ثبت backup/quarantine دقیق؛ foreign Block حفظ می‌شود. default-outbound Block به تنهایی همهٔ Allow قبلی را خنثی نمی‌کند. blanket Block-all rule هم با Allow انتخابی یکی نیست.
4. حفظ/اعتبارسنجی حمل دقیق SSTP مستقل، بعد profile defaults و نصب قواعد دادهٔ جدید ابتدا disabled با ownership/readback؛ ترتیب نهایی باید با تراکنش واقعی طراحی/آزموده شود، این لیست executor نیست.
5. تازه‌بودن هویت برنامه/نسل/binding/endpoint و effective rule enforcement پیش از enable؛ در disconnect/unknown داده disabled بماند، transport فقط ازپیش‌تأییدشده حفظ شود.
6. commit و recovery scopeدار با baseline واقعی؛ baseline Block همان Block است، نه بازیابی خودکار اینترنت عادی.

تعویض مود اتمیک، بستن فوری flowهای برقرار، packet/reboot/reconnect و رفتار سایر WFP providerها هنوز حل/آزموده نشده‌اند. در هیچ خطا یا cache سرد اجازهٔ عمومی داده/443/DNS یا تبدیل خودکار Block به Allow ایجاد نشود.

## SSTP، سایت و recorder

سازندهٔ exact transport قبلی (milestone b42fc14bfce5c665e74d8459df17a88882e1cf06) بدون تغییر باقی است؛ ۸۶ assertion آن دوباره پاس شدند. این compiler آن را صدا نمی‌زند یا از approved bool پل نمی‌سازد؛ composition/مرجع approval/سرویس بومی/DNS/certificate/underlay bootstrap و observer→executor integration همچنان blockers مستقل‌اند. کنترل‌پلین SSTP نباید با Any-program داده ترکیب شود.

ثبت آینده باید برنامه و علت وابستگی را جدا از هم‌زمانی صرف ثبت کند؛ parent/child/service خودکار مجاز نیست. بستهٔ capture فقط پیشنهاد محلی است، نه وایت‌لیست خودکار. ثبت بدون رضایت ابزار را از isolation خارج نمی‌کند. پوشش یک سناریو برای همهٔ قابلیت‌ها/آینده کافی نیست؛ دامنه‌های login/CDN/redirect/subresource و TTL/refresh به بازبینی نیاز دارند. این نسخه hostname enforcement یا DNS resolution/refresh ندارد؛ IP مشترک را به سایت خاص یا محتوای HTTPS تفکیک نمی‌کند. مجازبودن برنامه/مقصد نیز fingerprint داخل ارتباط مجاز را منع نمی‌کند.

## شواهد

۲۵ test method با subcaseهای validation، سه مود/یک active، نبود grant-cross-product، رد approval ساختگی، حذف/تعویض/digest/عدم mutation ورودی و AST boundary پاس شد. ۱۰۰۰ مورد randomized با seed ثابت روی predicate مستقلِ آفلاین templateها بررسی شد؛ این predicate WFP یا native firewall نیست. exact transport قبلی ۸۶ assertion regression پاس شد. همه روی Linux؛ نه هویت exe واقعی، نه SSTP واقعی، نه mode switch Windows و نه هرگونه حفاظت no-leak تایید نشده است.

شواهد قبلی Windows storage/preparation/reopen حفظ شده‌اند و نیاز به تکرار ندارند. فعلاً کاربر اقدام ندارد. مرحلهٔ بعد native/local program-and-destination review برای پروفایل نصاب و گیت‌های identity است، سپس composition با baseline/transport؛ recorder و Apply هنوز deliverable نیستند. این milestone صرفاً قرارداد برنامه‌محور را در کد تثبیت می‌کند، نه وعدهٔ آماده‌بودن ابزار نهایی.
