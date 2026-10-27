# ثبت پیش‌نویس برنامه‌های نصاب — UFW-PROGRAM-CANDIDATE-01

این مرحله برای اولین بار **فهرست خصوصی برنامه‌های انتخابی را محلی و محافظت‌شده ذخیره می‌کند**؛ فقط پس از بازبینی و کلیک صریح Save candidate. هنوز مقصدی ندارد و پروفایل کامل/قابل‌اعمال نیست. هیچ EXE اجرا، trust/Authenticode بررسی، یا firewall/VPN/DNS/route/rule/task/baseline journal خوانده/تغییر داده نمی‌شود. ماژول‌های storage فقط برای helperهای مسیر/ACL/فایل reuse شده‌اند، نه اجرای session یا Apply.

## اجرا روی همان سیستم آزمایشی

1. ZIP را در پوشهٔ محلی تازه و جدا Extract کنید؛ روی برنامهٔ قبلی یا بسته‌های قبلی کپی نکنید. شبکه/SSTP و ژورنال baseline قبلی همان وضعیت بمانند؛ نه reboot و نه تکرار آزمون قبلی لازم است.
2. `Run-Candidate.cmd` را **با Run as administrator و همان حساب ویندوز** اجرا کنید. برخلاف نسخهٔ مشاهده، این بار ادمین برای ایجاد پوشهٔ محافظت‌شدهٔ Administrators/SYSTEM در ProgramData لازم است، نه برای خواندن یا اجرای نصاب. Windows PowerShell 5.1 x64/STA لازم است.
3. در پنجرهٔ انتخاب فایل، همان EXE واقعی نصاب موجود را انتخاب و Open بزنید؛ فایل اجرا نمی‌شود. فعلاً یک فایل کافی است. Ctrl فقط برای helper مشخص و صریح موردنظر، حداکثر۱۶؛ فرزندان یا سرویس‌ها خودکار مجاز نمی‌شوند. فایل‌ها فقط روی fixed local drive؛ Network/UNC/OneDrive reparse/shortcut یا preview استفاده نکنید.
4. پس از خواندن فایل، پنجرهٔ خصوصی بازبینی باز می‌شود. **همین برنامه‌ها و مسیرها را بررسی کنید**. اگر می‌خواهید فهرستشان فقط به‌عنوان پیش‌نویس نصاب ثبت شود، در حداکثر دو دقیقه Save candidate را کلیک کنید. Cancel/بستن پنجره/ESC بدون ثبت candidate لغو می‌کند؛ گزارش کنار بسته همچنان ساخته می‌شود. Save به معنی مجوز اجرای فایل یا Apply نیست و default/focus روی Cancel است؛ Enter خودکار Save نیست.
5. تا نتیجه صبر کنید و هم‌زمان دوباره اجرا نکنید. فقط JSON تازهٔ `UFW-PROGRAM-CANDIDATE-01-*.json` را بفرستید، حتی در لغو/شکست. اگر JSON ساخته نشد فقط stage/code کوتاه را بدون مسیر خصوصی بفرستید.

**مسیر، هش، شناسهٔ فایل، خود EXE، فایل candidate.json یا عکس/متن پنجرهٔ خصوصی را نفرستید.** در write_status=attempted_may_exist_inspect_if_failed ممکن است رکورد وجود داشته باشد؛ حذف، جابجایی، ویرایش یا تکرار خودکار نکنید و فقط گزارش را بفرستید.

## چه چیزی ثبت می‌شود؟

Root جداگانهٔ `CommonApplicationData/UnifiedFW-ProgramCandidates-01` و یک پوشهٔ تازهٔ `UfwProgramCandidate-...`، با owner Administrators و DACL محافظت‌شدهٔ فقط Administrators/SYSTEM. هر candidate فقط یک candidate.json دارد؛ ACL در زمان ایجاد فایل/پوشه تنظیم می‌شود، نه با پنجرهٔ بعدی Set-Acl. root موجود با ACL/reparse نامعتبر اصلاح نمی‌شود و بازنویسی پوشه/فایل موجود مجاز نیست. فایل با CreateNew/FileShare.None و Flush(true) نوشته، readback/قالب/receipt/checksum دوباره بررسی می‌شود. محافظت ACL به معنی رمزگذاری، امضای ناشر یا دفاع در برابر administrator مخرب نیست؛ hash هم external trust/anti-rollback نیست و Flush تضمین عمومی قطع برق نیست.

دادهٔ خصوصی شامل مسیر و hash و file ID/volume/اندازه/معماری برنامه‌ها، شناسهٔ candidate، SID حساب تأییدکننده، زمان/هش nonce و digest محتواست. receipt فقط اجازهٔ ثبت انتخاب برنامه برای installer است؛ authorizes_program_execution و authorizes_firewall_change=false. phase=`programs_reviewed_destinations_pending`، destinations خالی و ready_for_apply=false؛ این فایل ورودی کامل compiler grantها نیست، نباید با افزودن approved=true به policy تبدیل شود. این root به ژورنال baseline قبلی یا root قدیمی برنامه دسترسی ندارد و baseline_linked=false باقی می‌ماند.

موفقیت سه نوبت مشاهدهٔ تازهٔ تمام EXEها دارد: پیش از بازبینی، بعد از Save محلی و قبل از نوشتن، بعد از نوشتن. هر نوبت از reader قبلی با دو SHA روی همان handle استفاده می‌کند. تغییر path/hash/identity/size/architecture، تغییر actor یا انقضای دو دقیقه باعث توقف می‌شود؛ پس از write ممکن است فایل باقی بماند و خودکار rollback/delete نمی‌شود. success یعنی ثبت و بررسی همان اجرا، نه هویت دائمی یا بستن تغییر بعدی فایل. هیچ انتخاب خودکار «آخرین candidate» یا جمع‌کردن مجوز چند candidate نداریم.

## کنترل‌های قبلی و مرز UI

ProgramReader.cs و ProgramReview.ps1 انتخاب فایل، و سه ماژول storage بایت‌به‌بایت از milestoneهای قبلی‌اند. reader fixed local path، parent pin root-to-leaf و رد reparse/چند hardlink، EXE header x86/x64، ۵۱۲MiB max و final path/metadata/two-hash دارد. این‌ها امنیت کد/ناشر یا ACL موثر فایل برنامه را اثبات نمی‌کنند. input_valid، hash و receipt اجازهٔ اجرای فایروال نیستند. بعد از آزادشدن handle فایل می‌تواند تغییر کند؛ هنگام استفادهٔ بعدی بازبینی تازه لازم است. هم‌زمان installer/update روی همان مسیر اجرا نکنید؛ pinها ممکن است عملیات متعارض را موقتاً رد کنند.

پنجرهٔ Windows ممکن است metadata/icon/recents و در صورت مرور Network دسترسی shell/شبکه داشته باشد؛ از شبکه و preview دوری کنید. ابزار خودش resolver/HTTP/WinVerifyTrust/اجرای EXE منتخب ندارد، اما صفر ترافیک سیستم با packet capture ثابت نشده است. compiler .NET ممکن است Temp/cache بنویسد و گزارش کنار بسته هم خروجی جدید است؛ پاک‌سازی متغیرها پاک‌کردن امن console/memory نیست.

## شواهد

۲۳۶ assertion ثبت/لغو، تغییر فایل پیش/پس از ثبت، انقضا/actor change، save failure/wrong head/uncertain write، فایل واقعی Linux، عدم بازنویسی، checksum/قالب/authority/partial refusal، privacy و قرارداد شبیه‌سازی‌شدهٔ JSON PS5.1 پاس شد. ۷۳ assertion ژورنال و۲۶۰ assertion picker قبلی نیز دوباره پاس شدند. فرم تأیید، file picker، Windows API فایل برنامه و ACL بومی در مدل این مرحله mock/اجرا‌نشده‌اند؛ این کد روی Windows هنوز اجرا نشده است. شش PS source و bootstrap/manifest/ZIP کنترل شده‌اند.

receipt قبلی Windows انتخاب و مشاهدهٔ یک EXE با header x86 پاس شده بود؛ storage helpers هم در fixture قبلی پاس بودند. آن‌ها اجرای این فرم/ثبت candidate یا policy اجرایی نیستند. آزمون‌های موفق قبلی را تکرار نکنید. recorder، مقصدهای هر برنامه، native Apply/recovery، SSTP binding/bootstrap/reconnect، mode switch، packet/reboot/no-leak/fingerprint همچنان آماده یا certified نیستند. ابتدا candidate نصاب، سپس destination review و گیت‌های native ادامه می‌یابند.

CMD manifest/payload را با SHA256 می‌سنجد و فقط شش PS1/PSM1 همین بسته را Unblock می‌کند؛ RemoteSigned فقط process فرزند، نه policy دائمی/GPO. -STA برای پنجره‌هاست. امضای ناشر/sandbox وجود ندارد؛ SHA256 ZIP را با مقدار تحویل مقایسه کنید.
