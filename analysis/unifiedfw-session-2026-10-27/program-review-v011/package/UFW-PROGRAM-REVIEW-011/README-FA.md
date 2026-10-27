# انتخاب فایل با پنجره — UFW-PROGRAM-REVIEW-011

در این نسخه دیگر تایپ مسیر لازم نیست؛ پنجرهٔ انتخاب فایل Windows باز می‌شود. هستهٔ C# مشاهدهٔ EXE بدون تغییر بایت از نسخهٔ قبل است. این ابزار **فایل انتخابی را اجرا نمی‌کند**، program config ذخیره نمی‌کند و به firewall/VPN/journal دسترسی نمی‌خواهد.

## اجرا

1. ZIP را در پوشهٔ محلی تازه و جدا Extract کنید. شبکه و SSTP همان وضعیت فعلی بمانند؛ نه reboot و نه اجرای نصاب لازم است.
2. `Run-Review.cmd` را با دوبارکلیک معمولی اجرا کنید؛ **ادمین لازم نیست**. Windows PowerShell 5.1 x64 لازم است و CMD آن را با `-STA` برای پنجره باز می‌کند.
3. در پنجرهٔ انتخاب فایل، به پوشهٔ نصاب موجود خودتان بروید، EXE را انتخاب و **Open** را بزنید. Open در این پنجره یعنی انتخاب برای خواندن، نه اجرای نصاب. فعلاً یک فایل کافی است. اگر helper مشخص و موردنظر دیگری دارید با Ctrl چند EXE انتخاب کنید؛ حداکثر ۱۶ فایل. برنامه‌های child/helper/service خودکار انتخاب یا مجاز نمی‌شوند.
4. مسیر باید روی دیسک ثابت محلی باشد، نه Network/UNC/OneDrive reparse یا shortcut. پوشهٔ شبکه را مرور نکنید و preview را فعال نکنید. اگر فایل موجود ندارید، **Cancel** کنید؛ فایل نامربوط انتخاب نکنید.
5. پس از انتخاب، به پنجرهٔ CMD برگردید و تا نتیجه صبر کنید. فقط فایل تازهٔ `UFW-PROGRAM-REVIEW-011-*.json` را بفرستید، حتی در لغو/شکست. pause آخر CMD فقط برای بستن پنجره است؛ دیگر پرسش تایپ مسیر نداریم.

**مسیر، هش، شناسهٔ فایل، خود EXE یا عکس/متن کامل پنجره را نفرستید.** اطلاعات خصوصی فقط در پنجرهٔ محلی نمایش داده می‌شوند، نه گزارش. اگر JSON ساخته نشد فقط stage/code کوتاه را بدون مسیر خصوصی بفرستید. در شکست فایل یا تنظیمات را خودسرانه عوض نکنید.

## انتخاب و لغو

Cancel یعنی بدون فراخوانی observer هویت EXE پایان می‌یابد؛ completed=true در cancellation، موفقیت بررسی فایل نیست. خود پنجرهٔ Windows برای نمایش فهرست فایل‌ها، metadata یا icon ممکن است filesystem/shell را بخواند، مسیرهای اخیر را نگه دارد و در صورت رفتن به Network دسترسی شبکه‌ای ایجاد کند. AutoUpgrade=false، DereferenceLinks=false، ValidateNames/CheckFileExists/CheckPathExists=true و RestoreDirectory=true تنظیم شده‌اند؛ این تنظیم‌ها sandbox یا تضمین صفر شبکهٔ shell نیستند. ابزار خودش resolver/درخواست HTTP یا اجرای EXE منتخب ندارد، اما نبود ترافیک کل سیستم/handlerهای ثبت‌شده با packet capture اثبات نشده است.

تعداد نامعتبر، انتخاب بیش از ۱۶ فایل، مسیر نامعتبر یا تکراری پیش از اجرای observer روی هر EXE رد می‌شود؛ truncation خودکار نداریم. تکرار identity پس از observation هم رد می‌شود. خطای فایل میانی، ادامهٔ خواندن بقیه و ساخت config انجام نمی‌دهد؛ observed_count فقط تعداد قبلی را نشان می‌دهد و completed=false است.

## هستهٔ مشاهدهٔ بدون تغییر

local absolute exe path؛ fixed drive؛ pin والدها از root به leaf با OPEN_REPARSE_POINT و handle بدون write/delete sharing؛ رد junction/symlink/reparse/UNC/ADS/wildcard/مسیر غیرcanonical؛ فایل OPEN_EXISTING/GENERIC_READ/share READ. یک hardlink، size حداکثر ۵۱۲ MiB، PE header offset حداکثر ۱ MiB، header EXE x86/x64 و subsystem GUI/CUI. DLL و shared-hostهای شناخته‌شدهٔ svchost/rundll32/dllhost پذیرفته نمی‌شوند؛ این denylist تشخیص کامل broker نیست. PE header بررسی اولیه است، نه loader کامل یا اثبات سالم‌بودن کد.

دو SHA256 روی یک handle و مقایسهٔ file ID/volume/metadata/final path انجام می‌شود؛ handleها در using/finally آزاد می‌شوند. هم‌زمان نصاب/update روی همان فایل/مسیر اجرا نکنید؛ عملیات متعارض ممکن است موقتاً رد شود. پس از آزادسازی فایل قابل تغییر است و در Apply آینده بازبینی تازه لازم است. effective ACL/ناشر/Authenticode/ابطال/اعتماد برنامه بررسی نشده‌اند؛ hash و هویت مشاهده‌شده approval یا consent نیستند. دفاع در برابر admin/درایور مخرب یا تغییرات پیشرفتهٔ namespace تضمین نشده است.

نام و ID/hash برنامه محلی‌اند؛ پیکربندی یا مجوز دائمی ساخته نمی‌شود. picker به معنی دادن مجوز شبکه نیست. recorder، destination review، native Apply/recovery، binding/reconnect SSTP، mode switch، reboot، no-leak و fingerprint همچنان qualified نشده‌اند. آزمون‌های storage/preparation/reopen قبلی را تکرار نکنید و ژورنال محافظت‌شده را تغییر ندهید.

## شواهد و بسته

۲۶۰ assertion انتخاب/لغو/چندفایلی/حریم‌خصوصی در ۱۶ سناریوی mock پاس شدند؛ ۱۴۷ assertion نسخهٔ قبلی reader/review دوباره پاس شدند. C# همان نسخهٔ قبل است و روی Linux کامپایل شده؛ dialog واقعی Windows و Windows file API در این تست‌ها اجرا نشده‌اند. دو PS1 و bootstrap/manifest/ZIP کنترل شدند. receipt قبلی Windows فقط cancellation بدون انتخاب بود، نه موفقیت native file observation؛ این فاصله هنوز باقی است.

CMD ابتدا SHA256 manifest و payload را بررسی، فقط دو PS1 همین بسته را Unblock و RemoteSigned را فقط برای process فرزند اعمال می‌کند؛ نه policy دائمی/GPO. امضای ناشر یا sandbox نداریم؛ SHA256 ZIP را با مقدار تحویل تطبیق دهید. Add-Type از helper همین بسته استفاده می‌کند و compiler ممکن است Temp/cache بسازد؛ گزارش کنار بسته هم فایل جدید است. مشاهدهٔ محلی داخل console/memory می‌ماند و پاک‌سازی متغیرها تضمین پاک‌کردن امن حافظه/scrollback نیست.
