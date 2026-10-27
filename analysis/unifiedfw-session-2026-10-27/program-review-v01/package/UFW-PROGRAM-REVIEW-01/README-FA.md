# مشاهدهٔ محلی فایل برنامه — UFW-PROGRAM-REVIEW-01

این بسته مسیرهای EXE را از خود شما می‌گیرد و فقط فایل را می‌خواند. هیچ‌یک از فایل‌های انتخاب‌شده اجرا نمی‌شوند؛ هیچ firewall/VPN/DNS/route/rule/task یا journal خوانده/تغییر داده نمی‌شود. **این انتخاب یا نمایش، مجوز اعتماد/Apply نیست و config برنامه هم ذخیره نمی‌شود.** هدف این گام، آزمودن مشاهدهٔ بومی فایل‌های واقعی پیش از اتصال آن به پلن برنامه‌محور است.

## اجرا

1. در پوشهٔ محلی تازه و جدا از برنامهٔ قدیمی/بسته‌های قبلی Extract کنید. شبکه/SSTP همان وضعیت بمانند؛ reboot یا اجرای برنامهٔ نصاب لازم نیست.
2. `Run-Review.cmd` را با دوبارکلیک معمولی اجرا کنید. **Run as administrator لازم نیست**؛ Windows PowerShell 5.1 x64 لازم است. همان حسابی که به فایل نصاب دسترسی دارد کافی است.
3. وقتی مسیر خواست، مسیر کامل EXE نصاب موجود روی سیستم آزمایشی را وارد کنید، مثلاً فایل واقعی Battle.net-Setup.exe خودتان؛ مسیر نمونهٔ فرضی وارد نکنید و فایل را اجرا نکنید. اگر مسیر را در گیومه وارد کنید فقط جفت گیومهٔ بیرونی حذف می‌شود؛ whitespace اضافی/متغیر محیطی یا مسیر نسبی اصلاح نمی‌شوند.
4. فعلاً یک EXE شناخته‌شدهٔ نصاب کافی است. فقط اگر helper مشخص و موردنظر دیگری دارید مسیرش را جدا وارد کنید؛ child/helper/service خودکار شناسایی یا مجاز نمی‌شود. حداکثر ۱۶ فایل؛ Enter خالی انتخاب را تمام می‌کند. Enter در ابتدای کار بدون خواندن EXE لغو می‌کند.
5. جدول خصوصی مسیر/هش/شناسهٔ فایل را فقط محلی ببینید. تا نمایش نتیجه صبر کنید و فقط JSON تازهٔ `UFW-PROGRAM-REVIEW-01-*.json` را بفرستید، حتی در لغو/شکست. پنجرهٔ CMD در پایان فقط pause دارد.

**مسیر، هش، شناسهٔ فایل، خود EXE و عکس/متن کامل پنجره را نفرستید.** اگر JSON ساخته نشد، فقط stage/code کوتاه را بدون مسیر خصوصی بفرستید. در شکست، فایل یا تنظیمات را تغییر ندهید؛ کد خطا کافی است. اگر نصاب موجود/مسیرش را ندارید Enter بزنید؛ برای pass فایل ساختگی یا برنامه‌ای نامربوط انتخاب نکنید.

## کنترل‌های پیاده‌شده

- ورودی local absolute با drive uppercase، exe، بدون UNC/device path/ADS/wildcard/environment expansion، segment نقطه/فضای انتهایی یا نام رزروشده؛ fixed local drive. فایل ابری reparse، junction، symbolic link و مسیر alias غیرcanonical در نسخهٔ فعلی رد می‌شوند، نه اینکه خودکار دنبال/کپی شوند. نام‌های shared-host شناخته‌شدهٔ svchost/rundll32/dllhost به طراحی service-scoped جدا نیاز دارند و رد می‌شوند؛ این فهرست تشخیص کامل broker نیست.
- parent directory handleها از root به leaf با OPEN_REPARSE_POINT و BACKUP_SEMANTICS باز می‌شوند؛ reparse پیش از پایین‌رفتن رد می‌شود و handleها تا پایان مشاهده بدون write/delete sharing نگه داشته می‌شوند. اگر pin ممکن نباشد توقف می‌کند. فایل هم OPEN_EXISTING با GENERIC_READ و share READ، بدون write/delete sharing، باز می‌شود. همهٔ handleها در finally/using بسته می‌شوند. در مدت خواندن، عملیات متعارض روی همان فایل/پوشه ممکن است موقتاً رد شود؛ هم‌زمان installer/update روی این مسیر اجرا نکنید.
- final path باید با مسیر انتخابی برابر باشد؛ directory/reparse و بیش از یک hardlink رد می‌شوند. size حداکثر ۵۱۲ MiB، PE header offset حداکثر ۱ MiB؛ EXE header x86/x64 و subsystem GUI/CUI پذیرفته می‌شود. DLL/native subsystem/معماری دیگر/ساختار نامعتبر رد می‌شود. بررسی PE فقط کنترل اولیهٔ header است، نه loader کامل یا اثبات قابل‌اجرابودن/سلامت کد.
- دو SHA256 روی همان handle، همراه با تطبیق file index/volume/size/mtime/creation/attributes/link count و final path. parentها در تمام مشاهده pinned هستند؛ مشاهدهٔ تغییر باعث توقف است. هویت و hash داخل حافظه و پنجرهٔ محلی‌اند؛ report فقط شمارنده، معماری header و flags محدود دارد. actual ACL/effective write authority و Authenticode/trust بررسی نمی‌شوند؛ revalidation هنگام Apply آینده الزامی است.

## مرزها

فایل درست و دو هش مساوی **به معنی معتبر/ایمن‌بودن ناشر یا برنامه نیست**. ابزار Get-AuthenticodeSignature/WinVerifyTrust یا اعتبارسنجی آنلاین امضا/ابطال را صدا نمی‌زند، تا این گام درخواست عمدی شبکه نداشته باشد؛ absence ترافیک سیستم با packet capture اثبات نشده است. درایور مخرب/admin مخرب یا تغییر namespace پیشرفته خارج از ضمانت این مشاهده‌اند. پس از آزادشدن handle فایل می‌تواند تغییر کند؛ output، pin دائمی یا consent نیست.

بررسی native API به خودی خود گزارش شبکه یا تشخیص فرآیندهای فرزند نیست. برنامه‌های مورد نیاز واقعی، destination review و recorder هنوز باید به مسیر بعدی متصل شوند. private config ساخته نمی‌شود؛ انتخاب path در مرحلهٔ بعد ممکن است دوباره لازم شود و در هر Apply آینده هویت فایل باید تازه بررسی شود. این نسخه صرفاً observer است، نه تکمیل recorder یا پروفایل قابل‌اعمال.

CMD manifest و payload را با SHA256 کنترل و فقط دو PS1 همین بسته را Unblock می‌کند؛ .cs فقط به‌صورت متن خوانده می‌شود. RemoteSigned فقط process فرزند است، نه policy دائمی/GPO. هیچ بسته‌ای sandbox یا امضاشدهٔ ناشر نیست؛ SHA256 ZIP را با مقدار تحویل تطبیق دهید. Add-Type helper همین بسته را با کامپایلر .NET می‌سازد و ممکن است فایل‌های موقت compiler/cache در Temp ایجاد کند؛ EXE انتخابی شما اجرا نمی‌شود. گزارش کنار بسته هم یک فایل جدید است. پاک‌کردن متغیرها تضمین پاک‌شدن فیزیکی حافظه/console نیست؛ از screenshot/transcript خودداری کنید.

## شواهد

۱۴۷ assertion روی Linux/PowerShell7 پاس شده: کامپایل واقعی C# با ساختار سازگار C# قدیمی، fixtureهای path/PE، metadata-drift شبیه‌سازی‌شده، review/prompt/native observation mock، لغو/حداکثر/duplicate/failure/privacy و static boundary. این آزمون‌ها API واقعی Windows یا parent pin/هویت فایل واقعی/سازگاری runtime WinPS5.1 را اجرا نکرده‌اند. package guard روی Linux پیش از انتخاب متوقف شد؛ دو PS1 و CMD parse و hashها کنترل شده‌اند. نتیجهٔ Windows این observer هنوز pending است؛ نه native firewall write، SSTP، mode-switch، reboot، no-leak یا جلوگیری از fingerprint تأیید نشده‌اند.

آزمون‌های قبلی storage/preparation/reopen موفق‌اند و تکرار نمی‌شوند. فقط این مرحلهٔ جدید به هویت فایل برنامه مربوط است. ژورنال محافظت‌شدهٔ قبلی را نگه دارید؛ هیچ Apply/Restore/تغییر Allow لازم نیست.
