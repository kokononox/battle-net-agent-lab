# بررسی بومی Authenticode بدون PowerShell

## دلیل تغییر

در [گزارش b5414e6](https://github.com/kokononox/battle-net-agent-lab/blob/b5414e65c35f39410127aea916f208ac79488729/reports/latest.json)، هر ۶۷ تست Windows موفق شد ولی Get-AuthenticodeSignature در پردازهٔ قدیمی PowerShell پس از ۶۰ ثانیه timeout داد. Setup اجرا نشد. علت داخلی آن timeout از روی گزارش تفکیک نشده؛ این تغییر مشکل شبکه یا خرابی امضای Blizzard را از پیش فرض نمی‌کند.

## قرارداد امنیتی جدید

- helper مستقیم .NET، WinVerifyTrust را با `WINTRUST_ACTION_GENERIC_VERIFY_V2` فراخوانی می‌کند. فقط return value دقیقاً صفر معتبر است؛ positive warning یا HRESULT SUCCEEDED مجوز نیست.
- UI خاموش: WTD_UI_NONE و INVALID_HANDLE_VALUE. امضای فایل، زنجیره و policy ویندوز بررسی می‌شود؛ revocation با WTD_REVOKE_WHOLECHAIN و CHAIN_EXCLUDE_ROOT روشن است و MD2/MD4 غیرفعال‌اند. هیچ fallback بدون revocation، cache-only برای دورزدن شبکه، نصب root یا تغییر trust store نداریم.
- publisher از certificate برگ اولِ signer در **همان state تأییدشدهٔ WinVerifyTrust** خوانده می‌شود؛ نه از رشته‌های EXE، filename، issuer، countersigner یا certificate مستقلِ استخراج‌شده از فایل. subject ساده با فهرست دقیق قبلی Blizzard مقایسه می‌شود. نبود state/signer/certificate/subject به معنی عدم تأیید publisher و عدم اجراست.
- فایل هنگام verification با FileShare.Read باز می‌ماند و handle همان فایل در WINTRUST_FILE_INFO قرار می‌گیرد؛ تغییر/حذف هم‌زمان از طریق share عادی Windows مجاز نیست. این با یک sandbox امنیتی کامل در برابر مهاجم privileged برابر نیست.
- state همیشه با WTD_STATEACTION_CLOSE آزاد می‌شود. DLLهای verification فقط از System32 بارگذاری می‌شوند؛ helper/محتوای certificate هیچ برنامه‌ای را اجرا نمی‌کنند.
- deadline پردازهٔ verifier همچنان ۶۰ ثانیه است؛ افزایش کورکورانه انجام نشده. timeout یا خطای API/JSON/ناشر/امضا اجرای Setup را مسدود می‌کند. شبکهٔ revocation ممکن است لازم باشد؛ صفر بودن ترافیک یا قطع‌ناپذیری را تضمین نمی‌کنیم.

## گزارش و سازگاری

schema5 مقدار backend را ثبت می‌کند. امضای موفق/ناموفق شامل همان سه bool قبلی و `winverifytrust_status` عددی است؛ native helper فقط status عددی و تأیید publisher را به Python می‌دهد، بدون نام subject، مسیر، certificate یا raw exception. validator تطبیق boolها با کد صفر را کنترل می‌کند. گزارش‌های schema4 قدیمی بازنویسی نمی‌شوند.

اجازهٔ اجرای Setup فقط وقتی صادر می‌شود که **امضای معتبر و publisher مورد انتظار هر دو تأیید شده باشند**. helperهای WTHelper مستندند ولی Microsoft امکان تغییر/عدم دسترسی آن‌ها را یادآوری کرده است؛ ABI و اجرای بومی روی Windows مقصد تست می‌شوند و نبود API/ساختار قابل‌فهم باعث fail-closed است، نه fallback ضعیف.

## آزمون‌ها

Linux: ۸۲ تست کشف، ۷۸ موفق و چهار تست بومی فقط روی Windows اجرا می‌شوند. ۱۵ تست جدید شامل zero-only trust، رد publisher نامعتبر/پاسخ ناسازگار، stdin/environment/deadline، JSON و fields حساس، gate گزارش، سیاست revocation/cleanup و منبع signer هستند.

چهار تست بومیِ الزامی روی Windows شامل smoke قبلی UIA و سه تست جدید است: ABI ساختارها، رد helper واقعاً بدون امضا، و رد فایل ساختگی با نام/متن Blizzard. این‌ها تست مثبت ناشر Blizzard یا موفقیت بررسی پنجرهٔ واقعی نیستند؛ مورد مثبت در دریافت رسمی بعدی فقط از نتیجهٔ actual WinVerifyTrust پذیرفته می‌شود. تست Windows حذف یا موفق فرض نشده است.

منبع دانلودر، Lab و فایل‌های بازی تغییر نکرده‌اند؛ این عملیات نصب/آپدیت بازی نیست و درخواست تست تازه از کاربر ندارد.

## مستندات رسمی مبنا

- [WinVerifyTrust: Authenticode policy و فقط صفر به معنی موفقیت](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [WINTRUST_DATA: UI، revocation، flags و بستن state](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)
- [WINTRUST_FILE_INFO: path و handle](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info)
- [WTHelperProvDataFromStateData](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelperprovdatafromstatedata)
- [WTHelperGetProvSignerFromChain](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain)
- [CRYPT_PROVIDER_SGNR](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr) و [CRYPT_PROVIDER_CERT](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_cert)
- [CertGetNameStringW: subject simple display type](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringw)

## نتیجهٔ واقعی اجرای Windows

گزارش [b4e3ee2](https://github.com/kokononox/battle-net-agent-lab/blob/b4e3ee257209a2443ba01796f57780de01fef111/reports/latest.json) برای source 3a9fa21 / run 38837055113: هر ۸۲ تست Windows موفق، skip صفر؛ WinVerifyTrust دقیقاً صفر، امضای معتبر و publisher مورد انتظار true. Setup واقعاً اجرا شد و هر دو بررسی UIA در حدود ۵ و ۴۶ ثانیه صفحهٔ select_language، گزینهٔ english_us و دکمهٔ continue را نشان دادند؛ errors=0 و truncated=false. state انتخاب فعلی زبان خوانده نشده است.

هیچ کلیک/selection انجام نشد. Agent process/binary مشاهده نشد و نصب کامل اثبات نشده است. نتیجه نشان می‌دهد در این بازه Setup روی صفحهٔ انتخاب زبان مانده؛ تضمین نمی‌کند عبور از آن به‌تنهایی Agent را آماده می‌کند. گام پیشنهادی بعدی صرفاً انتخاب زبان و Continue در VM دورریختنی و توقف/بررسی صفحهٔ بعد است؛ پذیرش توافق‌نامه، ورود حساب یا دانلود بازی بخشی از آن نیست و هنوز اجرا نشده. منبع و Lab دانلودر کاربر بدون تغییر است.

NATIVE-AUTHENTICODE-MANIFEST.json snapshot تغییر قبل از نتیجهٔ اجراست، نه فهرست تمام به‌روزرسانی‌های مستندات بعدی.
