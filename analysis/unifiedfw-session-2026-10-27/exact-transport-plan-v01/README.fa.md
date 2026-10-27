# طرح آفلاین حمل دقیق SSTP — نسخهٔ ۰٫۱

هدف: پس از مشاهدهٔ موفق endpoint، مرز «IP مشاهده‌شده» و «مقصد صریحاً بازبینی‌شده» را در قرارداد کد جدا کنیم؛ بدون ادعای approval یا اجرای هیچ قاعده‌ای. این توسعه فقط برای فونداسیون ابزار کوچک نصاب Battle.net است.

## آنچه پیاده شد

`Sstp.TransportPlan.ps1` یک سازندهٔ draft خالص است. ورودی محدود به schema، GUID پروفایل، scope، SID صاحب، نام/آدرس سرور و حداکثر ۸ IP دقیق است. نام خام پروفایل و physical adapter/index در ورودی نیست. دادهٔ واقعی کاربر در نمونه/آزمون ذخیره نشده؛ همهٔ داده‌ها fixture مستند هستند.

برای هر IP، template غیرقابل‌اجرای Outbound/TCP/443 با service=SstpSvc و token مسیر svchost سیستم می‌سازد؛ token مسیر باید در adapter بومی معتبر resolve شود و مسیر ساختگی قابل اجرا نیست. interface Any فقط برای حمل دقیق VPN است، نه مجوز عمومی 443 یا دادهٔ برنامه. ترافیک برنامه همچنان تنها روی binding تازه و تأییدشدهٔ SSTP مجاز به طراحی است؛ این ماژول آن قانون را اجرا یا تولید نمی‌کند.

CIDR حتی /32، بازه، wildcard، آدرس loopback/unspecified/multicast/link-local، IPv4 مبهم، mapped/scoped IPv6، pin تکراری و ورودی اضافهٔ approved/cache_correlated رد می‌شوند. IPv4 خصوصی یا IPv6 ULA ذاتاً رد نمی‌شوند چون مقصد خصوصی می‌تواند عمدی باشد؛ پذیرش قالب، تأیید مقصد یا دسترس‌پذیری نیست. hostname با IP جایگزین نمی‌شود و TLS bypass نداریم. literal server باید دقیقاً همان تک IP باشد.

digest به GUID/scope/SID/server/IPها وابسته و از ترتیب pinها مستقل است. **digest امضا، رضایت کاربر، اثبات هویت یا مرجع اعتماد نیست.** endpoint_approval_status همیشه not_verified است. JSON کاربر، cache و boolهای ادعایی منبع approval نیستند. سازنده حتی با ورودی سالم همیشه plan_executable=false و ready_for_apply=false دارد.

نمونهٔ تولیدشده شامل metadata خام ورودی است و **فایل sanitized تشخیصی نیست**؛ اگر بعداً برای ورودی واقعی فراخوانی شود، آن را خودکار export/commit نکنید. ذخیره‌سازی امن، تأیید انسانی متصل به نمایش دقیق مقصد، جلوگیری از تعویض فایل و بازاعتبارسنجی native هنوز پیاده نشده‌اند. ورودی از گزارش sanitized اخیر قابل بازسازی نیست؛ آن گزارش IP/GUID/SID واقعی را منتشر نکرده است.

## شواهد

۸۶ assertion در Linux/PowerShell7 گذشت؛ شامل محدودیت مقصد، نقش hostname، literal mismatch، digest، عدم پذیرش approval ساختگی و AST command allowlist است. ماژول هیچ cmdlet شبکه، DNS، فایل یا فایروال فراخوانی نمی‌کند؛ hash در حافظه است. فقط Test script نتیجهٔ مدل را به فایل می‌نویسد. Windows، کارایی، packet، cold-start یا reconnect با این تست‌ها تأیید نمی‌شوند.

این کد روی candidate/guardian نصب نشده و برای اجرای کاربر بستهٔ Windows جدیدی ندارد. مدل موجود reconnect بدون تغییر باقی مانده؛ flags آن نباید از input_valid یا digest این draft به true تبدیل شوند.

## گام بعد

[طرح پیش‌نیازهای اتصال](BOOTSTRAP-GATES.fa.md) مرزهای باقی‌مانده را مشخص می‌کند. adapter ثبت بازبینی محلی و اثبات محدودیت سرویس/قواعد، resolution نام با VPN خاموش و وابستگی‌های گواهی هنوز ساخته/تأیید نشده‌اند. هیچ Apply/Restore یا آزمون زندهٔ قطع/وصل لازم نیست؛ اقدام تازه‌ای از کاربر فعلاً لازم نیست.
