# G58 — attach دوطرفه و تشخیص شکاف پردازش

نسخه RC کاربر دست‌نخورده است. آزمایش فقط روی VM موقت گیت‌هاب با pin/امضای همان نصب‌کننده و همان gate IP دو مقصد و استثناهای مدیریت CI اجرا می‌شود. guard یک‌باره صفحه زبان حفظ شده؛ Install/ورود/شروط/نصب بازی کلیک نمی‌شود.

## مشاهده دوطرفه
ناظر علاوه بر ورودی HttpSendRequestA پس از return، ورودی قبل از call را هم مستقل ثبت می‌کند تا call معلق با نبود درخواست اشتباه نشود. begin و completion شناسهٔ ترتیبی دارند؛ این دو ردیف را دو درخواست شبکه حساب نکنید.

InternetReadFile و InternetReadFileExA/W فقط پس از return موفق، با تعداد بایت واقعی و buffer معتبر مشاهده می‌شوند. linked INTERNET_BUFFERS و async ناقص گزارش شکاف دارند و به‌عنوان متن کامل پاسخ صادر نمی‌شوند. response metadata به server ثبت‌شده همان request handle نسبت داده می‌شود؛ automatic redirects، Unicode request APIs و handleهای پیش از attach پوشش کامل ندارند. پاسخ خام در حافظه است؛ فقط اندازه و قالب محدود، بدون مقدار فیلدها صادر می‌شود. HTTP، JSON و TACT chunk هم نبود اطلاعات شخصی در درخواست را ثابت نمی‌کنند.

کنترل مثبت در x86/x64، ورودی POST مصنوعی با receiving-server دقیق و پاسخ معلوم دو تکه را در InternetReadFile و InternetReadFileExA آزمایش می‌کند. سرور فقط loopback است و هیچ TLS fixture اجرا نمی‌شود؛ بنابراین موفقیت این کنترل اثبات «رمزگشایی TLS واقعی» نیست. اعتبارسنجی TLS کلاینت واقعی دست‌نخورده است. پاسخ‌های WinINet در صورت استفادهٔ کلاینت از HTTPS در لایهٔ API مشاهده می‌شوند، نه با شکستن TLS.

## پردازش و UI
snapshot فقط‌خواندنی، فرایندهای هدف/مسیر Battle.net یا Blizzard/فرزندان PIDهای مشاهده‌شده و socketهای TCP متعلق به IPهای هدف را با PIDهای تحت hook مقایسه می‌کند. command line جمع نمی‌شود و path خام خصوصی می‌ماند. فقط process تازه با امضای معتبر بلیزارد، image/hash تأییدشده و handle نگه‌داشته‌شده برای هویت، late attach می‌شود و به Job کنترل‌شده افزوده می‌شود. late attach دادهٔ گذشته را برنمی‌گرداند؛ فعالیت brokerهای سیستم به بتل‌نت نسبت داده نمی‌شود. شکست identity/job/attach موفقیت پوشش محسوب نمی‌شود.

کدهای ثابت BLZ و چند طبقهٔ عبارت خطا از متنِ همین کنترل‌های visible و مجاز استخراج می‌شود؛ متن خام UI و مسیر کمک/URL صادر نمی‌شود. همان محدودیت‌های UIA و provider باقی‌اند. هیچ کنترل Edit/password/Document خوانده نمی‌شود.

## منابع ساختار و flags
https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_buffersa
https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfileexa
https://learn.microsoft.com/en-us/windows/win32/wininet/api-flags
