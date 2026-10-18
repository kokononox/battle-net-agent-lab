# G1 — ثبت HTTP در API از ابتدای پردازش

## هدف
پرکردن شکاف محتوای nydus.battle.net و us.cdn.blizzard.com بدون تکرار تنظیمات pktmon. روش جدید از send/WSASend همان پردازشِ دارای هویت/امضای تأییدشده نمونه می‌گیرد. هیچ TLS session key، packet raw یا پاسخ دریافت‌شده صادر نمی‌شود.

## gate واقعی قبل از هر Battle.net
یک Python worker متعلق به آزمایش با Frida.spawn و envp پاک ایجاد می‌شود و تا بارگذاری hook و فعال‌شدن child gating متوقف است. worker فقط به سرور 127.0.0.1 همین VM وصل می‌شود و یک child متعلق به آزمایش می‌سازد. gate باید اولین درخواست root، اولین درخواست child، ارسال چندقطعه‌ای و WSASend چندبافری را هم در API و هم در سرور loopback عیناً تطبیق دهد. send و WSASend و اینکه هر دو پردازش پیش از resume instrument شده‌اند الزامی‌اند. داده‌های synthetic جدا هستند و در evidence واقعی وارد نمی‌شوند.

وجود متد در wheel به معنی پشتیبانی Windows نیست. اگر child gating یا spawn یا اولین درخواست در Windows کار نکند، gate رد می‌شود و هیچ bootstrap Battle.net دانلود/اجرا نمی‌شود. خطا و مرحله در گزارش حفظ می‌شود؛ اجرای کورکورانهٔ دوباره مجاز نیست.

## اجرای واقعی فقط بعد از gate
فقط فراخوانی Popen همان مسیر دقیق bootstrap دانلودشده و بررسی‌شده با Frida.spawn جایگزین می‌شود. هش bootstrap ثابت de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf است؛ تغییر آن باعث توقف است. PID root و فرزندان gated با تصویر زنده، hash، WinVerifyTrust و ناشر Blizzard بررسی و هویت PID پیش از resume دوباره کنترل می‌شود. کودک ناشناخته یا ردشده اجرا نمی‌شود و خطای coverage/fatal ثبت می‌شود. این محدودیت ممکن است رفتار startup را عوض کند؛ ابزار تضمین انطباق کامل نیست.

hookهای Winsock با module observer همزمان، پیش از ادامهٔ کد برنامه نصب می‌شوند. hook فقط می‌خواند؛ argument، return، buffer، تنظیم TLS یا certificate check عوض نمی‌شود. spawn/child gating زمان‌بندی را تغییر می‌دهد. handleها فقط با alias محلی منتشر می‌شوند. close/connect استفادهٔ مجدد را تفکیک می‌کند؛ ترتیب sendهای همزمان هنوز می‌تواند مبهم باشد.

فقط streamهایی که از ابتدا HTTP قابل‌تشخیص‌اند خوانده می‌شوند و فقط Hostهای nydus، us.cdn، level3 و ocsp.digicert منتشر می‌شوند. auth/cookie header ماسک می‌شود. مسیر و body آزمایش مجازند؛ VM حساب شخصی ندارد. body/URL مقادیر دلخواه ناشناختهٔ سرویس را می‌تواند داشته باشد و ناشناس‌سازی معنایی عمومی انجام نمی‌شود.

send فقط به تعداد بایت پذیرفته‌شده در return استفاده می‌شود؛ WSASend تنها با تعداد بایت معتبر گزارش‌شده بازسازی می‌شود. completion asynchronous مشاهده نمی‌شود و ورودی pending/نامعلوم، stream را incomplete می‌کند. پذیرش API اثبات رسیدن یا ذخیره‌شدن در سرور نیست. نشانهٔ بارگذاری DLL جای callback واقعی را نمی‌گیرد.

## سقف و ایمنی
runner استاندارد windows-2025، job حداکثر۱۲ دقیقه، startup۱۲۰ثانیه، فقط انتخاب زبان قبلی؛ بدون account/login، install action، درخواست بازی، تغییر hosts یا فایل‌های کاربر. هیچ larger runner/گروه پولی فعال نمی‌شود؛ سهمیه و تعرفهٔ عادی حساب GitHub مستقل است. محیط child فاقد توکن است؛ Windows فقط read و انتشار از Ubuntu جدا با write. Frida17.24.2 و typing_extensions به hash دقیق requirements قبلی pin شده‌اند.
حداکثر۸ پردازش هدف، ۲۵۶ buffer در hook هر پردازش، هر buffer۱۶KiB، حداکثر۵۱۲ input و مجموع۱MiB خام در RAM؛ حداکثر۱۲۸ request و گزارش۲MiB. برخورد با سقف‌ها/خواندن ناقص می‌تواند داده از دست بدهد؛ نبود CPU یا درخواست اثبات پاک بودن نیست. raw bufferهای میانی منتشر نمی‌شوند. ابزار child سقف سخت دانلود شبکه ندارد؛ دانلود بازی درخواست نمی‌شود.

## QA و provenance
۱۴ تست محلی API/gate failure و ۴۲ تست پارسر مشترک HTTP پاس شدند؛ JS syntax و Python compile و YAML runner/permission/message guards بررسی شدند. این‌ها اثبات native Windows نیستند؛ gate بومی در همان اجرای واقعی، پیش از هر bootstrap شرط مستقل است. دو خطای محلی module path و YAML پیش از push کنترل شدند.
فقط شاخهٔ پژوهشی و پیام commit دقیق و attempt=1 اجرا را فعال می‌کنند. خروجی: reports/startup-api-g1.json و bootstrap اختیاری. در صورت رد gate، bootstrap report وجود ندارد و این انتظار ایمن است.
