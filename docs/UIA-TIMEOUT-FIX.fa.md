# اصلاح timeout تست Windows و گزارش شکست

## شاهد واقعی

اسکرین‌شات کاربر از [run 38834184617 / observe](https://github.com/kokononox/battle-net-agent-lab/actions/runs/38834184617/job/116759456274) نشان می‌دهد مرحلهٔ Test safety and sanitization rules با ۵۷ تست و یک error به دلیل timeout پردازهٔ PowerShell پس از ۱۲ ثانیه شکست خورده است. مرحلهٔ Observe signed bootstrapper صفر ثانیه و skipped است؛ پس این run اصلاً Setup را اجرا نکرده. FileNotFoundError گزارش و نبود artifact در publish پیامد شکست تست‌اند.

این شاهد ثابت نمی‌کند خود UIA، بارگذاری اسمبلی یا startup PowerShell کدام‌یک کند/معطل بوده؛ محل داخلی توقف هنوز معلوم نیست. آن را به Battle.net، شبکهٔ بازی یا Lab کاربر نسبت نمی‌دهیم.

## تغییر هدفمند

مسیر UIA دیگر PowerShell اجرا نمی‌کند. منطق فقط‌خواندنی مشابه در `uia_readonly.cs` قرار دارد؛ با compiler موجود .NET Framework روی runner، بدون دریافت پکیج/شبکه ساخته و به‌صورت پردازهٔ STA مستقل اجرا می‌شود. compiler حداکثر ۳۰ ثانیه و helper حداکثر ۱۲ ثانیه فرصت دارند. باینری فقط در temp خصوصی runner ساخته می‌شود، بین پردازه‌ها از EXE موجود ارث نمی‌بریم و هیچ باینری آپلود نمی‌شود.

C# فقط HWND/PIDهای native مجاز، tree و metadata را می‌خواند؛ بدون UI action، Value/Text pattern، screenshot یا raw name export. محدودیت ۸ ریشه/۶۴ عنصر/عمق۶/سه‌ثانیهٔ داخلی و نگاشت label/marker ثابت حفظ شده است. اسکریپت `.ps1` قبلی صرفاً تاریخچهٔ منبع است و دیگر فراخوانی نمی‌شود. PowerShell مورد استفاده برای Authenticode، همان مسیر مستقل قبلی است؛ امضا/ناشر قبل از اجرای Setup همچنان الزامی‌اند.

**تست بومی Windows حذف، skip یا موفق فرض نشده است.** روی Windows باید واقعاً compiler/helper را با target خالی اجرا کند و خروجی امن ok بگیرد. شکست آن همچنان Setup را مسدود می‌کند.

## گزارش هنگام شکست، نه فقط هنگام موفقیت

Workflow اکنون `run_safety_tests.py` را اجرا می‌کند. اگر تستی شکست خورد، exit code همچنان ۱ است و مرحلهٔ Setup اجرا نمی‌شود، اما یک گزارش schema4 با phase=safety_tests و error_code=safety_test_suite_failed ساخته می‌شود. فقط تعداد تست‌ها، ID محدود تست، نوع خطای مجاز و کد toolchain از enum ثابت منتشر می‌شوند؛ خطای compiler در حد کدهایی مثل CS0006 مجاز است، نه متن، مسیر، command یا traceback.

همان validator سخت‌گیر و writer تمیز قبلی این گزارش شکست را هم کنترل و منتشر می‌کنند. بنابراین برای این نوع شکست لازم نیست هر بار از کاربر تصویر لاگ بخواهیم. این تضمین شامل قطع کامل runner، checkout ناموفق یا خرابی خود validator نمی‌شود.

## اعتبارسنجی و حدود نتیجه

Linux: ۶۷ تست کشف، ۶۶ موفق، یک تست صرفاً بومی Windows اجرا نشده. ده تست تازه برای حفظ انسداد ایمن، گزارش timeout بدون متن حساس، compiler/runtime failure و schema افزوده شده است. smoke check Windows و اجرای واقعی UIA پس از push باید از گزارش منشأدار بررسی شوند؛ رفع timeout یا تشخیص صفحه از قبل ادعا نشده است.

کد دانلودر، Lab، بازی و checkpoint کاربر تغییر نکرده‌اند؛ prepare/اسکن/دانلود تازه درخواست نشده است.

## نتیجهٔ واقعی اجرای اصلاح‌شده

گزارش [b5414e6](https://github.com/kokononox/battle-net-agent-lab/blob/b5414e65c35f39410127aea916f208ac79488729/reports/latest.json) برای source 535fc827 / run 38835800120: تمام ۶۷ تست روی Windows موفق شدند، skip صفر؛ بنابراین compiler و smoke واقعی UIA با target خالی از مانع قبلی گذشتند. این به معنی خوانده‌شدن پنجرهٔ واقعی Setup نیست.

Installer با همان hash و اندازهٔ ۴٬۸۹۶٬۴۶۴ بایت دریافت شد، اما مرحلهٔ مستقل installer_signature با TimeoutExpired در helper قدیمی PowerShell (مهلت ۶۰ ثانیه) متوقف شد. Setup اجرا نشد، GUI نمونه‌ای ندارد و امضا دور زده نشد. علت داخلی timeout، از startup/runtime تا revocation/network، هنوز تفکیک نشده است. گام بعد فقط رفع/بررسی مسیر معتبر Authenticode است؛ افزایش کورکورانهٔ زمان، اجرای بدون امضا یا انتخاب publisher از رشته‌های فایل مجاز نیست. نتیجهٔ ساختاریافته در UIA-TIMEOUT-FIX-RESULT.json ثبت شده است.
