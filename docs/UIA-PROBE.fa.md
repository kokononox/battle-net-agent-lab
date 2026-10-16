# بررسی هدفمند UI Automation — فقط‌خواندنی

## دلیل این تغییر

گزارش واقعی [c56c036](https://github.com/kokononox/battle-net-agent-lab/blob/c56c0360e400fe14dc8ba518b37322938dc2b93e/reports/latest.json) برای source c8abd46 و run 38830493104: دو probe در حدود ۵ و ۴۵ ثانیه، session مشترک ۲، window station قابل‌مشاهده و input desktop قابل‌دسترسی. یک پنجرهٔ مرئی در کلاس ناشناخته و دو پنجرهٔ مخفی؛ کنترل native فرزند پیدا نشد. خطای probe صفر، اما Agent مشاهده نشد. پس محدودیت دسترسی سادهٔ دسکتاپ تأیید نشد و علت انتظار Setup هنوز ناشناخته است.

این تغییر فقط مسیر UIA را اضافه می‌کند تا اگر رابط سفارشی ساختار دسترس‌پذیری دارد، نام‌های مجاز صفحه/دکمه در آن شناخته شوند. این دوباره‌اسکن بازی، دریافت asset، نصب یا پذیرش توافق‌نامه نیست. schema جدید ۳ است؛ گزارش‌های schema۱/۲ تاریخی دست‌نخورده می‌مانند.

## محدودیت و حریم خصوصی

- native_gui فقط HWND/PID پنجره‌های مرئی همان processهای Setup/Agent مشاهده‌شده را به helper می‌دهد؛ خود HWND به گزارش نهایی نمی‌رود. helper از RootElement دسکتاپ اسکن عمومی نمی‌کند.
- خواندن فقط tree و metadata است. هیچ Invoke/Select/SetValue/SetFocus/Expand یا ورودی صفحه‌کلید/ماوس اجرا نمی‌شود.
- برای edit/document/custom/listitem/unknown و موارد password/offscreen، Name خوانده نمی‌شود. ValuePattern و TextPattern هم خوانده نمی‌شوند. برای Window/Pane/Text/Button و سایر نقش‌های مجاز، Name فقط در حافظه به label/marker ثابت تبدیل می‌شود؛ متن خام، AutomationId، class یا خطای provider به stdout/log/report نمی‌رود.
- حداکثر ۸ ریشه، ۶۴ عنصر، عمق ۶ و deadline داخلی سه ثانیه. helper PowerShell با STA و environment بدون token، stdin بسته، stderr دورریخته و timeout بیرونی ۱۲ ثانیه اجرا می‌شود. هر provider معطل شود، timeout با status صریح ثبت می‌شود، نه متن خطا یا نتیجهٔ فرضی.
- helper فقط JSON دارای enum/عدد/bool چاپ می‌کند؛ Python اندازه/کلیدهای دقیق/PID/label و اطلاعات حساس را کنترل می‌کند؛ publisher تمیز دوباره همین schema را بررسی می‌کند.
- بودجهٔ قبلی Windows workflow/مشاهده ۴۵ثانیه حفظ می‌شود؛ callهای محدود GUI/cleanup می‌توانند زمان کل را بیشتر کنند. cap ۱۲۸MiB فقط برای body خود installer است، نه کل شبکهٔ child.

## چه نتیجه‌ای می‌خواهیم؟

اگر UIA page/labelهای روشن مثل language/license/error را ارائه کرد، شاهد مشخص ثبت می‌کنیم؛ صرف marker را علت قطعی stall یا مجوز کلیک نمی‌نامیم. اگر UIA فقط Pane/Custom یا خروجی بدون label بدهد، نتیجه «رابط از این دو روش محتوای تشخیص‌پذیر نداده» است؛ نه اینکه زبان یا خطای خاص را حدس بزنیم. همان run بی‌تغییر دوباره اجرا نمی‌شود. نصب/کلیک/تصویربرداری یا ورود حساب نیازمند طرح جداست و بخشی از این آزمایش نیست.

در این مرحله هیچ اقدام جدیدی روی Lab کاربر خواسته نشده. منبع TagFix و پنج گزارش قبلی دست‌نخورده‌اند؛ SYNC-MANIFEST.json snapshot عملیات sync قبلی است، نه فهرست تمام تغییرات آتی. برای این تغییر UIA-PROBE-MANIFEST.json ثبت می‌شود.

## آزمون‌ها

Linux: مجموع ۵۷ تست کشف شد؛ ۵۶ موفق و یک smoke test بومی Windows به‌درستی skip شد. ۱۹ تست تازهٔ accessibility افزوده شده است. تست بومیِ بدون target روی Windows ابتدا parsing/بارگذاری UIA و JSON خالی را بررسی می‌کند؛ بعد observer فقط روی Setup رسمی اجرا می‌شود. اجرای واقعی Windows یا تشخیص صفحه قبل از دریافت گزارش معتبر ادعا نمی‌شود. تست‌های ۴۴۶تایی دانلودر در این تغییر دوباره اجرا/دستکاری نشده‌اند.
