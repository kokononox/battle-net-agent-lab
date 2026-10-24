# تحویل جلسه — ادغام SSTP Whitelist و چندبرنامه‌ای Blacklist

این یادداشت مرجع ادامهٔ همین مسیر است؛ سابقهٔ دانلودر، تحلیل باینری و آزمایش‌های Battle.net در اسناد قبلی حفظ شده و این کار نتیجهٔ آن‌ها را تغییر نمی‌دهد. فقط روی شاخهٔ `analysis/entry-loader-startup-2026-10-23` ثبت می‌شود؛ `main` تغییر نکرده است.

## وضعیت فعلی به یک جمله

**نسخهٔ ۰.۸.۱ واقعاً روی ویندوز اجرا شده، هر ۱۲۶ probe ثبت شده و بازیابی قواعد/برابری خط مبنا تأیید شده است؛ ولی یک timeout اتصال TCP در آخرین ماتریس پس از Restore باعث توقف با نتیجهٔ `inconclusive` شده است. قبولی کامل هم‌زیستی و حفاظت نهایی هنوز نداریم.**

[رسید پالایش‌شدهٔ اجرای آخر](../reports/unifiedfw-session-20261024/windows-081-review.json) · [وضعیت ماشین‌خوان جلسه](UNIFIED-FIREWALL-SESSION-2026-10-24.json) · [سورس ۰.۸.۱](../analysis/unified-firewall-https-paced-lab-0.8.1-2026-10-24/README.fa.md).

## هدف و معماری

- هدف کاربر: یک برنامهٔ جامع برای وایت‌لیست SSTP و بلک‌لیست چند EXE، بدون خنثی‌کردن بلاک صریح توسط مجازبودن IP در وایت‌لیست.
- UI اصلی فعلی **PowerShell Windows Forms** در `app/ui.ps1` است؛ Tkinter مربوط به ابزار دیگر است و چارچوب این برنامه تعویض نشده است. Python backend و PowerShell NetSecurity برای قواعد/بازیابی استفاده می‌شوند. EXE واحد امضاشده هنوز آماده نیست.
- مدل backend انتخاب چند EXE (حداکثر ۳۲، مسیر canonical و SHA256) را می‌پذیرد؛ این به معنی تکمیل مهاجرت همهٔ امکانات رابط ابزار قدیمی نیست.
- وایت‌لیست با Block مکمل روی `RemoteAccess` ساخته می‌شود؛ بلک‌لیست Block صریح مختص EXE با `Any` interface است. Allow جبرانی برای خنثی‌کردن Block نداریم.
- فعال‌سازی وایت‌لیست سراسری همچنان gated است؛ `full_isolation`/kill-switch پیاده‌سازی/تأیید نشده است. دکمه‌های Apply عمومی GUI فعال نشده‌اند.
- دو مهارت پیشنهادی کاربر بررسی شدند؛ `improve-powershell-winforms-ui` برای مرحلهٔ بعدی UI مناسب است. این جلسه بازطراحی UI، تغییر framework یا تست DPI/نمایش Windows انجام نشده است. فارسی RTL برای متن و LTR بدون تغییر برای مسیر/IP، حفظ انتخاب پایدار و WinPS5.1/BOM از ملاحظات بعدی‌اند.

## نسخه‌ها و شواهد، بدون خلط محیط‌ها

1. **۰.۵.۱:** اصلاح Package=null در native adapter، بازیابی دقیق orphan شناخته‌شده و self-test دو تصویر در گزارش ویندوز تأیید شد. آزمون بسته‌ها در آن مرحله نبود.
2. **۰.۶.۱:** آزمون واقعی blacklist-only روی IPv4 TCP برای دو EXE بسته و مرجع مستقل موفق بود؛ منع فقط A، فقط B، هر دو و بازیابی کامل ثبت شدند. این نتیجه را به وایت‌لیست/UDP/IPv6 تعمیم ندهید.
3. **۰.۷.۰:** ماتریس محدود هم‌زیستی افزوده شد؛ نسخهٔ تحویلی Windows-qualified نبود. ایراد child admission بین `traffic-jobs` و `coexistence-jobs` در ۰.۸.۰ اصلاح و با entry-point regression پوشش داده شد. خطای اجرای child نباید موفقیت بلاک محسوب شود.
4. **۰.۸.۰:** پاسخ‌دهندهٔ کوچک PHP روی سایت تحت کنترل کاربر، جای نیاز به raw TCP server مجزا را گرفت. GET health و POST challenge با TLS معتبر روی ویندوز کاربر موفق بودند؛ DNS با IP منتخب تطبیق داشت. پیش‌بررسی، route منتخب را با SSTP متصل منطبق دید؛ این packet-path proof نیست.
5. اجرای هم‌زیستی ۰.۸.۰ اول همهٔ مراحل را پیمود، ولی یک timeout مرجع باعث `inconclusive` شد؛ بازیابی کامل بود. اجرای دوم در phase بدون قاعده به‌علت timeout اتصال متوقف شد و اصلاً rule mutation نداشت. پس از آن یک endpoint check دوباره موفق بود. هیچ‌کدام قبولی هم‌زیستی محسوب نمی‌شوند.
6. **Connectivity Diagnostic ۰.۱.۰ مستقل:** بدون تغییر فایروال/VPN/route، شش اتصال برای هر A/B/REF، جمعاً ۱۸، با فاصلهٔ چهار ثانیه موفق شد. Python 3.13.12 و Windows PowerShell 5.1 در گزارش ثبت شدند. پوشه و مسیر EXE آن با بستهٔ ۰.۸.۰ فرق داشت؛ نتیجه علت timeout را مشخص نکرد.
7. **۰.۸.۱:** فاصلهٔ monotonic حداقل چهار ثانیه میان پایان probe و شروع بعدی، در تمام ماتریس‌ها و مرز Restore، اضافه شد. بودجهٔ TCP همان سه ثانیه، اجرای child همان ۱۲ ثانیه و retry صفر است. بعد از مکث و پیش از هر probe نیز route بررسی می‌شود. هستهٔ سیاست، admission و native journal/restore byte-identical با ۰.۸.۰ مانده است.
8. تست‌های توسعهٔ ۰.۸.۱: **۱۳۲ روش Python، ۷۱۳ assertion PowerShell و parse ۲۸ فایل PS** موفق؛ provider/network/clock doubles از اجرای واقعی Windows جدا هستند. TLS واقعی فقط در localhost Linux برای تست مثبت/رد نام و CA اجرا شد؛ هیچ site deployment توسط عامل انجام نشد.

## اجرای واقعی ۰.۸.۱ — نتیجهٔ دقیق

- آرشیو گزارش و همهٔ اعضای درج‌شده در manifest SHA256 تطبیق داده شدند؛ دادهٔ خام خصوصی منتشر نشده است.
- `read_only=false`، `firewall_mutation_attempted=true`، ۷ phase و ۱۲۶ row وجود دارد؛ شماره‌های سراسری صفر تا ۱۲۵ درست‌اند و تمام ۱۲۵ فاصلهٔ بعد از اول حداقل ۴۰۰۰ میلی‌ثانیه ثبت شده‌اند. retry صفر مانده است.
- baseline، WL شامل مقصد، WL خارج از مقصد، WL شامل مقصد همراه BLِ A/B/هر دو، و WL خارج از مقصد همراه BLِ A در phaseهای during الگوی مورد انتظار داشتند.
- تنها mismatch اتصال مجاز، **REF در round=2 ماتریس `after_restore` از phase آخر `wl_denies_bl_A`** است. `pacing_sequence=123`، `connected=false`، `tls_verified=false`، `http_status=null` و `stage=tcp_connect`؛ خطا `https_connect_timeout` با حدود سه ثانیه زمان بوده است. A/B بعدی آن ماتریس موفق‌اند.
- پس از تک‌تک phaseها `restored=true` و `baseline_strict_equal=true` است؛ top-level `restore_verified=true`. شکست بررسی اتصال را شکست بازیابی سیاست تلقی نکنید.
- `completed=false` و `progress=stopped_with_error` درست حفظ شده‌اند، هرچند ۱۲۶ probe ثبت شده است: شرط پایان موفق و guard نهایی اجرا نشده‌اند. `route_checks_ok=false` در مسیر catch تنظیم می‌شود و به‌تنهایی شاهد تغییر route نیست. ۲۱۷ route check ثبت شده؛ اثبات مستقل packet path نداریم.
- `cleanup=not_needed` برچسب پیش‌فرض catch در حالتی است که نشست فعالی برای cleanup اضطراری باقی نمانده؛ **به معنی «هیچ قاعده‌ای ساخته نشده» نیست**. وضعیت mutation و رسیدهای بازیابی هر phase ملاک‌اند.
- نتیجهٔ رسمی `inconclusive` با خطای `coexistence_post_restore_connectivity_check_failed; policy_restore_status_is_separate` است. آن را به `passed` تغییر ندهید و گزارش نسخهٔ ساخته‌شده را پس‌نگرانه بازنویسی نکنید.

## قواعد ایمنی و بازیابی

ژورنال `%ProgramData%\UnifiedFirewallLab-050` و marker داخلی ۰.۶.۰ برای سازگاری حفظ شده‌اند. نام دقیق owner/name، snapshot کامل قاعده و هفت فیلتر، ساخت Disabled، ثبت capture و تأیید پیش از Enable، ActiveStore readback و قفل مشترک وجود دارند. Restore فقط قواعد دقیق و بدون drift متعلق به همان نشست را حذف می‌کند؛ Force یا group delete نداریم. نشست بازیابی‌نشده مانع اجرای بعدی است. بستهٔ قبلی یا ژورنال را پاک نکنید. crash، قطع برق و بستن اجباری تضمین cleanup ندارند و CAS اتمیک Windows وجود ندارد.

raw TCP قدیمی با HTTPS/cPanel یکی نیست. HTTPS فقط یک IPv4 عمومی منتخب:۴۴۳ است؛ DNS اولیه باید همان IP را تأیید کند و hostname برای SNI/Host/گواهی است. certificate bypass، HTTP fallback، redirect، proxy یا IP fallback نداریم. TLS/HTTP/challenge نامعتبر و خطای اجرای فرایند به معنی block موفق نیست. مرجع باید سالم بماند؛ هیچ timeout نادیده گرفته نمی‌شود.

این lab هیچ rule سراسری Program Any، تغییر default profile، تغییر route/VPN/DNS، kill-switch یا ضمانت no-leak نصب نکرده است. نتیجه دربارهٔ دو runtime بسته و اتصال‌های تازهٔ IPv4 TCP است؛ نه EXEهای دلخواه کاربر، همهٔ برنامه‌ها، اتصال‌های باز قبلی، UDP/IPv6 یا قطع VPN.

## زیرساخت موقت و حریم خصوصی

- پاسخ‌دهندهٔ raw TCP موقت Ubuntu و کلید SSH موقت قبلاً پاک شدند؛ VPN در لحظهٔ آن cleanup فعال گزارش شد. این مشاهدهٔ تاریخی است، نه بررسی زندهٔ فعلی. هیچ SSH key/مجوز ورود ماندگاری در دست عامل نیست و اتصال مجدد خودکار مجاز فرض نمی‌شود.
- روش جدید فقط یک PHP مستقل محدود روی هاست تحت کنترل کاربر است؛ رمز cPanel/SSH لازم نبوده و عامل چیزی روی سایت نصب نکرده است. فایل‌های WordPress/index/.htaccess تغییر نکردند.
- PHP حدود ۴۸ ساعت پس از ساخت، با **انقضای مطلق `2026-10-26T05:47:49Z`**، 410 می‌دهد؛ زمان از دانلود/بازدید بعدی شروع نمی‌شود. پس از پایان آزمون، کاربر فایل را حذف کند. نام تصادفی جای احراز هویت نیست و دادهٔ حساس نباید ارسال شود.
- transcript خام، گزارش خصوصی Windows، hostname/IP واقعی، مسیر محلی، نام پروفایل، request ID/nonce، credential، key و runtime باینری در این sync منتشر نمی‌شوند. فقط شواهد پالایش‌شده و hash هویت artifact ثبت می‌شود.

## قدم بعدی، نه تکرار کور آزمون

1. فعلاً تست کامل ۰.۸.۱ را دوباره درخواست نکنید؛ تغییر pacing به‌تنهایی timeout را برطرف نکرده است.
2. طرح بعدی باید اندازه‌گیری بدون mutation در **همان مسیر runtimeهای ۰.۸.۱**، با مرجع مستقل، توالی/زمان ثبت‌شده و حفظ شرایط اتصال باشد. تفاوت مسیر standalone diagnostic قبلی باید کنترل شود؛ موفقیت آن را شاهد قطعی سلامت همین مسیر ندانید.
3. در صورت نیاز فقط با مجوز مقصد/دسترسی مناسب، شواهد زمان‌مند TCP از سمت client/host بررسی شود. timeout پیش از TLS/HTTP فقط محل توقف را نشان می‌دهد؛ علت ISP/VPN/هاست/Windows Firewall/کد هنوز معلوم نیست. endpoint عمومی دلخواه، packet capture گسترده، TLS interception یا تغییر تنظیم امنیتی اضافه نشود.
4. retry خودکار، افزایش timeout برای گرفتن نمرهٔ قبولی، حذف مرجع یا نادیده‌گرفتن شکست پس از Restore پذیرفته نیست. هر تغییر احتمالی طراحی باید صریح، versioned و با شواهد قبلی حفظ‌شده باشد.
5. پس از روشن‌شدن پایداری/روش اندازه‌گیری، آزمون scoped دوباره و با مجوز کاربر ارزیابی شود. وایت‌لیست سراسری، قطع VPN/IPv6/UDP و UI نهایی milestones مستقل و هنوز باز هستند.

## مسیرهای مرجع و commitهای منبع

- ۰.۷.۰: `analysis/unified-firewall-coexistence-lab-0.7.0-2026-10-24/`، commit `b271e0195bda60570259f132281904b7b7e9d923`.
- ۰.۸.۰: `analysis/unified-firewall-https-lab-0.8.0-2026-10-24/`، commit `9a145e9678f3a13efa869289812713b7486f82ad`.
- diagnostic ۰.۱.۰: `analysis/unifiedfw-connectivity-diagnostic-0.1.0-2026-10-24/`، commit `1271cd07a69cf3cc8590d6d8b21161da6600d5ef`.
- ۰.۸.۱: `analysis/unified-firewall-https-paced-lab-0.8.1-2026-10-24/`، commit `62c481fbd8f96f107e6f538cea257aeeb2da3809`.

سورس‌ها و QAهای نسخه‌های تحویلی snapshot زمان ساخت‌اند. رسید اجرای Windows پس از ساخت جدا نگه داشته می‌شود تا «هنوز در زمان ساخت آزموده نشده بود» به «اجرای بعدی موفق بوده» تبدیل نادرست نشود. این sync نه کد برنامه را تغییر می‌دهد، نه workflow اجرا/سرویس راه می‌اندازد، نه نسخهٔ انتشار تازه می‌سازد.
