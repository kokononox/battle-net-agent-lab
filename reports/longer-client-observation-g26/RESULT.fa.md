# G26 — گزارش کامل بازیابی شد؛ نصب بسته تأیید، بازیابی policy رد شد

## اصلاح وضعیت قبلی شواهد
گزارش پایانی همان اجرای قبلی، بدون نصب مجدد، از مسیر live backscroll مرورگر احرازشدهٔ GitHub بازیابی شد. بر خلاف raw job log که BlobNotFound می‌داد، این مسیر184خطِ حفظ‌شده و دو checkpoint کامل داشت. آخرین گزارش79بخش،165179بایت و SHA-256 برابر `2424b640b0934cedf8b01a3f18ee71f7da65c2939c537672e7bdb5513b5e4202` دارد. تعداد/ترتیب بخش‌ها، اندازه، digest، هویت source/run و schema/فیلدهای مجاز تطبیق داده شدند.

- Run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/40187789184
- Windows job: https://github.com/kokononox/battle-net-agent-lab/actions/runs/40187789184/job/121152153276
- Source آزمایش: `a814cd7b929f415363bc57f0cd27dc6d5f86d791`
- گزارش اولیهٔ شکاف شواهد در EVIDENCE-GAP.initial.fa.md حفظ شده است. وضعیت cancelled برای Windows، failure برای collect و نبود artifact تغییر نکرده‌اند؛ بازیابی گزارش، workflow را success نمی‌کند. علتِ cancelled را تنها از این برچسب استنتاج نمی‌کنیم.

## آنچه دربارهٔ نصب تأیید شد
- Setup حدودثانیه118.5، پیش از پایان اجباری Job، طبیعی و با کد0 خارج شد.
- فایل‌های launcher و client در مسیر مورد انتظار موجود بودند؛ Authenticode کامل هر دو با trust_status=0 و امضاکنندهٔ پذیرفتهٔ Blizzard تأیید شد. client همان SHA-256 مشاهده‌شده در G24/G25 را داشت.
- رجیستری uninstall نام Battle.net و InstallLocation صحیح داشت. فایل مشخص Blizzard Uninstaller.exe زیر ProgramData/Battle.net وجود داشت؛ پس نبودش درون Program Files، شاهد نبود uninstaller نبود. این بررسی فقط‌خواندنی است و امضای خود uninstaller در این آزمون تأیید نشده است؛ هیچ فایل تازه‌ای برای این بررسی اجرا نشد.
- یک main client با no_type_switch ازثانیه118.410 تا زمان بسته‌شدن کنترل‌شده زنده بود:151760ms، حدود152ثانیه. هشت نمونهٔ دیگر client نقش فرزند typed داشتند؛ شمار فرایندها شمار restart کامل نیست.
- پنجرهٔ client با marker login در نمونه‌های با فاصلهٔ بیش از30ثانیه دیده شد؛ اما UIA محدود/truncated بود و مجموعهٔ کامل کنترل‌های فرم ورود تأیید نشد. هیچ حساب یا بازی وارد/دانلود نشد.

بنابراین package_installation_verified=true و main_process_survival_60s_observed=true تأیید شده‌اند؛ اما complete_installation_verified و پرچم legacy installation_verified همچنان false هستند. نصب بسته و بقای main را با آمادگی کامل رابط ورود یا موفقیت سرتاسری ابزار یکی نمی‌گیریم. این نتیجه فقط برای همین محیطِ دارای آماده‌سازی آنلاین گواهی قبل از gate است، نه ویندوز با کش خالی.

## علت دقیق توقف در پایان
مشاهدهٔ270ثانیه‌ای با gate تأییدشده قبل و بعد پایان یافت. canary مستقیم زیر gate متصل نشد. در cleanup، سه تغییر task که policy موجود طبقه‌بندی/تأیید نکرده بود مانع restore شدند:

| شناسه | تغییر مشاهده‌شده | وضعیت |
| --- | --- | --- |
| RefreshCache | TimeTrigger/StartBoundary | مسدودکنندهٔ طبقه‌بندی‌نشده |
| PrintJobCleanupTask | Settings/Enabled | مسدودکنندهٔ طبقه‌بندی‌نشده |
| Registration | TimeTrigger/StartBoundary | مسدودکنندهٔ طبقه‌بندی‌نشده |
| SvcRestartTask | CalendarTrigger/StartBoundary | reschedule محدودِ از قبل مجاز |

در این چهار diff، تصویر action/command تغییر نکرده است. این به‌تنهایی benign بودن، انتساب تغییرها به Windows، یا نبود دخالت نصاب را ثابت نمی‌کند. سه مورد جدید خودکار معاف نشده‌اند.

چهار تغییر خام، یک reschedule پذیرفته و سه blocker ثبت شد. error_code بازیابی `unclassified_external_component_blocks_restore` و خطای Driver در مرحله scoped_cleanup برابر `cleanup_not_verified` است. Job به صفر فرایند فعال رسید و proxy بسته و drain شد، ولی firewall_restored=false و iis_restored=false باقی ماندند. post-restore canary اصلاً تأیید نشد. BITS تازه/تغییریافته و candidate بیرون Job در این snapshot صفر بود؛ این سیاست را دور نمی‌زند و نبود همهٔ brokerها/نشت‌ها را ثابت نمی‌کند.

## تعمیر مسیر گزارش، بدون اجرای Setup تازه
مسیر بازیابی live backscroll مستند شد؛ fetch پیش‌فرض بدون headerهای viewer می‌توانست400 بدهد، در حالی که درخواست همان endpoint در همان مرورگر با headerهای ثابت viewer دادهٔ کامل را برمی‌گرداند. cookie/token استخراج یا به CI منتقل نشد؛ فقط گزارش پاک‌سازی‌شدهٔ تأییدشده منتشر می‌شود.

Reporter اکنون یک رسید بحرانی مستقل و محدود تولید می‌کند: برای دادهٔ واقعی G26،2871بایت و سه بخش. همان receipt پیش و پس از گزارش بلند چاپ می‌شود تا بخش‌های اول/آخر log بتوانند وضعیت gate، package، main و علت refusal را مستقل با source/run/size/hash تأیید کنند. core-g26.json هم در فهرست artifact آینده قرار گرفت.15 تست مستقل و آزمون integration با متن واقعی Reporter و گزارش بازیابی‌شده پاس شدند؛ گزارش کامل بدون تغییر باقی ماند و exit failure مربوط به refusal حفظ شد. این receipt در اجرای تاریخی G26 تولید نشده بود؛ تعمیر بعداً روی دادهٔ ذخیره‌شده آزموده شد، نه با نصب یا CI تازه.

هیچ تغییر gate، exception مقصد، پذیرش مالک، شرط بازیابی، task سیستم یا Desktop0.9.10 اعمال نشد. بازیابی خودکار artifact در تمام حالت‌های quarantine تضمین نشده است؛ receipt کوتاه و مسیر احرازشدهٔ live log، راه خروج شواهد هستند، نه مجوز آزادسازی policy.

## مانع باقی‌مانده
خود نصب بسته در همین آزمایش تأیید شده؛ مانع ابزار قابل‌انتشار، تصمیم امن دربارهٔ تغییرهای محیطیِ تأییدنشده و بازیابی policy است. نسبت‌دادن یا معاف‌کردن این سه task بدون شواهد اتصال/هویت/سیاست کافی مجاز نیست. EXE نهاییِ امن و آمادهٔ انتشار هنوز ادعا نمی‌شود.
