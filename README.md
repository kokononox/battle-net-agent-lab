# WoW project continuity + bounded Battle.net Agent lab

## قدم فعلی — WLab CodeRead 0.1.0، خواندن محدود و فقط‌خواندنی

[راهنما](user-tools/wlab-coderead-0.1.0/README.fa.md) · [QA](user-tools/wlab-coderead-0.1.0/QA.json) · [هش و provenance](user-tools/wlab-coderead-0.1.0/PROVENANCE.json) · [وضعیت](user-tools/wlab-coderead-0.1.0/SYNC-STATUS.json).

پس از کنترل موفقِ هدف کوچک و نبود artifact بازی، کاربر شروع روش پیشنهادی خواندن محدود را تأیید کرد. ابزار تازه فقط metadata و ReadProcessMemory درخواست می‌کند: تطبیق PID/creation FILETIME، مسیر ماژول/پایه/اندازه، SHA256 دقیق دیسک build 12.1.5.70448 و PE header، سپس سه صفحهٔ ثابت و کنترل header/identity بعد. حداکثر پنج خواندن ۴ KiB است؛ سه صفحه به اضافهٔ دو header. فقط پس از موفقیت همهٔ gates، سه صفحه و سه پنجرهٔ نامزد صادر می‌شوند. Guard/no-access، read/query error، partial read یا تغییر هویت باعث توقف بدون صدور bytes staged می‌شود. هیچ retry، debug privilege adjustment، protection change، clone، debugger attach، injection یا target write وجود ندارد. UAC در آغاز ممکن است با تأیید کاربر درخواست شود؛ پس از رد دسترسی bypass یا escalation انجام نمی‌شود.

۲۲ آزمون Go، fake reader برای خطا/guard/partial/تغییر، fixture واقعی دیسک پین‌شده، قفل و child runner مستقل، مسیر unsupported-platform، سه parse PowerShell، vet، compile assertion ABI Windows و دو build یکسان گذشتند. **Windows live read و رابط واقعی این روش در Linux ساخت آزموده نشده‌اند.** داده‌ها sequential هستند، نه snapshot اتمیک؛ اختلاف raw کد ≠ decryption/execution/serialization/send. خروجی کوچک روی درایو بازی در WLabCodeRead است؛ ProcDump دانلود/اجرا نمی‌شود. قدم بعد یک Read code once و ارسال ZIP کوچک و گزارش قابل‌استفاده‌بودن بازی است. main و GUI BIOS Path 0.2 دست‌نخورده‌اند؛ CPU/BIOS روی TCP/3724 همچنان نامعلوم است. دستورهای ابزارهای قدیمی زیر سابقه‌اند، نه درخواست اجرای دوبارهٔ آن‌ها.

## نتیجهٔ پیشین — هر دو dump کنترل ساخته شدند؛ label عمومی خروج گمراه‌کننده است

[بررسی](reports/control-0.1.0-first-run/REVIEW.fa.md) · [گزارش ساختاریافته](reports/control-0.1.0-first-run/OBSERVATION.json) · [لاگ clone](reports/control-0.1.0-first-run/control-clone.decoded.txt) · [لاگ direct](reports/control-0.1.0-first-run/control-direct.decoded.txt).

در هر دو مسیر، ProcDump پیام Dump complete داده، فایل با اندازهٔ ثبت‌شده وجود داشته و header ابتدایی معتبر بوده است. هر دو کد خروج 1 دارند؛ label عمومی failed فقط از عدد غیرصفر آمده و نباید به‌تنهایی شکست تولید dump شمرده شود. این مشاهده هم مجوز فرض کلی «۱ همیشه موفق است» نیست. dumpها فقط از هدف کنترل‌اند؛ کامل parse نشده‌اند و هیچ نتیجه‌ای از حافظهٔ بازی نداریم. worker پس از هر دو آزمون زنده بود و در cleanup خود ابزار بسته شد.

نوشتن روی G و PSS/direct برای همین هدف کنترل کار کرده‌اند؛ شکست قبلی روی بازی هنوز توضیح قطعی ندارد. آزمون کنترل و full dump قبلی فعلاً تکرار نشوند. قدم پیشنهادی بعد: خواندن محدود سه صفحهٔ کد ثابت با API فقط‌خواندنی Windows، بدون clone/debugger/injection/patch/تغییر protection؛ با تطبیق هویت و توقف در access denied. این مسیر هنوز ساخته/اجرا نشده است. main و GUI BIOS Path 0.2 دست‌نخورده‌اند؛ CPU/BIOS روی TCP/3724 همچنان نامعلوم است.

## ابزار کنترل اجراشده — WLab Control 0.1.0، فقط هدف آزمایشی متعلق به خود ابزار

[راهنما](user-tools/wlab-control-0.1.0/README.fa.md) · [QA](user-tools/wlab-control-0.1.0/QA.json) · [هش و provenance](user-tools/wlab-control-0.1.0/PROVENANCE.json) · [وضعیت](user-tools/wlab-control-0.1.0/SYNC-STATUS.json).

کاربر تأیید کرد در تلاش شکست‌خوردهٔ 0.1.5 هیچ snapshot.dmp باقی نمانده و بازی عادی بوده است؛ بنابراین artifact برای تحلیل آفلاین نداریم. به‌جای تکرار capture بازی، ابزار مستقل کنترل آماده شد: write/flush/readback یک MiB روی G، و دو dump از فرزند تازهٔ خود WLab، یکی PSS clone و یکی بدون clone. PID فقط از فرزند ساخته‌شده می‌آید؛ هیچ انتخاب Wow، PID دلخواه یا CLI استخراج بازی در این ابزار وجود ندارد. روش مستقیم فقط برای همین هدف کنترل است و مجوز/پیشنهاد attach مستقیم به بازی نیست. dumpهای کنترل محلی می‌مانند؛ ZIP فقط گزارش و لاگ‌هاست.

۱۰ آزمون Go، پنج parse PowerShell، شش header fixture، write/readback واقعی Linux، decode لاگ UTF-16LE، آزمون child runner و قفل مستقل و worker CLI واقعی، vet و دو build یکسان گذشتند. **ProcDump/PSS و رابط Windows واقعاً در محیط ساخت اجرا نشده‌اند.** این آزمون کنترل هنوز باید روی دستگاه کاربر اجرا شود؛ هیچ علت قطعی برای خطای قبلی یا موفقیت capture بازی اعلام نشده است. بازی برای کنترل لازم نیست باز باشد. main و GUI BIOS Path 0.2 دست‌نخورده‌اند؛ CPU/BIOS روی TCP/3724 همچنان نامعلوم است. دستورهای قدیمی Snapshot زیر سابقه‌اند، نه درخواست capture مجدد بازی.

## مشاهدهٔ پیشین — تلاش واقعی 0.1.5، شکست ProcDump با بازی عادی

[بررسی و قدم بعد](reports/snapshot-0.1.5-first-capture/REVIEW.fa.md) · [گزارش ساختاریافته](reports/snapshot-0.1.5-first-capture/OBSERVATION.json) · [لاگ decoded](reports/snapshot-0.1.5-first-capture/procdump-decoded.txt).

سنجش native و خود ProcDump بر 17,312,059,392 بایت فضای آزاد روی G توافق دارند. capture شروع شد ولی با خروج 1، Target process no longer running و 0x8007001D شکست خورد. کاربر تأیید کرد **خود بازی عادی مانده است**؛ از این پیام نمی‌توان بسته‌شدن بازی، خرابی دیسک یا دخالت anti-cheat را نتیجه گرفت. PSS clone در لاگ ذکر شده، اما وضعیت و علت شکست clone قطعی نیست. تحلیل کد هنوز تولید نشده است.

قدم بعد فقط بررسی وجود و اندازهٔ artifact محلی snapshot.dmp همین اجراست؛ بدون تکرار capture یا تغییر روش زنده تا روشن‌شدن شواهد. دستور تست انتشار زیر سابقهٔ قبل از این نتیجه است، نه درخواست تکرار. CPU/BIOS روی TCP/3724 همچنان نامعلوم است.

## آخرین گام — WLab Snapshot 0.1.5، سنجش native فضای خروجی

[راهنما](user-tools/wlab-snapshot-0.1.5/README.fa.md) · [شواهد صفر خلاف گزارش کاربر](user-tools/wlab-snapshot-0.1.5/USER-FREE-SPACE-OBSERVATION.json) · [QA](user-tools/wlab-snapshot-0.1.5/QA.json) · [هش](user-tools/wlab-snapshot-0.1.5/PROVENANCE.json) · [وضعیت](user-tools/wlab-snapshot-0.1.5/SYNC-STATUS.json).

گزارش 0.1.4 خروجی درست روی G را تأیید کرد، اما PSDrive.Free صفر بود؛ کاربر دوباره ۱۶ گیگ فضای آزاد را تأیید کرد. capture شروع نشد و علت دقیق عدد صفر provider هنوز معلوم نیست. این نسخه GetDiskFreeSpaceExW را روی همان پوشهٔ موجود خروجی فراخوانی می‌کند؛ معیار caller-available است و total/total_free و خطای Win32 جدا ثبت می‌شوند. PSDrive و DriveInfo فقط تشخیصی‌اند، نه مجوز انتخاب عدد بزرگ‌تر. خطای سنجش/null از صفر واقعی جداست. سنجش حین capture هم native است؛ حداقل ۸ GiB و لغو آرام زیر ۱ GiB حفظ شده‌اند. مسیر درایو بازی و cache/قفل کوچک LocalAppData عوض نشده‌اند.

۲۵ آزمون Go، پنج fixture مصنوعی، قفل و child runner مستقل، کامپایل declaration native، mock عدد native ۱۶ GiB در برابر provider صفر، صفر واقعی، مرزها و خطاهای API و دو build یکسان گذشتند. فراخوانی واقعی Windows API در Linux ساخت آزموده نشده است؛ نسخهٔ جدید پیش از capture نتیجهٔ واقعی آن را ثبت می‌کند. main و GUI BIOS Path 0.2 تغییر نکرده‌اند؛ CPU/BIOS روی TCP/3724 همچنان نامعلوم است. قدم بعد فقط یک تلاش با 0.1.5 و ارسال گزارش جدید است؛ بخش‌های قدیمی زیر سابقه‌اند.

## گام پیشین — WLab Snapshot 0.1.4، خروجی روی درایو بازی

[راهنما](user-tools/wlab-snapshot-0.1.4/README.fa.md) · [گزارش توقف کمبود فضا](user-tools/wlab-snapshot-0.1.4/USER-STORAGE-OBSERVATION.json) · [QA](user-tools/wlab-snapshot-0.1.4/QA.json) · [هش باینری](user-tools/wlab-snapshot-0.1.4/PROVENANCE.json) · [وضعیت](user-tools/wlab-snapshot-0.1.4/SYNC-STATUS.json).

گزارش 0.1.3 موفقیت آزمون فرزند، آماده‌سازی، هش بازی و امضای Microsoft را نشان داد؛ capture به‌علت حداقل فضای آزاد قبل از شروع متوقف شد. کاربر بازی را عادی گزارش کرد، اما چون capture_started=false است، این پایداری حین snapshot نیست. طبق درخواست تازه، dump و گزارش در DRIVE:\WLabSnapshot\TIMESTAMP-ID روی درایو همان Wow.exe انتخاب‌شده نوشته می‌شوند؛ cache کوچک، launcher log و قفل مشترک در LocalAppData باقی می‌مانند. بررسی حداقل ۸ GiB و لغو زیر ۱ GiB روی همان خروجی جدید است؛ مقدار آزاد و مسیر ثبت می‌شوند. هیچ fallback پنهان به C و هیچ کاهش حداقل فضا وجود ندارد. ۱۶ گیگ گزارش‌شده تضمین کفایت dump نیست.

۲۵ آزمون Go، پنج fixture مصنوعی، آزمون مستقل قفل و child runner، چهار نگاشت مسیر و چهار رد مسیر نامعتبر، mock فضای آزاد، parse چهار اسکریپت و دو build یکسان گذشتند. اجرای واقعی Windows نسخهٔ جدید و snapshot هنوز نیاز به تأیید دارند. main و GUI BIOS Path 0.2 تغییر نکرده‌اند؛ CPU/BIOS روی TCP/3724 همچنان نامعلوم است. قدم بعد فقط یک تلاش با 0.1.4 و ارسال گزارش جدید است؛ دستورهای قدیمی زیر سابقه‌اند.

## گام پیشین — WLab Snapshot 0.1.3، اصلاح نتیجهٔ نامعلوم helper و ثبت خطا

[راهنما](user-tools/wlab-snapshot-0.1.3/README.fa.md) · [شواهد کاربر](user-tools/wlab-snapshot-0.1.3/USER-PREPARATION-OBSERVATION.json) · [QA](user-tools/wlab-snapshot-0.1.3/QA.json) · [منشأ و هش باینری](user-tools/wlab-snapshot-0.1.3/PROVENANCE.json) · [وضعیت](user-tools/wlab-snapshot-0.1.3/SYNC-STATUS.json).

گزارش 0.1.2 نشان داد کاربر از رابط به آماده‌سازی رسیده است، اما capture_started=false و prepare_exit_code=null بوده‌اند. این شواهد شکست قطعی دانلود یا اجرای snapshot نیستند. مقایسهٔ مستقیم null با صفر در کد قبلی نتیجه را به‌اشتباه failure می‌کرد؛ علت دقیق null روی Windows کاربر اثبات نشده است.

اجرای مرحله‌ها اکنون با Process.Start و handle متعلق به برنامه انجام می‌شود؛ صفر، غیرصفر و unknown جدا هستند. دو probe متعلق به WLab با خروج عمدی 0 و 7 پیش از دانلود/capture، دریافت کد خروج و stdout/stderr را کنترل می‌کنند. گزارش کوچک شامل لاگ و نتیجهٔ مرحله‌های موجود است؛ dump کامل محلی می‌ماند. پیام پایان در توقف پیش از capture دیگر ادعای وجود dump نمی‌کند. روش ProcDump، hash pinها و اصلاح نمایش حفظ شده‌اند.

۲۴ آزمون Go، پنج fixture مصنوعی، آزمون قفل، ۱۰ فرزند آزمایشی واقعی در Linux PowerShell، بررسی نحو و دو build یکسان گذشتند. **اجرای Windows نسخهٔ 0.1.3 و capture واقعی هنوز تأیید نشده‌اند.** گام بعد یک تلاش با نسخهٔ جدید و ارسال READY-TO-SEND.zip حتی در صورت خطاست؛ بدون تکرار خودکار. main و GUI BIOS Path 0.2 تغییر نکرده‌اند؛ ارسال CPU/BIOS روی TCP/3724 همچنان نامعلوم است. بخش‌های قدیمی زیر سابقه‌اند، نه دستور اجرای فعلی.

## گام پیشین — WLab Snapshot 0.1.2، اصلاح نمایش بر پایهٔ لاگ کاربر

[راهنمای نسخه](user-tools/wlab-snapshot-0.1.2/README.fa.md) · [شواهد شروع کاربر](user-tools/wlab-snapshot-0.1.2/USER-STARTUP-OBSERVATION.json) · [QA](user-tools/wlab-snapshot-0.1.2/QA.json) · [هش باینری](user-tools/wlab-snapshot-0.1.2/PROVENANCE.json) · [وضعیت](user-tools/wlab-snapshot-0.1.2/SYNC-STATUS.json).

آرشیو Documents.zip دو marker رویداد Shown، یک marker elevation و لاگ‌های بدون متن خطای شروع داشت؛ کاربر بااین‌حال هیچ پنجره‌ای نمی‌دید. Shown صرفاً رویداد WinForms است، نه تأیید قابل‌دیدن‌بودن رابط. این شواهد نشان‌دهندهٔ اجرای snapshot یا ارسال شبکه نیستند.

منبع Go تأیید کرد `HideWindow: true` در launcher قبلی، STARTF_USESHOWWINDOW/SW_HIDE را تنظیم می‌کرد. این گزینه با CREATE_NO_WINDOW جایگزین شد تا کنسول جدا ساخته نشود، بدون درخواست مخفی‌شدن رابط. ارتباط علّی آن با desktop کاربر هنوز اثبات نشده است. monitor تازه فقط برای PID همان worker و عنوان همین نسخه، وضعیت native پنجره را ثبت و restore/center/foreground را درخواست می‌کند؛ هیچ پنجرهٔ بازی یا فرایند دیگری تغییر/خاتمه داده نمی‌شود. window-state.json جای اعتماد صرف به UI shown را می‌گیرد؛ وضعیت native نیز به‌تنهایی اثبات دیده‌شدن انسانی نیست.

۲۳ آزمون (۱۸ parser، چهار هندسه و یک guard منبع flags)، پنج fixture مصنوعی، چهار وضعیت قفل، بررسی نحو و دو build یکسان گذشتند. **نمایش واقعی 0.1.2 روی Windows هنوز تأیید نشده است.** قدم بعد فقط بازکردن WLab-Snapshot-0.1.2.exe و تأیید رابط است؛ بازی و Capture برای این آزمون لازم نیست. main، GUI BIOS Path 0.2 و روش capture قبلی تغییر نکرده‌اند. CPU/BIOS روی TCP/3724 همچنان نامعلوم است.

## گام پیشین — WLab Snapshot 0.1.1، اصلاح قفل و مشکل نمایش تأییدنشده

[نسخه و راهنمای اصلاحی](user-tools/wlab-snapshot-0.1.1/README.fa.md) · [QA](user-tools/wlab-snapshot-0.1.1/QA.json) · [هش باینری](user-tools/wlab-snapshot-0.1.1/PROVENANCE.json) · [وضعیت](user-tools/wlab-snapshot-0.1.1/SYNC-STATUS.json).

کاربر در 0.1.0 پیام «already open» را پیش از دسترسی به رابط گزارش کرد. از این گزارش، مالک قفل یا بازبودن واقعی یک رابط قبلی تأیید نشده است. قفل Mutex در شروع رابط حذف شد؛ فقط تلاش ثبت snapshot با handle انحصاری فایل هماهنگ می‌شود. فایل باقی‌مانده بدون handle فعال مانع نیست. رابط‌های متعدد ممکن‌اند، اما فقط یک تلاش capture در هر زمان برای این کاربر در نسخهٔ تازه مجاز است. در نسخهٔ قدیمی Capture نزنید؛ روش ضبط، hash pinها و بررسی ProcDump موجود تغییر نکرده‌اند.

نام اجرایی تازه `WLab-Snapshot-0.1.1.exe` است. لاگ شروع هر اجرا جداست و اگر بازشدن رابط تأیید نشود، پوشهٔ لاگ باز می‌شود. هیچ فرایند موجود کاربر، بازی یا PowerShell به‌زور بسته نمی‌شود. main و GUI BIOS Path 0.2 تغییر نکرده‌اند.

۱۸ آزمون parser، پنج fixture مصنوعی، چهار وضعیت قفل میان فرایندهای آزمایشی Linux، بررسی نحو و دو build یکسان گذشتند. **Windows UI و capture روی بازی هنوز تأیید نشده‌اند**؛ این اصلاح نیز اثبات ارسال/عدم ارسال CPU/BIOS روی 3724 نیست.

## گام پیشین — WLab Snapshot 0.1.0 و گزارش مشکل شروع

[راهنما و منبع ابزار مستقل](user-tools/wlab-snapshot-0.1.0/README.fa.md) · [QA و حدود آزمون](user-tools/wlab-snapshot-0.1.0/QA.json) · [هش باینری و منشأ ابزارها](user-tools/wlab-snapshot-0.1.0/PROVENANCE.json) · [وضعیت](user-tools/wlab-snapshot-0.1.0/SYNC-STATUS.json).

پس از تأیید تازهٔ کاربر برای بررسی روی حساب آزمایشی، ابزار یک‌کلیکی تازه‌ای برای **یک snapshot مبتنی بر clone و استخراج آفلاین سه محدودهٔ کد** آماده شد. این ابزار CDB/Frida قبلی نیست؛ GUI BIOS Path 0.2 و main تغییر نمی‌کنند. بازی را خودکار اجرا نمی‌کند و capture تنها با انتخاب کاربر و پذیرش EULA شروع می‌شود.

فایل Wow.exe به همان SHA256 بیلد 12.1.5.70448 pin شده است. ProcDump مستقیماً از Microsoft دریافت می‌شود، نه بازتوزیع داخل بسته؛ هش ZIP/EXE و امضای معتبر Microsoft پیش از اجرا الزام‌اند. روش مستند `-ma -r 1 -n 1 -at 120` است. dump کامل محلی می‌ماند؛ READY-TO-SEND.zip فقط گزارش و byte windowهای کوچک را شامل می‌شود. برنامه آپلود، تزریق، patch، تغییر firewall یا retry خودکار ندارد.

**وضعیت واقعی:** cross-compile Windows x64 GUI، ۱۸ آزمون parser، پنج fixture مصنوعی، کنترل نحو PowerShell در Linux و دو باینری یکسان انجام شد. **اجرای واقعی WinForms/Windows PowerShell 5.1 و capture روی بازی هنوز تأیید نشده است.** یک دقیقه مشاهدهٔ بقای فرایند/Responding جای تأیید قابل‌استفاده‌بودن بازی را نمی‌گیرد. باینری پروژه امضای تجاری ندارد؛ هش آن در provenance ثبت و نسخهٔ اجرایی در بستهٔ تحویل ارائه می‌شود، نه به‌عنوان متن Git.

هنوز شاهد جدیدی از مقداردهی BIOS یا ارسال روی TCP/3724 نداریم. معیار گام بعد، دریافت خروجی واقعی و بررسی قابل‌تحلیل‌بودن بایت‌های کد حافظه است؛ اختلاف بایت به‌تنهایی به معنای رمزگشایی یا ارسال نیست. مسیر عمومی لودر همچنان گسترش داده نمی‌شود.

## گام پیشین — گلوگاه کد اختصاصی پیام سخت‌افزار

[گزارش بررسی محدود سه ورودی](analysis/entry-loader-startup-2026-10-23/hardware-message-code-gate/README.fa.md) · [شواهد دو دیکدر](analysis/entry-loader-startup-2026-10-23/hardware-message-code-gate/evidence.json) · [وضعیت و شرط ادامه](analysis/entry-loader-startup-2026-10-23/hardware-message-code-gate/SYNC-STATUS.json).

سه اشاره‌گرِ نامزد merge/creator/parse-fallback از متادیتای ClientEngineLogV2 به ابتدای رکوردهای pdata در `.text` دنبال شدند؛ اسلات هر سه DIR64 relocation دارد. دیکد خطی معمول با Capstone و objdump از این ورودی‌ها بدنهٔ قابل اتکایی برای دنبال‌کردن مقداردهی سخت‌افزار به دست نداد. این نتیجه دربارهٔ بایت روی دیسک و ابزارهای ثبت‌شده است، نه اثبات نامعتبر بودن کد زمان اجرا، رمزگذاری، حفاظت یا نبود ارسال.

**تصمیم:** این مسیر نیز فعلاً در انتظار شاهد تازهٔ مجاز و منطبق با build متوقف است؛ اسکن تکراری رشته‌ها و گسترش عمومی لودر پیشرفت رفتاری محسوب نمی‌شوند. صحت اسلات/relocation/pdata/بایت با PE reader مستقل کنترل و گزارش دو بار یکسان تولید شد؛ این کنترل‌ها اثبات معنایی نیستند. CPU/BIOS روی TCP/3724 همچنان نه اثبات و نه رد شده است. بازی اجرا/patch نشد؛ main، GUI 0.2 و firewall دست‌نخورده‌اند.

## گام پیشین — منشأ بافر، تطبیق نام ماژول و توقف گسترش عمومی

[گزارش منشأ U و N، منابع و بازتولید](analysis/entry-loader-startup-2026-10-23/record-provenance/README.fa.md) · [وضعیت و تصمیم ادامه](analysis/entry-loader-startup-2026-10-23/record-provenance/SYNC-STATUS.json).

با فرض معمول Windows x64 و layout مرجع تطبیق‌یافته، زنجیرهٔ `GS:[0x60] → PEB+0x18 → Ldr+0x10` به فهرست load-order و فیلدهای `record+0x58/+0x60` به Length/Buffer در BaseDllName منطبق است. هیچ نام ماژول واقعی، OS build کاربر یا محتوای حافظه مشاهده نشده است.

برای wordِ global در RVA `0x20F9B98` با مقدار دیسک `0xF92D`، `N=floor(L/2)` و گسترهٔ بایتی `2*N=L&0xFFFE` ثابت شد. شرط global عمومی نیست؛ همهٔ شمارش‌های شیفت ۰ تا ۶۳ در دامنهٔ مدل ممکن‌اند. ۶۵٬۵۳۶ global و ۶۵٬۵۳۶ طول در سناریوی دیسک، هفت fixture ساختگی و ۱۴ آزمون خراب‌سازی ردشده بررسی شدند. انتقال قبلی دوباره بازبینی و دو گزارش اصلی یکسان بازتولید شد.

**تصمیم:** این شاخه فعلاً مسیر عمومیِ نام/بافر ماژول محسوب می‌شود، نه شاهد مستقیم CPU/BIOS. گسترش کور `0x6995D0` متوقف می‌شود؛ ادامه باید به شواهد اختصاصی جمع‌آوری سخت‌افزار یا مقداردهی پیام برگردد. ارسال CPU/BIOS روی 3724 همچنان اثبات یا رد نشده است. هیچ فایل بازی اجرا/patch نشد؛ main و GUI 0.2 تغییر نکردند. تست بازی یا بلاک تازه لازم نیست.


## گام پیشین — نقش داده‌ای 0x683780

[گزارش و بازتولید دو قطعه](analysis/entry-loader-startup-2026-10-23/callee-683780/README.fa.md) · [وضعیت و تصمیم ادامه](analysis/entry-loader-startup-2026-10-23/callee-683780/SYNC-STATUS.json).

در مسیر مشروط به globalهای ثبت‌شده، دو جفتِ آغاز/پایان `D..D+256` و `U..U+2*N` با بررسی دو آماده‌ساز کوچک ساخته می‌شوند. تحلیل پیش از call ناشناختهٔ `0x6995D0` متوقف شد. در snapshot جداگانهٔ پس از call، عبارت خروجی به `*Q = A-D (mod 2^64)` ثابت شد؛ این snapshot نتیجهٔ اثبات‌شدهٔ call نیست. معنای محتوای بافرها، encoding، پیشروی درست A و تولید واقعی بایت هنوز معلوم نیست.

۱۰۶ نمونهٔ عددی برای هر قطعه، گواه جبری قفل‌شده به بایت‌ها، ۱۴ آزمون خراب‌سازی ردشده و بازتولید یکسان سه گزارش ثبت شد؛ دیکدر مسیر در دو مدل مشترک است. هیچ PE اجرا یا patch نشد؛ main و GUI 0.2 تغییر نمی‌کنند.

این گام یک نقش داده‌ای را روشن کرد، نه ارسال CPU/BIOS روی 3724. قدم پیشنهادی بعد تطبیق منشأ U و N در record قبلی است؛ بازکردن کور کل تابع داخلی آغاز نمی‌شود. تست بازی، attach و بلاک تازه لازم نیست.


## گام پیشین تحلیل آفلاین — تابع 0x5C6440

[گزارش و بازتولید گام سوم](analysis/entry-loader-startup-2026-10-23/callee-5c6440/README.fa.md) · [وضعیت این گام](analysis/entry-loader-startup-2026-10-23/callee-5c6440/SYNC-STATUS.json).

در اولین dispatcher این تابع، ۱۷ مسیر با ۱۷ مقصد متمایز و پوشش ورودی DWORD بررسی شد. مسیر کامل‌تر فقط مشروط به مقادیر سراسری روی دیسک و محافظ stack است: `0x5C6440 → call at 0x5C6ED9 → 0x683780`. آدرس یک DWORD محلی و چند آرگومان ورودی به مقصد منتقل می‌شود. مقدار محلی در سناریوی دیسک صفر است؛ یک ضدنمونهٔ مدل نشان داد این صفر بودن عمومی نیست.

مدل عددی جداگانه، بایت‌ها، شاخه‌ها و انتقال آرگومان‌ها را تطبیق داد؛ دیکدر مسیر در دو مدل مشترک است. ۱۱ آزمون خراب‌سازی مسیر و سه آزمون dispatcher رد شدند؛ دو اجرای entrypoint چهار گزارش اصلی یکسان ساختند. هیچ PE اجرا یا patch نشد. نویسندهٔ اسلات EXE، آماده‌سازی کد، خواندن BIOS و ارسال CPU/BIOS روی 3724 همچنان اثبات نشده‌اند. هدف بعدی بررسی مصرف داده در `0x683780` است، نه تست شبکه یا بلاک تازه.

این بخش وضعیت تازهٔ مسیر تحلیل راه‌اندازی است؛ بخش‌های زیر سابقهٔ سایر مراحل و آزمایش‌ها هستند. ثبت این گام تنها روی شاخهٔ `analysis/entry-loader-startup-2026-10-23` انجام می‌شود؛ main و GUI 0.2 تغییر نمی‌کنند.


<!-- project-current-status-link:start -->
## وضعیت روز — ابتدا این بخش را بخوانید

**مرحلهٔ فعلی:** [ردیابی آفلاین پیام مشخصات سیستم و مرز نتیجه](docs/WOW-TRACE-2026-10-20.fa.md)؛ بررسی حریم خصوصی خود WoW Retail؛ [تحویل جلسهٔ شبکه و بازیابی](docs/SESSION-NETWORK-2026-10-20.fa.md) و [یافتهٔ جدید CPU/BIOS در schema بازی](docs/WOW-STATIC-2026-10-20.fa.md).

ClientEngineLogV2 شامل فیلدهای CPU/مادربرد/BIOS است؛ تعریف پیام اثبات ارسال در اجرای کاربر نیست. مشاهدهٔ passive فقط metadata مقصد و HTTPهای ساده را روشن کرده؛ TLS بازی هنوز خوانده نشده. proxy آزمایشی login را مختل کرد و با recovery مشکل برطرف شد؛ تکرار آن توصیه نمی‌شود. فایل‌های بازی، capture خام، CA/key و runtime باینری وارد مخزن نشده‌اند.

[وضعیت هماهنگی](docs/STATUS.fa.md) · [وضعیت ماشین‌خوان](docs/current-state.json) · [منبع ابزارها](user-tools/session-20261020/) · [manifest sync](docs/SESSION-SYNC-2026-10-20.json). متن پایین تاریخچه است؛ مجوز نصب Classic/اجرای مجدد آزمایش‌ها نیست.
<!-- project-current-status-link:end -->


## آزمایش جاری — نصب پایهٔ Classic در ویندوز دورریختنی

کاربر دانلود/نصب آزمایشی را تأیید کرد. اجرای یک‌باره با کنترل فضای واقعی دو volume، مقصد تازه، فرم auth/min-spec/legal و عدم جعل کشور آماده شد. اینجا هنوز نتیجهٔ اجرای واقعی نصب ادعا نمی‌شود؛ گزارش پس از پایان در `reports/classic-install-latest.json` منتشر خواهد شد. [دامنه و محدودیت‌ها](docs/CLASSIC-BASELINE-EXPERIMENT.fa.md). سقف سخت ترافیک Agent وجود ندارد و نصب با حذف VM نگهداری نمی‌شود؛ محتوای بازی صادر نمی‌شود. این نصب تازه جای آزمون آپدیت نسخه‌به‌نسخه نیست.


## نتیجهٔ تازه — متادیتای رسمی Classic Era

نسخهٔ EU برابر `1.15.9.70003` مشاهده شد؛ configهای ساخت/CDN و هویت کامل manifestهای نصب/دانلود تأیید شدند. تنها 4,957,673 بایت متادیتا دریافت شد؛ هیچ بازی، Agent یا نصب/آپدیتی اجرا نشد. جمع کل catalogue دانلود حدود 7.93 GiB است، **نه حجم نصب پروفایل انتخابی یا حجم آپدیت**. جزئیات و مرز مجوز در [نتیجهٔ بررسی](docs/CLASSIC-ERA-METADATA-RESULT.fa.md)، [receipt](reports/classic-era-metadata-preflight.json) و [اندازه‌گیری](reports/classic-era-manifest-sizing.json).

گام بعد تهیهٔ baseline آزمایشی Classic روی Windows VM جداست؛ چون دانلود/نصب بازی است به مجوز تازه نیاز دارد. هیچ workflow نصب فعالی اضافه نشده و سقف سخت شبکهٔ Agent هنوز پیاده نشده است. آزمایش‌های قبلی `/agent` و `/game` موفق بودند، نه آپدیت واقعی بازی.


## نتیجهٔ عملی تازه — مشاهدهٔ وضعیت Agent بدون حساب

[نتیجهٔ گام دوم و مرز بعدی](docs/AGENT-STATUS-RESULT.fa.md) · [دامنهٔ دو درخواست](docs/AGENT-STATUS-EXPERIMENT.fa.md) · [گام اول](docs/AGENT-INTERFACE-RESULT.fa.md). اجرای Windows تازه، `GET /agent` و سپس `GET /game` با token محلی همان اجرا را با HTTP 200 پاسخ داد. summary خالی با صفر محصول گزارش شد. source/run تطبیق داده شد؛ هیچ حساب، دانلود بازی، initialization، update یا repair درخواست نشد. موفقیت آپدیت بازی و سیاست Retail هنوز اثبات نشده‌اند. گام بعدِ پیشنهادی، متادیتای تازهٔ Classic Era با سقف شبکهٔ مشخص است؛ درخواست دانلود بازی یا ثبت عملیات نصب نیست و منتظر تأیید همین دامنهٔ تازه است.

## تصمیم معماری پیشین — نه اعلام حل کامل

[بررسی مسیر Agent و شرط استقلال](docs/UPDATER-BACKEND-DECISION.fa.md). موتور مستقل هنوز قواعد کامل انتخاب Retail و نویسندهٔ تراکنشی CASC ندارد. مسیر جایگزین به Agent رسمی وابسته است؛ ورود حساب شرط عمومی آپدیت Battle.net اعلام نمی‌شود. شرط ورودِ README ابزار واسط نباید به خود موتور تعمیم داده شود. کاربر امکان آپدیت بدون لاگین را گزارش کرده است؛ سازگاری کلاینت ما با آن مسیر هنوز آزمایش نشده. بدون تأیید کاربر معماری عوض نمی‌شود. در بررسی اولیهٔ معماری Agent اجرا نشد؛ آزمایش‌های واقعی بعدی در بخش بالا ثبت شده‌اند. درخواست آپدیت بازی هنوز اجرا نشده؛ رمز حساب یا ورود لازم نیست.

## وضعیت پیشین مسیر اپدیتر — selection semantic discrimination

[شرح تغییر عملکردی و آزمون](docs/UPDATER-SELECTION-SEMANTICS.fa.md) · [باقی‌مانده](docs/UPDATER-REMAINING.fa.md).

تشخیص اختلاف locale/category و فرضیه‌های 0x4000 به review اصلی هر دو manifest وصل شد؛ candidate/plan تاریخی تغییر نکرد. منبع community Classic بررسی شد، اما fallback انتخاب همه و taxonomy ناسازگار آن وارد نشد و شاهد مستقل Retail اعلام نشد. Linux=823 و Windows=524 پاس، 10 regression تازه. سیاست کامل انتخاب، variant/dependency/patch هنوز بازند؛ اشتراک فرضیه‌ها required set نیست. هیچ game/CDN access یا ZIP تازه انجام نشد؛ در آن گام اقدام کاربر لازم نبود.

## شروع ادامهٔ پروژه — فارسی (سابقه)

هدف اصلی **اثبات تله‌متری WoW در سطح فیلد/درخواست/مقصد** است. دانلودر/تعمیر پیش‌نیاز موقت است؛ آزمایش Battle.net در GitHub مسیر تحقیق مستقل است.

- [تحویل جامع جلسه و وضعیت آخر](docs/SESSION-HANDOFF.fa.md)
- [معماری و اجرای تست‌ها](docs/ARCHITECTURE.fa.md)
- [مسیر نسخه‌ها و تصمیم‌ها](docs/HISTORY.fa.md)
- [شواهد، واقعیت‌ها و محدودیت‌ها](docs/EVIDENCE-AND-LIMITS.fa.md)
- [گام بعد و شرط توقف](docs/NEXT-STEPS.fa.md)
- [دامنهٔ sync و حریم خصوصی](docs/SYNC-SCOPE.fa.md) · [وضعیت ماشین‌خوان](docs/current-state.json)
- [منبع آخرین دانلودر TagFix](downloader/README-fa.md) · [فهرست گزارش‌های کاربر](evidence/INDEX.json)

منبع TagFix با ۴۴۶ تستِ انتشار در `downloader/` نگهداری می‌شود؛ محیط Linux و تست‌های واقعی Windows کاربر جدا مستندند. **هنوز CASC writer/نصب نهایی نداریم؛ حجم قطعی دانلود null است.** Lab فعلی را حفظ کنید؛ این sync درخواست تکرار prepare، اسکن کامل یا دانلود گسترده نیست. raw transcript، PRIVATE، فایل بازی و اطلاعات ورود منتقل نشده‌اند.

## Independent GitHub experiment

This repository is separate from the WoW downloader Lab and from the user's game.
It requests **no account login, no game installation/download, no repair, no CASC
writes, no anti-cheat changes and no TLS interception**.

## Initial experiment

A manual run or a push changing the lab's scripts/tests/workflow starts one
`windows-2025` GitHub-hosted job (8-minute maximum). It:

1. Refuses self-hosted runners, non-Windows systems and preexisting Battle.net state.
2. Downloads the bootstrapper from an official HTTPS endpoint with an allowlisted
   redirect chain and a 128 MiB installer-body cap.
3. Requires a valid Windows Authenticode signature and an expected Blizzard publisher
   before executing it. No certificate validation is disabled.
4. Launches the normal setup program **without guessed silent/EULA flags or GUI
   clicks by default**, with a reduced environment excluding GitHub/account credentials.
   The explicitly authorized one-off language exception is documented below.
5. Observes for 45 seconds by default, 90 in the approved language run (configurable 30–150): known process names/PIDs, sampled public TCP
   destinations, bounded file metadata and log **keyword counts only**.
6. Attempts to stop observed setup/Agent processes. The hosted VM is disposable.
7. Adds up to two bounded, read-only GUI/session inspections; no clicks, edit/hidden/unknown control text, raw captions or screenshots. Only fixed class/label/marker enums are exported. Schema6 includes source commit/run identity and the separately reported language-step result.
8. Exports only one strictly validated JSON report; no binaries, screenshots,
   packet captures, raw logs, command lines, account/geoip values or user files.

A separate clean Linux job (4-minute maximum) revalidates the JSON and commits it to
`reports/latest.json` and `reports/run-<id>-<attempt>.json`. The observation job has
only `contents: read`; only the clean publication job has `contents: write`.
All external Actions are pinned to full commit SHAs (`action-pins.json`).
No schedule, background persistence or automatic retry is configured. Private
repository Actions minutes/storage are subject to the account's quota; no purchase
or paid runner is configured. A run may be queued/blocked by account policy/quota.

## One-off approved language step

The user explicitly approved English (US) → Continue on the observed language page.
Only the push commit `lab: approved language-only step 2026-10-15 7ce42b91-yamlfix`, first run
attempt, enables this exception. Manual workflow runs and later pushes remain
read-only. The helper checks the original verified Setup PID/executable, visible
Setup window, language group, exactly one English-US radio and Continue button.
It selects only if needed, confirms selection, rechecks the same page/controls,
and invokes Continue at most once. No legal consent, install button, account,
login, or game action follows. A private pre-action journal preserves attempted
operations on timeout; uncertainty is reported and never retried automatically.
Only fixed enums/booleans leave the runner. Installer/Agent components may download;
no game download is requested. Details: [language-step scope](docs/LANGUAGE-STEP.fa.md).

## Important limits

- Windows hosted runners are not an interactive consumer Windows desktop. If setup
  waits for interaction or does not expose an Agent process, the report says so;
  installation completion is **not** inferred. No login or UI interaction is added
  automatically to get past that limit.
- Time, download-body and output limits are separate: the **128 MiB cap applies to
  the fetched installer only**, not the bootstrapper's own subsequent network use.
  Its observation window/job timeout are bounded; there is no hard child-network
  byte cap in this initial experiment.
- Sampled TCP destinations are not full network capture or evidence of plaintext
  HTTP bodies. Log keyword occurrences do not prove an operation executed.
- A process may start/exit between samples. No Agent observed is not proof of absence.
- A fresh hosted VM isolates this experiment from user machines; it is **not** a
  security sandbox against malicious code. Only a signed expected publisher's
  bootstrapper is executed. No account or repository secrets are configured here.
- This first experiment is a bootstrap investigation, **not reverse-engineering of
  the full WoW update/patch/activation algorithm**. A real version-to-version update
  with game data needs a different, sufficiently large disposable Windows machine.
- Results must not be mixed with the separate Wow.exe telemetry study.

## Current downloader work continues independently

Keep the existing `WoW-Downloader-Lab`. Do not repeat metadata preparation/full
payload verification or start the broad conditional download queue. The current
TagFix update-scope report is evidence, not installation authorization or an exact
network download estimate.

## Sources

- https://docs.github.com/en/actions/concepts/runners/github-hosted-runners
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://github.com/barncastle/Battle.Net-Installer — delegates to the Battle.net
  Agent; its README states a recent-login prerequisite for that third-party tool,
  not a universal Battle.net update requirement. It is not run here.
