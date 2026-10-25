# پیش‌آزمون مجازی‌سازی مهمان داخل GitHub

هدف: تشخیص امکان مسیر VM مهمان برای آزمون reboot ویندوز، بدون reboot میزبان یا دانلود سیستم‌عامل. فقط شاخهٔ تحقیق، attempt اول، GitHub-hosted و commit دقیق c1 مجازند.

## Linux / KVM

- از /proc فقط وجود flag مجازی‌سازی و مقدار کلی RAM خوانده می‌شود؛ مدل CPU، hostname، IP و شناسه‌های دستگاه صادر نمی‌شوند.
- /dev/kvm در دو زمینه بررسی می‌شود: کاربر runner و یک diagnostic تحت sudo بدون تغییر permission یا گروه دستگاه.
- API version 12 و قابلیت user memory کنترل می‌شوند؛ یک VM **خالی و بدون vCPU/حافظهٔ مهمان** با KVM_CREATE_VM ساخته و fd فوراً بسته می‌شود.
- موفقیت یعنی ایجاد VM خالی مجاز است؛ اجرای vCPU، بوت Windows و reboot مهمان هنوز ثابت نیستند.
- هیچ package، module، service، udev rule یا permission دستگاه تغییر نمی‌کند.

## Windows / Hyper-V

فقط capabilityهای boolean، وضعیت feature/service موجود و وجود New-VM بررسی می‌شوند. اگر feature قبلاً نصب و vmms در حال اجرا باشد، فقط یک تعریف VM بدون دیسک، بدون Start-VM ساخته و حذف می‌شود. feature فعال یا service روشن نمی‌شود؛ هیچ reboot میزبان انجام نمی‌شود. ساختن تعریف VM با اجرای Windows مهمان یکی نیست.

## کیفیت و خروجی

۱۸ آزمون قرارداد، عدم پذیرش ادعای بوت/reboot، نشت hostname/model یا تغییر permission را کنترل می‌کنند. گزارش‌های عمومی فقط provenance کد، booleanها، چند شمارندهٔ منابع و diagnosticهای ثابت دارند. خطاهای خام، مسیر خصوصی و اطلاعات ماشین منتشر نمی‌شوند.

حتی نتیجهٔ مثبت این مرحله فقط **پیش‌نیاز** است. برای نتیجهٔ اصلی باید تصویر Windows معتبر و مجاز، دیسک ماندگار همان مهمان، کنترل بوت/پروفایل و آزمون قبل/بعد فراهم شود. artifact یا job تازه جای reboot همان مهمان نیست.

[محدودیت رسمی nested virtualization در GitHub-hosted runners](https://docs.github.com/actions/using-github-hosted-runners/about-github-hosted-runners): ممکن است از نظر فنی عملی باشد، اما پشتیبانی رسمی/تضمین ثبات ندارد.


## گسترش c2: کنترل اجرای vCPU

پس از c1 که ساخت VM خالی در KVM با دسترسی privileged را تأیید کرد، c2 یک مهمان مصنوعی ۷بایتی ساخته‌شده از سورس همین پروژه را اجرا می‌کند: یک marker ثابت روی پورت I/O مجازی خروجی می‌دهد و HLT می‌کند. فقط 4KiB حافظه، یک vCPU و fdهای موقت KVM دارد؛ دیسک، شبکه، BIOS، سیستم‌عامل یا برنامهٔ ثالث ندارد. marker و HLT باید هر دو از KVM_RUN دریافت شوند؛ timeout/خطا هیچ ادعای مثبت نمی‌دهد. ۲۸ آزمون قرارداد پاس شدند و C با -Werror کامپایل شد. اجرای این مهمان با بوت Windows و reboot مهمان یکی نیست.

probe ویندوز در c1 خطای ابزار داشت؛ c2 فراخوانی PowerShell را به command متنِ کنترل‌شده تغییر می‌دهد، خطای فرمان/timeout/JSON را جدا ثبت می‌کند و query نبود command/service را محافظت می‌کند. هیچ execution policy یا feature تغییر نمی‌کند. علت دقیق خطای c1 بدون شاهد اضافی قطعی اعلام نمی‌شود.


## نتیجهٔ واقعی c2

در run `40153443222`، مهمان مصنوعی روی KVM با vCPU اجرا شد و marker/HLT مورد انتظار دریافت شدند. Windows مهمان هنوز بوت نشده است. probe مسیر Hyper-V با timeout نامشخص ماند؛ نبود Hyper-V ثابت نشده است. [گزارش نتیجه و مراحل باقی‌مانده](../../docs/PRELOGIN-NESTED-KVM-RESULT.fa.md).
