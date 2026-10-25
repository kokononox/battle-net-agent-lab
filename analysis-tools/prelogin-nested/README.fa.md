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
