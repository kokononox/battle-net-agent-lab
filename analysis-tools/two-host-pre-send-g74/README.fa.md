# G74 — نمونهٔ بستهٔ کنترل قبل از ارسال، فقط با گیرندهٔ محلی

این مرحله به جای تکرار مشاهدهٔ نصب، کد تصمیم‌گیری و بازسازی درخواست را اضافه می‌کند. **هنوز فیلتر نصب‌کننده یا پراکسی شفاف نیست.** هیچ target، دانلود خارجی، تغییر firewall، certificate یا allowlist اجرا نمی‌شود. دو مقصد اصلی و استثنای مدیریت CI بدون تغییرند؛ main و Unified Firewall Desktop 0.9.10 دست‌نخورده‌اند.

## قرارداد نمونه
یک adapter مورد اعتماد باید دقیقاً یک درخواست کامل HTTP/1.1 plaintext را به `CompleteRequestGate.feed` و سپس یک بار `finish` بدهد. تا قبل از finish هیچ خروجی ندارد. درخواست ناقص، چندتایی، bodyدار، بیش از 16KiB یا دارای query/fragment، مسیر ناپین‌شده، header ناشناخته، credential یا Range نامنطبق رد می‌شود. duplicate، obs-fold، bare newline و ambiguity framing هم رد می‌شوند.

فقط GET، Host دقیق و مسیر عمومی پین‌شده پذیرفته می‌شود. CDN از catalog مستقل G69 با قواعد Range G73 و config عمومی G72 استفاده می‌کند. metadata فقط 11 مسیر دقیق v2 در دریافت مستقل را می‌پذیرد. seqn، مسیرهای short alias، Range metadata و UAهای غیر از literal ثابت bootstrap هنوز پشتیبانی نمی‌شوند؛ برای سازگاری بی‌دلیل قاعده باز نشده است.

ورودی مستقیم forward نمی‌شود: متد/Host/Accept/Connection ثابت بازسازی می‌شود، UA ورودی صادر نمی‌شود، و فقط مسیر کامل عمومی و Range دقیقِ canonical اجازهٔ تغییر دارند. صرف تطابق دامنه یا هش کافی نیست. خروجی wire فقط داخل برنامه است و در گزارش ذخیره نمی‌شود. خطاها reason code ثابت دارند، نه exception یا مقدار خصوصی.

## آزمون
unittestها syntax، قطعه‌بندی در هر مرز، یک‌بایت‌یک‌بایت، ورودی ناقص/اضافی، mutation، خطا و pin را پوشش می‌دهند. `pre_send_fixture.py` روی loopback یک گیرندهٔ فیزیکی دارد. موارد مجاز باید دقیقاً درخواست canonical را دریافت کنند و برای موارد ردشده حتی اتصال upstream هم ایجاد نشود. Host ورودی هیچ‌گاه آدرس socket fixture را تعیین نمی‌کند؛ آدرس همیشه literal 127.0.0.1 است. این شاهد فقط همین harness است، نه همهٔ APIهای سیستم.

## مرزهای صریح
EOF/finish این harness قرارداد adapter آزمایشی است و راه‌حل completion عمومی برای client HTTP نیست. TLS opaque رد می‌شود؛ TLS interception، جایگزینی send/WSASend، فرایندهای فرزند، async I/O و integration واقعی وجود ندارند. تغییر تصمیم در onLeave یا ارسال بخشی از header قبل از تصمیم امن نیست و استفاده نشده است.

قبل از هر integration واقعی باید assembly/framing و محدودیت حافظه/timeout، اتصال تصمیم به ارسال دقیق همان bytes، endpoint/port/TLS binding و جلوگیری از bypass تمام مسیرهای خروجی آزموده شود. انتخاب بین مقادیر عمومی، ترتیب، تعداد و timing همچنان ممکن است کانال اطلاعاتی باشد. این نمونه ادعای نبود fingerprint، دانلود کامل موفق یا آماده‌بودن محصول ندارد. مراجع snapshot ثابت‌اند؛ update فقط مستقل، validate و pin می‌شود، نه یادگیری خودکار از درخواست target.
