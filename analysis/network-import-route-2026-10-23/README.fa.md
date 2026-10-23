# بررسی مسیر import تا ارسال شبکه — مرحلهٔ محدود و آفلاین

## نتیجه
مسیر «ساخت پیام V2 → ارسال شبکه» با این مرحله بازیابی نشد. مانع مشخص این است که importهای استاندارد و تأخیری Wow.exe ورودی نام‌دار send/recv/WSASend/WSARecv ارائه نمی‌کنند؛ اسکن ارجاع‌های RIP-relative به IAT آن نیز صفر نتیجه داشت. این به معنی نداشتن شبکه، ناممکن بودن تحلیل یا اثبات روش خاص حفاظت نیست.

## روش و دامنه
سه فایل موجود Wow.exe، wow_loader.dll و libxell.dll بدون اجرا، patch، attach یا تغییر تنظیمات بررسی شدند. SHA-256 هر فایل در inventory.json ثبت است. جدول import استاندارد و delay-import دستی خوانده شد؛ pefile مستقلاً همان ورودی‌ها را تأیید کرد. نام‌هایی که pefile از ordinal حدس/نگاشت می‌کند برای مقایسه به ordinal اصلی برگردانده شدند؛ نام افزودهٔ کتابخانه به عنوان نام ذخیره‌شده در باینری گزارش نمی‌شود.

تمام بخش‌های file-backed با پرچم executable برای شکل‌های RIP-relative دارای disp32 و tailهای ۰،۱،۲،۴،۸ اسکن شدند. تطبیق عددی با Capstone در مرز displacement و انتهای دستور کنترل شد. نتیجه صرفاً candidate نحوی است؛ مرز دستور واقعی و reachability عمومی را ثابت نمی‌کند. دستورهای CALL/JMP با شش بایت FF15/FF25 مستقلاً با regex و محاسبهٔ signed disp32 کنترل شدند. اشاره‌گرهای VA64 دارای relocation نوع DIR64 به اسلات‌های IAT نیز بررسی شدند.

## یافته‌ها
| فایل | import معمول | import تأخیری | candidate به IAT | FF15/FF25 مستقل | DIR64 به IAT |
|---|---:|---:|---:|---:|---:|
| Wow.exe | ۱ | ۲۰ | ۰ | ۰ | ۰ |
| wow_loader.dll | ۳۶ | ۰ | ۱ | ۱ | ۰ |
| libxell.dll | ۲۱۲ | ۰ | ۷۳۶ | ۶۷۱ | ۰ |

- تنها import معمول Wow.exe، ordinal 1 از Wow_loader.dll است. تأخیری‌ها شامل OLEAUT32، libHttpClient و overlay هستند. وجود libHttpClient/overlay، مسیر World V2 یا TCP/3724 را ثابت نمی‌کند.
- loader دارای WS2_32!WSASocketW و یک ordinal دیگر از WS2_32 است. به اسلات WSASocketW در دامنهٔ RIP-relative این اسکن ارجاعی پیدا نشد. اسلات import، آدرس نهایی تابع resolveشده در حافظه نیست.
- تنها candidate ارجاع IAT در loader، `jmp qword ptr [rip + 0x640a2]` در RVA 0x203BFE0 به InitSecurityInterfaceA است؛ pdata owner ندارد. وجود این thunk به معنی کشف handler یا مسیر ارسال نیست.
- libxell کنترل مثبت برای تشخیص ارجاع‌های متعارف IAT است، نه نتیجهٔ شبکهٔ بازی. ۷۳۶ candidate با ۶۷۱ CALL/JMP شش‌بایتی یکسان نیست؛ بقیه می‌توانند LOAD، prefix یا decode همپوشان باشند و نباید به تعداد فراخوان‌های مستقل تبدیل شوند.

### کنترل محدود resolver در libxell
از سه pdata function اول دارای candidate GetProcAddress، یک walk محلی حداکثر ۱۰۰۰ دستور با دنبال‌کردن پرش‌های مستقیم داخل همان محدوده و fallthrough ساخته شد؛ وارد calleeها نشد و exception edgeها مدل نشدند. شمار دستورهای نحوی ۱۱۶،۳۹،۵۵ بود. هیچ توقف undecodable یا indirect-jump و هیچ عبور از سقف دیده نشد. این فقط walk محلی از entry انتخاب‌شده است، نه اجرای واقعی یا CFG کامل برنامه.

- RVA 0x1A47A: رشته‌های NtQueryTimerResolution و NtSetTimerResolution در LEAهای RIP دیده شدند.
- RVA 0x2C320: advapi32.dll، EventRegister، EventUnregister و EventWrite دیده شدند.
- این زمینه‌ها شواهدی برای مرتبط بودن این نمونه‌ها با تایمر/رویداد هستند؛ اتصال دادهٔ هر رشته به آرگومان هر فراخوان مستقل اثبات نشده است. هیچ‌یک سازندهٔ پیام V2 شناسایی نشدند.

### کنترل رشته‌های API
جست‌وجوی محدود send/recv/connect/socket و چند API مرتبط انجام شد. تطبیق انتهای NUL با مرز غیرحرفی لزوماً نام مستقل API نیست؛ مثلاً انتهای متن تشخیصی ممکن است match شود. verification.json موارد دقیقاً بین دو NUL را جدا کرده است.

- Wow.exe رشتهٔ `connect` در RVA 0x42491D8 دارد؛ در زمینهٔ نزدیک WSAStartup و RouteResolutionWorkerThread نیز دیده می‌شوند. این anchor شبکه‌ای محتمل است، نه import یا تابع فراخوانندهٔ اثبات‌شده. در این مرحله xref/مصرف این رشته دنبال نشده است.
- رشتهٔ `socket` در RVA 0x40525D0 کنار gemItem، enchantSlot و JamItemGemData است؛ نباید آن را صرفاً از روی نام به Winsock نسبت داد.
- WSASocketW در loader در بخش .eid در RVA 0x27DDFC9 ذخیره شده است؛ این نام با import آن سازگار است، نه مدرک استفاده در مسیر V2.

## محدودیت و تصمیم
ارسال ممکن است از pointerهای محاسبه‌شده، load از رجیستر، resolver غیرمتعارف، کد runtime یا مسیر دیگری انجام شود؛ این‌ها در این مرحله نه اثبات و نه رد شدند. اسکن absolute addressing، همهٔ فرم‌های RIP با هر tail ممکن، CFG سراسری و dataflow runtime انجام نشده‌اند. فقدان xref در این دامنه را نباید به فقدان فراخوان واقعی تعمیم داد.

این مسیر استاندارد import برای Wow.exe فعلاً متوقف است؛ تکرار همان اسکن ارزش افزوده ندارد. anchor بعدی کم‌هزینه، رشتهٔ connect و زمینهٔ WSAStartup است، با شرط موفقیت صریح: xref و مصرف واقعی یا wrapper قابل‌بررسی، نه صرفاً چند رشتهٔ نزدیک. اگر آن هم فاقد مصرف قابل‌بازیابی باشد، با داده‌های موجود وعدهٔ بازیابی handler نمی‌دهیم.

نه تابع serialization، نه کلید، نه plaintext رمزگشایی‌شده و نه ارسال CPU/BIOS در این مرحله به دست آمد. نتیجهٔ قبلی مرزبندی ۳۱۹ پیام شبکه تغییر نکرد. هیچ آزمایش جدیدی از کاربر لازم نبود.

## بازتولید
با Python و numpy، capstone 5.0.9 و pefile، ابتدا source/analyze.py و سپس source/verify.py اجرا شوند؛ فایل‌های ورودی باید در /data/wlab-inputs باشند. مسیر PYTHONPATH باید source و وابستگی‌ها را پوشش دهد. خروجی‌ها در reports ذخیره می‌شوند. pefile در یک اجرای اولیه نام‌های افزودهٔ ordinal را باعث اختلاف مقایسه کرد؛ پس از normalize به دادهٔ اصلی، تطبیق هر سه فایل موفق شد.

فایل‌های خام، دامپ، capture، کلید یا مقادیر سخت‌افزاری در این بسته/commit وجود ندارند. main و BIOS Path GUI تغییر نمی‌کنند.
