# b4: Popen عادی + فقط ردیابی رجیستری بوت‌استرپ

این مرحله پس از موفقیت b3 است و به همان bootstrapِ دارای SHA pin، پس از Popen عادی، attach می‌کند. فقط registry_hook.js موجود و ثابتِ مسیر prelogin-registry-stack همراه پیام readiness بارگذاری می‌شود؛ wire hook، Frida spawn، child gating و attach به Agent درخواست نمی‌شوند. اتصال همچنان کد ابزار را در فرایند بارگذاری می‌کند.

## دامنه و دادهٔ خروجی

فقط HKCU\Software\Blizzard Entertainment\Blizzard Error، مقدار UserUUID، زیر نظر است. کلید مصنوعی مخصوص fixture نیز برای گیت بومی استفاده می‌شود، نه دادهٔ شخصی کاربر. observer مقادیر رجیستری هدف را تغییر نمی‌دهد. baseline قبل/بعد صرفاً وجود مقدار و معتبر بودن قالب UUIDv4 را گزارش می‌کند؛ مقدار یا هش شناسه صادر نمی‌شود.

هر callback موفق/ناموفق فقط API، نوع read/write، status/type، معتبر بودن قالب و RVA/frame داخل تصویر تأییدشده را صادر می‌کند. هیچ UUID، PID، مسیر، متن UI یا آدرس مطلق صادر نمی‌شود. تعداد callback به تعداد مستقل عملیات تعبیر نمی‌شود، چون wrapperهای API ممکن است تو در تو باشند.

این مرحله payload شبکه ندارد و هیچ مقایسهٔ UUID با host_id شبکه انجام نمی‌دهد. برای جلوگیری از سوءبرداشت، فیلد equals_wire_host_id از خروجی حذف و wire_comparison_performed=false اجباری شده است. نام فایل/تصویر SHA مربوط به باینری عمومی pinشده است، نه هش شناسهٔ کاربر.

## گیت بومی و ایمنی

در x64/x86، fixture C++ قبل از تماس با کلید مصنوعی روی stdin منتظر می‌ماند. پس از Popen عادی و اتصال registry-only، readiness حداقلی و رجیستری، تمام APIهای مورد انتظار، bitness و identity قبل/بعد کنترل می‌شوند؛ سپس newline اجازهٔ اجرای تست‌ها را می‌دهد. گیت باید writeW/readW/readA/RegGetValueW، کنترل منفی size-only، frameهای دقیق متعلق به تصویر fixture در readW/writeW، exit صفر و errors/limits صفر را ثبت کند. فقط عبور هر دو معماری اجازهٔ شروع target است. fixture فقط کلید خودش را می‌سازد و پاک می‌کند؛ باینری، PDB و build خروجی عمومی ندارند.

شکست baseline قبل از هدف، امضا/pin، native gate یا identity مانع ادعای موفقیت می‌شود. عملیات Frida محدود است؛ فقط ویندوز تازهٔ GitHub-hosted، push دارای guard، attempt اول و شاخهٔ تحقیق مجاز است. هیچ Install، login، دانلود بازی، remote access یا تغییر TLS درخواست نمی‌شود. محیط پاک فرزند token گیت‌هاب ندارد.

## تفسیر از پیش تعیین‌شده

- اگر startup با registry-only به Agent برسد، این ترکیب در نمونهٔ ما مانع startup نشده است؛ این حکم دربارهٔ تمام hookها یا نسخه‌ها نیست.
- اگر UserUUID با write/read موفق ثبت شود، فقط همان رخداد در bootstrap و بازهٔ پس از attach اثبات می‌شود؛ انتساب به provider، یکتایی نصب یا ارسال روی شبکه از آن نتیجه نمی‌شود.
- اگر رکوردی نباشد، به دلیل attach پس از launch و دامنهٔ bootstrap_only، نبود جمع‌آوری، نبود فعالیت Agent یا نبود ارسال ثابت نمی‌شود.
- status=observation_complete صرفاً تکمیل observer است. target_attach، registry.ready_processes، errors/limits، records، baseline و readiness جدا خوانده می‌شوند. Attach.ready وضعیت زمان راه‌اندازی ابزار است، نه تضمین اتصال پیوسته تا cleanup.

مقایسهٔ b3 و b4 روی یک ماشین نیست. process_birth_coverage=false، network_payload_observed=false، provider_assignment_causality_proven=false و observer_causality_proven=false اجباری‌اند. شواهد a11 و b2/b3 محفوظ و سؤال دوم همچنان در صف است.

۵۶ آزمون محلیِ پروتکل/گزارش و ۶۰ آزمون موجود به‌همراه ۶۲ کنترل JS hook در CI در نظر گرفته شده‌اند؛ نتیجهٔ Windows باید جداگانه خوانده شود. گزارش عمومی فقط دو JSON محدود runtime/CI است؛ فایل کامل مشاهده، UUID/هش UUID، باینری یا capture منتشر نمی‌شود.
