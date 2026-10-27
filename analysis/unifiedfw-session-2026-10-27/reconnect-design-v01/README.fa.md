# اتصال مجدد SSTP — kernel تصمیم v0.1، نه ابزار اجرایی

این ماژول فقط از مشاهدهٔ نوع‌سنجی‌شده تصمیم پیشنهادی می‌سازد. native observer، اجرای تغییر قوانین، ثبت ژورنال، bootstrap DNS/گواهی و اتصال واقعی VPN ندارد. وارد guardian یا کپی توسعه HF1.2.2 نشده است.

برای offline/connecting، data باید قبلاً با بررسی دقیق غیرفعال شده باشد؛ تنها حمل محدود از قبل تأییدشده قابل حفظ است. نبود DNS، TLS یا underlay آماده نتیجهٔ blocked می‌دهد، نه اجازهٔ عمومی. اتصال تازه با binding متفاوت ابتدا تعلیق و طرح rebind محدود می‌خواهد؛ online شدن از روی alias/index تنها مجاز نیست.

`bound_online_candidate` تأیید packet/no-leak یا دستور فعال‌سازی نیست؛ executor مجزا باید هویت، seal و وضعیت تازه را کنترل کند. تمام خروجی‌ها `native_executor_implemented=false` دارند. ورودی bool باید از observer معتبر بیاید؛ دادهٔ کاربر و config مرجع اعتماد نیستند.

اجرای مدل: `pwsh -NoProfile -File Test-Decision.ps1`. نتیجهٔ فعلی ۶۷ بررسی موفق در Linux/PowerShell 7 است؛ Windows و reconnect واقعی آزموده نشده‌اند. هیچ دستور اجرا روی سیستم کاربر در این پوشه وجود ندارد.
