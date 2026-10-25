# بازبینی محافظه‌کارانهٔ مجوز Task

این ابزار فقط گزارش G30 را می‌خواند و یک بازبینی advisory تولید می‌کند. هیچ Task، فایروال یا قاعدهٔ runtime را تغییر نمی‌دهد و هیچ خروجی آن معافیت نیست. کنترل ACEهای استاندارد WRITE_DAC، WRITE_OWNER، GENERIC_ALL و GENERIC_WRITE در خارج از SYSTEM/Administrators برای تصمیم اعتماد خودکار مانع ایجاد می‌کند. شکل پشتیبانی‌نشده یا دادهٔ ناقص unknown است؛ AccessCheck مؤثر یا exploit انجام نمی‌شود.

اجرا:
```bash
python ReviewTaskSecurity.py task-security-g30.json review.json
python TestTaskSecurityReview.py
```

تصمیم واقعی بازیابی در Classify.py/Recover.ps1 با این ابزار عوض نشده است. گزارش‌های G29 و G30 نتایج عملی و دامنهٔ محدود آن‌ها را ثبت می‌کنند.
