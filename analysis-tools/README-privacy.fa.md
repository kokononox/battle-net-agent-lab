# بازتولید آفلاین مشاهده درخواست‌ها

این ابزار هیچ اتصال شبکه، اجرای کلاینت یا خواندن نصب بازی ندارد. نمونه ثابت E2 را از شاخه پژوهش/commit d64629013489a4a51d93defbc11531b629aacccb بگیرید؛ path: reports/startup-tls-e2-buffers.json.

اجرا:

```sh
python analysis-tools/reconstruct_tls_requests.py startup-tls-e2-buffers.json analysis-output/tls-values
```

SHA256 هر sample پیش از تحلیل بررسی می‌شود. فقط EncryptMessage با context alias برای بازسازی stream استفاده می‌شود. خروجی شامل bodyهای بازسازی‌شده، ASCII strings، JSON در صورت امکان و evidence.json است؛ مقدارهای همین VM آزمایشی با اجازه کاربر نگه‌داری می‌شوند. API input/تکمیل Content-Length دریافت یا ذخیره سرور را ثابت نمی‌کند. Alias context و ترتیب محلی می‌تواند در صورت sample ازدست‌رفته یا آدرس بازیافت‌شده محدودیت داشته باشد.

CPU finding مستقل و hashهای multipart در evidence/telemetry-e2-cpu-evidence.json ذخیره شده‌اند؛ برای بازتولید مستقل از خود sampleهای base64 مقدار CPU مرجع را جست‌وجو کنید و با PID/hash امضاشده در reports/startup-tls-e2-live.json تطبیق دهید. مدل CPU مرجع را به سیستم کاربر یا فیلدهای هنوز decodeنشده RAM/GPU تعمیم ندهید. معنای field numberهای باینری بدون schema نامعلوم می‌ماند.
