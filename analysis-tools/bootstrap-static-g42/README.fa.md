# بررسی استاتیک bootstrap رسمی — G42

این ابزارهای پژوهشی نصاب را اجرا نمی‌کنند و به کارگزار production مجوز نمی‌دهند.

- acquire.py: لینک دقیق موجود در صفحهٔ عمومی رسمی، redirect محدود HTTPS، دریافت حداکثر32MiB، ذخیرهٔ خصوصی0600 و hash. دریافت مجدد روی فایل موجود عمداً overwrite نمی‌کند.
- inspect_pe.py: بررسی محدود PE32، resource، import، گواهیِ تعبیه‌شده و schemaهای protobuf. parse گواهی به معنی اعتبارسنجی trust نیست. فقط همین فایل بررسی‌شده پشتیبانی می‌شود؛ ابزار عمومی reverse-engineering یا parser مقاوم به همهٔ فایل‌های خصمانه نیست.
- Verify-Signature.ps1: دریافت URL ثابت با اندازه/hash دقیق و Get-AuthenticodeSignature روی Windows؛ فایل فقط داده است، اجرا نمی‌شود و پس از بررسی حذف می‌شود. workflow فقط در branch/message دقیق و run_attempt=1 فعال است.

در Linux به Python، cryptography و google.protobuf نیاز است. از ریشهٔ clone، acquire.py سپس inspect_pe.py اجرا می‌شوند؛ فایل باینری محلی زیر private می‌ماند. برای تست evidenceهای ثبت‌شده، همان hash فایل لازم است. گزارش امضای بومی مربوط به source/run پین‌شده است؛ آزمون آفلاین آن را دوباره روی Windows اجرا نمی‌کند.

نتیجه و محدودیت‌ها: reports/bootstrap-static-g42/RESULT.fa.md. هیچ telemetry واقعی، مقدار client_id/uuid یا capture کاربر در گزارش نیست؛ فقط نام فیلدهای موجود در خود فایل عمومی ثبت شده‌اند. manifest کامل و resource واقعی approved هنوز وجود ندارد.
