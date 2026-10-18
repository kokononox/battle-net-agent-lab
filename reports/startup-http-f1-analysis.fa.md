# نتیجهٔ بررسی HTTP مقصدهای باقی‌مانده — F1

- Run: `39162766730`
- Source: `d65a2e226baaf4fe232fc9dfc83dcc559b3e1f61`
- Receipt: `411d9f0125a477284f8ca1ef318ca3435f32df52`
- رانر استاندارد windows-2025؛ هیچ larger runner یا گروه رانر پولی فعال نشده است.
- ۲۶ آزمون محلی parser/validator و ۲۱ آزمون پیشین parser بسته‌ها پاس شدند.
- اجرا و تبدیل capture موفق، bootstrap hash مطابق، Agent مشاهده شد؛ بدون login/game/install action.

## آنچه به دست آمد
سه درخواست کامل خروجی به `level3.blizzard.com` ثبت شد:
1. Setup: `GET /tpr/bnt001/data/c8/56/c856402fe1c953bf80faeda4cfe6c234`
   با `Range: bytes=252585721-252585761` و `Accept: */*`.
2. Agent: `GET /tpr/configs/data/e8/a9/e8a9e3b2b36cc844d7a26a18fce57792`
   با `User-Agent: agent/2.41.1.9824` و `Accept: */*`.
3. Agent: `GET /tpr/bnt002/config/97/16/9716142876376fa69386c7b79f78755f`
   با `Accept: */*`.

همهٔ این سه درخواست بدنهٔ صفر بایت دارند؛ مدل CPU مرجع VM در مسیر، هدر یا بدنهٔ آن‌ها یافت نشد.
الگو با درخواست داده و پیکربندی سازگار است؛ اثبات نمی‌کند همهٔ درخواست‌های این مقصد فقط دانلودند.
شناسه‌های ۳۲رقمی hex در مسیرها را نمی‌توان بدون تحلیل مستقل، fingerprint سیستم یا عکس آن دانست.
هیچ response body یا وضعیت ذخیرهٔ سرور بررسی نشده است؛ پاسخ پرسش A→B همچنان باز است.

## شکاف‌های باقی‌مانده؛ از آن‌ها نتیجهٔ پاک بودن نگیرید
برای `nydus.battle.net`، `us.cdn.blizzard.com` و `ocsp.digicert.com` درخواست کامل به دست نیامد.
وجود stream خالی در capture، اثبات عدم ارسال داده نیست. capture خام از VM خارج نشده و
دیگر قابل بازتحلیل نیست؛ علت دقیق پوشش ناقص مشخص نشده است. تکرار کورکورانهٔ همین اجرا توصیه نمی‌شود.
پیش از اجرای بعدی باید دلیل پوشش ناقص یا روش ثبت درخواست‌های جاافتاده روشن شود.
این نتیجه، شواهد CPU در تله‌متری E2 را نقض نمی‌کند و آزمون آپدیت بازی روی سیستم کاربر نیست.

## بازتولید تحلیل آفلاین
`python privacy-http/analyze_report.py reports/startup-http-f1.json analysis-output/http-f1`
گزارش خام در receipt ثابت بالا، فایل `reports/startup-http-f1.json` قرار دارد.
