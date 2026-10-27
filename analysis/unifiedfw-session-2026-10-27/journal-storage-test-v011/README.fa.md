# اصلاح fixture ذخیره‌سازی Windows — ۰٫۱٫۱

[راهنمای بسته](package/UFW-JOURNAL-STORAGE-011/README-FA.md)، [ZIP hash](PACKAGE-SUMMARY.json)، [نتیجهٔ واقعی نسخهٔ قبلی](evidence/Windows-storage-01-partial-result.json) و [diff محدود fixture](fixture-only.patch).

Windows PS5.1 x64 نسخهٔ قبلی payload، ACL root/session/record/lock، roundtrip اولیه، no-overwrite، stale head و lock را پاس کرد؛ سپس در append_and_memory_recovery با ufw_core_profile_coverage متوقف شد. cleanup موفق بود و هیچ real profile query/legacy journal/network mutation درخواست نشد. checkpoint_count=0 در این گزارش مقدار نهاییِ تنظیم‌نشده است، نه اثبات اینکه هیچ فایل checkpoint ایجاد نشده بود. flagهای false مراحل بعد به معنی اجرا/رد شدن آن‌ها نیستند.

علت شناسایی‌شده در adapter دادهٔ ساختگی است: whole-array ConvertFrom-Json در WinPS5.1 ممکن است آرایه را یک object pipeline بدهد و array-expression یک ردیف nested بسازد. مدل PS7 با shim همین قرارداد خروجی، خطای دقیق همان stage/code را در v01 بازتولید کرد؛ v011 در همان shim کل fixture و ۱۱ checkpoint را گذراند. این شبیه‌سازی execution واقعی WinPS5.1 نیست و موفقیت نهایی Windows v011 هنوز pending است.

فقط یک خط ReadProfiles fixture به clone سطر‌به‌سطر object تغییر کرده؛ سه module تولیدی byte-identical و guard دقیق سه profile بدون تغییرند. ۳۶ assertion fixture و ۷۳ journal و ۱۰ regression سازگاری گذشتند؛ parse پنج فایل و CMD/pin/hash نیز بررسی شد.

اقدام کاربر: فقط ZIP v011 در پوشهٔ تازه، Run-Test.cmd با admin همان حساب؛ شبکه/SSTP همان حالت. JSON جدید UFW-JOURNAL-STORAGE-011-*.json حتی failure برگردد. نسخهٔ قبلی تکرار نشود و برای pass کردن هیچ تنظیمی عوض نشود. همچنان no Apply، no real-session consent/store، no legacy access و no protection qualification.
