# بازتولید تحلیل G38

`review_sources.py` آفلاین است و هیچ مجوز یا کاتالوگ اجرایی تولید نمی‌کند. ورودی‌ها:
- پوشهٔ raw با online-g26.json از گزارشِ pinned و Reporter.py از source commit آن؛ projection request_metadata، صفحه‌های رسمی و مشاهدهٔ HEAD نیز برای provenance hash می‌شوند.
- پوشهٔ derived با official-windows-links.json: ویژگی‌های لینک استخراج‌شده از HTML رسمی.

```bash
python analysis-tools/download-source-review-g38/review_sources.py --raw RAW_DIR --derived DERIVED_DIR --output evidence-local.json
```

گزارش اصلی از این URL قابل دریافت است:
```
https://raw.githubusercontent.com/kokononox/battle-net-agent-lab/494752c2d647f5c83ac87b502b1e1c535cc7d468/reports/longer-client-observation-g26/online-g26.json
```

source Reporter در commit `a814cd7b929f415363bc57f0cd27dc6d5f86d791` و مسیر `analysis-tools/two-destination-g26/Reporter.py` است. تحلیل pandas با direct filter مستقل کنترل شده است. ردیف‌ها رخدادِ پالایش‌شده‌اند و سقف نمونه، hash-only path و null ساختاری در نتیجه لحاظ شده‌اند. نمودار عددی برای این تصمیم کیفیِ منشأ/مجوز معنی‌دار نیست.

صفحات و اسکریپت رسمی به‌صورت inert خوانده شدند، نه اجرا؛ hash و ویژگی‌های لینک در گزارش همراه هستند. درخواست HEAD فقط هدر را می‌خواند و checksum تازهٔ فایل را ثابت نمی‌کند. نسخهٔ رسمی آینده ممکن است تغییر کند. کل HTML/JavaScript شخص ثالث دوباره در مخزن منتشر نشده است؛ برای snapshot تاریخی، hashها provenance هستند نه جایگزین متن اصلی. ابزار online discovery به محصول یا به کاتالوگ allowlist متصل نشده است.
