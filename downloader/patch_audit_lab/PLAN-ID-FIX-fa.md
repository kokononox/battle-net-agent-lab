# اصلاح قرارداد شناسهٔ plan

این افزونه را کنار source_check.py در پوشهٔ ابزار قبلی استخراج و جایگزینی فایل‌ها را تأیید کنید. سپس START-SOURCE-CHECK.cmd را اجرا و ریشهٔ همان Lab را انتخاب کنید. فقط Retail-Patch-Source-Binding-to-share.json ارسال شود؛ PRIVATE-Patch-Source-Plan.json محلی بماند.

اشکال ابزار جدید: شناسهٔ plan را UUID خالی ۳۲کاراکتری فرض کرده بود. کد اصلی content_plan.build در commit fcc60791762a2deb98f14867e287827b45684539 مقدار out.path.stem را ذخیره می‌کند؛ یعنی content-plan-UUID، نه UUID خالی. نام فایل‌ها همچنان با الگوی دقیق و fingerprint کنترل می‌شود.

اصلاح: plan_id بانک plan باید دقیقاً با نام همان فایل بدون پسوند و plan_id ثبت session برابر باشد. source_plan_id هر سه بانک queue/inventory/evidence نیز باید با آن برابر باشند. شناسهٔ یکسان ولی متعلق به فایل plan دیگری رد می‌شود. هیچ داده‌ای در Lab تغییر یا مهاجرت داده نمی‌شود.

۱۱۹ آزمون محلی در Linux/Python 3.13 پاس شد. fixture قبلی نیز اصلاح شد تا مانند تولیدکنندهٔ اصلی شناسهٔ دارای پیشوند را ذخیره کند. پنج آزمون جدید شامل پذیرش قرارداد اصلی، رد UUID خالی حتی در صورت یکسانی همهٔ منابع، رد شناسهٔ فایل دیگر، اختلاف session و اختلاف تک‌تک بانک‌های وابسته است. موفقیت Windows یا Lab واقعی هنوز ادعا نشده است.

منابع کد اصلی:
https://github.com/kokononox/battle-net-agent-lab/blob/fcc60791762a2deb98f14867e287827b45684539/downloader/content_plan.py
https://github.com/kokononox/battle-net-agent-lab/blob/fcc60791762a2deb98f14867e287827b45684539/downloader/local_review.py

همچنین قرارداد snapshot، source_snapshot_id، جدول‌های candidates/archives/evidence و رابطه evidence.ordinal=candidates.id در local_casc.py همان commit بازبینی شد. این بازبینی جای اجرای واقعی روی Lab نیست. نیازی به تکرار اسکن یا دانلود نیست.
