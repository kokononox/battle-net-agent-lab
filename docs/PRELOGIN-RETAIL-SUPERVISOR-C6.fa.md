# ناظر مستقل c6: ساخت ناموفق، Agent اجرا نشد

کد منبع `7b903317825d5382cadbff830a8f1dd2bc0cc2ab`، اجرای `40455690433`، رسید `063b07d3705d55f07f83b03a8f9eaa34398dd5ee`.

آزمون‌های Python گذشتند، اما دروازه ناظر با status=refused و error_kind=build_failed متوقف شد. fixtures خالی و observation=null بود؛ بنابراین نه آزمون‌های بومی فرزند/نوه و نه Agent اجرا شدند. نتیجهٔ تازه‌ای از فرم یا دانلود نداریم. شکست اعتبارسنجی فرم در CI به دلیل تولید نشدن گزارش فرم در اجرای انجام‌نشده است، نه شاهد جدید از رفتار نصب.

دلیل دقیق خطای ساخت در این رسید تفکیک نشده است. c7 فراخوانی ساخت را به فایل فرمان صریح تغییر می‌دهد و فقط مرحله، کد خروج و کدهای استاندارد خطای کامپایلر را ثبت می‌کند؛ این تغییر را اثبات علت خطای قبلی نمی‌دانیم. هیچ مسیر بدون ناظر برای ادامه اضافه نشده است.

منابع ثابت:
- https://github.com/kokononox/battle-net-agent-lab/blob/063b07d3705d55f07f83b03a8f9eaa34398dd5ee/reports/prelogin-retail-prepare-ci.json
- https://github.com/kokononox/battle-net-agent-lab/blob/063b07d3705d55f07f83b03a8f9eaa34398dd5ee/reports/prelogin-retail-supervision-latest.json
