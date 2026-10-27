# آزمایش Retail c1: اجرا نشد

رسید CI برای کد `4c70236eaaa0f5e2b2912c110e4f36918047dece`، اجرای `40446257915`، مرحله آزمون را failure و مشاهده Agent را skipped ثبت کرد. بنابراین این اجرا هیچ شاهدی از پاسخ فرم نصب، احراز هویت یا دانلود نیست.

بدون PYTHONPATH، خطای ModuleNotFoundError برای probe در آزمون محلی بازتولید شد. c2 مسیر وابستگی را در خود ماژول تعیین می‌کند؛ ۳۱ آزمون در چیدمان مشابه checkout و بدون PYTHONPATH گذشت. این بازتولید علت محتمل است؛ لاگ خام اجرای CI بررسی نشده است.

رسید ثابت: https://github.com/kokononox/battle-net-agent-lab/blob/bbcf01f63e7323ac099f941fd24df10f37ea540d/reports/prelogin-retail-prepare-ci.json
