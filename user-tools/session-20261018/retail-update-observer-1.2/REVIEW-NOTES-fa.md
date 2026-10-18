# مرور سابقه برای جلوگیری از تکرار خطا

## دامنهٔ واقعی مرور
مخزن مرجع خصوصی kokononox/battle-net-agent-lab از اتصال GitHub خوانده شد؛ clone بدون احراز هویت ممکن نبود. هیچ فایل، branch، workflow، Release یا run مخزن تغییر/اجرا نشد.

- main در commit `54a3d309f8a6e001d34ff4c43fa676e04d5e83ec`.
- patch-audit-20261016 در commit `7916903f5378f72a28f745fd30fe3ae11670451a`.
- فهرست شاخه‌ها، تاریخچهٔ main در دو صفحه، نبود Issue/PR در نتایج موجود، ساختار پوشه‌های اصلی، README، handoff/history/next steps/current state، محدودیت شواهد، الزامات محصول، باقیماندهٔ updater، فهرست شواهد کاربر، کد observe_agent و checkpointهای تعیین‌کنندهٔ شاخهٔ پژوهش مرور شدند.
- این مرور ساختار، تصمیم‌ها و شواهد مرتبط است؛ **ادعای ممیزی خط‌به‌خط همهٔ فایل‌ها، خواندن همهٔ پیوست‌های خصوصی، بازسازی همهٔ گفتگوها یا اجرای دوبارهٔ تست‌های تاریخی نیست**. فایل‌های Lab و Portable خصوصی در محیط این جلسه نیستند.

## تصمیم‌هایی که باید حفظ شوند
1. هدف بلندمدت اولیه، اثبات تله‌متری WoW در سطح فیلد → درخواست → مقصد است. آماده‌کردن بازی پیش‌نیاز موقت است؛ مشاهدهٔ آپدیت جای تست تله‌متری را نمی‌گیرد.
2. هدف نهایی مسیر آپدیت Retail است. Classic فقط fixture کم‌حجم است و نتیجه‌اش به Retail تعمیم داده نمی‌شود.
3. prepare و مرور سنگین محلی سابق تمام شده‌اند؛ تعویض جلسه مجوز تکرار اسکن، دانلود یا پاک‌کردن کش نیست. عدد اندازهٔ نمایش encoded، IO محلی یا فضای پوشه، حجم قطعی اینترنت نیست.
4. موفقیت GET /agent و GET /game و token محلی Agent، اثبات ورود حساب یا موفقیت آپدیت بازی نیست. ابزار تازه ورود را لازم فرض نمی‌کند.
5. latest.json و current-state در همهٔ بخش‌ها همزمان به‌روز نیستند؛ receipt مشخص با source_commit/run_id برای ادعای همان اجرا اولویت دارد.
6. آخرین Classic receipt، form_diagnostic_complete است: eula_review_pending، game_dir_error و minimum_spec_error؛ finalization_attempted=false و version_to_version_update_proven=false. نصب کامل یا علت یگانهٔ شکست ادعا نشود.
7. برای Classic قدیمی، سابقهٔ جلسه محل‌های جایگزین ۳۷۳ فایل را در سطح metadata ثبت کرده؛ آن را دانلود/نصب کامل یا آزمایش واقعی آپدیت نمی‌نامیم. ابزار جدید این جست‌وجوی CDN را تکرار نمی‌کند.
8. main دارای اجزای انتخاب، انتقال، resume و capture است، اما required set معتبر و نصب نهایی هنوز تأیید نشده‌اند. تست مصنوعی و عدد تست معیار نصب واقعی نیست.
9. شاخهٔ patch-audit دارای کار بیشتر است: patch تک‌نمونهٔ واقعی Retail، lookup/cache/header gates، خواندن مستقیم تحت lease و CLI آفلاین Linux با failpoint/recovery. بنابراین «هیچ patch/writer آزمایشی نداریم» نادرست است. این پژوهش همچنان Windows/game updater کامل نیست؛ اصل Lab، Portable و .build.info در آن دست‌نخورده بودند.
10. timeoutهای WMI/PowerShell/UIA و موانع hosted desktop سابقه دارند. recorder حاضر از WMI، UI Automation، دانلود Setup، taskkill، proxy/TLS interception و فرمان Agent استفاده نمی‌کند؛ ابزار VM disposable را مستقیماً روی سیستم واقعی کاربر اجرا نمی‌کنیم.

## این بسته چه پرسش محدودی را جواب می‌دهد؟
آیا در یک بازهٔ کنترل‌شده روی Windows واقعی کاربر، نسخهٔ Retail قبل/بعد و زمان‌بندی سرنخ‌های لاگ، همراه با مشاهدهٔ صریح کاربر، قابل ثبت است؟

این فقط ثبت اولیه است؛ به‌تنهایی policy انتخاب فایل، الگوریتم patch، صحت نصب، بایت واقعی شبکه یا فیلدهای تله‌متری را آشکار نمی‌کند. نخست تست check_only، سپس تصمیم دربارهٔ آزمون واقعی؛ اگر نسخه/لاگ پیدا نشد، قبل از مصرف فرصت آپدیت توقف شود.

## مراجع ثابت برای ادامه
- https://github.com/kokononox/battle-net-agent-lab/blob/54a3d309f8a6e001d34ff4c43fa676e04d5e83ec/docs/SESSION-HANDOFF.fa.md
- https://github.com/kokononox/battle-net-agent-lab/blob/54a3d309f8a6e001d34ff4c43fa676e04d5e83ec/docs/HISTORY.fa.md
- https://github.com/kokononox/battle-net-agent-lab/blob/54a3d309f8a6e001d34ff4c43fa676e04d5e83ec/docs/UPDATER-REMAINING.fa.md
- https://github.com/kokononox/battle-net-agent-lab/blob/54a3d309f8a6e001d34ff4c43fa676e04d5e83ec/reports/classic-install-latest.json
- https://github.com/kokononox/battle-net-agent-lab/blob/54a3d309f8a6e001d34ff4c43fa676e04d5e83ec/scripts/observe_agent.py
- https://github.com/kokononox/battle-net-agent-lab/blob/7916903f5378f72a28f745fd30fe3ae11670451a/docs/SESSION-DIRECT-AND-SAMPLE-APP-2026-10-17.fa.md
- https://github.com/kokononox/battle-net-agent-lab/blob/7916903f5378f72a28f745fd30fe3ae11670451a/docs/SESSION-INSTALL-DOWNLOAD-CHECKPOINT-2026-10-17.fa.md
