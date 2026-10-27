# ادامهٔ جلسه: مدل تراکنش ایزولاسیون و بازیابی

## آخرین رسید و تصمیم

ALLOW-REVIEW-01 روی Windows5.1 بدون خطای فیلتر تمام شد:۳پروفایل ActiveStore فعال/outboundBlock،۴۲۶قاعدهٔ دیده‌شده،۱۰۶Allowخروجی فعال و۱۰۶عدم‌تطبیق با predicateحمل محدود. match=0. قواعد سرویس غیرSstpSvcدقیق۱۰۶،پورت غیر443دقیق۱۰۴،مقصد غیرIPصریح۱۰۳،پروتکل غیرTCP۷۸،مسیر غیرsvchostدقیق۷۶؛ دلیل‌ها هم‌پوشان‌اند. هیچ تغییر یا اجرای هدف درخواست نشده است. رسید پالایش‌شده: allow-review-v01/evidence/Windows-allow-review-completed-106-mismatches.json.

این نتیجه نه خطرناک‌بودن همهٔ۱۰۶قاعده، نه قابل‌استفاده‌بودن همه برای نصب‌کننده و نه۱۰۶قاعدهٔ local قابل‌تغییر را ثابت می‌کند. تطبیق local/effective/منشأ و فیلتر کامل در diagnostic صادر نشده و backup از شمارش ساخته نمی‌شود. کاربر پس از توضیح مرحلهٔ طراحی ایزولاسیون قابل‌بازگشت گفت «شروع کن»؛ این مرحله طراحی/تست آفلاین بود، نه رضایت محلی setter واقعی.

## خروجی این مرحله

[قرارداد و مدل](../analysis/unifiedfw-session-2026-10-27/isolation-transaction-v01/README.fa.md) و NATIVE-GATES.json اضافه شد. core خالص Python بدون file/network/subprocess/native API است. schemaمدل با Ruleهای fixture/اثر در حافظه کار می‌کند و import/export ویندوز نیست. flags آمادهٔApply/noLeakهمیشهfalse. هیچ ZIPاجرایی تازه، backupخصوصی، taskیاsetter Windows ساخته/اجرا نشد.

ترتیب مدل: baseline/readback و رضایت فرضی مدل → intentپایدار → بررسی before → اثر حافظه‌ای → readback → checkpoint نتیجه → عملیات بعد. اگر حمل دقیق وجود ندارد، فقط در مدل شیء متعلق به نشست ابتداdisabledساخته وenableمی‌شود، سپس foreignAllowهای local و بازبینی‌شده یکی‌یکیdisabledمی‌شوند. پروفایل‌ها از ابتدا بایدlocal/effectiveBlockتازه باشند و در این نسخه تغییر نمی‌کنند. Block،inbound،ازقبلdisabled،GPO/managedدست‌نخورده‌اند؛ Allowغیرقابل‌کنترل/نامعلوم مانع ادامه است. صفرgrantدادهٔ برنامه/فرزند وجود دارد.

recoveryازintentها، نه فقط successcounter، before/afterقابل‌دسترسی را می‌سنجد. driftناشناخته/بازگشت به قبل ازcheckpointکامل رد می‌شود. بازیابی نیاز به رضایت مستقل و quiescenceهدف/helperدارد؛ Allowهایقبلی خودکار درحالی‌که هدف فعال است باز نمی‌شوند. recoveryخودش تراکنش جدا و قابلresumeمدل است؛ duplicatewriteبعد ازاثرِمشاهده‌شده تاثبتنتیجه رد می‌شود. فقط toggleهایخودنشست restore و اشیایownedحملخودنشست باخواندنمشخصاتدقیق پاک می‌شوند. baselineBlockبهAllowتبدیلنمی‌شود؛normalinternetexitفرایندجداست.

## شواهد و موانع

۱۱testmethodمدل جدید،۶۰حالتابهاماثرِنوشتن،۱۰گامresumeبازیابی،fixtureساختگی۱۰۶Allow،drift/ترتیب/consent/عدمIO؛۸۶assertionحمل و۲۵testmethodپروفایلقبلی نیز rerun شدند. شمارشmethodباassertionوnativequalificationیکی نیست. `python qa.py --pwsh <pwsh>` ازپوشهٔmilestoneآن‌ها را اجرا می‌کند. فایلmanifestسورسبرایبازتولیداست،نهامضا/مجوز.

هنوزمانع‌اند: inventoryخصوصیکامل و منشأ/نگاشتمؤثر،baselineقابل‌بازخوانی واقعی،رضایتدقیقحملSSTP،DNS/TLS/DHCP/routeسرد،بازیابیمحلیبدونشبکه،setter/restoreبومی،coverageِflowقدیمی/IPC/WSH/AppContainer/WFPثالث،packet/reconnect/reboot. مشاهداتچندcmdletاتمیکنیستند وinstallerِelevatedیاGPOمی‌تواند بینمشاهدات تغییر دهد. Get-NetFirewallRuleبه‌تنهایی fullWFPinventoryرااثباتنمی‌کند. مدل هیچ‌یک راحل‌شدهفرضواقعی نمی‌کند.

## نزدیک‌ترین کار توسعه

adapter **فقط‌خواندنی و خصوصیِ inventory/منشأ و baselineباstorage/readback** با consentتازه و حفظفایل‌هایکنونی؛هم‌زمان بستن موانعحمل/بازیابی. از assumptions=trueدرfixtureیاdigestطرح،capabilityبومینسازید؛DisableیاApplyعمومیتحویلندهید. کاربر فعلاً اقدام/تست تازه ندارد و diagnosticموفق Allowنبایدبی‌دلیل تکرارشود. وضعیتتاریخیبازیابی و journalهایقبلی بدونتغییرباقی‌اند.
