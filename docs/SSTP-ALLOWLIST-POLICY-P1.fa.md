# P1 — هستهٔ سیاست و config، نه برنامهٔ آمادهٔ Enable

[منبع](https://github.com/kokononox/battle-net-agent-lab/tree/7b64da0705c00c8884102b9c3f1ff4e2624199fa/sstp-allowlist-policy) شامل Policy.ps1، Test-Policy.ps1 و allowlist.example.json است. نیاز نهایی در [سند دامنه قطعی](SSTP-ALLOWLIST-REQUIREMENTS.fa.md) ثبت شده است.

- ویرایش خالص فهرست مجاز: افزودن/حذف domain یا host-IP، normalization، deduplication، رد wildcard/URL/CIDR/Any و config با کلید اضافه. حذف آخرین مقصد رد می‌شود، نه تبدیل به Allow عمومی.
- انتخاب پروفایل بدون hardcode اجباری: فعال یکتا، موجود یکتا، holand ترجیحی؛ ambiguity خطا است. تست‌ها از رکوردهای ساختگی استفاده می‌کنند، نه Get-VpnConnection واقعی.
- تولید plan از snapshot ورودی، نه DNS زنده: مقصدهای عادی فقط داخل تونل منتخب؛ transport SSTP به‌صورت استثنای محدود، DNS بیرون تونل ممنوع، LAN عادی بسته، بدون resident/انقضا و با Disable مبتنی بر journal فقط‌خود.
- این خروجی plan اعلام امنیت نیست. selected_interface_binding_qualified=false، enforcement_tested=false و ready_for_user_apply=false هستند. هیچ Enable/Disable اجرایی یا تنظیم hosts نوشته نشده است.

## آزمون و نتیجه
[run39197656262](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39197656262)، منبع `7b64da0705c00c8884102b9c3f1ff4e2624199fa`: syntax/AST و۳۵fixture مصنوعی روی Windows PowerShell موفق شد. network_changed=false، dns_queried=false و resident_program_created=false. هشت fixture محلی Python برای schema/scope رسید نیز جداگانه پاس شد؛ با۳۵fixture native جمع یا به عنوان آزمون enforcement معرفی نشود.

[رسید](../reports/sstp-allowlist-policy-p1-build.json) از artifact دریافت و digestZIP با مقدار UI برابر شد؛ source_commit/run_id و هش سه فایل با منبع LF/CRLF تطبیق داده شد. artifact فقط رسید محدود دارد، نه اطلاعات VPN یا فایل‌های کاربر. فقط یک runner استاندارد windows-2025 استفاده شد؛ larger/paid runner فعال نشد و رایگان‌بودن سهمیه تضمین نشده است.

## گام بعد، نه کار انجام‌شده
پیاده‌سازی و آزمون backend پایدار Enable/Disable، journal خصوصی، transition guard، rule ownership و کنترل Allowهای قبلی/GPO، سپس qualification اتصال واقعی SSTP/IPv6/DNS/reconnect/reboot. هیچ monitor یا task دوره‌ای به‌عنوان میان‌بر برای الزام «اعمال و خروج» اضافه نشود. موفقیت P1 یا تست provider قبلی مجوز Apply روی Windows11 کاربر نیست.
