# گزارش فقط‌خواندنی وضعیت فعلی پس از آماده‌سازی موفق

کاربر resume-result.json موفق با prepared/۳قاعدهٔ غیرفعال/guard-v4 unchanged/coverage unchanged/automatic enable false/existing kill switch changed false ارسال کرد. این موفقیت، رفع خطای آماده‌سازی روی همان دستگاه را نشان می‌دهد، نه نبود نشتی. کاربر صریحاً خواست تغییرات پراکندهٔ قبلی و انتقال به دستگاه‌های دیگر لحاظ شوند؛ بررسی وضعیت واقعی پیش از Enable پیشنهاد و سپس با «شروع کن» درخواست شد.

ابزار جدید هیچ فرمان تغییردهندهٔ شبکه ندارد؛ اسکریپت read-only core شامل نسخهٔ دقیق توابع خواندن و مقایسهٔ پایه است، بدون import ماژول mutation، بدون ساخت lock یا write journal. گزارش فقط کنار ابزار نوشته و نسخهٔ قبلی همین گزارش جایگزین می‌شود. هیچ hosts/registry/DNS/route/VPN/service/task/firewall rule/profile تغییر نمی‌کند، DNS lookup یا TCP probe ندارد و background service/expiry ندارد.

۱۴بخش محدود: OS/PS، پروفایل‌ها، شمار قواعد قدیمی/overlay/سایر Allowها، تطبیق journal اصلی و سه قاعدهٔ موجود، saved profileهای کیل‌سوییچ قدیمی، markerها و aliasهای شناخته‌شدهٔ BAT06 در hosts، رجیستری IPv6، bindingهای قابل‌مشاهده، شمار Windows VPN، شمار DNS/NRPT/routes، نشانگرهای WinINet proxy حساب elevated و وضعیت BFE/MpsSvc. Error هر بخش unavailable است نه سالم/خالی. report همیشه activation_approved=false،outside_vpn_protection_certified=false،complete_security_audit=false دارد. snapshot اتمیک نیست؛ تغییر همزمان journal/hosts علامت می‌خورد. نام/رمز/سرور VPN، IP، نام رابط، URL یا hosts/journal خام صادر نمی‌شود. مرحلهٔ بعد پس از دریافت گزارش کاربر، بررسی یافته‌هاست؛ Enable هنوز درخواست نشده است.

محدودیت‌ها صریح: قواعد نامرتبط به‌صورت جامع، driver/task/WFP ثالث، VPN غیرWindows، hidden adapters، WinHTTP/application proxies، packets/reconnect/reboot ممیزی نمی‌شوند. وجود current settings انتساب آن به ما/ابزار قبلی را ثابت نمی‌کند. هیچ restore/پاک‌سازی از روی نام یا این summary مجاز نیست. saved legacy state بدون اثبات provenance میزبان، مجوز restore نیست. UAC با حساب دیگر برای داده‌های user-scoped همان حساب elevated را می‌خواند.

آزمون source af842e70f57c3c5bf3186e2a268931b59ced0f8e/run39329245844 روی دو Server runner windows-2022 وwindows-2025 موفق: model20/native22؛ parse و رد static mutation cmdletها، hosts parser چندalias/comment/marker-malformed و عدم افشای دادهٔ فرضی/عدم ساخت پوشه در absent؛ اجرای admin با Unicode+spaced path و مقایسهٔ strict کامل P8 فایروال، hosts SHA، مقدار رجیستری IPv6 و وجود پوشهٔ overlay قبل/بعد. CI فاقد journal واقعی prepared کاربر بود؛ تطبیق آن در همان محیط کاربر خوانده خواهد شد. UAC غیرمدیر و Windows10/11 واقعی/دستگاه کاربر هنوز آزموده نشده است. این محدودیت‌ها پنهان نشده‌اند.

دو ZIP receipt با digestهای fd0f6ccac8693d3b3875cf4001d78dd49e6184363ecf98e6d61fb68e02882230 وab937d5f163a4ff674cc17fddff55bc6dfd47d238e127a4dc210246585be65cc و هر۱۰فایل کد با payload دقیق LF/CRLF تطبیق داده شدند. بستهٔ۱۱فایلی با manifest و readback ZIP تأیید شد.

https://github.com/kokononox/battle-net-agent-lab/actions/runs/39329245844

```json
{
  "filename": "Sstp-System-Audit.zip",
  "zip_sha256": "85aa53f55fea597c6fe045c3e324bef0d98d446c53f7d8a45d0cc9d19e086ff7",
  "bytes": 18866,
  "files": 11,
  "source_commit": "af842e70f57c3c5bf3186e2a268931b59ced0f8e",
  "run_id": "39329245844",
  "complete_security_audit": false
}
```
