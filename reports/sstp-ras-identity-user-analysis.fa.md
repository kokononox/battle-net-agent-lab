# P6 — گزارش زندهٔ هویت SSTP کاربر: زنجیرهٔ جاری مشاهده شد

## نتیجه
**identity_chain_observed=true**؛ گزارش ارسالی روی دستگاه کاربر از parser/model/CI فراتر رفته و مسیر زندهٔ پروفایل→RAS→PPP→رابط شبکه را برای **همین اتصال و همین بازهٔ خواندن** موفق گزارش کرده است. هیچ خطایی ثبت نشده و stable_recheck موفق بوده است. این نتیجه هنوز qualification فیلتر فایروال یا no-leak نیست.

منبع: فایل ارسالی کاربر SstpRasIdentityReport.json، schema=sstp-ras-identity-report-1، زمان 2026-10-19T05:39:54.3496803Z، پردازش۶۴بیتی، build26200. SHA256 فایل `07cb302a0032b0e6a24c8083dde1dcb89dbdb373347debed7171f11ce07d843e`. فایل خام دستگاه در مخزن منتشر نشده است. این دادهٔ ابزار ارسالی است، نه مشاهدهٔ مستقل packet/kernel از سوی عامل.

## شروط موفق گزارش‌شده
- inventory پروفایل کامل؛ یک SSTP فعال؛ GUID پروفایل یکتا.
- enumeration RAS در دسترس؛ دقیقاً یک entry با GUID همان پروفایل؛ تطابق name و scope و device-type VPN؛ marker نشست موجود.
- projection IPv4 همان handle در دسترس؛ فقط یک interface محلی دارای آن آدرس؛ interface از نوع PPP و operational Up.
- تبدیل index↔NET_LUID و GUID با adapter منطبق؛ در خواندن مجدد profile، نشست و رابط پایدار بوده‌اند.
- alias هم با profile برابر و برای فیلتر literal مناسب گزارش شده، ولی تصمیم مثبت صرفاً به alias تکیه ندارد. همهٔ شروط الزامی از مقادیر observation مستقل از status نهایی دوباره کنترل شدند.

گزارش نشان می‌دهد logon LUID به‌جای NET_LUID استفاده نشده و projection، IP کلاینت PPP است، نه سرور transport. نام/IP/GUID/handle خام صادر نشده و credential/DNS/upload/policy-change انجام نشده است.

## چیزی که هنوز اثبات نشده
firewall_filter_binding_qualified=false؛ reconnect_persistence_tested=false؛ enforcement_tested=false؛ ready_for_user_apply=false.

یعنی این گزارش:
- صحت بسته‌شدن packet بیرون allowlist/VPN، اثر واقعی InterfaceAlias/InterfaceType/LocalAddress در policy و نبود نشت DNS/IPv6 را نمی‌سنجد؛
- ماندگاری هویت یا فیلتر در disconnect/reconnect، reuse شناسه یا reboot را اثبات نمی‌کند؛
- مجوز استفاده از شناسه/IP همین گزارش در زمانی دیگر نیست؛ Apply واقعی باید در همان اجرا زیر guard دوباره از OS بخواند و با snapshot/شرایط کامل تطبیق دهد؛
- مجوز عمومی همهٔ پیش‌نیازهای backend، GPO/WFP یا restore نیست.

## تصمیم و گام بعد
مانع **alias-only بودن شناساییِ اتصال جاری** برطرف شده است. نیازی به تکرار همین دو ابزار فقط‌خواندنی یا اجرای دوباره با مدیر نیست. گزارش جدید، اطلاعات خام برای rule یا secret ارائه نمی‌دهد؛ backend آینده شناسه‌ها را محلی و تازه می‌خواند، نه از فیلدهای boolean ارسالی.

گام بعد فنی، اتصال این مسیر هویت به backend واقعی Enable/Disable با guard، snapshot کامل، مدیریت حساب‌شدهٔ۱۰۰Allow گزارش قبلی و بازگردانی مقدار stored اولیهٔ NotConfigured است. سپس qualification مستقل packet، DNS/IPv6، disconnect/reconnect و boot لازم است. guard/default/Allowهای مؤثر هنوز در محصول کامل و qualified نشده‌اند؛ تست‌های P1–P6 جایگزین این مرحله نیستند.

نیاز ثابت کاربر حفظ می‌شود: allowlist فقط از SSTP، LAN بسته، اتصال دستی، بدون resident/service/task دائمی، بدون انقضا، apply-and-exit و restore فقط تغییرات خود ابزار. از این گفتگو هیچ policy تازه‌ای روی دستگاه کاربر اعمال نشده و فعلاً اجرای فایل جدید یا تغییر تنظیمات از کاربر خواسته نمی‌شود.
