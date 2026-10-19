# بررسی جزئیات Allowهای خروجی پیش از فعال‌سازی

گزارش سیستم کاربر system-audit-1 نشان داد سه قاعده دقیقاً prepared/disabled هستند، hosts بخش BAT06 با۲۴ورودی دارد و سطح PersistentStore شش Allow legacy و۱۰۰Allow خروجی دیگر فعال دارد. شمار Allow اثبات نشتی نیست. user با «باشه» بررسی دامنهٔ اثر Allowها را پذیرفت؛ هیچ اجازه‌ای برای غیرفعال‌سازی جمعی یا reset داده نشده است.

ابزار جدید فقط ActiveStore.Enabled/Outbound/Allow را با هفت کلاس address/application/interface/interface_type/port/security/service join می‌کند؛ duplicate identity/filter یا missing filter و سقف‌ها موجب توقف‌اند، نه خروجی ناقصِ ظاهراً کامل. شمار ActiveStore ممکن است با PersistentStore قبلی فرق کند. enabled به معنی enforcement واقعی نیست؛ profile/statusهای عددی هم صادر می‌شوند.

نام/آدرس/مسیر/alias/SID خام صادر نمی‌شود؛ label محدود شناخته‌شده، دسته‌ها، پورت/پروتکل و hashes استفاده می‌شوند. snapshot قدیمی serverIPs و DNS فعلی فقط در همان دستگاه با remote entryها مقایسه می‌شوند و خود IPها ارسال نمی‌شوند؛ صحت snapshot برای VPN متصل و pin بودن DNS تأیید نشده است. service/program/IPsec/override-block metadata نامفهوم Unknown/null است. شاخهٔ Windows برنامه صرفاً تشخیص string-prefix است؛ canonical path یا امضا/اصالت فایل تأیید نمی‌شود.

candidate_for_non_vpn_review فقط نبودِ منع NonVPN از روی interface-type است، نه اثبات خروج واقعی یا قابل‌حذف‌بودن. aliasهای صریح، blockها، جزئیات امنیتی و packetها هنوز می‌توانند نتیجه را تغییر دهند. remote_access_type_only به همهٔ RemoteAccess اشاره دارد، نه یک پروفایل خاص. is_proven_safe/is_proven_leak/activation_approved همیشه false هستند. این گزارش هیچ مجوز ownership یا cleanup نیست.

Headerهای قواعد قبل/بعد مقایسه می‌شوند؛ filterها در پایان دوباره خوانده نمی‌شوند و snapshot اتمیک نیست. Block precedence، تمامی IPsec/authenticated-bypass، WFP ثالث و مسیر/قطع‌وصل/boot packetها جامع بررسی نمی‌شوند. Cmdletهای تغییردهنده وجود ندارند؛ تنها output/error خود ابزار در پوشه‌اش نوشته و جایگزین می‌شود. journal/hosts/registry/VPN/service/task/route/firewall تنظیم نمی‌شوند؛ DNS lookup/TCP probe ندارد.

CI source9de08bc4aa3adbdce36bbe157cbf91bf5ac2d3d2/run39333073771 روی windows-2022 وwindows-2025 موفق: model37/native20؛ static parse/mutation-cmdlet guard؛ join هفت کلاس ActiveStore، schemas، hashes و false بودن مجوزهای امنیتی؛ admin child از مسیرUnicode+spaced؛ strict P8 firewall، hosts SHA، IPv6 registry و وجود پوشهٔ overlay قبل/بعد برابر. UAC غیرمدیر و دستگاه کاربر آزموده نشده‌اند؛ Server CI جای Windows client/packets نیست.

ZIP receiptها با digest2504d63b48627720af7e9645dbb63a8fb8aa1d10110902de23c951791f96ffc8 وcc6807e60929dd01b881ea4d83b1e4aa7bd70c21a2438f1947fc91de8a5df73c و هر۹فایل با payload دقیق LF/CRLF تطبیق داده شدند. بسته۱۰فایلی با manifest و بازخوانی ZIP تأیید شد. اقدام کاربر فقط Read-Allows.cmd، سپس ارسال outbound-allow-report.json یا allow-review-error.json است؛ Enable یا حذف خواسته نشده است.

https://github.com/kokononox/battle-net-agent-lab/actions/runs/39333073771

```json
{
  "filename": "Sstp-Allow-Review.zip",
  "sha256": "3d709b796febb5ac1ebc88c1420d2c5a257fb4c8c7319ab49d4f5216d7159d67",
  "bytes": 16383,
  "files": 10,
  "source_commit": "9de08bc4aa3adbdce36bbe157cbf91bf5ac2d3d2",
  "run_id": "39333073771",
  "activation_approved": false
}
```
