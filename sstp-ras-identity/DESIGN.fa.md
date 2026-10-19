# P6 — هویت اتصال RAS/SSTP؛ فقط بازرسی

به‌جای alias-only، پروفایل SSTP فعال یکتا با GUID Get-VpnConnection و scope انتخاب می‌شود؛ همان GUID در RasEnumConnectionsW باید یکتا باشد و name/scope/device-type VPN/correlation نیز تطبیق کنند. IPv4 کلاینت از RasGetProjectionInfoW(RASP_PppIp) همان handle خوانده و باید فقط روی یک interface محلی یافت شود. interface باید PPP و Up باشد؛ index از .NET IPv4Properties با IP Helper به NET_LUID و GUID تبدیل و با GUID adapter برابر باشد. نمونهٔ دوم باید connection handle/correlation/profile/projection/index/NET_LUID/GUID را همان‌گونه ببیند. اختلاف، ابهام، نبود query، IPv6-only و projection نامعتبر هیچ fallback بر اساس alias ندارند.

**RASCONN.luid شناسهٔ logon session است، نه NET_LUID.** در helper این دو عمداً نوع/مسیر جدا دارند. هیچ تابع credential/dial/hangup وجود ندارد و P/Invokeها به System32 محدودند. تعداد رکورد RAS حداکثر۱۲۸ است؛ اندازه‌ها/offsetها با probe مستقل C++ از SDK همان Windows CI مقایسه می‌شوند. شناسه‌ها فقط در حافظه‌اند؛ گزارش فقط boolean/count/codeهای محدود دارد.

این ابزار snapshotهای متوالی را بررسی می‌کند، نه مشاهدهٔ اتمیک kernel یا تضمین در برابر تغییر بلافاصله پس از خواندن. خالی‌بودن correlation/نامعتبر بودن GUID یا duplicate IP به توقف منجر می‌شود. روش فعلاً IPv4 PPP و active SSTP است؛ ipv6-only، disconnected و reconnect تازه qualification نمی‌شوند. قواعد فایروال ساخته نمی‌شوند. اگر identity chain مشاهده شد هم firewall_filter_binding_qualified=false و ready_for_user_apply=false باقی می‌ماند. قواعد future backend همچنان به guard/readback/آزمون packet واقعی نیاز دارند.

منابع رسمی:
- https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumconnectionsw
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376725(v=vs.85)
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa377634(v=vs.85)
- https://learn.microsoft.com/en-us/powershell/module/vpnclient/get-vpnconnection?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/windows/win32/network-interfaces
