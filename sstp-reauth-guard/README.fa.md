# P15 — محدود به آزمایش اتصال TCP قدیمی و ALE reauthorization

primitive آزمایشگاهی، نه کیل‌سوییچ یا transition guard کامل: فقط برای exe تصادفی fixture در ALE_AUTH_CONNECT_V4/V6، AppID برابر و IS_REAUTHORIZE از نوع FLAGS_ALL_SET → BLOCK. اتصال اولیه از این primitive مجوز نمی‌گیرد و مسدود هم نمی‌شود؛ policy مقصد/مسیر باید جداگانه کنترلش کند. این مرحله P14 یا P12 را یکپارچه نمی‌کند.

یک sublayer و دو filter پایدار/INDEXED بدون provider، با journal امن P2 و ممیزی دقیق سه object، در یک تراکنش ساخته/حذف می‌شوند. kernel بعد از خروج installer اجرا می‌کند؛ سرویس/task/watchdog اختصاصی ساخته نمی‌شود. هر reauthorization، نه فقط policy-change، مسدود می‌شود؛ احتمالاً اتصال‌های مشروع pending یا تغییر interface نیز نیازمند اتصال تازه می‌شوند. برای استفاده دائمی محصول qualified نشده است.

آزمون فقط localhost IPv4 و IPv6 است و گیرنده byteها را بعد از handshake هر اتصال جدا می‌شمارد. A و B قبل از نصب socket باز دارند. بعد از خروج installer، B ادامه می‌دهد ولی A باید BLOCKED بدهد و شمار دریافت byte برای A ثابت بماند. A تازه تحت همان guard باید initial connect/echo موفق داشته باشد. پس از حذف دقیق، اتصال تازه قبلی و B باید ادامه دهند. receiver واقعی است؛ timeout فرستنده به‌تنهایی مدرک عدم دریافت حساب نمی‌شود. fixtureهای فرستنده/گیرنده فقط در مدت آزمون بازند، نه به‌عنوان monitor یا resident محصول.

بر اساس مستند ALE Reauthorization، تغییر policy باعث بررسی packet بعدی flow می‌شود؛ commit مترادف barrier هم‌زمانِ همه flowها نیست. اندازه‌گیری محدود زمانی receiver، packet capture یا اثبات zero-wire/no-leak برای کل سیستم نیست. هیچ VPN واقعاً قطع نشد، NIC/route/service تغییر نکرد، BFE restart و reboot انجام نشد. اگر old flow داده دریافت کند یا control/fresh flow نتواند کار کند، آزمون failed می‌ماند. فقط receipt محدود و هش کد upload می‌شوند، نه tag/nonce/port/journal/inventory خصوصی.
