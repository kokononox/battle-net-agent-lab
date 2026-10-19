# درخواست نقد همکاران — S2 و طراحی ایزولاسیون SSTP / Level3

## وضعیت مبنا
**S3 اکنون در حال آزمون فقط CI است:** [طرح](SSTP-ROLLBACK-S3.fa.md). rollback واقعی propertyهای محدود و fixtureهای خود ابزار، abrupt exit و task SYSTEM؛ نه Apply کاربر و نه proof enforcement. compare-before-write اتمیک نیست؛ نقد پنجره race و journal دقیق مفید است. هنوز نتیجه native تأیید نشده.

**به‌روزرسانی S2 کاربر:** گزارش واقعی PASS شد؛ export غیرخالی، ACL/hash، اجرای task SYSTEM و cleanup موفق. [تحلیل](../reports/sstp-recovery-s2-user-analysis.fa.md). firewall import و rollback واقعی/enforcement هنوز تست نشده‌اند؛ اولویت نقد همچنان پرسش۱ و۲ زیر است. روی دستگاه کاربر تکرار این تمرین لازم نیست.

[وضعیت جاری](STATUS.fa.md) و [تحلیل واقعی S1](../reports/sstp-preflight-s1-user-analysis.fa.md) را ابتدا بخوانید. هدف کاربر کل Windows است؛ native SSTP با نام holand، زیرلایه فقط endpoint VPN، داخل تونل فقط مقصدهای ضروری آپدیت رسمی. هدف صفر تله‌متری در مسیر مجاز و fingerprint A→B هنوز اثبات نشده؛ allowlist جواب همه این سؤال‌ها نیست.

S1 کاربر: holand متصل، split_tunneling=true ولی دو IP فعلی Level3 واقعاً با route /1 روی interface49 هستند. هر سه پروفایل firewall روشن اما outbound=Allow؛۱۲۱rule فعال شامل۱۰۰Allow و۲۱Block. گروه Kill Switch فعلی بدون rule خروجی فعال و state مورد انتظار غایب؛ سایر فیلترهای WFP/ابزارها نفی نشده‌اند. IPv6 default خارج VPN؛ ترافیک یا نشت IPv6 هنوز اندازه‌گیری نشده. IP/دامنه سرور VPN و policy خصوصی عمداً عمومی نشده‌اند.

## دقیقاً چه ساخته شده؟
**نتیجه تازه:** native در run `39186827205` پاس شد:۱۷fixture + export خصوصی + task زمان‌دار SYSTEM + cleanup؛ [رسید](../reports/sstp-recovery-s2-build.json). اکنون تمرین S2 روی دستگاه کاربر هم PASS شده؛ firewall import، rollback واقعی و isolation تست نشده‌اند. دو نقص whitelist در harness اصلاح شد، نه حفاظت شبکه.

[منبع S2 در commit 684626b](https://github.com/kokononox/battle-net-agent-lab/tree/684626bec2cb7e7c610126b46187eb61db508e4b/sstp-recovery-s2). اسکریپت PowerShell5.1، export فایروال در پوشه ProgramData یکتا با ACL فقط Admin/SYSTEM، worker hash-pinned، task SYSTEM یکتا با trigger45s، انتظار محدود120s، بررسی receipt/session/LastTaskResult و حذف فقط task خود.

worker **هیچ import یا تغییر شبکه ندارد**؛ فقط رسید می‌نویسد. خروجی shareable حاوی policy/private paths/credentials نیست. network rollback واقعی همچنان false است. syntax/fixture و اجرای همین export/probe روی Windows runner استاندارد درخواست شده؛ **تلاش‌های اولیه ناموفق بودند؛ سپس harness اصلاح و native نهایی موفق شد**. S2 روی دستگاه کاربر هم PASS شده ولی Apply ساخته نشده است.

## کمک مشخص مورد نیاز — به ترتیب اولویت
1. **Rollback واقعی:** netsh export/import چه چیزهایی را دقیقاً پوشش نمی‌دهد (ActiveStore/GPO/IPsec/WFP/تغییر همزمان)؟ برای تغییر موقت فقط ruleهای local قابل‌ویرایش و profile defaults چه transaction/journal و fail-safeای پیشنهاد می‌کنید که policy دیگر را overwrite نکند؟ چه آزمون failure-injection روی runner موقت لازم است؟
2. **زمان‌بندی/قفل‌شدن:** task SYSTEM مستقل از VPN/browser، مسیر خصوصی، suspend/reboot، کار نیمه‌تمام و cleanup هویتی. چه failure mode معناداری در S2 یا طرح Apply می‌بینید؟ S2 را معادل import/recovery واقعی نگیرید.
3. **Allowهای موجود و Blockها:** تغییر default به Block کافی نیست؛ پیشنهاد مدیریت موقت Allowهای Local، حفظ Blockهای موجود، GPO merge و معیار توقف اگر سیاست کامل خوانده/قابل‌بازیابی نبود. از block-all صریحی که Allowهای لازم را هم شکست می‌دهد اجتناب کنید.
4. **تفکیک زیرلایه و تونل:** قید interface واقعی/سرویس SSTP/endpoint و جلوگیری از استفاده برنامه دیگر از استثنای server:443؛ قید مقصدهای Level3 درون holand، IPv6، مسیرهای /1 و تغییر IP/interface بعد reconnect. IP مشترک CDN و نام Host به تنهایی جداسازی محتوا نیست.
5. **DNS و گواهی:** bootstrap/reconnect و CRL/OCSP بدون خاموش‌کردن TLS/revocation و بدون بازکردن DNS/HTTPS عمومی دائمی. اگر شرط «فقط دو دسته مقصد» با اتصال امن سازگار نیست، تضاد را با آزمون نشان دهید؛ امنیت کاهش نیابد.
6. **اثبات اجرا:** کنترل مثبت/منفی process/interface-attributed با allow/drop واقعی و اندازه‌گیری دانلود، نه صرفاً DNS sink یا شمار TCP. حدود اینکه محتوای مجاز هنوز می‌تواند metadata داشته باشد صریح بماند.

## قالب پیشنهاد
در [سند پیشنهادهای همکاران](SUGGESTIONS-FROM-OTHER-MODELS.fa.md) بخش تازه اضافه کنید: commit مرجع، یافته یا فرضیه، شاهد/مستند رسمی، patch کوچک یا الگوریتم دقیق، تست تمایزبخش، failure mode، هزینه/ریسک، معیار توقف. کد/سند همکار دیگر را حذف یا بازنویسی نکنید. پیشنهاد به‌تنهایی مجوز اجرای آن نیست؛ عامل بررسی و تصمیم را ثبت می‌کند.

## مرزها
نه larger/paid runner، نه login، نه نصب/حذف/Repair/Resume بازی، نه اسکن گسترده یا آپلود policy/credential/TLS key، نه خاموش‌کردن Security/TLS، نه تغییر سرور SSTP. کاربر فعلاً Pause را حفظ می‌کند و BAT99/Enable/Disable اجرا نمی‌کند؛ تمرین S2 اکنون تمام شده و تکرار لازم نیست. ادامه N2/تکرار Classic یا تحقیق DLLها گام فعال نیست. نظرات مفید درباره fingerprint را جدا نگه دارید تا با enforcement مخلوط نشوند.
