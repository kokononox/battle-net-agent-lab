# P4 — تراکنش write-ahead و بازیابی فرایند؛ فقط adapter مدل فایلی

## نتیجه و مرز صریح
**PASS محدود مدل: ۲۴۳ بررسی بومی، ۳۸ termination عمدی و ۳۸ recovery در فرایند تازه؛ ۷ fixture محلی اعتبارسنجی رسید.** job موفق۴دقیقه‌و۵ثانیه بود.

**این اجرا هیچ قاعدهٔ فایروال واقعی یا guard شبکه‌ای اعمال نمی‌کند.** فقط journal واقعی P2 و یک model.json خصوصی به‌عنوان adapter آزمایشی استفاده می‌شوند. میزبان Windows به معنی qualification شبکهٔ Windows/SSTP نیست. P3 همچنان فقط adapter قواعد غیرفعال است و هنوز به تراکنش فعال متصل نشده است.

- منبع نهایی: [cab16a4a8d3ddea55e49167db102cc3baf8bef53](https://github.com/kokononox/battle-net-agent-lab/tree/cab16a4a8d3ddea55e49167db102cc3baf8bef53/sstp-allowlist-transaction)
- اجرا: [39201053220](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39201053220)، windows-2025 استاندارد، timeout پنج دقیقه، بدون larger runner.
- [رسید نهایی](../reports/sstp-allowlist-transaction-p4-build.json)، artifact12164101713؛ SHA256 ZIP: `a4bad568b02ca3abafa2df0e82a63230ded6f8a5eb471ba0f4fda2fbff8262b0`.
- ZIP دانلود و digest آن با نمایش GitHub تطبیق داده شد؛ schema، شمارنده‌ها، source/run و هش چهار منبع ModelEngine.ps1، Worker.ps1، Test-Transactions.ps1 و Journal.ps1 با پایان خط checkout ویندوز تأیید شدند.

## آنچه پیاده‌سازی شد
1. snapshot مدل با schema صریح برای guard، سه default پروفایل، Allowهای قدیمی و قواعد خود ابزار؛ نگهداری مقدار اولیهٔ دقیق و after مورد انتظار. هیچ مقدار NotConfigured به Allow تبدیل نمی‌شود.
2. intent پیش از تغییر، ذخیرهٔ cursor/pending و readback بعد از تغییر در journal. adapter مدل هر بار مستقل از حافظهٔ قبلی خوانده می‌شود.
3. تطبیق همهٔ منابع با frontier مورد انتظار؛ pending فقط برای همان عملیات جاری اجازهٔ before یا after می‌دهد. پیشرفت صرفاً از شمارهٔ مرحله حدس زده نمی‌شود. تغییر خارجی به هر منبع تأییدشده یا هنوز اجرا‌نشده، توقف ایجاد می‌کند.
4. ترتیب مدل Enable: guard؛ Allowهای قبلی غیرفعال؛ defaultهای Block؛ قواعد own؛ بررسی کامل؛ حذف guard. Disable نیز guard می‌گیرد، originalها را دقیق برمی‌گرداند، ownها را حذف و کل وضعیت را قبل از حذف guard بررسی می‌کند. **این‌ها تغییرات مقادیر در فایل مدل‌اند، نه NetSecurity/WFP.**
5. Disable از Enable نیمه‌تمام snapshot اولیه را حفظ و وضعیت فعلی واقعی adapter مدل، حتی عملیات اجراشده ولی ackنشده، را ثبت می‌کند. تغییر جهت به Enable وسط Disable نیمه‌تمام متوقف می‌شود. تکرار کامل‌شده، journal را بیهوده بازنویسی نمی‌کند.
6. قفل انحصاری transaction.lock برای کل فراخوانی، جدا از قفل داخلی نوشتن journal؛ پس از خروج فرایندی باقی نمی‌ماند. نبود journal، primary خراب با backup معتبر یا schema معنایی نامعتبر اجازهٔ reset/ادامهٔ کور نمی‌دهد. هیچ fallback عمومی Allow وجود ندارد.

## معنای دقیق آزمون‌های قطع
- ۳۶ حالت: قبل و بعد هر یک از۹عملیات مدل، در هر دو جهت Enable و Disable.
- ۲ حالت اضافی: تبدیل Enable نیمه‌تمام به Disable، پیش و پس از یک تغییر پروفایل مدل.
- worker پس از durable intent با Environment.Exit(73) واقعاً خاتمه می‌یابد، بدون اجرای finally؛ recovery در powershell.exe جدید است، نه ادامهٔ همان حافظه. قفل‌های فرایند مرده توسط سیستم‌عامل آزاد می‌شوند.
- در هر حالت، invariant مدل بررسی می‌شود: یا guard مدل blocked است یا کل مدل دقیقاً baseline یا policy نهایی است. نتیجهٔ recovery، cursor/pending و تکرار بی‌اثر هم بررسی می‌شوند. **این invariant اثبات بسته‌شدن packet واقعی نیست.**
- آزمون اضافه: journal مفقود/primary خراب/schema معنایی نامعتبر؛ ویرایش خارجی؛ قفل همزمان در همان میزبان؛ منع برگشت از Disable نیمه‌تمام و snapshot نامعتبر.
- termination داخل syscall نوشتن فایل، قطع برق/خرابی دیسک، reboot واقعی و دو worker رقابتی همزمان در این اجرا شبیه‌سازی نشده‌اند. adapter مدل File.WriteAllText عادی دارد؛ مدل تضمین اتمیک WFP یا دیسک نیست. P2 همچنان نوشتن جایگزینی/backup journal را تأمین می‌کند.

## دو اجرای اول ناموفق؛ حفظ شواهد
- [39200412969](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39200412969)، منبعd9a23368f1e2254df7827a39644cbe1865f78b5d: صفر بررسی کامل/صفر fault و recovery؛ passed=false. خروجی child ابتدا پنهان بود و assertion اولیه فقط شکست را نشان داد.
- [39200865287](https://github.com/kokononox/battle-net-agent-lab/actions/runs/39200865287)، منبع9afa56892defa7b34aa6f771ceaef6bc26b4b7fa: تشخیص محدود transaction_resources در worker، باز هم صفر بررسی. شمارهٔ خط و نوع خطا بدون snapshot خصوصی منتشر شد.
- مشکل در بسته‌بندی نتیجهٔ ConvertFrom-Json در @() هنگام خواندن آرایه در Windows PowerShell5.1 بود. ابتدا decoded مقداردهی و سپس به object[] تبدیل شد؛ همین الگو برای clone آرایهٔ fixture هم اصلاح شد. دو fixture بازگردانی جزئی اضافه شدند. اجرای نهایی source جدید دارد؛ شکست‌ها success بازنویسی نشده‌اند.
- [رسید نخست](../reports/sstp-allowlist-transaction-p4-first-build.json)، artifact12163865873؛ digestZIP `f05168ad717b8e0a2879a16dbd73dc997d2bddd58374b03d505bf9aaf451b838`.
- [رسید تشخیصی](../reports/sstp-allowlist-transaction-p4-diagnostic-build.json)، artifact12163742153؛ digestZIP `79e419a9aa96cccbf0c59e1c2cfe57ee0632725967e088ab34baddea1ca281b7`.

## گام بعد و شرط تحویل
این موتور مرجع هنوز باید به adapter واقعی و snapshot تمام شروط متصل شود: guard و readback واقعی، Allowهای محلی/GPO و unmanaged، defaultهای stored/effective، inbound/LAN و مالکیت قواعد. سپس binding SSTP و packet واقعی، قطع‌وصل، DNS/IPv6/boot باید جداگانه آزموده شوند. روی runner راه‌دور، BlockAll واقعی بدون محیط ایزولهٔ جداگانه اجرا نشود؛ کانال کنترل ممکن است قطع شود.

هیچ دستور Enable/Disable محصول یا نسخهٔ قابل نصب تحویل نشده است. هیچ firewall/VPN/DNS/hosts/route کاربر تغییر نکرد. هیچ برنامهٔ مقیم، سرویس یا task اختصاصی ساخته نشد؛ workerهای موقت فقط فرایند تست CI بودند و پایان یافته‌اند. نیاز [Allowlist فقط از SSTP، بدون انقضا و مقیم](SSTP-ALLOWLIST-REQUIREMENTS.fa.md) حفظ شده، ولی از موفقیت مدل نتیجهٔ no-leak گرفته نمی‌شود.

ready_for_user_apply=false؛ real_guard_tested=false؛ enforcement_tested=false؛ sstp_binding_tested=false؛ user_device_tested=false.
