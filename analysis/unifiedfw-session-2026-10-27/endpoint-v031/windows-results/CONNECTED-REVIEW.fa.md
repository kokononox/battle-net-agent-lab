# رسید واقعی Windows — مشاهدهٔ مقصد ۰٫۳٫۱ موفق

پس از خروجی خواندنی Connected/True، کاربر تغییر هدفمند SplitTunneling=False را روی تنها پروفایل SSTP حساب فعلی اجرا کرد و Connected/False گزارش شد. سپس v0.3.1 بدون درخواست تغییر شبکه/فایروال اجرا شد. علت ۷۳۴ موقت همچنان نامعلوم است؛ تغییر full-tunnel را درمان آن خطا تلقی نکنید.

رسید تازه روی PS5.1 x64 با payload معتبر diagnostic_completed=true و endpoint_unshared_service_host_correlated دارد. هر دو lifecycle identity_chain_verified=true هستند؛ دومی binding را با اولی مقایسه کرده و binding_changed_since_previous=false است. این مقایسهٔ داخل یک اجراست، نه بین اجراها یا پس از reconnect.

service_host_stable=true، hosted_service_count=1، service_host_sharing=unshared، host_TCP443_count=1، configured_address_count=1، stable_candidate_count=1 و endpoint_correlation_observed=true است. configured_address_source=local_cache_not_trusted_pin؛ نام/IP خام ذخیره نشده است. مسیر/hash فایل خوانده شده‌اند؛ امضای فایل عمداً برای پرهیز از retrieval شبکه‌ای ضمنی بررسی نشده است. همهٔ snapshotها متوالی و غیراتمیک‌اند.

این اولین رسید واقعی تکمیل‌شدن reader مقصد است: همبستگی endpoint با پردازش میزبان تک‌سرویس، نه service-tag، اعتماد امضا، تأیید pin، bootstrap DNS/TLS، guardian، no-leak یا مجوز Apply. firewall_approval_granted، ready_for_apply، no_leak_certified همه false هستند. هیچ DNS query، dial/hangup یا تغییر شبکه/فایروال توسط مشاهده‌گر درخواست نشده است.

کاربر گفته اتصال فعلی LAN است؛ گزارش sanitized نوع carrier را مستقلاً اندازه نمی‌گیرد. بنابراین موفقیت مشاهدهٔ endpoint را آزمون تعویض رابط زیر ایزولاسیون یا استقلال اجرایی Wi-Fi/Ethernet ندانید.

گام بعد توسعهٔ آفلاینِ ورودی تأییدشدهٔ مقصد و طرح bootstrap اتصال/اتصال مجدد است؛ آدرس cache خودکار pin مصوب نشود. تا طراحی و آزمون پیش‌نیازها، Apply/Restore یا آزمون قطع/وصل تحت ایزولاسیون درخواست نشود. اقدام تازه‌ای از کاربر فعلاً لازم نیست؛ تکرار مشاهده‌گر نیز لازم نیست. هدف ابزار کوچک اختصاصی نصاب Battle.net باقی است.
