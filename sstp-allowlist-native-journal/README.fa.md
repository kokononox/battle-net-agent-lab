# P5 — اتصال journal به قواعد واقعی غیرفعال

این bridge از journal واقعی P2 و adapter بومی P3 استفاده می‌کند؛ **مدل فایلی P4 نیست**، ولی موتور guard/default/Allowهای قدیمی P4 را هم به فایروال واقعی متصل نمی‌کند. فقط چرخهٔ عمر یک قاعدهٔ DISABLED را به صورت write-ahead ثبت می‌کند. هیچ Enable، تغییر default، VPN، DNS، route، guard فعال، سرویس، task یا برنامهٔ مقیم ندارد. نسخهٔ نهایی محصول نیست.

چرخه: prepared با نبود نام در store؛ create_intent؛ NewDisabledStagedRule و readback هفت filter؛ staged با snapshot و hash ذخیره‌شده؛ remove_intent؛ حذف فقط با hash قبلی؛ removed پس از خواندن absence. کل فراخوانی قفل جداگانه دارد. journal خراب یا spec تغییرکرده یا نام موجود بدون journal اجازهٔ حذف/بازنویسی نمی‌دهد.

**مرز مهم recovery:** اگر cmdlet ساخت تمام شود ولی snapshot آن پیش از قطع برنامه ذخیره نشده باشد، rule موجود حتی با نام و شروط ظاهراً یکسان خودکار پذیرفته یا حذف نمی‌شود: staging_unacknowledged_rule_requires_review. این توقف عمدی است، نه recovery خودکار موفق. قاعده غیرفعال باقی می‌ماند. در CI، بازبینی/پاک‌سازی صریح fixtureها جدا از موتور انجام می‌شود؛ این مجوز حذف خودکار روی دستگاه کاربر نیست. خرابی بعد از ثبت snapshot یا حین حذف، در صورت تطابق fingerprint، قابل recovery است.

۵ termination واقعی worker: BeforeCreate، AfterCreate قبل از ثبت snapshot، AfterRecord، BeforeRemove و AfterRemove. چهار مسیر recovery در فرایند جدید و دو امتناع Stage/Remove برای همان مورد مبهم بررسی می‌شوند. ویرایش خارجی description، spec ناسازگار، نام بدون journal، corruption و lock contention نیز بررسی می‌شوند. تمام قواعد تست غیرفعال‌اند؛ cleanup تنها specهای شناخته‌شدهٔ GUID همین اجرا را پس از readback دقیق می‌پذیرد. snapshotهای خام و journal خصوصی upload نمی‌شوند.

مقایسهٔ baseline فقط خواص منتخب profile stored/effective و خواص rule-level قواعد محلی موجود است؛ نه تمام filterهای دیگر یا WFP. ساخت/حذف قواعد غیرفعال، نوشتن واقعی در store فایروال است، اما ادعای packet enforcement یا fail-closed شبکه ندارد.

کار باقیمانده: guard و snapshot/adapter تغییرات مؤثر واقعی، Allowهای محلی/GPO/unmanaged، inbound/LAN، binding SSTP، قطع‌وصل/DNS/IPv6/boot و آزمون packet. این محیط CI اتصال SSTP واقعی کاربر ندارد و عامل به دستگاه کاربر وصل نیست. پیش از qualification، ready_for_user_apply=false باقی می‌ماند.
