# P9 — تراکنش بومی Enabled با journal و inventory کامل P8
کتابخانه داخلی؛ نه کیل‌سوییچ، نه Enable/Disable قابل اجرای کاربر. هیچ guard/profile setter/استثنای شبکه‌ای اضافه نشده است.

## اتصال واقعی
- P8 همهٔ ruleهای PersistentStore، هفت filter و profileهای هر دو store را می‌خواند؛ P2 همان ACL/lock/flush/revision/backup را نگه می‌دارد.
- journal اصلی schema جدید مستقل دارد: original کامل فقط ruleهای انتخاب‌شده و profileها؛ seal policy و strict برای تمام ruleهای inventory، از جمله انتخاب‌نشده‌ها. inventory کامل خام برای همهٔ ruleها در journal تکرار نمی‌شود تا اندازه بی‌جهت زیاد نشود. هیچ snapshot/seal برای دورزدن خطای provider ساخته نمی‌شود.
- seal policy همان قرارداد سه label خارجی P8 را نگه می‌دارد: فقط حضور و نوع string/null در دو طرف قابل معافیت‌اند؛ shape یا فیلد ناشناخته و تمام هفت filter در hash هستند. strict seal و audit جدا باقی می‌ماند. OwnedRuleNames صریح strict است و نمی‌تواند جزو انتخاب قرنطینه باشد.
- selected باید local Enabled=True/Outbound/Allow یکتا باشد. فقط Enabled آن‌ها False و سپس True اصلی می‌شود؛ نه label/filter/group/profile. Restore هیچ برچسب خارجی تغییرکرده‌ای را overwrite نمی‌کند.
- تمام inventory در شروع/بازیابی و پیش از اعلام پایان دوباره بررسی می‌شود؛ بین آن‌ها، خود قانون هدف و هفت فیلترش بلافاصله قبل/بعد setter به‌صورت دقیق بررسی می‌شوند. journal فقط mutation همان resource مشاهده‌شده را تأیید می‌کند. تغییر بیرونی وسط چند mutation ممکن است تا checkpoint پایان تشخیص داده نشود؛ در این صورت phase تمام‌شده ثبت نمی‌شود و guard coordinator باید همچنان برقرار بماند. اجرای standalone روی دستگاه کاربر همچنان مجاز/آماده نیست. تغییر policy هر rule انتخاب‌نشده، rule اضافه/حذف‌شده، profile یا مالکیت موجب توقف است. pending فقط حالت قبل/بعد دقیق همان یک Enabled را قبول می‌کند.
- بازیابی در فرایند جدید از journal و همان مرز مقایسه انجام می‌شود؛ Restore از Quarantine ناقص هم پشتیبانی می‌شود. schema قدیمی P7 خودکار migrate/adopt/reset نمی‌شود؛ دو failed receipt قدیمی دست‌نخورده‌اند.
- ظرفیت envelope با revision حداکثری، طولانی‌ترین phase، cursor و pending در حالت حداکثری پیش از اولین mutation سنجیده می‌شود؛ سقف۱MiB P2 حفظ شده است. seal SHA برای خرابی اتفاقی/مقایسه است، نه احراز اصالت در برابر admin مهاجم.

## آزمون
CI فقط fixtureهای ساختگی GUIDدار، برنامهٔ ناموجود و IP مستندسازی و TCP/65534 دارد. همهٔ fixtureهای عادی پیش از baseline ساخته می‌شوند. شش termination قبل/بعد از تغییر در Quarantine/Restore و بازیابی با powershell.exe تازه، دو Restore مستقیم از اجرای ناقص، idempotency، حفظ label خارجی بعد از restart، توقف روی owned-label و آدرس rule انتخاب‌نشده، اضافه/حذف rule، فساد/نبود journal، lock و ظرفیت۱MiB بررسی می‌شوند. منفی‌های seal تک‌تک propertyهای یک rule و هفت filter آن فقط در حافظه‌اند.

پاک‌سازی CI از recovery محصول جداست: فقط fixtureهای همین اجرا با هویت دقیق، Group و policy hash کامل original/disabled حذف می‌شوند. هیچ rule واقعی قبلی حذف یا reset نمی‌شود. baseline نهایی نامرتبط با P8 و همهٔ هفت filter مقایسه می‌شود؛ drift نمایشی audit است، نه حذف از گزارش. فقط receipt محدود و hash کد upload می‌شود.

## مرز واقعی
این اتصال فقط بخش مدیریت Enabled است و اجرای standalone روی Allowهای واقعی کاربر امن/مجاز اعلام نشده؛ coordinator باید guard پایدار و تأییدشده را قبل از آن برقرار کند. فعلاً guard نداریم و گذر بسته/no-leak تست نشده است. ActiveStore rule/GPO کامل، SSTP binding/قطع‌وصل/boot، IPv6/DNS/LAN و profile mutation هنوز خارج از qualification است. خواندن‌ها و check/set اتمیک نیستند؛ lock فقط عامل همکار همین journal را سریالی می‌کند، نه admin هم‌زمان. صد rule واقعی دستگاه و ظرفیت journal آن‌ها هنوز تست نشده‌اند.

هیچ resident/task/expiry محصول ساخته نمی‌شود و دستگاه کاربر تغییر نمی‌کند. هنوز بستهٔ اجرا یا فرمان Enable برای کاربر وجود ندارد؛ ready_for_user_apply=false.

اجرای اولیهٔ 29317e9 به علت هزینهٔ تکرار inventory کامل به‌ازای هر mutation توسط عامل لغو شد؛ نه شکست اثبات‌شدهٔ setter و نه PASS. نسخهٔ بعد checkpointها را به مرزهای action/recovery محدود می‌کند و direct readback هر resource و write-ahead را نگه می‌دارد. این یک تفاوت واقعی در زمان تشخیص تغییرات هم‌زمان است و پنهان نشده است.

اجرای checkpoint نسخهf7cceb3 شش fault/recovery و حفظ metadata خارجی را تکمیل کرد، اما پیش از انتهای suite در پاک‌سازی fixture به PropertyNotFoundException رسید و passed=false ماند. گیت Group پاک‌سازی باید از property عمومی Get-NetFirewallRule یعنی Rule.Group خوانده شود، نه فرضِ وجود همان alias در CimInstanceProperties. شرط hash کامل و Group حذف نشده؛ فقط accessor مدل داده اصلاح شد و suite کامل باید تکرار شود.
