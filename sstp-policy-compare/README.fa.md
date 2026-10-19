# P8 — مقایسهٔ policy کامل در برابر drift نمایشی
کتابخانه فقط‌خواندنی و مقایسه‌گر؛ نه Apply/Enable/Disable. هیچ ماژول mutation وارد نمی‌کند و هیچ policy/rule/filter را تغییر نمی‌دهد.

## قرارداد
ReadPolicyInventory همهٔ قواعد PersistentStore و هفت نوع فیلتر را به‌صورت bulk می‌خواند. هر rule باید از Local باشد و InstanceID/Name دقیق، یکتا و غیرخالی داشته باشد؛ هر فیلتر با همان InstanceID و پوشش کامل یک‌به‌یک join می‌شود. orphan/duplicate/missing یا خطای provider متوقف‌کننده است؛ نه تبدیل خطا به absence. پروفایل‌های هر سه حالت در هر دو PersistentStore/ActiveStore با همهٔ CIM propertyهای قابل تبدیل snapshot می‌شوند، نه فقط defaultها. آرایه‌ها به‌صورت محافظه‌کارانه با ترتیب واقعی حفظ می‌شوند؛ reorder فیلدهای ناشناخته مخفی نمی‌شود.

ComparePolicyInventory خروجی دوگانه دارد:
- برای ruleهای غیرمتعلق به برنامه، فقط Description/DisplayGroup/DisplayName از بخش policy جدا و در audit نمایشی گزارش می‌شوند. فقط مقدار string/null در دو طرفِ همان فیلد شناخته‌شده می‌تواند نمایشی باشد؛ حذف فیلد یا تغییر نوع حتی برای label موجب stop است. raw Group، Enabled، Action، InstanceID و هر فیلد دیگر، از جمله فیلد ناشناختهٔ آینده، strict هستند.
- هیچ property از هفت فیلتر معاف نیست؛ address،port،application،service،interface،interface_type،security همگی وارد مقایسه می‌شوند.
- برای OwnedRuleNames صریح، حتی همان سه برچسب هم strict و موجب stop هستند. ownership از display یا prefix حدس زده نمی‌شود. نام ownership ناموجود/ناهمسان/تکراری رد می‌شود.
- snapshot کامل حفظ می‌شود؛ هیچ label/value پاک یا بازنویسی نمی‌شود. خروجی فقط unchanged/display_only/stop_policy_change و شمارش/نام property و component است؛ نه نام rule یا مقدار خصوصی.
- تغییر مجموعهٔ ruleها یا هر property پروفایل باعث stop است. schema، identity، type یا filter ناقص خطاست، نه «فقط نمایشی».

runtime-statusها همان exclusion پیشین P3/P7 را دارند؛ فیلدهای drift پس از شکست برای PASS کورکورانه حذف نشده‌اند: این سه فیلد با شاهد کنترل P7C و مستند Microsoft به کانال audit جدا منتقل می‌شوند. مقایسه‌گر قدیمی P7 و دو failed receipt آن تغییر نکرده‌اند. اتصال این قرارداد به journal/transaction فعلی هنوز جداگانه لازم است.

## qualification
تست فقط‌خواندنی Windows-2025 دو inventory واقعی می‌گیرد. پوشش bulk تمام ruleها و تمام هفت filter را چک می‌کند و روی شش rule با فاصلهٔ یکنواخت، هر هفت join را با AssociatedNetFirewallRule تأیید می‌کند (۴۲association). این نمونهٔ association است، نه اجرای جداگانهٔ lookup برای همهٔ ruleها؛ InstanceID/coverage همهٔ داده‌ها بررسی می‌شود.

منفی‌ها فقط در حافظه‌اند: تک‌تک CIM propertyهای یک rule، هر هفت filter و یک profile واقعی تغییر مصنوعی می‌کنند؛ policy-change باید stop شود. display خارجی audit-only، display متعلق به برنامه stop، حذف فیلتر/فیلد، property جدید، هویت تکراری، اضافه/حذف rule و ownership نامعتبر هم تست می‌شوند. هیچ setter برای این آزمون‌ها روی Windows اجرا نمی‌شود. snapshotهای واقعی/مقادیر/نام‌ها upload نمی‌شوند؛ فقط رسید محدود و hash کد.

خواندن‌ها اتمیک نیستند؛ دو inventory برابر ثبات بین نمونه‌ها را نشان می‌دهد، نه عدم تغییر گذرا، lock سراسری یا مقابله با admin هم‌زمان. ActiveStoreِ تمام ruleها/GPO هنوز اینجا inventory نمی‌شود؛ فقط profileهای ActiveStore خوانده می‌شوند. این ابزار به‌تنهایی gate کافی برای محصول نیست. guard، profile setter، SSTP binding، packet/reconnect/reboot/no-leak همچنان خارج از این qualification و ready_for_user_apply=false هستند. دستگاه کاربر دست‌نخورده است و بستهٔ اجرای کاربر نداریم.
