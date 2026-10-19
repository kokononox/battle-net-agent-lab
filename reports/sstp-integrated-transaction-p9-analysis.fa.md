# P9 — اتصال تراکنش بومی به inventory کامل و journal پایدار

## نتیجه اجرای ثبت‌شده
نتیجه: **PASS**؛ این نتیجه فقط اتصال native Enabled/quarantine/restore به مقایسهٔ P8 و journal P2 است، نه Enable/Disable کامل محصول یا کیل‌سوییچ.

- source: `9a18f0d5f44297ccdcc648ae593c779bca3fd156`
- run: https://github.com/kokononox/battle-net-agent-lab/actions/runs/39219067146
- checks=198؛ seal_field_cases=130؛ fault_cases=6؛ fresh_process_recoveries=6؛ partial_quarantine_restores=2.
- توقف روی policy/ownership/membership بیرونی=4؛ حفظ metadata خارجی بعد از Restore=1؛ capacity_rejections=1؛ corrupt/missing-journal stops=1/1.
- fixture rules=21؛ remaining=0؛ حداقل sealهای durable ثبت‌شدهٔ inventory=367؛ baseline نهایی همهٔ هفت filter/rule/profile نامرتبط برابر=True؛ اختلاف نمایشی auditشده=0.
- digest ZIP: `d9f8da9ef8e66c8eb0fbdd0f127aea9183835ea9f8be88a46bb2e9fe55ee2b10`. digest واقعی، source/run و hash فایل‌های منبع با نسخهٔ دقیق اجراشده (LF/CRLF checkout) مستقلاً تطبیق داده شدند؛ schema/نوع/count/flags محدود validate شد.

## چه چیزی واقعاً وصل شد
Engine.ps1 مستقل و با schema جدید به P2 Journal.ps1 و P8 Inventory.ps1 وصل است؛ P7های قبلی، source و دو failed receiptشان بازنویسی یا به PASS تبدیل نشده‌اند. تنها setter محصولِ این جزء Set-NetFirewallRule -InputObject ... -Enabled است. هیچ label/filter/group/profile overwrite، reset یا broad Allow وجود ندارد.

original کاملِ ruleهای انتخاب‌شده و شش profile در journal ذخیره می‌شود. برای همهٔ ruleهای inventory، policy seal و strict seal پایدار همراه با نام دقیق نگه داشته می‌شود؛ به این ترتیب هفت filter قواعد انتخاب‌نشده هم تحت مقایسه‌اند بدون تکرار تمام raw inventory در journal. SHA برای تشخیص خرابی و مقایسه است، نه احراز اصالت در برابر admin مهاجم؛ ACL، قفل، flush، revision و توقف پس از backup-recovery همان P2 است.

policy seal فقط سه label خارجی را با حضور و نوع string/null معاف می‌کند؛ حضور/نوع با marker مشخص در hash حفظ می‌شود. shape ناشناخته، تغییر هر filter، Group/Enabled/Action و propertyهای آینده strict هستند. OwnedRuleNames صریح full-strict است و اجازه ندارد جزو selection قرنطینه باشد. strict hash و شمارش audit نمایشی هم نگه داشته می‌شود. Restore فقط Enabled اصلی را می‌نویسد و برچسب خارجیِ تغییرکرده را برنمی‌گرداند.

cursor/pending و write-ahead قبل از تک‌تک setterها ثبت می‌شود. recovery فقط حالت before/after دقیق همان یک mutation معلق را با بقیه frontier برابر می‌پذیرد. Restore از Quarantine ناقص هم به original Enabled بازمی‌گردد. journal گمشده یا خراب، policy جدید، profile تغییرکرده، rule اضافه/حذف و owned metadata conflict باعث توقف‌اند؛ نه adoption، reset یا EnableAll.

حداکثر envelope journal با revision ده‌رقمی، طولانی‌ترین phase و cursor/pending حداکثری قبل از اولین mutation سنجیده می‌شود؛ سقف۱MiB حفظ شده است. ظرفیت صد rule واقعی کاربر هنوز اندازه‌گیری نشده است.

## آزمون و مرز ادعا
fixtureهای CI دارای GUID، Group اختصاصی، برنامهٔ ناموجود، آدرس‌های مستندسازی IPv4/IPv6 و TCP/65534 هستند. همهٔ fixtureهای عادی قبل از baseline ساخته شدند. تغییرهای seal فقط در حافظه‌اند؛ تست‌های native فقط fixtureهای همین اجرا را دست‌کاری می‌کنند. پاک‌سازی CI از recovery محصول جدا و فقط با هویت/Group/policy hash کامل original یا disabled است. journal و raw inventory/نام‌ها/مقادیر خصوصی upload نمی‌شوند؛ تنها receipt محدود و hash کد artifact است.

این موتور guard ندارد و standalone روی Allowهای واقعی کاربر ایمن/مجاز اعلام نشده است. coordinator نهایی باید guard پایدار و تأییدشده را برقرار کند. این آزمون profile defaults را تغییر نمی‌دهد، SSTP یا packet/no-leak/قطع‌وصل/reboot را نمی‌سنجد و ActiveStore rule/GPO کامل را inventory نمی‌کند. check/read/set اتمیک نیست؛ lock فقط عامل همکار همین journal را سریالی می‌کند، نه admin هم‌زمان. برابر بودن snapshotها نبود تغییر گذرا را اثبات نمی‌کند.

هیچ resident/task/expiry محصول اضافه نشده، دستگاه کاربر دست‌نخورده است، فایل اجرا یا فرمان Enable تازه‌ای برای کاربر وجود ندارد و گزارش تشخیصی تکراری لازم نیست. ready_for_user_apply=false. گام بعد پس از qualification این اتصال، guard/coordinator و adapter دقیق پیش‌فرض profileها است؛ نه تحویل زودهنگام نسخهٔ مدعی no-leak.

## اجرای اولیه و بازطراحی صریح checkpoint
منبع29317e90d6a313041d924041e964c72bee627ae9 در run39216161437 به علت هزینهٔ ممیزی کامل به‌ازای هر mutation توسط عامل از UI لغو شد؛ این تصمیم صریح ثبت شد، نه لغو نامعلوم قبلی و نه PASS. رسید native_outcome=cancelled، checks=159 و۳fault/۳recovery ثبت کرد؛ integrated_cleanup_failure و remaining=-1 یعنی پاک‌سازی و ممیزی نهایی این اجرای قطع‌شده تأیید نشدند، نه صفر بودن باقی‌مانده. همهٔ mutationهای این تست به fixtureهای همان VM موقت محدود بودند. رسید و هر شش hash منبع اصلی حفظ و تأیید شدند.

نسخهٔ بعد full inventory را در شروع/بازیابی و پیش از phase نهایی مقایسه می‌کند؛ بین این مرزها، خود resource و هر هفت فیلترش بلافاصله پیش/پس setter بررسی و فقط همان mutation در journal تأیید می‌شود. این تفاوت واقعی در زمان تشخیص تغییر هم‌زمان است: تغییر rule انتخاب‌نشده وسط action ممکن است تا checkpoint پایان دیده نشود؛ آنجا action ناتمام می‌ماند و coordinator باید guard را همچنان برقرار نگه دارد. هیچ standalone محصول آماده نیست. قبل از آزادکردن guard در coordinator نهایی، recheck تازه همچنان ضروری است. کاهش تعداد readها جایگزین guard یا تست no-leak نشده است.

## اجرای دوم و اصلاح پاک‌سازی آزمون
source f7cceb331ee77f62b38c1d6e7e37f3d6db94d64a در run39217511673 واقعاً failed شد: checks=187، شش قطع فرایند/شش بازیابی تازه و دو Restore ناقص اجرا شدند، ولی پاک‌سازی با PropertyNotFoundException متوقف شد؛ remaining=-1 و baseline نهایی تأیید نشد. این رسید PASS نیست و آزمون‌های اجرا‌نشده از آن استنباط نمی‌شوند.

اشکال در harness پاک‌سازی بود: Group از تصویر خام CIM خوانده شده بود، درحالی‌که نام خام آن RuleGroup است. اصلاح بعدی Group را از شیء عمومی Get-NetFirewallRule می‌خواند؛ شرط Group اختصاصی و تطبیق کامل policy hash original/disabled حذف نشد. موتور تراکنش در اجرای سوم تغییری نکرد. هر شش hash منبع اجرای دوم هم بررسی و رسید ناموفق جداگانه حفظ شد. مرجع نام خام RuleGroup: https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule .
