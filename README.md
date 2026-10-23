# WoW project continuity + bounded Battle.net Agent lab

## آخرین گام — گلوگاه کد اختصاصی پیام سخت‌افزار

[گزارش بررسی محدود سه ورودی](analysis/entry-loader-startup-2026-10-23/hardware-message-code-gate/README.fa.md) · [شواهد دو دیکدر](analysis/entry-loader-startup-2026-10-23/hardware-message-code-gate/evidence.json) · [وضعیت و شرط ادامه](analysis/entry-loader-startup-2026-10-23/hardware-message-code-gate/SYNC-STATUS.json).

سه اشاره‌گرِ نامزد merge/creator/parse-fallback از متادیتای ClientEngineLogV2 به ابتدای رکوردهای pdata در `.text` دنبال شدند؛ اسلات هر سه DIR64 relocation دارد. دیکد خطی معمول با Capstone و objdump از این ورودی‌ها بدنهٔ قابل اتکایی برای دنبال‌کردن مقداردهی سخت‌افزار به دست نداد. این نتیجه دربارهٔ بایت روی دیسک و ابزارهای ثبت‌شده است، نه اثبات نامعتبر بودن کد زمان اجرا، رمزگذاری، حفاظت یا نبود ارسال.

**تصمیم:** این مسیر نیز فعلاً در انتظار شاهد تازهٔ مجاز و منطبق با build متوقف است؛ اسکن تکراری رشته‌ها و گسترش عمومی لودر پیشرفت رفتاری محسوب نمی‌شوند. صحت اسلات/relocation/pdata/بایت با PE reader مستقل کنترل و گزارش دو بار یکسان تولید شد؛ این کنترل‌ها اثبات معنایی نیستند. CPU/BIOS روی TCP/3724 همچنان نه اثبات و نه رد شده است. بازی اجرا/patch نشد؛ main، GUI 0.2 و firewall دست‌نخورده‌اند.

## گام پیشین — منشأ بافر، تطبیق نام ماژول و توقف گسترش عمومی

[گزارش منشأ U و N، منابع و بازتولید](analysis/entry-loader-startup-2026-10-23/record-provenance/README.fa.md) · [وضعیت و تصمیم ادامه](analysis/entry-loader-startup-2026-10-23/record-provenance/SYNC-STATUS.json).

با فرض معمول Windows x64 و layout مرجع تطبیق‌یافته، زنجیرهٔ `GS:[0x60] → PEB+0x18 → Ldr+0x10` به فهرست load-order و فیلدهای `record+0x58/+0x60` به Length/Buffer در BaseDllName منطبق است. هیچ نام ماژول واقعی، OS build کاربر یا محتوای حافظه مشاهده نشده است.

برای wordِ global در RVA `0x20F9B98` با مقدار دیسک `0xF92D`، `N=floor(L/2)` و گسترهٔ بایتی `2*N=L&0xFFFE` ثابت شد. شرط global عمومی نیست؛ همهٔ شمارش‌های شیفت ۰ تا ۶۳ در دامنهٔ مدل ممکن‌اند. ۶۵٬۵۳۶ global و ۶۵٬۵۳۶ طول در سناریوی دیسک، هفت fixture ساختگی و ۱۴ آزمون خراب‌سازی ردشده بررسی شدند. انتقال قبلی دوباره بازبینی و دو گزارش اصلی یکسان بازتولید شد.

**تصمیم:** این شاخه فعلاً مسیر عمومیِ نام/بافر ماژول محسوب می‌شود، نه شاهد مستقیم CPU/BIOS. گسترش کور `0x6995D0` متوقف می‌شود؛ ادامه باید به شواهد اختصاصی جمع‌آوری سخت‌افزار یا مقداردهی پیام برگردد. ارسال CPU/BIOS روی 3724 همچنان اثبات یا رد نشده است. هیچ فایل بازی اجرا/patch نشد؛ main و GUI 0.2 تغییر نکردند. تست بازی یا بلاک تازه لازم نیست.


## گام پیشین — نقش داده‌ای 0x683780

[گزارش و بازتولید دو قطعه](analysis/entry-loader-startup-2026-10-23/callee-683780/README.fa.md) · [وضعیت و تصمیم ادامه](analysis/entry-loader-startup-2026-10-23/callee-683780/SYNC-STATUS.json).

در مسیر مشروط به globalهای ثبت‌شده، دو جفتِ آغاز/پایان `D..D+256` و `U..U+2*N` با بررسی دو آماده‌ساز کوچک ساخته می‌شوند. تحلیل پیش از call ناشناختهٔ `0x6995D0` متوقف شد. در snapshot جداگانهٔ پس از call، عبارت خروجی به `*Q = A-D (mod 2^64)` ثابت شد؛ این snapshot نتیجهٔ اثبات‌شدهٔ call نیست. معنای محتوای بافرها، encoding، پیشروی درست A و تولید واقعی بایت هنوز معلوم نیست.

۱۰۶ نمونهٔ عددی برای هر قطعه، گواه جبری قفل‌شده به بایت‌ها، ۱۴ آزمون خراب‌سازی ردشده و بازتولید یکسان سه گزارش ثبت شد؛ دیکدر مسیر در دو مدل مشترک است. هیچ PE اجرا یا patch نشد؛ main و GUI 0.2 تغییر نمی‌کنند.

این گام یک نقش داده‌ای را روشن کرد، نه ارسال CPU/BIOS روی 3724. قدم پیشنهادی بعد تطبیق منشأ U و N در record قبلی است؛ بازکردن کور کل تابع داخلی آغاز نمی‌شود. تست بازی، attach و بلاک تازه لازم نیست.


## گام پیشین تحلیل آفلاین — تابع 0x5C6440

[گزارش و بازتولید گام سوم](analysis/entry-loader-startup-2026-10-23/callee-5c6440/README.fa.md) · [وضعیت این گام](analysis/entry-loader-startup-2026-10-23/callee-5c6440/SYNC-STATUS.json).

در اولین dispatcher این تابع، ۱۷ مسیر با ۱۷ مقصد متمایز و پوشش ورودی DWORD بررسی شد. مسیر کامل‌تر فقط مشروط به مقادیر سراسری روی دیسک و محافظ stack است: `0x5C6440 → call at 0x5C6ED9 → 0x683780`. آدرس یک DWORD محلی و چند آرگومان ورودی به مقصد منتقل می‌شود. مقدار محلی در سناریوی دیسک صفر است؛ یک ضدنمونهٔ مدل نشان داد این صفر بودن عمومی نیست.

مدل عددی جداگانه، بایت‌ها، شاخه‌ها و انتقال آرگومان‌ها را تطبیق داد؛ دیکدر مسیر در دو مدل مشترک است. ۱۱ آزمون خراب‌سازی مسیر و سه آزمون dispatcher رد شدند؛ دو اجرای entrypoint چهار گزارش اصلی یکسان ساختند. هیچ PE اجرا یا patch نشد. نویسندهٔ اسلات EXE، آماده‌سازی کد، خواندن BIOS و ارسال CPU/BIOS روی 3724 همچنان اثبات نشده‌اند. هدف بعدی بررسی مصرف داده در `0x683780` است، نه تست شبکه یا بلاک تازه.

این بخش وضعیت تازهٔ مسیر تحلیل راه‌اندازی است؛ بخش‌های زیر سابقهٔ سایر مراحل و آزمایش‌ها هستند. ثبت این گام تنها روی شاخهٔ `analysis/entry-loader-startup-2026-10-23` انجام می‌شود؛ main و GUI 0.2 تغییر نمی‌کنند.


<!-- project-current-status-link:start -->
## وضعیت روز — ابتدا این بخش را بخوانید

**مرحلهٔ فعلی:** [ردیابی آفلاین پیام مشخصات سیستم و مرز نتیجه](docs/WOW-TRACE-2026-10-20.fa.md)؛ بررسی حریم خصوصی خود WoW Retail؛ [تحویل جلسهٔ شبکه و بازیابی](docs/SESSION-NETWORK-2026-10-20.fa.md) و [یافتهٔ جدید CPU/BIOS در schema بازی](docs/WOW-STATIC-2026-10-20.fa.md).

ClientEngineLogV2 شامل فیلدهای CPU/مادربرد/BIOS است؛ تعریف پیام اثبات ارسال در اجرای کاربر نیست. مشاهدهٔ passive فقط metadata مقصد و HTTPهای ساده را روشن کرده؛ TLS بازی هنوز خوانده نشده. proxy آزمایشی login را مختل کرد و با recovery مشکل برطرف شد؛ تکرار آن توصیه نمی‌شود. فایل‌های بازی، capture خام، CA/key و runtime باینری وارد مخزن نشده‌اند.

[وضعیت هماهنگی](docs/STATUS.fa.md) · [وضعیت ماشین‌خوان](docs/current-state.json) · [منبع ابزارها](user-tools/session-20261020/) · [manifest sync](docs/SESSION-SYNC-2026-10-20.json). متن پایین تاریخچه است؛ مجوز نصب Classic/اجرای مجدد آزمایش‌ها نیست.
<!-- project-current-status-link:end -->


## آزمایش جاری — نصب پایهٔ Classic در ویندوز دورریختنی

کاربر دانلود/نصب آزمایشی را تأیید کرد. اجرای یک‌باره با کنترل فضای واقعی دو volume، مقصد تازه، فرم auth/min-spec/legal و عدم جعل کشور آماده شد. اینجا هنوز نتیجهٔ اجرای واقعی نصب ادعا نمی‌شود؛ گزارش پس از پایان در `reports/classic-install-latest.json` منتشر خواهد شد. [دامنه و محدودیت‌ها](docs/CLASSIC-BASELINE-EXPERIMENT.fa.md). سقف سخت ترافیک Agent وجود ندارد و نصب با حذف VM نگهداری نمی‌شود؛ محتوای بازی صادر نمی‌شود. این نصب تازه جای آزمون آپدیت نسخه‌به‌نسخه نیست.


## نتیجهٔ تازه — متادیتای رسمی Classic Era

نسخهٔ EU برابر `1.15.9.70003` مشاهده شد؛ configهای ساخت/CDN و هویت کامل manifestهای نصب/دانلود تأیید شدند. تنها 4,957,673 بایت متادیتا دریافت شد؛ هیچ بازی، Agent یا نصب/آپدیتی اجرا نشد. جمع کل catalogue دانلود حدود 7.93 GiB است، **نه حجم نصب پروفایل انتخابی یا حجم آپدیت**. جزئیات و مرز مجوز در [نتیجهٔ بررسی](docs/CLASSIC-ERA-METADATA-RESULT.fa.md)، [receipt](reports/classic-era-metadata-preflight.json) و [اندازه‌گیری](reports/classic-era-manifest-sizing.json).

گام بعد تهیهٔ baseline آزمایشی Classic روی Windows VM جداست؛ چون دانلود/نصب بازی است به مجوز تازه نیاز دارد. هیچ workflow نصب فعالی اضافه نشده و سقف سخت شبکهٔ Agent هنوز پیاده نشده است. آزمایش‌های قبلی `/agent` و `/game` موفق بودند، نه آپدیت واقعی بازی.


## نتیجهٔ عملی تازه — مشاهدهٔ وضعیت Agent بدون حساب

[نتیجهٔ گام دوم و مرز بعدی](docs/AGENT-STATUS-RESULT.fa.md) · [دامنهٔ دو درخواست](docs/AGENT-STATUS-EXPERIMENT.fa.md) · [گام اول](docs/AGENT-INTERFACE-RESULT.fa.md). اجرای Windows تازه، `GET /agent` و سپس `GET /game` با token محلی همان اجرا را با HTTP 200 پاسخ داد. summary خالی با صفر محصول گزارش شد. source/run تطبیق داده شد؛ هیچ حساب، دانلود بازی، initialization، update یا repair درخواست نشد. موفقیت آپدیت بازی و سیاست Retail هنوز اثبات نشده‌اند. گام بعدِ پیشنهادی، متادیتای تازهٔ Classic Era با سقف شبکهٔ مشخص است؛ درخواست دانلود بازی یا ثبت عملیات نصب نیست و منتظر تأیید همین دامنهٔ تازه است.

## تصمیم معماری پیشین — نه اعلام حل کامل

[بررسی مسیر Agent و شرط استقلال](docs/UPDATER-BACKEND-DECISION.fa.md). موتور مستقل هنوز قواعد کامل انتخاب Retail و نویسندهٔ تراکنشی CASC ندارد. مسیر جایگزین به Agent رسمی وابسته است؛ ورود حساب شرط عمومی آپدیت Battle.net اعلام نمی‌شود. شرط ورودِ README ابزار واسط نباید به خود موتور تعمیم داده شود. کاربر امکان آپدیت بدون لاگین را گزارش کرده است؛ سازگاری کلاینت ما با آن مسیر هنوز آزمایش نشده. بدون تأیید کاربر معماری عوض نمی‌شود. در بررسی اولیهٔ معماری Agent اجرا نشد؛ آزمایش‌های واقعی بعدی در بخش بالا ثبت شده‌اند. درخواست آپدیت بازی هنوز اجرا نشده؛ رمز حساب یا ورود لازم نیست.

## وضعیت پیشین مسیر اپدیتر — selection semantic discrimination

[شرح تغییر عملکردی و آزمون](docs/UPDATER-SELECTION-SEMANTICS.fa.md) · [باقی‌مانده](docs/UPDATER-REMAINING.fa.md).

تشخیص اختلاف locale/category و فرضیه‌های 0x4000 به review اصلی هر دو manifest وصل شد؛ candidate/plan تاریخی تغییر نکرد. منبع community Classic بررسی شد، اما fallback انتخاب همه و taxonomy ناسازگار آن وارد نشد و شاهد مستقل Retail اعلام نشد. Linux=823 و Windows=524 پاس، 10 regression تازه. سیاست کامل انتخاب، variant/dependency/patch هنوز بازند؛ اشتراک فرضیه‌ها required set نیست. هیچ game/CDN access یا ZIP تازه انجام نشد؛ در آن گام اقدام کاربر لازم نبود.

## شروع ادامهٔ پروژه — فارسی (سابقه)

هدف اصلی **اثبات تله‌متری WoW در سطح فیلد/درخواست/مقصد** است. دانلودر/تعمیر پیش‌نیاز موقت است؛ آزمایش Battle.net در GitHub مسیر تحقیق مستقل است.

- [تحویل جامع جلسه و وضعیت آخر](docs/SESSION-HANDOFF.fa.md)
- [معماری و اجرای تست‌ها](docs/ARCHITECTURE.fa.md)
- [مسیر نسخه‌ها و تصمیم‌ها](docs/HISTORY.fa.md)
- [شواهد، واقعیت‌ها و محدودیت‌ها](docs/EVIDENCE-AND-LIMITS.fa.md)
- [گام بعد و شرط توقف](docs/NEXT-STEPS.fa.md)
- [دامنهٔ sync و حریم خصوصی](docs/SYNC-SCOPE.fa.md) · [وضعیت ماشین‌خوان](docs/current-state.json)
- [منبع آخرین دانلودر TagFix](downloader/README-fa.md) · [فهرست گزارش‌های کاربر](evidence/INDEX.json)

منبع TagFix با ۴۴۶ تستِ انتشار در `downloader/` نگهداری می‌شود؛ محیط Linux و تست‌های واقعی Windows کاربر جدا مستندند. **هنوز CASC writer/نصب نهایی نداریم؛ حجم قطعی دانلود null است.** Lab فعلی را حفظ کنید؛ این sync درخواست تکرار prepare، اسکن کامل یا دانلود گسترده نیست. raw transcript، PRIVATE، فایل بازی و اطلاعات ورود منتقل نشده‌اند.

## Independent GitHub experiment

This repository is separate from the WoW downloader Lab and from the user's game.
It requests **no account login, no game installation/download, no repair, no CASC
writes, no anti-cheat changes and no TLS interception**.

## Initial experiment

A manual run or a push changing the lab's scripts/tests/workflow starts one
`windows-2025` GitHub-hosted job (8-minute maximum). It:

1. Refuses self-hosted runners, non-Windows systems and preexisting Battle.net state.
2. Downloads the bootstrapper from an official HTTPS endpoint with an allowlisted
   redirect chain and a 128 MiB installer-body cap.
3. Requires a valid Windows Authenticode signature and an expected Blizzard publisher
   before executing it. No certificate validation is disabled.
4. Launches the normal setup program **without guessed silent/EULA flags or GUI
   clicks by default**, with a reduced environment excluding GitHub/account credentials.
   The explicitly authorized one-off language exception is documented below.
5. Observes for 45 seconds by default, 90 in the approved language run (configurable 30–150): known process names/PIDs, sampled public TCP
   destinations, bounded file metadata and log **keyword counts only**.
6. Attempts to stop observed setup/Agent processes. The hosted VM is disposable.
7. Adds up to two bounded, read-only GUI/session inspections; no clicks, edit/hidden/unknown control text, raw captions or screenshots. Only fixed class/label/marker enums are exported. Schema6 includes source commit/run identity and the separately reported language-step result.
8. Exports only one strictly validated JSON report; no binaries, screenshots,
   packet captures, raw logs, command lines, account/geoip values or user files.

A separate clean Linux job (4-minute maximum) revalidates the JSON and commits it to
`reports/latest.json` and `reports/run-<id>-<attempt>.json`. The observation job has
only `contents: read`; only the clean publication job has `contents: write`.
All external Actions are pinned to full commit SHAs (`action-pins.json`).
No schedule, background persistence or automatic retry is configured. Private
repository Actions minutes/storage are subject to the account's quota; no purchase
or paid runner is configured. A run may be queued/blocked by account policy/quota.

## One-off approved language step

The user explicitly approved English (US) → Continue on the observed language page.
Only the push commit `lab: approved language-only step 2026-10-15 7ce42b91-yamlfix`, first run
attempt, enables this exception. Manual workflow runs and later pushes remain
read-only. The helper checks the original verified Setup PID/executable, visible
Setup window, language group, exactly one English-US radio and Continue button.
It selects only if needed, confirms selection, rechecks the same page/controls,
and invokes Continue at most once. No legal consent, install button, account,
login, or game action follows. A private pre-action journal preserves attempted
operations on timeout; uncertainty is reported and never retried automatically.
Only fixed enums/booleans leave the runner. Installer/Agent components may download;
no game download is requested. Details: [language-step scope](docs/LANGUAGE-STEP.fa.md).

## Important limits

- Windows hosted runners are not an interactive consumer Windows desktop. If setup
  waits for interaction or does not expose an Agent process, the report says so;
  installation completion is **not** inferred. No login or UI interaction is added
  automatically to get past that limit.
- Time, download-body and output limits are separate: the **128 MiB cap applies to
  the fetched installer only**, not the bootstrapper's own subsequent network use.
  Its observation window/job timeout are bounded; there is no hard child-network
  byte cap in this initial experiment.
- Sampled TCP destinations are not full network capture or evidence of plaintext
  HTTP bodies. Log keyword occurrences do not prove an operation executed.
- A process may start/exit between samples. No Agent observed is not proof of absence.
- A fresh hosted VM isolates this experiment from user machines; it is **not** a
  security sandbox against malicious code. Only a signed expected publisher's
  bootstrapper is executed. No account or repository secrets are configured here.
- This first experiment is a bootstrap investigation, **not reverse-engineering of
  the full WoW update/patch/activation algorithm**. A real version-to-version update
  with game data needs a different, sufficiently large disposable Windows machine.
- Results must not be mixed with the separate Wow.exe telemetry study.

## Current downloader work continues independently

Keep the existing `WoW-Downloader-Lab`. Do not repeat metadata preparation/full
payload verification or start the broad conditional download queue. The current
TagFix update-scope report is evidence, not installation authorization or an exact
network download estimate.

## Sources

- https://docs.github.com/en/actions/concepts/runners/github-hosted-runners
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://github.com/barncastle/Battle.Net-Installer — delegates to the Battle.net
  Agent; its README states a recent-login prerequisite for that third-party tool,
  not a universal Battle.net update requirement. It is not run here.
