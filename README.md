# WoW project continuity + bounded Battle.net Agent lab

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
