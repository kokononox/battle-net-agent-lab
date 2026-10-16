# WoW project continuity + bounded Battle.net Agent lab

## وضعیت پژوهش به‌روزرسان مستقل — ۲۰۲۶-۱۰-۱۶

**برای ادامهٔ جلسه ابتدا [تحویل فعلی](docs/SESSION-2026-10-16.fa.md) و [راهنمای پرتابل](docs/PORTABLE-RESEARCH.fa.md) را بخوانید.** این بخش وضعیت جدید شاخهٔ `patch-audit-20261016` است؛ مدارک تاریخی پایین حذف نشده‌اند.

- یک نمونهٔ واقعی Retail از source+ZBSDIFF1 به target بازسازی شد؛ CKey هدف و سپس اندازه/EKey دقیق encoded و roundtrip تأیید شدند.
- آزمایش CASC ساختگی و recovery انجام شد: **۳۶۰ آزمون، صفر failure/error/skip**. این عدد متعلق به patch-audit است، نه جایگزین ۴۴۶ تست تاریخی دانلودر یا تست‌های Windows Agent.
- [جدیدترین گزارش payload اصلی و مسیر نام](downloader/patch_audit_lab/research/primary-payload-9824/README-fa.md): دو آرایهٔ ۴۰بیتی با ظرفیت ۱۰۹۰ و مسیر rollback حالت ۲ ردیابی شد؛ مشاهده‌گر نسخهٔ ۳ فقط‌خواندنی، بدون صدور رکوردها یا اجرای بازیابی. normalizer مسیر استاتیک بررسی شد؛ binding واقعی Windows و writer نهایی هنوز اثبات نشده‌اند. مجموع ۳۶۰ آزمون.
- [checkpoint قبلی binding و extension](downloader/patch_audit_lab/research/binding-extension-9824/README-fa.md): نام guard از control+8 و انتخاب نوع قفل از mode شیء ردیابی شد. parser اصلاح شد: فیلد v5 برابر 0x154 است؛ 0x258 طول copy افزونه‌دار است. directory slot0 و اندازهٔ 20KiB حالت مشاهده‌شده افزوده شدند؛ مجموع ۳۳۸ آزمون، هنوز بدون اجرای Agent/Windows یا shmem واقعی.
- [checkpoint قبلی publication و قفل‌ها](downloader/patch_audit_lab/research/publication-static-9824/README-fa.md): محل store شرطی sequence در header و reader مصرف‌کننده، قفل‌های SRW داخلی و حالت mutex/critical-section guard بیرونی بررسی شدند؛ ۱۰ آزمون verifier تازه، مجموع ۳۱۸. نام/binding قفل نصب و دوام دیسک اثبات نشده‌اند.
- writer/activation قابل‌استفاده روی بازی هنوز نداریم. در Agent ثابت، منشأ mapping و مسیر FlushFileBuffers → MoveFileExW با byte anchor و import table بررسی شده؛ مشاهده‌گر محدود shmem اضافه شده، اما قرارداد نهایی activation هنوز استخراج نشده است.
- ZIP اصلی Portable-Retail-Sample با اندازهٔ 169,779,901 بایت و کد companion در [Release خصوصی پژوهش](https://github.com/kokononox/battle-net-agent-lab/releases/tag/retail-research-2026101) منتشر شدند؛ اندازه و digest سرور GitHub برای هر سه asset با فایل محلی تطبیق داده شد. [رسید تأیید](evidence/portable/RELEASE-RECEIPT.json).
- [checkpoint قبلی activation و آزمون‌های ۳۰۸تایی](downloader/patch_audit_lab/research/activation-static-9824/README-fa.md). ZIP companion روی Release snapshot پیشینِ ۲۷۸تایی است؛ برای ماژول‌های جدید از آخر شاخه استفاده کنید.
- ZIP اصلی تغییر نکرده است؛ برای عبور از محدودیت قدیمی parser داخل آن، از runner و کد فعلی مخزن استفاده کنید، نه تعویض فایل‌ها در fixture و نقض manifest.
- هیچ PRIVATE/SQLite، اطلاعات ورود یا transcript خام منتشر نمی‌شود. fixture رسمی متادیتا و نمونهٔ کوچک patch، استثنای مشخص و درخواست‌شدهٔ انتشار در مخزن خصوصی است.

## زمینهٔ اولیهٔ پروژه — فارسی

هدف اصلی **اثبات تله‌متری WoW در سطح فیلد/درخواست/مقصد** است. دانلودر/تعمیر پیش‌نیاز موقت است؛ آزمایش Battle.net در GitHub مسیر تحقیق مستقل است.

- [تحویل جامع جلسه و وضعیت آخر](docs/SESSION-HANDOFF.fa.md)
- [معماری و اجرای تست‌ها](docs/ARCHITECTURE.fa.md)
- [مسیر نسخه‌ها و تصمیم‌ها](docs/HISTORY.fa.md)
- [شواهد، واقعیت‌ها و محدودیت‌ها](docs/EVIDENCE-AND-LIMITS.fa.md)
- [گام بعد و شرط توقف](docs/NEXT-STEPS.fa.md)
- [دامنهٔ sync و حریم خصوصی](docs/SYNC-SCOPE.fa.md) · [وضعیت ماشین‌خوان](docs/current-state.json)
- [منبع آخرین دانلودر TagFix](downloader/README-fa.md) · [فهرست گزارش‌های کاربر](evidence/INDEX.json)

منبع TagFix با ۴۴۶ تستِ انتشار در `downloader/` نگهداری می‌شود؛ محیط Linux و تست‌های واقعی Windows کاربر جدا مستندند. **هنوز CASC writer/نصب نهایی نداریم؛ حجم قطعی دانلود null است.** Lab فعلی را حفظ کنید؛ این sync درخواست تکرار prepare، اسکن کامل یا دانلود گسترده نیست. در sync تاریخی این بخش، raw transcript، PRIVATE، فایل بازی و اطلاعات ورود منتقل نشده بودند؛ برای استثنای fixture جدید، بخش وضعیت پژوهش بالا را ببینید.

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
  Agent and requires a recent login for game installation; it is not run here.
