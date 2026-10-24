# بازبینی کامل برابری قابلیت‌ها — بلک‌لیست قدیمی و Desktop 0.9.0

## نتیجه
نسخهٔ 0.9.0 RC جایگزین کامل برنامهٔ بلک‌لیست قبلی نیست. انتقال رابط و رصد ساده انجام شده، اما ضبط‌کننده، ابزار تحلیل، hosts و چند ابزار و تأیید ایمنی منتقل نشده‌اند. تکمیل رابط ظاهری یا قبول‌شدن تست‌های هسته، جای این برابری قابلیت را نمی‌گیرد.

این سند نتیجهٔ بررسی سورس همهٔ ۲۹ فایل app در ZIP کاربر است، نه آزمون اجرای ویندوز و نه ادعای تکمیل بازگردانی. نام ZIP نسخهٔ 0.1.0 دارد ولی رابط داخل آن خود را 0.1.8 معرفی می‌کند. خروجی‌های خصوصی موجود در ZIP برای این ممیزی خوانده یا منتشر نشدند.

## فهرست کامل یافته‌ها

### monitor

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| پنجرهٔ مانیتور زندهٔ مستقل / پاپ‌آپ | جاافتاده | `ui-live.ps1: New-LiveWindow/Open-LiveWindow` | Restore docked live view plus independent non-modal popup sharing one recorder, not two captures. |
| پالس کشف، نمونهٔ جدید و دیده‌شدن دوباره | جاافتاده | `ui-live-model.ps1: Live-PulseKind; ui-live.ps1: Paint-LivePulses` | Restore distinct textual and optional subtle color signals; pulses mean sampled TCP state, never packets/HTTP. |
| نمایش حضور در آخرین نمونه / رکورد تاریخی | جاافتاده | `ui-live.ps1: Render-LiveSnapshot/Paint-LivePulses` | Reset presence only after a successful sample; failure must mean unknown, not absent. |
| همیشه روی پنجره‌ها / پنهان و بازکردن مانیتور | جاافتاده | `ui-live.ps1: liveTop/liveHide/Open-LiveWindow` | Restore user-controlled topmost/hide/show; hiding must not stop recording. |
| مکث نمایش بدون توقف ضبط | جاافتاده | `ui-live.ps1: livePause/Render-LiveSnapshot` | Pause rendering only; recording and storage continue, with a persistent paused label. |
| دنبال‌کردن ردیف تازه و خاموش‌کردن پالس | جاافتاده | `ui-live.ps1: liveFollow/liveFlash` | Restore configurable follow and reduced-motion/pulse-off options. |
| مدت ۶۰، ۱۲۰، ۳۰۰ ثانیه و تا توقف | ناقص / جایگزین ساده‌شده | `ui.ps1 duration; backend.py observe accepts 0,60,120,300` | Restore original recording choices only in a separately reviewed read-only recorder path; never extend native mutation timeouts. |
| پیام آمادگی ضبط پیش از اجرای برنامه | جاافتاده | `observe.ps1 ready_path; ui.ps1 ready message` | Readiness must follow successful setup; selecting an EXE must never launch it. |
| سلامت ضبط، فریم مانده، خطای خواندن و انتشار | ناقص / جایگزین ساده‌شده | `ui-session.ps1: Recorder-HealthText; ui-live.ps1 Poll-LiveCapture` | Live heartbeat, frame age, query/publication errors, caps and finalization must be visible separately. |
| توقف، انتظار نهایی‌سازی و نتیجهٔ نهایی معتبر | ناقص / جایگزین ساده‌شده | `ui-tools.ps1 Request-RecordingStop/Accept-CaptureReport` | Keep existing stop semantics; distinguish stopping, finalized and failed; do not treat latest live frame as saved final capture. |

### observation

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| جدول دیداری مقصدهای رصدشده | جاافتاده | `ui.ps1 found/covered grids` | Restore IP, port, protocol, EXE path, PID, process start, TCP states, samples and first/last UTC columns. |
| تفکیک فرایند تازه از قدیمی | جاافتاده | `observation_model.py fresh_process_seen; ui.ps1 onlyFresh` | Use process birth vs capture start, exact path and PID+birth; unknown remains unknown. |
| تفکیک مقصد تازه، قدیمی و سابقهٔ نامطمئن | جاافتاده | `live_recording.py history_baseline; Live-DestinationLabel` | Keep destination freshness independent of process age and scoped per exact EXE identity in multi-EXE version. |
| تطابق با Block تأییدشده و تب زیر پوشش Block | جاافتاده | `backend.py block_snapshot/classify_observation; observation_model.py classify_rows` | Restore read-only exact native readback with timestamp and unknown status; stored configuration is not proof of active Block or packet drops. |
| بازبینی تفکیک Block و فیلتر موارد تحت پوشش | جاافتاده | `ui-observation.ps1 Show-ObservedRows; backend.py classify_observation` | Read-only reclassification; stale/unknown matches remain visible, never silently hide them. |
| انتخاب مقصد و افزودن مستقیم آن به بلک‌لیست | جاافتاده | `ui.ps1 Add observed rows handler` | Restore checked observed rows mapped to their actual EXE IDs; add to config only, never automatic Apply. |
| دیدن حالت‌ها، PID، زمان‌ها و دفعات نمونه | ناقص / جایگزین ساده‌شده | `ui-observation.ps1 Observed-Detail; ui-live.ps1 grid` | Restore readable table/details; samples are not bytes, packets or successful requests. |

### phase

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| مرحلهٔ جاری اجرای برنامه / ورود / داشبورد / بازی | جاافتاده | `ui-session.ps1; observe-phase.ps1` | Restore explicit user selection, append-only UTC journal and recorder acknowledgment; not automatic game-state detection. |
| مرحله‌ها و برچسب چندانتخابی هر ردیف | جاافتاده | `ui-tools.ps1 Pick-Stages/Edit-LiveStages; ui-analysis.ps1` | Restore independent row annotations, bulk edit and durable saves with error/unsaved indicators. |
| تفکیک مرحلهٔ همین ضبط و سابقهٔ ضبط‌های دیگر | جاافتاده | `capture_store.py with_annotations/stage_history; phase_context.py` | Never project previous-capture labels as actual current-stage observations. |
| حفظ برچسب‌های زنده و بازیابی هنگام نهایی‌سازی | جاافتاده | `live_recording.py recover_live_labels; ui-tools.ps1 Finalize-LiveEdits` | Persist labels separately from immutable raw recordings, preserve journals on failure. |

### evidence

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| شواهد DNS واقعی از لاگ موجود Sysmon 22 | جاافتاده | `observe-events.ps1; event_evidence.py` | Read existing enabled logs only; do not install Sysmon or change audit/log configuration. |
| رویداد منع اتصال WFP / Security 5157 | جاافتاده | `observe-events.ps1; Live-EvidenceLabel` | Show exact logged application attribution, protocol and timestamp; do not claim the event belongs to this firewall rule. |
| نمایش نگاشت hosts مرتبط با DNS ثبت‌شده | جاافتاده | `event_evidence.py hosts_baseline; observe-events.ps1` | Keep hosts config, DNS observation and actual blocking distinct; do not infer connection-domain identity from PTR. |
| وضعیت دسترسی و کامل‌بودن منابع رویداد | جاافتاده | `Live-StreamLabel; Event-Evidence` | Unreadable/disabled/partial logs are unknown coverage, not evidence of no traffic. |

### ptr

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| PTR انتخاب‌ها، همهٔ قابل‌بررسی و استعلام تازه | جاافتاده | `dns_lookup.py Resolver; ui-tools.ps1 Start-LivePtr; ui.ps1 LookupNames` | Restore explicit public-literal-IP lookups, cache freshness, per-query bounds and no actual-domain claim. |
| پیشرفت PTR، توقف و ادامهٔ مستقل ضبط | جاافتاده | `dns_lookup.py progress/stop; ui-tools.ps1 Stop-LivePtr` | One bounded read-only resolver worker can coexist with recording; no native mutation parallelism. |

### history

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| ذخیرهٔ ضبط، خواندن فهرست و بازکردن ضبط قدیمی | جاافتاده | `capture_store.py history/read; ui-analysis.ps1` | Restore validated capture storage and history UI, separate from transient job outputs. |
| مقایسهٔ دقیق دو ضبط | جاافتاده | `capture_compare.py; ui-session.ps1 Show-CaptureComparison` | Compare EXE identity + destination/protocol; different durations/quality/stages must be warned, absence is not blocking success. |
| خروجی تحلیلی ZIP و گزارش خواندنی | جاافتاده | `analysis_export.py; ui-analysis.ps1` | Restore explicit export of selected captures, annotations, source limits and privacy disclosure; never auto-upload. |
| حذف رکورد با حفظ خام محلی | جاافتاده | `capture_store.py delete_records; ui-tools.ps1` | Keep logical deletions separate from raw recordings; excluded rows must remain excluded from later exports. |
| حذف ضبط با سطل محلی | جاافتاده | `capture_store.py delete_captures` | Validate selection before moving raw capture and sidecars, retain recovery in local trash. |

### hosts

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| نمایش و خواندن استاندارد فایل hosts | جاافتاده | `hosts_view.py; backend.py hosts; hosts tab` | Restore full-domain view, address list, mapping type, invalid/truncated warning and source hash. |
| افزودن دامنه برای انسداد با نگاشت محلی | جاافتاده | `hosts_edit.py prepare/apply_hosts; ui-tools.ps1 Edit-HostsMapping` | Restore separate explicit system-wide consent; show IPv4/IPv6 mappings and no per-EXE scope promise. |
| ویرایش و حذف نگاشت انتخابی دامنه | جاافتاده | `ui-tools.ps1 Edit-HostsMapping/Apply-HostsChanges` | Preserve unrelated aliases, comments, encoding/newlines and protected system names. |
| پشتیبان، کنترل hash، قفل انحصاری و بازخوانی | جاافتاده | `hosts_edit.py apply_hosts/locked_file` | Restore verified backup before change, stale-read rejection, readback, hardlink/reparse refusal and truthful partial-failure status. |
| بازگردانی داخل همان عملیات در صورت شکست نوشتن | جاافتاده | `hosts_edit.py apply_hosts exception rollback` | Restore existing same-handle rollback safeguards; never promise rollback after power loss or report success if rollback fails. |
| دکمهٔ مستقل Restore hosts از پشتیبان | در نسخهٔ قبلی هم نبود | `hosts_edit.py has backup+in-operation rollback, no standalone restore UI` | Potential new improvement, not a dropped old feature; needs separate safe stale-hash/backup/ownership design. |

### blacklist

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| IP/CIDR، TCP/UDP و پورت | حفظ‌شده | `backend.py parse_list/spec` | Keep new exact program IDs and stricter shared policy validation. |
| ورود TXT، خروجی TXT و ذخیرهٔ مستقل فهرست | ناقص / جایگزین ساده‌شده | `ui.ps1 load/export/save; backend.py persist` | Restore TXT import/export with preview and atomic config staging, not Apply; make per-EXE assignment explicit. |
| فرم آسان رنج: الگو، ابتدا/انتها و CIDR با پوشش دقیق | ناقص / جایگزین ساده‌شده | `range_builder.py; ui-range.ps1` | Restore pure preview with first/last/address count and explicit assignment to selected EXEs; no automatic broadening. |
| وضعیت واقعی هر ردیف قانون و دلیل انتخاب | ناقص / جایگزین ساده‌شده | `ui.ps1 State/Reason; firewall.ps1 status` | Show desired vs journal-owned vs ActiveStore-verified status; do not equate config with active protection. |
| حذف تکی، حذف و اعمال، اعمال و بستن | ناقص / جایگزین ساده‌شده | `ui.ps1 RemoveKeys/ApplyList` | Retain convenience only through unchanged native ownership/readback/confirm gates; do not silently replace an active journal session. |

### safety

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| تأیید اضافی برای پوشش شبکه/رنج | جاافتاده | `backend.py apply range_consent; ui.ps1 ApplyList` | Restore additional risk acknowledgment before any broad-range Apply without weakening current LAB confirmation. |
| هشدار ویژهٔ مقصد حساس ورود | جاافتاده | `backend.py apply critical_consent; ui.ps1 ApplyList` | Reinstate reviewed risk warning and explicit acknowledgment; never add a bypass or infer exemption from whitelist. |
| دو-store readback و بازیابی قواعد خودی | حفظ‌شده با موتور متفاوت | `firewall.ps1 apply/restore` | Keep new journal-exact, drift-refusing Restore; never reintroduce broad group deletion or rule adoption. |
| حفظ قواعد پس از بسته‌شدن برنامه | حفظ‌شده | `ui.ps1 warning; backend.py persist` | State clearly that closing/config deletion is not Restore; changing hosts also persists system-wide. |
| کنترل هویت مسیر/هش EXE و تغییر فایل | حفظ‌شده | `verify_program/digest and reselect guards` | Keep per-EXE SHA256, immutable plan digest/generation and native gate checks. |
| ارتقای خودکار UAC در شروع | تفاوت عمدی ایمنی | `main.py ShellExecute runas` | Do not restore auto-elevation silently; keep explicit user launch unless separately requested. |

### multi_exe

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| انتخاب حداکثر ۳۲ EXE و شناسهٔ مسیر مستقل | قابلیت جدید نسخهٔ ادغام‌شده | `old backend restricts selected Wow executable` | All restored monitors, evidence, histories and actions must retain per-EXE identity; no collapse by filename or PID alone. |

### selection

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| تیک پایدار، فیلتر و شمارش انتخاب‌های پنهان | قابلیت جدید نسخهٔ ادغام‌شده | `old observed checks use record identity` | Preserve current checked-set contract and extend to observed records; highlight is not an execution set. |

### whitelist

| قابلیت | وضعیت در 0.9.0 | منبع قبلی | الزام بازگردانی |
| --- | --- | --- | --- |
| وایت‌لیست سراسری و kill-switch | جزو برنامهٔ مستقل بلک‌لیست نبود | `not implemented by standalone blacklist app` | Do not label these as restored/working; preserve gates until qualified. hosts blocking is not a per-EXE whitelist feature. |

## مرزهای حیاتی اصلاح

- hosts روی کل ویندوز اثر دارد، نه EXE تیک‌خورده؛ پورت و wildcard دامنه در hosts وجود ندارد. IPv4 و IPv6، کش و برنامه‌هایی که hosts را دور می‌زنند می‌توانند نتیجه را متفاوت کنند. وایت‌لیست برنامه، hosts را خودکار خنثی نمی‌کند.
- پاپ‌آپ نباید ضبط دوم ایجاد کند؛ نمایش اصلی و پنجرهٔ شناور باید از یک ضبط مشترک تغذیه شوند. مکث نمایش و پنهان‌کردن، توقف ضبط نیست.
- پالس فقط نمونهٔ جدول TCP است. لاگ DNS، نام PTR، نگاشت hosts، مشخصات Block و رویداد WFP پنج نوع شاهد متفاوت‌اند؛ هیچ‌کدام نباید به‌اشتباه اثبات شمارش بسته، دامنهٔ واقعی یا مالکیت قاعده معرفی شوند.
- بازگردانی قابلیت hosts مجوز کاهش امنیت ویندوز، فعال‌کردن audit، نصب Sysmon، اجرای خودکار EXE یا تغییر سرور/VPN/DNS نیست.
- Restore فایروال و بازگردانی hosts دو عملیات جدا هستند؛ نباید یک دکمه با موفقیت یکی، دیگری را هم موفق اعلام کند.
- مهاجرت کامل تنظیمات/ضبط‌ها و برچسب‌های قدیمی باید مسیر مشخص و اعتبارسنجی‌شده داشته باشد؛ import settings موجود در 0.9.0 فقط بخشی از آن است.
- برخی راحتی‌های قدیمی (جایگزینی فهرست فعال یا اعمال و بستن) نباید هستهٔ ژورنال امن جدید و الزام Restore-before-reapply را دور بزنند.

## وضعیت کار
این ممیزی تحویل شد؛ بازگردانی کامل، تست اجرایی ویندوز و بستهٔ اصلاح‌شده هنوز تکمیل و منتشر نشده‌اند. پیش‌نویس محلی 0.9.1 غیرقابل انتشار است و به‌عنوان برنامهٔ آماده ارائه نشده است. هیچ بستهٔ آزمون اختیاری تازه‌ای از کاربر درخواست نمی‌شود.
