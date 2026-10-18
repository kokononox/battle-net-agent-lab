# تحویل کنترلر انتقال — ۰٫۲۰

ادامهٔ [۰٫۱۹](UPDATER-SESSION-0.19.fa.md). سورس فعلی updater-core/. محصول reusable/version-independent است؛ target 12.1.5.70448 فقط snapshot تاریخی است.

## نتیجهٔ این جلسه
کنترلر sequential چندشیء/Range به دو backend staging وصل شد. grant صریح به checkpoint و object/source و journal اولیه متصل است؛ سقف درخواست/body پیش از کار کنترل می‌شود. transfer.json پیش از هر fetch attempt را رزرو می‌کند. source/target/baseline ورودی و journal خارج از ledger نباید تغییر کنند. ETag و total بین اشیاء یک URL آرشیو هم pinned هستند. restore prefix SHAها را تازه می‌سنجد و finish همهٔ محتوای BLTE را از نو بررسی می‌کند؛ نتیجه owned staged input است، نه reuse نصب یا required set.

stream_http.py انتقال دقیق Range را با 206/Content-Range/Length/If-Range/ETag و رد redirect، encoding، Transfer-Encoding و هدرهای تکراری انجام می‌دهد؛ no retry و no EOF probe. API فقط با grant و approved_network صریح فعال می‌شود؛ در این جلسه همهٔ HTTPها mock بودند. هیچ scope قدیمی دوباره مصرف نشد.

قطع مبهم عمداً pending می‌ماند؛ حتی append موفق بدون commit ledger خودکار پذیرفته نمی‌شود. ادامه بین commitهای سالم در process تازه آزموده شد، نه recovery خودکار هر قطع شبکه. baseline equality جای اثبات freshness نصب زنده نیست. محدودیت عددی grant حداکثر ۶۴ شیء/۴۰۹۶ Range/۴ GiB است، نه آزمون کامل این سقف یا مجوز فعلی.

۵۳ تست تازهٔ کنترلر/HTTP، ۵۳۶ تست Linux و ۱۷۴ تست واقعی Windows/Python 3.12.10؛ صفر failure/error/skip در CI. source d9f7c14e3c40e4bf3432dd7e7b5505773384c208؛ receipt 9ab5f617da43cfa5836cf7e527283844d0bece23. شمار پلتفرم‌ها جمع نشود. ZIP بعد از تولید دوباره استخراج، CRC/hash و regression آن کنترل می‌شود.

مرور هدفمند wowdev/TACT و TACTSharp شاهد کافی برای policy رسمی/معنای Talebound نداد. Alternate طبق منبع community برای censored content است و enum آن 0x4000 است؛ این به معنی optional بودن هر tag 16384 نیست. candidateها و gateها تغییری نکردند. شواهد و منابع در research/POLICY-EVIDENCE-0.20.md ثبت شدند.

## ادامه و مرزها
policy مستقل feature/variant/dependency/patch، ترجیحات تازه، نسل فعال، reuse نصب و حجم‌ها حل نشده‌اند. همچنین recovery مجاز pending، HTTP/CDN واقعی، CASC writer/rollback/activation، E2E کپی Windows و UI باقی‌اند. native_windows_staging_backend_qualified=false، actual_game_CDN_transfer_qualified=false، installation_ready=false و apply_authorized=false؛ حجم ضروری null است. نوشتن بازی، admin/ACL/repair یا کپی بازی درخواست نشده است. کاربر Windows و فضای آزمایشی دارد، اما هنوز اجرای زنده لازم نیست.

مخزن با همین وضعیت و receiptها sync شد؛ workflow مستقل Agent دست‌نخورده ماند. metadata/cache موجود حفظ و دوباره دانلود نشوند. payload بازی، decoded بزرگ، SQLite، raw transcript و credential وارد مخزن/ZIP نیستند.

[رسید Windows](../updater-core/reports/WINDOWS-TRANSFER-CI-to-share.json) · [QA](../updater-core/QA.json) · [مرز انتقال](../updater-core/research/TRANSFER-SAFETY.md) · [اقدامات باقی‌مانده](UPDATER-REMAINING.fa.md)
