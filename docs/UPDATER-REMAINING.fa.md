# کارهای باقی‌مانده — پس از ۰٫۲۰

اصل محصول ثابت است: در هر اجرای جدید نصب موجود و مقصد سازگار جاری تشخیص داده شوند؛ target اجرای شروع‌شده pinned بماند و انتشار جدید checkpoint را خودکار منتقل نکند.

## انجام‌شدهٔ این جلسه
- native Windows staging و پذیرش محدود آن از مراحل قبل حفظ شد.
- کنترلر چندشیء/چند Range و HTTP adapter به staging وصل شدند؛ grant و budget، رزرو پیش از fetch، ETag/total مشترک، لغو و ادامهٔ commitهای سالم در process تازه آزموده شدند.
- ۵۳ تست انتقال روی هر backend؛ مجموع Linux برابر ۵۳۶ و Windows واقعی برابر ۱۷۴، بدون failure/error/skip در CI. HTTPها synthetic/mock هستند، نه دانلود واقعی بازی.
- مرور منابع عمومی معنای community Alternate/0x4000 را روشن‌تر کرد؛ policy رسمی Agent یا Talebound اثبات نشد و candidateهای قبلی تغییر نکردند.

## ترتیب باقی‌مانده
1. **بستن policy انتخاب و closure:** شاهد مستقل برای feature/Alternate/Talebound، اولویت/حذف variantها، dependency و patch/full. معنای enum یا parser/extractor عمومی به‌تنهایی کافی نیست. ترجیحات تازهٔ نصب هم لازم است؛ flagهای vendor/feature فعلاً false بمانند.
2. **نصب فقط‌خواندنی و نسل فعال:** backend منسجم Windows، baseline/profile تازه و حل معنای نسل/ایندکس؛ V8 ناشناخته حدس زده نشود. گزارش قدیمی یا کپی ایندکس اثبات وضعیت فعلی نیست. ابزار لازم باید قبل از درخواست اجرای کاربر دامنهٔ دقیق داشته باشد؛ بدون اسکن کور یا تغییر ACL.
3. **reuse و برنامه/حجم دقیق:** اثبات کامل محتوای نصب و source؛ چند locator خودسرانه حل نشود؛ نبود ref در کپی missing نیست. تفکیک reuse/دریافت/unknown و network/patch/write/temp/free-space؛ حجم ضروری هنوز null است.
4. **qualification انتقال واقعی و recovery:** طراحی reconciliation صریح attempt مبهم و crash/disk-full؛ فعلاً pending خودکار پاک یا تکرار نمی‌شود. سپس scope کوچک تازه برای HTTP واقعی CDN، کنترل TLS/رفتار سرور و شکست‌های عملیاتی. مجوزهای قدیمی بسته‌اند؛ سقف ۴ GiB عدد parser/grant است، نه آزمون مقیاس یا مجوز فعلی.
5. **CASC writer تراکنشی، rollback و activation:** پیاده‌سازی و check قبل/بعد، حفظ نسل قبلی تا commit معتبر؛ ابتدا فقط کپی مستقل Windows. flush/rename و آزمون مصنوعی جای qualification قطع برق واقعی نیستند. apply نصب اصلی مجاز نیست.
6. **end-to-end بومی:** چند baseline/target، نصب ناقص، بازی باز، قطع شبکه/پردازش، دیسک پر، قالب/رمزگذاری پشتیبانی‌نشده، مسیر غیرمجاز و rollback؛ هیچ حالت نیمه‌نوشته فعال نشود.
7. **UI/بستهٔ انتشار:** نمایش برنامه/حجم معتبر، تأیید روشن apply، پیشرفت/لغو/ادامه، گزارش حداقلی و ارتقای خود اپدیتر.

کاربر Windows و فضای کپی آزمایشی را دارد؛ فعلاً درخواست کپی بازی یا اجرای probe آماده‌نشده، prepare، اسکن، admin/permission یا دانلود گسترده داده نشده است. installation_ready=false و apply_authorized=false. این sync مسیر مستقل Agent/تله‌متری را اجرا نکرد.
