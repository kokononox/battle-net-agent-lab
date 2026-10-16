# نقشهٔ اولیهٔ فعال‌سازی — کار ناتمام

این پوشه محل توقف تحلیل فقط‌خواندنی Agent 2.41.1.9824 است، نه validator نصب و نه قرارداد کامل activation. فایل executable اجرا یا بازمنتشر نشده؛ SHA256 در STATUS.json ثبت است. هیچ دانلود جدید، اسکن payload یا نوشتن در نصب/Lab صورت نگرفته است.

## یافته‌های محدود

- در بازهٔ `0x47d57c..0x47d81e`، شاخه‌های diagnostic مربوط به اختلاف build، اختلاف installed build و نبود active row از `.build.info` دیده می‌شوند. این بخش فقط برای بررسی playable است؛ writer و ترتیب commit از آن استخراج نشده‌اند.
- مسیر mapped-pointer در `0x71e18c` و `0x71e194` اولین DWORD شیء اشاره‌شده را با بازهٔ unsigned چهار تا پنج بررسی می‌کند و بیرون آن به پیام unsupported shmem protocol می‌رود. سپس در `0x71e19c` مقدار offset `0x108` با `0x2ab8` مقایسه می‌شود. **هنوز ثابت نشده این pointer دقیقاً byte صفر هر فایل shmem است**؛ نباید از این مشاهده parser فایل ساخت یا معناهای فیلد را حدس زد. حالت‌های ورودی متفاوت نیز وجود دارند.
- ارجاع‌های مشخصی به پیام‌های create/sync/rename در flush، sequence refresh و writer lock وجود دارند. فایل flush-xrefs فقط نقشهٔ محل بررسی بعدی است؛ اثبات ترتیب یا موفقیت runtime نیست.
- CascLib مرجع، نسخهٔ بیشینهٔ نام فایل را برای هر bucket در IndexDirectory_OnFileFound نگه می‌دارد و LoadLocalIndexFiles از NewSubIndex استفاده می‌کند. خواندن فایل توسط CascLib، اثبات انتخاب همان نسل توسط Agent یا بازی نیست.

## روش و بازتولید

initial-xrefs و flush-xrefs از جستجوی آدرس VA رشته به صورت operand چهار‌بایتی PE32 ساخته شدند؛ این یک xref engine کامل نیست و byte-matchها می‌توانند نیاز به تأیید disassembly داشته باشند. دو excerpt محدود با objdump تولید شده‌اند:

```sh
objdump -d -Mintel --start-address=0x47d570 --stop-address=0x47d850 Agent.9824.exe
objdump -d -Mintel --start-address=0x71dc00 --stop-address=0x71e500 Agent.9824.exe
```

آدرس آغاز excerpt اول چند بایت پیش از تابع موردنظر است؛ دستورهای قبل از 0x47d57c نباید مرز تابع شمرده شوند. این رسیدها امضای معتبر ویندوز یا اجرای runtime را ادعا نمی‌کنند. اعتبار باینری بر اساس hash تثبیت‌شدهٔ پژوهش قبلی کنترل شد.

قدم بعد: دنبال‌کردن provenance pointer و KMT flush/refresh، بازیابی ساختار و binding ورودی واقعی و سپس بررسی ترتیب نوشتن `.build.info`. تا قبل از آن نوشتن shmem، انتخاب index با حدس یا تعویض build.info ممنوع است.
