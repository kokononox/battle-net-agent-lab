"""Read-only user-facing policy review. Never invokes Apply/Restore or changes Windows settings."""
import os
from policy import PolicyError,validate
from isolation_policy import make_policy

ERRORS={
 'firewall_disabled_or_local_rules_disallowed':('فایروال یا قواعد محلی آماده نیستند','یک پروفایل فایروال خاموش است یا اجرای قواعد محلی مجاز نیست.','با مدیر سیستم وضعیت فایروال را بررسی کنید؛ این ابزار محدودیت سازمانی را دور نمی‌زند.'),
 'firewall_profile_coverage':('اطلاعات پروفایل‌های فایروال کامل نیست','هر سه پروفایل ویندوز کامل خوانده نشدند.','فعلاً اعمال نکنید؛ وضعیت سرویس و دسترسی فایروال را بررسی کنید.'),
 'authenticated_bypass_rules_require_review':('قاعدهٔ عبور ویژه وجود دارد','یک قاعدهٔ احرازهویت‌شده ممکن است انسداد را دور بزند.','با مدیر سیستم منبع قاعده را بررسی کنید؛ فعلاً اعمال نکنید.'),
 'config_changed_reload_required':('تنظیمات در حین بررسی تغییر کرده‌اند','این نتیجه برای آخرین تنظیمات معتبر نیست.','تنظیمات را بازخوانی و بررسی را دوباره اجرا کنید؛ هنوز اعمال نشده است.'),
 'iso_operation_busy_retry_status':('محافظ یا عملیات دیگری مشغول است','قفل عملیات در این فرصت آزاد نشد؛ این خطا تأیید موفقیت نیست.','کمی صبر کنید و فقط وضعیت یا بررسی را بخوانید؛ Apply را کورکورانه تکرار نکنید.'),

 'isolation_requires_Windows_explicit_Run_as_administrator':('دسترسی مدیر لازم است','برنامه با دسترسی لازم اجرا نشده است.','برنامه را ببندید و Start.cmd را با Run as administrator اجرا کنید.'),
 'iso_exactly_one_connected_full_tunnel_SSTP_required':('VPN مناسب پیدا نشد','این حالت فعلاً یک اتصال SSTP متصل و بدون Split tunneling می‌خواهد.','SSTP مناسب را وصل کنید، یا ایزولاسیون معمولی را انتخاب و ذخیره کنید.'),
 'iso_unique_connected_VPN_interface_required':('رابط VPN مشخص نیست','رابط متصل یکتای VPN قابل تشخیص نیست.','اتصال VPN را بررسی و دوباره فقط آمادگی را بررسی کنید.'),
 'iso_vpn_inventory_incomplete':('اطلاعات VPN کامل خوانده نشد','دسترسی یا سرویس VPN اجازهٔ تشخیص کامل نداده است.','با دسترسی مدیر وضعیت VPN را بررسی کنید؛ فعلاً اعمال نکنید.'),
 'iso_SstpSvc_not_running':('سرویس SSTP فعال نیست','تونل SSTP قابل تأیید نیست.','اتصال SSTP و سرویس ویندوز را بررسی کنید.'),
 'iso_cannot_prove_SstpSvc_server_endpoint_no_broad_fallback':('سرور VPN قابل تأیید نیست','آدرس اتصال واقعی سرویس SSTP تأیید نشد؛ مجوز گسترده ساخته نمی‌شود.','VPN را بررسی کنید؛ پس از اتصال معتبر دوباره بررسی کنید.'),
 'iso_restore_native_blacklist_first_no_conflicting_Block':('بلک‌لیست قبلی هنوز اعمال است','قواعد قبلی این ابزار می‌توانند با تقدم وایت‌لیست تعارض داشته باشند.','ابتدا Restore قواعد ثبت‌شدهٔ بلک‌لیست را از همان نصب اجرا کنید؛ سپس بررسی کنید.'),
 'iso_nonlocal_allow_cannot_quarantine_review_GPO':('سیاست سازمانی مانع ایزولاسیون است','مجوز خروجی غیرمحلی وجود دارد که این ابزار مجاز به تغییرش نیست.','با مدیر سیستم هماهنگ کنید؛ این برنامه سیاست سازمانی را دور نمی‌زند.'),
 'iso_effective_allow_not_mutable_locally':('مجوز خروجی قابل مدیریت نیست','یک مجوز فعال از این مسیر قابل محدودسازی و بازیابی نیست.','فعلاً اعمال نکنید؛ منبع قاعده را با مدیر سیستم بررسی کنید.'),
 'iso_other_owner_active_restore_original_package':('ایزولاسیون متعلق به نصب دیگری است','این نصب مالک نشست فعال نیست.','با همان نصب و پشتیبان اصلی وضعیت و بازیابی را انجام دهید.'),
 'iso_connection_change_requires_explicit_restore':('روش اتصال فعال متفاوت است','تغییر بین روش معمولی و VPN روی نشست فعال، بدون بازیابی مجاز نیست.','ابتدا روش فعلی را آگاهانه بازیابی کنید؛ در فاصلهٔ بازیابی تا اعمال دوباره، ایزولاسیون این ابزار فعال نیست.'),
 'iso_protected_controller_changed_restore_with_original_version_first':('محافظ فعال متعلق به نسخهٔ قبلی است','نسخهٔ جدید محافظ فعال را خودسرانه جایگزین نمی‌کند.','ابتدا با نسخهٔ قبلی ایزولاسیون را بازیابی کنید، سپس با نسخهٔ جدید بررسی و اعمال کنید.'),
 'iso_partial_session_use_status_recovery_no_retry':('عملیات قبلی کامل نشده است','وضعیت حفاظت ممکن است ناقص باشد.','Apply را تکرار نکنید؛ وضعیت و بازیابی محدود را بررسی کنید.'),
 'iso_profile_not_ready_for_isolation':('پروفایل فایروال آماده نیست','فایروال فعال نیست یا اجازهٔ قواعد محلی داده نمی‌شود.','با مدیر سیستم وضعیت پروفایل‌ها را بررسی کنید؛ ابزار محدودیت سازمانی را دور نمی‌زند.'),
 'iso_authenticated_bypass_detected':('قاعدهٔ عبور ویژه وجود دارد','یک قاعدهٔ احرازهویت‌شده می‌تواند انسداد را دور بزند.','برای بررسی منبع قاعده با مدیر سیستم هماهنگ کنید؛ فعلاً اعمال نکنید.'),
 'iso_profile_effective_block_not_verified':('انسداد پیش‌فرض تأیید نشد','تنظیمات مؤثر فایروال با ایزولاسیون سازگار نیست.','با مدیر سیستم وضعیت پروفایل‌های فایروال را بررسی کنید؛ فعلاً اعمال نکنید.'),
}
def explain_error(error):
 code=str(error).split(';',1)[0].strip()
 if code in ERRORS:return dict(severity='error',title=ERRORS[code][0],detail=ERRORS[code][1],fix=ERRORS[code][2])
 if 'legacy_' in code or 'other_engine' in code:return dict(severity='error',title='قواعد ابزار قدیمی نیاز به بررسی دارند',detail='ابزار یا قواعد قبلی ممکن است هنوز فعال باشند.',fix='با ابزار اصلی وضعیت و بازیابی محدود را بررسی کنید؛ قواعد دیگران را حذف نکنید.')
 return dict(severity='error',title='آمادگی اعمال تأیید نشد',detail='بررسی ایمنی کامل نشد؛ هیچ موفقیت حفاظتی از این نتیجه برداشت نکنید.',fix='فعلاً اعمال نکنید. وضعیت و پشتیبان را حفظ کنید؛ برای بررسی بیشتر از جزئیات فنی استفاده کنید.')

def build_review(state):
 c=state['config'];validate(c);m=c['mode'];issues=[]
 def add(level,title,detail,fix):issues.append(dict(severity=level,title=title,detail=detail,fix=fix))
 legacy=m=='vpn_allowlist';isolation=m in ('full_isolation','direct_isolation')
 name={'blacklist_only':'فقط بلک‌لیست','full_isolation':'ایزولاسیون کل سیستم — فقط از VPN','direct_isolation':'ایزولاسیون کل سیستم — اتصال معمولی','vpn_allowlist':'مود قدیمی؛ نیازمند انتخاب روش جدید'}[m]
 if legacy:add('error','مود قدیمی باید تعیین تکلیف شود','مود قدیمی VPN فقط برای سازگاری خوانده شده و خودکار فعال نمی‌شود.','روش VPN یا معمولی را انتخاب و ذخیره کنید؛ فعال‌سازی مرحلهٔ جداست.')
 overlaps=[]
 if isolation:
  p=make_policy(state);overlaps=p['overlaps']
  grouped={}
  for overlap in overlaps:grouped.setdefault(overlap['entry_id'],[]).append(overlap)
  paths={x['id']:x['path'] for x in c['programs']}
  for items in grouped.values():
   item=items[0];programs='، '.join(paths.get(x,x) for x in item['program_ids']);white='، '.join(dict.fromkeys(x['whitelist'] for x in items))
   add('notice','وایت‌لیست برای این مقصد مقدم است؛ خطا نیست',f"بلک‌لیست: {item['target']} | {item['protocol']}:{item['port']} | EXE: {programs}؛ مجوز هم‌پوشان: {white}",'اگر این مقصد باید بسته بماند، مجوز هم‌پوشان را از وایت‌لیست حذف/محدود کنید. Block دیگران و hosts دور زده نمی‌شوند.')
  add('warning','این تنظیم برای کل ویندوز است','تمام برنامه‌ها محدود می‌شوند، نه فقط EXEهای تیک‌خورده. مجوزهای خروجی محلی پس از ثبت پشتیبان غیرفعال می‌شوند.','قبل از اعمال، وایت‌لیست و اثر قطع اینترنت سایر برنامه‌ها را بررسی کنید.')
  if m=='direct_isolation':add('warning','DNS، DHCP و اتصال VPN خودکار آزاد نمی‌شوند','فقط مقاصد و پورت‌های وایت‌لیست از رابط‌های موجود مجاز می‌شوند. نام‌گشایی، تمدید IP یا VPN ممکن است قطع شود.','مقاصد لازم را آگاهانه در وایت‌لیست وارد کنید؛ این روش VPN را اجباری نمی‌کند.')
  else:add('info','خروج مستقیم ممنوع است','فقط وایت‌لیست داخل SSTP منتخب و استثناهای محدود انتقال VPN/DNS داخل تونل مجاز می‌شوند.','SSTP را قبل از بررسی وصل کنید؛ با قطع تونل مجوز خروج مستقیم ساخته نمی‌شود.')
  add('info','hosts و Block دیگران حفظ می‌شوند','وجود در وایت‌لیست تضمین اتصال نیست؛ hosts یا قواعد دیگر می‌توانند همچنان مانع باشند.','اگر مقصد مجاز وصل نشد، فایل واقعی hosts و علت منع را بررسی کنید.')
 elif m=='blacklist_only':
  add('info','قواعد فعال ویندوز در این بررسی خوانده نشده‌اند','این صفحه تنظیمات ذخیره‌شدهٔ بلک‌لیست را توضیح می‌دهد؛ فعال‌بودن قواعد از آن معلوم نیست.','برای قواعد اعمال‌شده، وضعیت واقعی / نشست یا بررسی قواعد فعال بلک‌لیست را بخوانید.')
  if not c['blacklist']:add('warning','بلک‌لیست خالی است','در این حالت مقصدی برای انسداد ثبت نشده است.','مقصد و EXE دقیق را به بلک‌لیست اضافه کنید.')
  if c['whitelist']:add('info','وایت‌لیست در این حالت اعمال نمی‌شود','حالت فقط بلک‌لیست، ایزولاسیون عمومی ایجاد نمی‌کند.','برای محدودشدن کل ویندوز، ایزولاسیون را انتخاب و ذخیره کنید.')
 if c['legacy_imports']:add('warning','تنظیمات واردشده از ابزار قدیمی','واردکردن تنظیمات، قواعد فعال ابزار قبلی را بازیابی یا حذف نکرده است.','پیش از اعمال، ابزار اصلی و قواعد فعال آن را بررسی کنید.')
 return dict(schema='unified-policy-review-1',mode=m,mode_label=name,scope='whole_system' if isolation else 'selected_blacklist_EXEs',whitelist_count=len(c['whitelist']),blacklist_count=len(c['blacklist']),issues=issues,overlaps=overlaps,native_readiness='not_checked',read_only=True,firewall_changed=False,applied=False,no_leak_certified=False,checked_generation=c['generation'])

def is_windows():return os.name=='nt'

def handle(store,payload,job):
 state=store.read();review=build_review(state);technical={}
 if review['mode'] in ('full_isolation','direct_isolation'):
  if not is_windows():
   review['issues'].append(dict(severity='warning',title='بررسی واقعی ویندوز انجام نشد',detail='در این محیط فقط تنظیمات بررسی شده‌اند.',fix='برای بررسی آمادگی واقعی، نسخهٔ ویندوز را با Administrator اجرا کنید.'));review['native_readiness']='unknown'
  else:
   try:
    from isolation_ops import handle as isolation_handle
    result=isolation_handle(store,'isolation_prepare',dict(generation=state['config']['generation']),job)
    technical['read_only_preflight']=result;review['native_readiness']='ready_at_check_time';review['quarantine_allow_count']=result['isolation_plan']['review']['quarantine_allow_count']
   except Exception as error:
    review['native_readiness']='blocked';review['issues'].append(explain_error(error));technical['preflight_error']=str(error)
 if any(x['severity']=='error' for x in review['issues']):review['headline']='برای ادامه، مشکل‌های زیر را برطرف کنید'
 elif review['native_readiness']=='ready_at_check_time':review['headline']='مانع ایمنی در این بررسی پیدا نشد؛ هنوز اعمال نشده است'
 else:review['headline']='تنظیمات بررسی شد؛ فعال‌بودن حفاظت تأیید نشده است'
 return dict(policy_review=review,technical=technical)
