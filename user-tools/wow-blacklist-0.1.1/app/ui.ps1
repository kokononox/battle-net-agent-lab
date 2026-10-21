$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$root=$env:WOW_BL_ROOT;$private=Join-Path $root 'private-state';[void][IO.Directory]::CreateDirectory($private)
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-model.ps1'))))
$script:job=$null;$script:closeAfterObserve=$false;$script:reselected=$false;$script:observed=@();$script:actual=@{};$script:actualAt='';$script:loading=$false;$script:dirty=$false
$form=New-Object Windows.Forms.Form
$form.Text='WoW Blacklist · 0.1.1';$form.ClientSize=New-Object Drawing.Size(1120,920);$form.MinimumSize=New-Object Drawing.Size(1000,800);$form.StartPosition='CenterScreen';$form.BackColor=[Drawing.Color]::White;$form.Font=New-Object Drawing.Font('Tahoma',10.5);$form.AutoScaleMode='Dpi'
$layout=New-Object Windows.Forms.TableLayoutPanel;$layout.Dock='Fill';$layout.Padding=New-Object Windows.Forms.Padding(16);$layout.ColumnCount=1;$layout.RowCount=10
foreach($height in @(44,64,48,48,-1,74,52,44,100,62)){
 $style=if($height -eq -1){New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)}else{New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$height)}
 [void]$layout.RowStyles.Add($style)
}
$form.Controls.Add($layout)
function Label([string]$value){$c=New-Object Windows.Forms.Label;$c.Text=$value;$c.Dock='Fill';$c.TextAlign='MiddleRight';$c.RightToLeft='Yes';return $c}
function Button([string]$value){$c=New-Object Windows.Forms.Button;$c.Text=$value;$c.AutoSize=$true;$c.MinimumSize=New-Object Drawing.Size(130,44);$c.FlatStyle='Flat';$c.Margin=New-Object Windows.Forms.Padding(4);return $c}
function Flow {$p=New-Object Windows.Forms.FlowLayoutPanel;$p.Dock='Fill';$p.FlowDirection='RightToLeft';$p.AutoScroll=$true;return $p}
function Grid {
 $g=New-Object Windows.Forms.DataGridView;$g.Dock='Fill';$g.ReadOnly=$true;$g.AllowUserToAddRows=$false;$g.AllowUserToDeleteRows=$false;$g.RowHeadersVisible=$false;$g.MultiSelect=$true;$g.SelectionMode='FullRowSelect';$g.BackgroundColor=[Drawing.Color]::White;$g.BorderStyle='FixedSingle';$g.AutoSizeColumnsMode='Fill';$g.RightToLeft='No';$g.EnableHeadersVisualStyles=$false;$g.ColumnHeadersDefaultCellStyle.BackColor=[Drawing.Color]::FromArgb(240,239,237);$g.ColumnHeadersHeightSizeMode='DisableResizing';$g.ColumnHeadersHeight=38;$g.RowTemplate.Height=36;$g.AlternatingRowsDefaultCellStyle.BackColor=[Drawing.Color]::FromArgb(249,248,247);$g.DefaultCellStyle.Font=New-Object Drawing.Font('Tahoma',10);$g.DefaultCellStyle.SelectionBackColor=[Drawing.Color]::FromArgb(229,242,252);$g.DefaultCellStyle.SelectionForeColor=[Drawing.Color]::FromArgb(44,44,43);return $g
}
function Column($g,[string]$name,[string]$caption,[int]$weight){$c=New-Object Windows.Forms.DataGridViewTextBoxColumn;$c.Name=$name;$c.HeaderText=$caption;$c.FillWeight=$weight;$c.MinimumWidth=64;$c.SortMode='Automatic';[void]$g.Columns.Add($c)}
$heading=Label 'فهرست سیاه — مدیریت ردیفی و اعمال بدون خروج';$heading.Font=New-Object Drawing.Font('Tahoma',17,[Drawing.FontStyle]::Bold);$layout.Controls.Add($heading,0,0)
$warning=Label 'قوانین پس از بستن پنجره و ری‌استارت باقی می‌مانند. حذف یک ردیف ابتدا فقط فهرست را تغییر می‌دهد؛ «اعمال تغییرات» یا «حذف انتخاب‌ها و اعمال» فایروال را به‌روزرسانی می‌کند.';$warning.BackColor=[Drawing.Color]::FromArgb(255,241,223);$layout.Controls.Add($warning,0,1)
$programRow=New-Object Windows.Forms.TableLayoutPanel;$programRow.Dock='Fill';$programRow.ColumnCount=2;[void]$programRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100)));[void]$programRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,180)))
$program=New-Object Windows.Forms.TextBox;$program.ReadOnly=$true;$program.Dock='Fill';$program.RightToLeft='No';$program.Margin=New-Object Windows.Forms.Padding(4,10,8,0);$program.AccessibleName='Selected Wow.exe path';$pick=Button 'انتخاب Wow.exe';$programRow.Controls.Add($program,0,0);$programRow.Controls.Add($pick,1,0);$layout.Controls.Add($programRow,0,2)
$captureRow=Flow;$captureRow.WrapContents=$false;$observe=Button 'رصد مقصدهای TCP';$stop=Button 'توقف رصد';$stop.Enabled=$false
$duration=New-Object Windows.Forms.ComboBox;$duration.DropDownStyle='DropDownList';$duration.Width=80;$duration.Margin=New-Object Windows.Forms.Padding(8,12,8,0);[void]$duration.Items.AddRange(@('60','120','300'));$duration.SelectedItem='120'
$note=New-Object Windows.Forms.Label;$note.Text='ثانیه؛ رصد فقط TCP است، نه محتوای بسته‌ها';$note.AutoSize=$true;$note.Margin=New-Object Windows.Forms.Padding(8,14,8,0)
$captureRow.Controls.AddRange(@($observe,$stop,$duration,$note));$layout.Controls.Add($captureRow,0,3)
$tabs=New-Object Windows.Forms.TabControl;$tabs.Dock='Fill';$tabs.Font=New-Object Drawing.Font('Tahoma',11)
$blackTab=New-Object Windows.Forms.TabPage;$blackTab.Text='لیست سیاه';$blackTab.Padding=New-Object Windows.Forms.Padding(6)
$obsTab=New-Object Windows.Forms.TabPage;$obsTab.Text='مقصدهای رصدشده';$obsTab.Padding=New-Object Windows.Forms.Padding(6)
[void]$tabs.TabPages.Add($blackTab);[void]$tabs.TabPages.Add($obsTab);$layout.Controls.Add($tabs,0,4)
$black=Grid;$black.AccessibleName='Blacklist table: IP, port, protocol, rule status and reason'
Column $black 'ip' 'IP' 24;Column $black 'port' 'Port' 9;Column $black 'protocol' 'Protocol' 10;Column $black 'state' 'وضعیت قانون' 22;Column $black 'reason' 'شرح / مبنای انتخاب' 35
$black.Columns['ip'].MinimumWidth=190;$black.Columns['state'].MinimumWidth=170;$black.Columns['reason'].DefaultCellStyle.Alignment='MiddleRight';$black.Columns['state'].DefaultCellStyle.Alignment='MiddleRight';$black.ShowCellToolTips=$true
$black.Columns['ip'].DefaultCellStyle.Font=New-Object Drawing.Font('Consolas',11);$black.Columns['port'].ValueType=[int]
$delcol=New-Object Windows.Forms.DataGridViewButtonColumn;$delcol.Name='remove';$delcol.HeaderText='حذف تکی';$delcol.Text='حذف';$delcol.UseColumnTextForButtonValue=$true;$delcol.FillWeight=10;$delcol.MinimumWidth=72;[void]$black.Columns.Add($delcol);$blackTab.Controls.Add($black)
$found=Grid;$found.AccessibleName='Observed TCP endpoints; choose rows then add';$found.MultiSelect=$true
$check=New-Object Windows.Forms.DataGridViewCheckBoxColumn;$check.Name='choose';$check.HeaderText='انتخاب';$check.FillWeight=10;$check.MinimumWidth=70;[void]$found.Columns.Add($check);$found.ReadOnly=$false
Column $found 'ip' 'IP' 30;Column $found 'port' 'Port' 10;Column $found 'protocol' 'Protocol' 12;Column $found 'samples' 'دفعات مشاهده' 20;Column $found 'fresh' 'فرایند تازه' 18
foreach($c in $found.Columns){if($c.Name -ne 'choose'){$c.ReadOnly=$true}};$obsTab.Controls.Add($found)
$details=Label 'برای جزئیات یک ردیف را انتخاب کن. وضعیت قانون، اثبات قطع واقعی بسته نیست.';$details.BackColor=[Drawing.Color]::FromArgb(249,248,247);$layout.Controls.Add($details,0,5)
$listActions=Flow;$listActions.WrapContents=$false
$delete=Button 'حذف انتخاب‌ها';$deleteApply=Button 'حذف انتخاب‌ها و اعمال';$addFound=Button 'افزودن رصدشده‌ها';$import=Button 'بارگذاری TXT';$manual=Button 'افزودن دستی';$listActions.Controls.AddRange(@($delete,$deleteApply,$addFound,$import,$manual));$layout.Controls.Add($listActions,0,6)
$consent=New-Object Windows.Forms.CheckBox;$consent.Text='با اعمال فهرست فعلی و باقی‌ماندن قواعد پس از بستن برنامه موافقم.';$consent.Dock='Fill';$consent.RightToLeft='Yes';$layout.Controls.Add($consent,0,7)
$actions=Flow;$actions.WrapContents=$true
$apply=Button 'اعمال تغییرات';$apply.BackColor=[Drawing.Color]::FromArgb(23,104,176);$apply.ForeColor=[Drawing.Color]::White
$applyClose=Button 'اعمال و بستن';$restore=Button 'بازگردانی همه';$restore.ForeColor=[Drawing.Color]::FromArgb(168,52,41);$save=Button 'فقط ذخیرهٔ لیست';$refresh=Button 'بررسی وضعیت';$exit=Button 'بستن'
$actions.Controls.AddRange(@($apply,$applyClose,$restore,$save,$refresh,$exit));$layout.Controls.Add($actions,0,8)
$status=Label 'در حال خواندن وضعیت…';$layout.Controls.Add($status,0,9)
$script:controls=@($pick,$observe,$duration,$tabs,$delete,$deleteApply,$addFound,$import,$manual,$consent,$apply,$applyClose,$restore,$save,$refresh,$exit)
function Enabled([bool]$v){foreach($c in $script:controls){$c.Enabled=$v};$stop.Enabled=(!$v -and $script:job -and $script:job.Action -eq 'observe')}
function Entries {return @($black.Rows|ForEach-Object {$_.Tag})}
function Reason($e){if((Ui-Key $e) -eq '37.244.29.11|3724|TCP'){return 'هشدار: قبلاً ورود را مختل کرد'};if((Ui-Key $e) -in $script:seedKeys){return 'تست گروه ده‌تایی: کاربر مشکل ندید؛ نقش سرویس نامشخص'};return 'افزوده‌شده به فهرست؛ نقش سرویس تأیید نشده'}
function State($e){$key=Ui-Key $e;if(!$script:actual.ContainsKey($key)){return 'هنوز بررسی نشده'};$a=$script:actual[$key];if($a.persistent_verified -and $a.active_verified){return 'قانون تأییدشده در دو store'};if(!$a.persistent_present -and !$a.active_present){return 'قانونی برای این ردیف نیست'};return 'ناقص / ناسازگار؛ بررسی لازم'}
function ShowRows($entries,[bool]$dirty){$script:loading=$true;$black.Rows.Clear();foreach($e in @(Ui-Parse (Ui-Text $entries))){$i=$black.Rows.Add($e.ip,[int]$e.port,$e.protocol,(State $e),(Reason $e),'حذف');$black.Rows[$i].Tag=$e};$script:loading=$false;$script:dirty=$dirty;$consent.Checked=$false;$blackTab.Text='لیست سیاه ('+$black.Rows.Count+')'+$(if($dirty){' *'}else{''})}
function DetailText($e){
 $key=Ui-Key $e;$specific='وضعیت ردیفی هنوز بررسی نشده'
 if($script:actual.ContainsKey($key)){$a=$script:actual[$key];$specific='PersistentStore: present='+[string]$a.persistent_present+', verified='+[string]$a.persistent_verified+' | ActiveStore: present='+[string]$a.active_present+', verified='+[string]$a.active_verified}
 return $e.ip+':'+$e.port+' / '+$e.protocol+' — '+(Reason $e)+[Environment]::NewLine+$specific+[Environment]::NewLine+'فقط خروجی Wow.exe انتخابی | آخرین بررسی: '+$script:actualAt+' | نقش سرویس و اثر پینگ تأیید نشده است.'
}
function ReadActual($actual){$script:actual=@{};$script:actualAt=[DateTime]::Now.ToString('HH:mm:ss');foreach($e in @($actual.entries)){if($e){$script:actual[(Ui-Key $e)]=$e}};foreach($row in $black.Rows){$row.Cells['state'].Value=State $row.Tag};if($black.SelectedRows.Count){$details.Text=DetailText $black.SelectedRows[0].Tag}}
function Payload {return @{program=$program.Text;text=(Ui-Text (Entries));program_reselected=$script:reselected;persistent_consent=$consent.Checked}}
function BeginOp([string]$action,$payload,[bool]$closeOnSuccess=$false){
 if($script:job){return}
 $id=[Guid]::NewGuid().ToString('N');$request=Join-Path $private ('job-'+$id+'.request.json');$result=Join-Path $private ('job-'+$id+'.result.json')
 [IO.File]::WriteAllText($request,(@{action=$action;payload=$payload}|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
 $psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=Join-Path $root 'runtime\python.exe';$psi.Arguments='-I "'+(Join-Path $root 'app\backend.py')+'" "'+$request+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=$root
 try{$process=[Diagnostics.Process]::Start($psi)}catch{$status.Text='اجرای عملیات شروع نشد؛ موفقیت فرض نکن.';return}
 $script:job=@{Action=$action;Process=$process;Result=$result;Stop=(Join-Path $private ('job-'+$id+'.stop'));Ready=(Join-Path $private ('job-'+$id+'.ready'));ReadySeen=$false;CloseOnSuccess=$closeOnSuccess};Enabled $false
 $status.Text=if($action -eq 'observe'){'در حال آماده‌سازی رصد؛ منتظر پیام آمادگی بمان.'}else{'در حال اجرا؛ برای تأیید نتیجه منتظر بمان.'};$timer.Start()
}
function ApplyList([bool]$closeWindow){
 if(!$consent.Checked){$status.Text='ابتدا رضایت اعمال پایدارِ فهرست فعلی را تیک بزن.';return}
 $p=Payload
 if(!$p.text){if([Windows.Forms.MessageBox]::Show('لیست خالی است؛ همهٔ قواعد همین نصب حذف و لیست خالی ذخیره شود؟','بازگردانی فهرست خالی','YesNo','Warning') -ne 'Yes'){return};$p.empty_restore_consent=$true}
 if((Entries | Where-Object {(Ui-Key $_) -eq '37.244.29.11|3724|TCP'})){
  if([Windows.Forms.MessageBox]::Show('این مقصد قبلاً ورود را مختل کرد. با این حال اعمال شود؟','هشدار مقصد ورود','YesNo','Warning') -ne 'Yes'){return};$p.critical_consent=$true
 }
 BeginOp 'apply' $p $closeWindow
}
$timer=New-Object Windows.Forms.Timer;$timer.Interval=250
$timer.Add_Tick({
 if(!$script:job){$timer.Stop();return};$j=$script:job
 if($j.Action -eq 'observe' -and !$j.ReadySeen -and (Test-Path -LiteralPath $j.Ready)){$j.ReadySeen=$true;$status.Text='رصد آماده است؛ بازی را عادی باز کن. محدودیت‌های فعلی تغییر نمی‌کنند.'}
 if(!$j.Process.HasExited){return};$timer.Stop();$script:job=$null;Enabled $true;$stop.Enabled=$false
 try{
  $r=[IO.File]::ReadAllText($j.Result)|ConvertFrom-Json
  if(!$r.ok){$script:actual=@{};foreach($row in $black.Rows){$row.Cells['state'].Value='نتیجه نامشخص؛ بررسی / بازگردانی'};$status.Text='تأیید نشد: '+$r.error+'؛ ممکن است قوانین جزئی مانده باشند. از بازگردانی استفاده کن.';return}
  if($j.Action -eq 'observe'){
   $found.Rows.Clear();$script:observed=@($r.observation.endpoints)
   foreach($e in $script:observed){$i=$found.Rows.Add($false,$e.ip,[int]$e.port,'TCP',[int]$e.samples,$(if($e.fresh_process_seen){'بله'}else{'خیر'}));$found.Rows[$i].Tag=$e}
   $obsTab.Text='مقصدهای رصدشده ('+$found.Rows.Count+')';$tabs.SelectedTab=$obsTab;$status.Text='رصد پایان یافت؛ خطای خواندن: '+$r.observation.query_errors+'. موارد دلخواه را انتخاب و به لیست اضافه کن؛ هنوز مسدود نشده‌اند.'
   if($script:closeAfterObserve){$form.Close()};return
  }
  if($r.config){$program.Text=[string]$r.config.program;ShowRows @(Ui-Parse ([string]$r.config.text)) $false;$script:reselected=$false}
  if($j.Action -eq 'apply'){
   $rows=@(Entries);$verified=@(foreach($e in $rows){[pscustomobject]@{ip=$e.ip;port=$e.port;protocol=$e.protocol;persistent_present=$true;active_present=$true;persistent_verified=$true;active_verified=$true}});ReadActual @{entries=$verified}
   $status.Text='تغییرات اعمال و در دو store تأیید شد؛ '+$rows.Count+' قانون. پنجره باز است؛ می‌توانی ردیف بعدی را حذف و دوباره اعمال کنی.'
  }elseif($j.Action -eq 'restore'){
   $rows=@(foreach($e in (Entries)){[pscustomobject]@{ip=$e.ip;port=$e.port;protocol=$e.protocol;persistent_present=$false;active_present=$false;persistent_verified=$false;active_verified=$false}});ReadActual @{entries=$rows};$status.Text='تمام قواعد همین نصب حذف شدند؛ لیست برای استفادهٔ بعدی نگه داشته شد. پنجره باز است.'
  }elseif($j.Action -eq 'save'){$status.Text='فهرست ذخیره شد؛ فایروال تغییر نکرد. وضعیت هر ردیف مربوط به آخرین بررسی است.'
  }else{ReadActual $r.actual;$status.Text='بررسی '+$script:actualAt+' | پایدار: '+$r.actual.persistent_count+' | فعال: '+$r.actual.active_count+' | * یعنی تغییر ذخیره‌نشده؛ وضعیت قانون، اثبات افت بسته نیست.'}
  if($j.CloseOnSuccess){$form.Close()}
 }catch{$status.Text='نتیجه خوانده نشد؛ موفقیت فرض نکن. Restore.cmd در همین پوشه موجود است.'}
})
$script:seedKeys=@((ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $root 'app/defaults.json'))))|ForEach-Object {Ui-Key $_})
function RemoveKeys($keys,[bool]$applyNow){
 if(!$keys.Count){$status.Text='اول یک یا چند ردیف لیست سیاه را انتخاب کن.';return}
 $remaining=@(Ui-Without (Entries) $keys)
 if($applyNow){
  if([Windows.Forms.MessageBox]::Show('این '+$keys.Count+' ردیف حذف و فهرست باقی‌مانده ('+$remaining.Count+' مورد) همین حالا به‌صورت پایدار اعمال شود؟ پنجره بسته نمی‌شود.','حذف و اعمال','YesNo','Warning') -ne 'Yes'){return}
 }
 ShowRows $remaining $true;$tabs.SelectedTab=$blackTab
 if($applyNow){$consent.Checked=$true;ApplyList $false}else{$status.Text='ردیف از فهرست حذف شد؛ فایروال هنوز تغییر نکرده. برای اجرا «اعمال تغییرات» را بزن.'}
}
$black.Add_CellContentClick({param($sender,$e) if($e.RowIndex -ge 0 -and $e.ColumnIndex -eq $black.Columns['remove'].Index){RemoveKeys @((Ui-Key $black.Rows[$e.RowIndex].Tag)) $false}})
$black.Add_SelectionChanged({if(!$script:loading -and $black.SelectedRows.Count){$e=$black.SelectedRows[0].Tag;if($e){$details.Text=DetailText $e}}})
$found.Add_CurrentCellDirtyStateChanged({if($found.IsCurrentCellDirty){[void]$found.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit)}})
$delete.Add_Click({if($tabs.SelectedTab -ne $blackTab){$tabs.SelectedTab=$blackTab;return};RemoveKeys @($black.SelectedRows|ForEach-Object {Ui-Key $_.Tag}) $false})
$deleteApply.Add_Click({if($tabs.SelectedTab -ne $blackTab){$tabs.SelectedTab=$blackTab;return};RemoveKeys @($black.SelectedRows|ForEach-Object {Ui-Key $_.Tag}) $true})
$black.Add_KeyDown({param($sender,$e) if($e.KeyCode -eq 'Delete'){RemoveKeys @($black.SelectedRows|ForEach-Object {Ui-Key $_.Tag}) $false;$e.Handled=$true}})
$pick.Add_Click({$d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='World of Warcraft (Wow.exe)|Wow.exe';if($d.ShowDialog() -eq 'OK'){$program.Text=$d.FileName;$script:reselected=$true;$consent.Checked=$false;$script:actual=@{};foreach($row in $black.Rows){$row.Cells['state'].Value='مسیر عوض شد؛ بررسی لازم'}};$d.Dispose()})
$import.Add_Click({$d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='Text list (*.txt)|*.txt';if($d.ShowDialog() -eq 'OK'){try{if((Get-Item -LiteralPath $d.FileName).Length -gt 30000){throw 'too_large'};$entries=@(Ui-Parse ([IO.File]::ReadAllText($d.FileName)));ShowRows $entries $true;$status.Text='فایل در جدول بارگذاری شد؛ هنوز اعمال نشده است.'}catch{$status.Text='لیست معتبر نیست؛ هر خط IP:Port TCP یا UDP، حداکثر ۱۰۰ مورد. فهرست قبلی تغییر نکرد.'}};$d.Dispose()})
$manual.Add_Click({
 $d=New-Object Windows.Forms.Form;$d.Text='افزودن مقصد';$d.ClientSize=New-Object Drawing.Size(520,160);$d.StartPosition='CenterParent';$d.Font=$form.Font
 $l=New-Object Windows.Forms.Label;$l.Text='IP:Port TCP یا UDP — نمونه: 1.1.1.1:443 TCP';$l.SetBounds(16,16,488,28)
 $input=New-Object Windows.Forms.TextBox;$input.SetBounds(16,50,488,30);$input.RightToLeft='No';$input.Font=New-Object Drawing.Font('Consolas',11)
 $ok=Button 'افزودن';$ok.SetBounds(360,98,144,44);$ok.DialogResult='OK';$d.Controls.AddRange(@($l,$input,$ok));$d.AcceptButton=$ok
 if($d.ShowDialog($form) -eq 'OK'){try{$entries=@(Ui-Parse ((Ui-Text (Entries))+[Environment]::NewLine+$input.Text));ShowRows $entries $true;$status.Text='مقصد به لیست اضافه شد؛ هنوز اعمال نشده است.'}catch{$status.Text='فرمت مقصد معتبر نیست؛ لیست تغییر نکرد.'}};$d.Dispose()
})
$addFound.Add_Click({$lines=New-Object Collections.Generic.List[string];$lines.Add((Ui-Text (Entries)));foreach($row in $found.Rows){if($row.Cells['choose'].Value -eq $true){$lines.Add((Ui-Text @($row.Tag)))}};try{ShowRows @(Ui-Parse ($lines -join [Environment]::NewLine)) $true;$tabs.SelectedTab=$blackTab;$status.Text='انتخاب‌ها فقط به لیست اضافه شدند؛ برای انسداد باید اعمال کنی.'}catch{$status.Text='حداکثر ۱۰۰ مقصد مجاز است؛ لیست تغییر نکرد.'}})
$observe.Add_Click({if(!$program.Text){$status.Text='ابتدا Wow.exe را انتخاب کن.';return};BeginOp 'observe' @{program=$program.Text;seconds=[int]$duration.SelectedItem}})
$stop.Add_Click({if($script:job -and $script:job.Action -eq 'observe'){[IO.File]::WriteAllText($script:job.Stop,'stop');$stop.Enabled=$false}})
$save.Add_Click({BeginOp 'save' (Payload)})
$refresh.Add_Click({BeginOp 'status' (Payload)})
$apply.Add_Click({ApplyList $false});$applyClose.Add_Click({ApplyList $true})
$restore.Add_Click({if([Windows.Forms.MessageBox]::Show('تمام قواعد همین نصب حذف شوند؟ لیست می‌ماند و پنجره بسته نمی‌شود.','بازگردانی','YesNo','Warning') -eq 'Yes'){BeginOp 'restore' @{}}})
$exit.Add_Click({$form.Close()})
$form.Add_FormClosing({param($sender,$e)
 if($script:job){$e.Cancel=$true;if($script:job.Action -eq 'observe'){$script:closeAfterObserve=$true;[IO.File]::WriteAllText($script:job.Stop,'stop');$status.Text='پس از پایان رصد بسته می‌شود؛ قواعد موجود باقی می‌مانند.'}else{$status.Text='تا پایان عملیات منتظر بمان؛ نتیجه هنوز تأیید نشده است.'};return}
 if($script:dirty){if([Windows.Forms.MessageBox]::Show('تغییرات فهرست ذخیره/اعمال نشده‌اند. با این حال پنجره بسته شود؟ قواعد فعلی باقی می‌مانند.','تغییرات ذخیره‌نشده','YesNo','Warning') -ne 'Yes'){$e.Cancel=$true}}
})
$form.Add_Shown({BeginOp 'load' @{}})
[void]$form.ShowDialog();$timer.Dispose();$form.Dispose()
