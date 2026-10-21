$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$root=$env:WOW_BL_ROOT;$private=Join-Path $root 'private-state';[void][IO.Directory]::CreateDirectory($private)
$script:job=$null;$script:closeAfterObserve=$false;$script:reselected=$false;$script:observed=@()
$form=New-Object Windows.Forms.Form
$form.Text='WoW Blacklist · 0.1.0';$form.ClientSize=New-Object Drawing.Size(1040,900);$form.MinimumSize=New-Object Drawing.Size(920,760);$form.StartPosition='CenterScreen';$form.BackColor=[Drawing.Color]::White;$form.Font=New-Object Drawing.Font('Tahoma',11)
$layout=New-Object Windows.Forms.TableLayoutPanel;$layout.Dock='Fill';$layout.Padding=New-Object Windows.Forms.Padding(20);$layout.ColumnCount=1;$layout.RowCount=10
foreach($height in @(48,66,48,50,34,-1,46,50,50,58)){
 if($height -eq -1){$style=New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)}else{$style=New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$height)}
 [void]$layout.RowStyles.Add($style)
}
$form.Controls.Add($layout)
function Label([string]$text){$c=New-Object Windows.Forms.Label;$c.Text=$text;$c.Dock='Fill';$c.TextAlign='MiddleRight';$c.RightToLeft='Yes';return $c}
function Button([string]$text){$c=New-Object Windows.Forms.Button;$c.Text=$text;$c.AutoSize=$true;$c.MinimumSize=New-Object Drawing.Size(120,40);$c.FlatStyle='Flat';return $c}
$heading=Label 'فهرست سیاه بازی — پایدار تا بازگردانی دستی';$heading.Font=New-Object Drawing.Font('Tahoma',17,[Drawing.FontStyle]::Bold);$layout.Controls.Add($heading,0,0)
$warning=Label 'بستن پنجره یا ری‌استارت، انسداد را برنمی‌دارد. فقط IP/پورت‌های فهرست برای Wow.exe انتخابی محدود می‌شوند؛ قوانین دیگر دست‌نخورده‌اند. پوشه را برای بازگردانی نگه دار.';$warning.BackColor=[Drawing.Color]::FromArgb(255,241,223);$layout.Controls.Add($warning,0,1)
$programRow=New-Object Windows.Forms.TableLayoutPanel;$programRow.Dock='Fill';$programRow.ColumnCount=2;[void]$programRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100)));[void]$programRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,170)))
$program=New-Object Windows.Forms.TextBox;$program.ReadOnly=$true;$program.Dock='Fill';$program.Margin=New-Object Windows.Forms.Padding(0,8,8,0);$program.AccessibleName='Selected Wow.exe path';$pick=Button 'انتخاب Wow.exe';$programRow.Controls.Add($program,0,0);$programRow.Controls.Add($pick,1,0);$layout.Controls.Add($programRow,0,2)
$captureRow=New-Object Windows.Forms.FlowLayoutPanel;$captureRow.Dock='Fill';$captureRow.FlowDirection='RightToLeft';$captureRow.WrapContents=$false
$observe=Button 'رصد مقصدهای TCP';$stop=Button 'توقف رصد';$stop.Enabled=$false
$duration=New-Object Windows.Forms.ComboBox;$duration.DropDownStyle='DropDownList';$duration.Width=85;[void]$duration.Items.AddRange(@('60','120','300'));$duration.SelectedItem='120';$duration.AccessibleName='Observe duration in seconds'
$captureNote=New-Object Windows.Forms.Label;$captureNote.Text='ثانیه؛ فقط فهرست مقصدها، نه محتوای بسته‌ها';$captureNote.AutoSize=$true;$captureNote.Margin=New-Object Windows.Forms.Padding(10,10,10,0)
$captureRow.Controls.AddRange(@($observe,$stop,$duration,$captureNote));$layout.Controls.Add($captureRow,0,3)
$heads=New-Object Windows.Forms.TableLayoutPanel;$heads.Dock='Fill';$heads.ColumnCount=2;[void]$heads.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,55)));[void]$heads.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,45)));$heads.Controls.Add((Label 'لیست سیاه قابل‌ویرایش؛ هر خط: IP:Port TCP یا UDP'),0,0);$heads.Controls.Add((Label 'مقصدهای مشاهده‌شده؛ خودت موارد دلخواه را تیک بزن'),1,0);$layout.Controls.Add($heads,0,4)
$lists=New-Object Windows.Forms.TableLayoutPanel;$lists.Dock='Fill';$lists.ColumnCount=2;[void]$lists.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,55)));[void]$lists.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,45)))
$text=New-Object Windows.Forms.TextBox;$text.Multiline=$true;$text.AcceptsReturn=$true;$text.AcceptsTab=$false;$text.ScrollBars='Both';$text.WordWrap=$false;$text.Dock='Fill';$text.Font=New-Object Drawing.Font('Consolas',11);$text.AccessibleName='Editable blacklist'
$found=New-Object Windows.Forms.CheckedListBox;$found.Dock='Fill';$found.CheckOnClick=$true;$found.HorizontalScrollbar=$true;$found.Font=New-Object Drawing.Font('Consolas',10.5);$found.AccessibleName='Observed destinations available to add';$lists.Controls.Add($text,0,0);$lists.Controls.Add($found,1,0);$layout.Controls.Add($lists,0,5)
$listActions=New-Object Windows.Forms.FlowLayoutPanel;$listActions.Dock='Fill';$listActions.FlowDirection='RightToLeft';$listActions.WrapContents=$false
$add=Button 'افزودن انتخاب‌ها به لیست';$import=Button 'بارگذاری TXT';$listActions.Controls.AddRange(@($add,$import));$layout.Controls.Add($listActions,0,6)
$consent=New-Object Windows.Forms.CheckBox;$consent.Text='می‌دانم این قوانین پس از بستن برنامه و ری‌استارت باقی می‌مانند؛ با اعمال همین لیست موافقم.';$consent.Dock='Fill';$consent.RightToLeft='Yes';$consent.Checked=$false;$layout.Controls.Add($consent,0,7)
$actions=New-Object Windows.Forms.FlowLayoutPanel;$actions.Dock='Fill';$actions.FlowDirection='RightToLeft';$actions.WrapContents=$false
$apply=Button 'اعمال و بستن';$apply.BackColor=[Drawing.Color]::FromArgb(23,104,176);$apply.ForeColor=[Drawing.Color]::White
$restore=Button 'بازگردانی و بستن';$restore.ForeColor=[Drawing.Color]::FromArgb(168,52,41)
$save=Button 'فقط ذخیرهٔ لیست';$refresh=Button 'بررسی وضعیت';$exit=Button 'بستن';$actions.Controls.AddRange(@($apply,$restore,$save,$refresh,$exit));$layout.Controls.Add($actions,0,8)
$status=Label 'در حال خواندن وضعیت…';$status.Font=New-Object Drawing.Font('Tahoma',10);$layout.Controls.Add($status,0,9)
$script:controls=@($pick,$observe,$duration,$add,$import,$consent,$apply,$restore,$save,$refresh,$text,$exit)
function Enabled([bool]$value){foreach($c in $script:controls){$c.Enabled=$value};$stop.Enabled=(!$value -and $script:job -and $script:job.Action -eq 'observe')}
function Payload {return @{program=$program.Text;text=$text.Text;program_reselected=$script:reselected;persistent_consent=$consent.Checked}}
function BeginOp([string]$action,$payload){
 if($script:job){return}
 $id=[Guid]::NewGuid().ToString('N');$request=Join-Path $private ('job-'+$id+'.request.json');$result=Join-Path $private ('job-'+$id+'.result.json')
 [IO.File]::WriteAllText($request,(@{action=$action;payload=$payload}|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
 $psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=Join-Path $root 'runtime\python.exe';$psi.Arguments='-I "'+(Join-Path $root 'app\backend.py')+'" "'+$request+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=$root
 try{$process=[Diagnostics.Process]::Start($psi)}catch{$status.Text='اجرای عملیات شروع نشد؛ در صورت شک از Restore.cmd استفاده کن.';return}
 $script:job=@{Action=$action;Process=$process;Result=$result;Stop=(Join-Path $private ('job-'+$id+'.stop'));Ready=(Join-Path $private ('job-'+$id+'.ready'));ReadySeen=$false};Enabled $false
 $status.Text=if($action -eq 'observe'){'در حال آماده‌سازی رصد؛ پس از پیام آمادگی بازی را اجرا کن.'}else{'عملیات در حال اجراست؛ پنجره را نبند. اعمال ناموفق ممکن است قوانین جزئی باقی بگذارد.'}
 $timer.Start()
}
$timer=New-Object Windows.Forms.Timer;$timer.Interval=250
$timer.Add_Tick({
 if(!$script:job){$timer.Stop();return}
 $j=$script:job
 if($j.Action -eq 'observe' -and !$j.ReadySeen -and (Test-Path -LiteralPath $j.Ready)){$j.ReadySeen=$true;$status.Text='رصد آماده است؛ بازی را عادی اجرا کن. قوانین موجود تغییر نمی‌کنند؛ اگر انسداد فعال باشد بعضی مقصدها ممکن است دیده نشوند.'}
 if(!$j.Process.HasExited){return}
 $timer.Stop();$script:job=$null;Enabled $true;$stop.Enabled=$false
 try{
  $r=[IO.File]::ReadAllText($j.Result)|ConvertFrom-Json
  if(!$r.ok){$status.Text='عملیات تأیید نشد: '+$r.error+' — ممکن است قوانین باقی مانده باشند؛ از بازگردانی استفاده کن.';$status.ForeColor=[Drawing.Color]::FromArgb(168,52,41);return}
  $status.ForeColor=[Drawing.Color]::FromArgb(44,44,43)
  if($j.Action -eq 'observe'){
   $found.Items.Clear();$script:observed=@($r.observation.endpoints)
   foreach($e in $script:observed){$address=if($e.ip.Contains(':')){'['+$e.ip+']'}else{$e.ip};[void]$found.Items.Add(($address+':'+$e.port+' TCP'),$false)}
   $status.Text='رصد پایان یافت؛ '+$script:observed.Count+' مقصد TCP؛ خطای خواندن: '+$r.observation.query_errors+'. هیچ موردی خودکار مسدود نشد. گزارش در output است؛ UDP و محتوای بسته‌ها ضبط نشده‌اند.'
   if($script:closeAfterObserve){$form.Close()};return
  }
  if($r.config){$program.Text=[string]$r.config.program;$text.Text=[string]$r.config.text;$script:reselected=$false}
  if($j.Action -in @('apply','restore')){$form.Close();return}
  if($j.Action -eq 'save'){$status.Text='لیست فقط ذخیره شد؛ وضعیت فایروال تغییر نکرد.'}else{$status.Text='وضعیت: '+$r.config.phase+' | قوانین پایدار خود ابزار: '+$r.actual.persistent_count+' | فعال: '+$r.actual.active_count+'؛ شمارش، اثبات قطع بسته نیست.'}
 }catch{$status.Text='نتیجه خوانده نشد. موفقیت فرض نکن؛ تنظیمات را نگه دار و از Restore.cmd استفاده کن.'}
})
$text.Add_TextChanged({$consent.Checked=$false})
$pick.Add_Click({$dlg=New-Object Windows.Forms.OpenFileDialog;$dlg.Filter='World of Warcraft (Wow.exe)|Wow.exe';$dlg.Title='همان Wow.exe بازی را انتخاب کن';if($dlg.ShowDialog() -eq 'OK'){$program.Text=$dlg.FileName;$script:reselected=$true;$consent.Checked=$false};$dlg.Dispose()})
$import.Add_Click({$dlg=New-Object Windows.Forms.OpenFileDialog;$dlg.Filter='Text list (*.txt)|*.txt';if($dlg.ShowDialog() -eq 'OK'){if((Get-Item -LiteralPath $dlg.FileName).Length -gt 30000){$status.Text='فایل بزرگ‌تر از حد مجاز است.'}else{$text.Text=[IO.File]::ReadAllText($dlg.FileName);$consent.Checked=$false}};$dlg.Dispose()})
$add.Add_Click({
 $lines=New-Object Collections.Generic.List[string]
 foreach($line in $text.Lines){if($line.Trim()){$lines.Add($line.Trim())}}
 foreach($index in $found.CheckedIndices){$line=[string]$found.Items[[int]$index];if(!$lines.Contains($line)){$lines.Add($line)}}
 $text.Text=($lines -join [Environment]::NewLine);$consent.Checked=$false;$status.Text='موارد انتخابی فقط به لیست اضافه شدند؛ برای مسدودسازی باید جدا اعمال کنی.'
})
$observe.Add_Click({if(!$program.Text){$status.Text='اول Wow.exe را انتخاب کن.';return};BeginOp 'observe' @{program=$program.Text;seconds=[int]$duration.SelectedItem}})
$stop.Add_Click({if($script:job -and $script:job.Action -eq 'observe'){[IO.File]::WriteAllText($script:job.Stop,'stop');$stop.Enabled=$false;$status.Text='توقف رصد درخواست شد؛ منتظر نتیجه بمان.'}})
$save.Add_Click({BeginOp 'save' (Payload)})
$refresh.Add_Click({if([Windows.Forms.MessageBox]::Show('وضعیت دوباره خوانده و متن ذخیره‌شده بارگذاری می‌شود. تغییرات ذخیره‌نشده کنار گذاشته شوند؟','WoW Blacklist','YesNo','Question') -eq 'Yes'){BeginOp 'load' @{}}})
$apply.Add_Click({
 if(!$consent.Checked){$status.Text='برای اعمال پایدار باید رضایت پایین لیست را تیک بزنی.';return}
 $p=Payload
 if($text.Text -match '(?m)^\s*37\.244\.29\.11:3724\s+TCP\s*(#.*)?$'){
  if([Windows.Forms.MessageBox]::Show('این مقصد قبلاً ورود را مختل کرد. با این حال همین لیست اعمال شود؟','هشدار مقصد ورود','YesNo','Warning') -ne 'Yes'){return};$p.critical_consent=$true
 }
 BeginOp 'apply' $p
})
$restore.Add_Click({if([Windows.Forms.MessageBox]::Show('تمام قوانین همین نصب ابزار برداشته شوند؟ لیست ذخیره‌شده نگه داشته می‌شود؛ سایر قوانین تغییر نمی‌کنند.','بازگردانی','YesNo','Question') -eq 'Yes'){BeginOp 'restore' @{}}})
$exit.Add_Click({$form.Close()})
$form.Add_FormClosing({param($sender,$e)
 if($script:job){$e.Cancel=$true;if($script:job.Action -eq 'observe'){$script:closeAfterObserve=$true;[IO.File]::WriteAllText($script:job.Stop,'stop');$status.Text='پس از پایان رصد پنجره بسته می‌شود؛ قوانین موجود باقی می‌مانند.'}else{$status.Text='تا پایان عملیات فایروال/ذخیره منتظر بمان؛ نتیجه هنوز تأیید نشده است.'}}
})
$form.Add_Shown({BeginOp 'load' @{}})
[void]$form.ShowDialog();$timer.Dispose();$form.Dispose()
