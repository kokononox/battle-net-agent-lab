# Windows PowerShell 5.1 / WinForms desktop. Native engine and recovery gates unchanged.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$root=Split-Path $PSScriptRoot -Parent
$mutex=New-Object Threading.Mutex($false,'Local\UnifiedFWDesktop090')
$held=$false;try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
if(-not $held){[void][Windows.Forms.MessageBox]::Show('Unified Firewall is already open.');exit 1}
$script:state=$null;$script:job=$null;$script:closing=$false;$script:checks=@{};$script:rendering=$false;$script:legacyAck=''
$script:wrapLabels=New-Object 'System.Collections.Generic.List[System.Windows.Forms.Label]'
$ink=[Drawing.ColorTranslator]::FromHtml('#14243A');$blue=[Drawing.ColorTranslator]::FromHtml('#2366A2')
$form=New-Object Windows.Forms.Form
$form.Text='Unified Firewall Desktop 0.9.4 RC / LAB'
$form.Size=New-Object Drawing.Size(1240,860);$form.MinimumSize=New-Object Drawing.Size(980,720)
$form.StartPosition='CenterScreen';$form.Font=New-Object Drawing.Font('Tahoma',10)
$form.AutoScaleMode='Dpi';$form.RightToLeft='Yes';$form.RightToLeftLayout=$true
$form.BackColor=[Drawing.ColorTranslator]::FromHtml('#F6F8FB');$form.ForeColor=$ink
function Stack($Parent,[int]$Rows){
 $v=New-Object Windows.Forms.TableLayoutPanel;$v.Dock='Fill';$v.ColumnCount=1;$v.RowCount=$Rows;$v.Padding=New-Object Windows.Forms.Padding(8);$v.AutoScroll=$true
 for($i=0;$i -lt $Rows;$i++){[void]$v.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::AutoSize)))}
 $v.RowStyles[$Rows-1].SizeType='Percent';$v.RowStyles[$Rows-1].Height=100;$Parent.Controls.Add($v);return $v
}
function Label([string]$Text){$v=New-Object Windows.Forms.Label;$v.Text=$Text;$v.AutoSize=$true;$v.MaximumSize=New-Object Drawing.Size(1100,0);$v.Margin=New-Object Windows.Forms.Padding(6);$script:wrapLabels.Add($v);return $v}
function Button([string]$Text){$v=New-Object Windows.Forms.Button;$v.Text=$Text;$v.AutoSize=$true;$v.MinimumSize=New-Object Drawing.Size(125,36);$v.FlatStyle='Flat';$v.FlatAppearance.BorderColor=[Drawing.ColorTranslator]::FromHtml('#DCE3EB');$v.BackColor=[Drawing.Color]::White;$v.Margin=New-Object Windows.Forms.Padding(4);return $v}
function Flow{$v=New-Object Windows.Forms.FlowLayoutPanel;$v.Dock='Fill';$v.AutoSize=$true;$v.WrapContents=$true;$v.FlowDirection='RightToLeft';return $v}
function TextBox([int]$Width){$v=New-Object Windows.Forms.TextBox;$v.Width=$Width;$v.RightToLeft='No';$v.Margin=New-Object Windows.Forms.Padding(6,8,6,6);return $v}
function Grid($Columns){
 $v=New-Object Windows.Forms.DataGridView;$v.Dock='Fill';$v.BackgroundColor=[Drawing.Color]::White;$v.BorderStyle='None';$v.AllowUserToAddRows=$false;$v.AllowUserToDeleteRows=$false;$v.RowHeadersVisible=$false;$v.SelectionMode='FullRowSelect';$v.MultiSelect=$true;$v.AutoSizeColumnsMode='Fill';$v.AutoSizeRowsMode='AllCells';$v.EnableHeadersVisualStyles=$false
 $v.ColumnHeadersDefaultCellStyle.BackColor=[Drawing.ColorTranslator]::FromHtml('#EAF0F7');$v.ColumnHeadersDefaultCellStyle.ForeColor=$ink;$v.ColumnHeadersHeightSizeMode='AutoSize'
 $v.DefaultCellStyle.SelectionBackColor=[Drawing.ColorTranslator]::FromHtml('#DCEBFA');$v.DefaultCellStyle.SelectionForeColor=$ink;$v.AlternatingRowsDefaultCellStyle.BackColor=[Drawing.ColorTranslator]::FromHtml('#F7F9FC')
 foreach($c in $Columns){$col=New-Object Windows.Forms.DataGridViewTextBoxColumn;$col.Name=$c[0];$col.HeaderText=$c[1];$col.ReadOnly=$true;$col.SortMode='Automatic';[void]$v.Columns.Add($col)}
 return $v
}
function Tab([string]$Text){$v=New-Object Windows.Forms.TabPage;$v.Text=$Text;$v.BackColor=[Drawing.Color]::White;[void]$tabs.TabPages.Add($v);return $v}
$main=New-Object Windows.Forms.TableLayoutPanel;$main.Dock='Fill';$main.ColumnCount=1;$main.RowCount=5;$main.Padding=New-Object Windows.Forms.Padding(12)
foreach($size in @('AutoSize','AutoSize','Percent','AutoSize','AutoSize')){[void]$main.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::$size)))};$main.RowStyles[2].Height=100;$form.Controls.Add($main)
$header=Flow;$title=Label 'Unified Firewall  /  میزکار یکپارچه';$title.Font=New-Object Drawing.Font('Tahoma',16,[Drawing.FontStyle]::Bold);$header.Controls.Add($title)
$edition=Label '0.9.4 RC • Windows x64 • LAB';$edition.ForeColor=$blue;$header.Controls.Add($edition);$main.Controls.Add($header,0,0)
$notice=Label 'بلک‌لیست چند EXE + پیش‌نمایش وایت‌لیست | وایت‌لیست سراسری فعال نمی‌شود؛ Kill-switch پیاده نشده است. این نسخه تأیید حفاظت جامع ندارد.'
$notice.BackColor=[Drawing.ColorTranslator]::FromHtml('#FFF4D8');$notice.ForeColor=[Drawing.ColorTranslator]::FromHtml('#725010');$notice.Padding=New-Object Windows.Forms.Padding(8);$notice.Dock='Fill';$main.Controls.Add($notice,0,1)
$tabs=New-Object Windows.Forms.TabControl;$tabs.Dock='Fill';$main.Controls.Add($tabs,0,2)
$programTab=Tab '۱  برنامه‌ها و رصد';$blackTab=Tab '۲  بلک‌لیست';$policyTab=Tab '۳  وایت‌لیست و سیاست';$detailTab=Tab '۴  جزئیات و گزارش'
$p=Stack $programTab 4
$p.Controls.Add((Label 'تیک‌ها برای رصد / افزودن بلک‌لیست / حذف تنظیمات هستند؛ انتخاب ردیف یا تیک، کلید فعال‌سازی حفاظت نیست.'),0,0)
$bar=Flow;$filter=TextBox 270;$bar.Controls.Add((Label 'جست‌وجوی نام یا مسیر'));$bar.Controls.Add($filter)
$selectVisible=Button 'تیک همهٔ نمایان';$clearVisible=Button 'پاک‌کردن تیک نمایان';$clearAll=Button 'پاک‌کردن همهٔ تیک‌ها'
foreach($v in @($selectVisible,$clearVisible,$clearAll)){$bar.Controls.Add($v)};$p.Controls.Add($bar,0,1)
$pb=Flow;$add=Button 'انتخاب چند EXE';$remove=Button 'حذف تیک‌خورده‌ها';$observe=Button 'شروع رصد زنده TCP / DNS';$stop=Button 'توقف رصد';$copyPath=Button 'کپی مسیر ردیف';$reload=Button 'بازخوانی'
$dnsTrace=New-Object Windows.Forms.CheckBox;$dnsTrace.Text='DNS زنده مستقل (Administrator)';$dnsTrace.AutoSize=$true;$dnsTrace.Checked=$true;$pb.Controls.Add($dnsTrace)
$duration=New-Object Windows.Forms.ComboBox;$duration.DropDownStyle='DropDownList';$duration.Width=160;[void]$duration.Items.AddRange(@('۳۰ ثانیه','۶۰ ثانیه','۱۲۰ ثانیه','۳۰۰ ثانیه','تا توقف دستی'));$duration.SelectedIndex=1;$duration.Margin=New-Object Windows.Forms.Padding(5,9,5,5)
foreach($v in @($add,$remove,$observe,(Label 'ثانیه'),$duration,$stop,$copyPath,$reload)){$pb.Controls.Add($v)};$p.Controls.Add($pb,0,2)
$programGrid=Grid @(@('name','برنامه'),@('path','مسیر دقیق / LTR'),@('hash','SHA256 / خلاصه'),@('enabled','در تنظیمات'))
$check=New-Object Windows.Forms.DataGridViewCheckBoxColumn;$check.Name='pick';$check.HeaderText='تیک';$check.ReadOnly=$false;$check.FillWeight=25;$programGrid.Columns.Insert(0,$check)
$programGrid.Columns['path'].FillWeight=260;$programGrid.Columns['hash'].FillWeight=105;$programGrid.Columns['enabled'].FillWeight=65;$programGrid.RightToLeft='No';$p.Controls.Add($programGrid,0,3)
$b=Stack $blackTab 3
$b.Controls.Add((Label 'مقصد را به‌صورت IP، CIDR یا بازه وارد کنید. هر قاعده فقط برای EXEهای تیک‌خورده و پروتکل/پورت مشخص ثبت می‌شود؛ مسیرها، نه نام فایل، هویت برنامه‌اند.'),0,0)
$bb=Flow;$target=TextBox 260;$proto=New-Object Windows.Forms.ComboBox;$proto.DropDownStyle='DropDownList';$proto.Width=80;[void]$proto.Items.AddRange(@('TCP','UDP'));$proto.SelectedIndex=0
$port=New-Object Windows.Forms.NumericUpDown;$port.Minimum=1;$port.Maximum=65535;$port.Value=443;$port.Width=85
$addEntry=Button 'افزودن برای تیک‌خورده‌ها';$deleteEntry=Button 'حذف قواعد انتخابی'
foreach($v in @((Label 'مقصد'),$target,$proto,$port,$addEntry,$deleteEntry)){$bb.Controls.Add($v)};$b.Controls.Add($bb,0,1)
$blackGrid=Grid @(@('target','مقصد'),@('protocol','پروتکل'),@('port','پورت'),@('programs','مسیرهای دقیق EXE'))
$blackGrid.ReadOnly=$true;$blackGrid.RightToLeft='No';$blackGrid.Columns['programs'].FillWeight=300;$b.Controls.Add($blackGrid,0,2)
$pol=Stack $policyTab 4
$pol.Controls.Add((Label 'بلک‌لیست صریح بر وایت‌لیست مقدم است؛ Allow برای خنثی‌کردن Block ساخته نمی‌شود. vpn_allowlist و full_isolation فقط ذخیره/پیش‌نمایش می‌شوند و قابل Apply نیستند.'),0,0)
$mode=New-Object Windows.Forms.ComboBox;$mode.DropDownStyle='DropDownList';$mode.Width=240;$mode.RightToLeft='No';[void]$mode.Items.AddRange(@('blacklist_only','vpn_allowlist','full_isolation'));$mode.SelectedIndex=0
$polBar=Flow;$polBar.Controls.Add((Label 'حالت سیاست'));$polBar.Controls.Add($mode);$polBar.Controls.Add((Label 'وایت‌لیست: هر خط IP / CIDR / بازه؛ دامنه پشتیبانی نمی‌شود.'));$pol.Controls.Add($polBar,0,1)
$polButtons=Flow;$save=Button 'ذخیرهٔ سیاست';$preview=Button 'پیش‌نمایش و تعارض‌ها';$importBlack=Button 'ورود settings قدیمی';$importWhite=Button 'ورود config قدیمی'
foreach($v in @($save,$preview,$importBlack,$importWhite)){$polButtons.Controls.Add($v)};$pol.Controls.Add($polButtons,0,2)
$whitelist=TextBox 500;$whitelist.Multiline=$true;$whitelist.Dock='Fill';$whitelist.ScrollBars='Vertical';$whitelist.Font=New-Object Drawing.Font('Consolas',11);$pol.Controls.Add($whitelist,0,3)
$d=Stack $detailTab 2;$detailHint=Label 'جزئیات آخرین عملیات؛ فایل کامل JSON در پوشهٔ گزارش‌ها باقی می‌ماند. رصد TCP نمونه‌برداری است، نه ضبط همهٔ بسته‌ها. گزارش‌ها شامل اطلاعات خصوصی مسیر/شبکه هستند.';$d.Controls.Add($detailHint,0,0)
$output=TextBox 500;$output.Multiline=$true;$output.ReadOnly=$true;$output.ScrollBars='Both';$output.WordWrap=$false;$output.Dock='Fill';$output.Font=New-Object Drawing.Font('Consolas',10);$d.Controls.Add($output,0,1)
$actions=Flow;$apply=Button 'اعمال بلک‌لیست • LAB';$apply.BackColor=$blue;$apply.ForeColor=[Drawing.Color]::White
$restore=Button 'Restore قواعد ثبت‌شده';$nativeStatus=Button 'وضعیت واقعی / نشست';$reports=Button 'پوشهٔ گزارش‌ها'
foreach($v in @($apply,$restore,$nativeStatus,$reports)){$actions.Controls.Add($v)};$main.Controls.Add($actions,0,3)
$footer=New-Object Windows.Forms.TableLayoutPanel;$footer.Dock='Fill';$footer.AutoSize=$true;$footer.ColumnCount=1;$footer.RowCount=3
$counts=Label 'در حال خواندن تنظیمات…';$status=Label 'آماده‌سازی';$scope=Label 'ویرایش تنظیمات، قواعد فعال را تغییر نمی‌دهد: برای تغییر قواعد ابتدا Restore سپس Apply. بستن پنجره Restore خودکار نیست. اعمال/بازیابی به اجرای صریح Start.cmd با Administrator نیاز دارد.'
$scope.ForeColor=[Drawing.ColorTranslator]::FromHtml('#57677C')
$footer.Controls.Add($counts,0,0);$footer.Controls.Add($status,0,1);$footer.Controls.Add($scope,0,2);$main.Controls.Add($footer,0,4)
function CheckedIds {
 if($programGrid.IsCurrentCellDirty){[void]$programGrid.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit)};[void]$programGrid.EndEdit()
 if($null -eq $script:state){return ,@()};return ,@($script:state.config.programs|Where-Object{$script:checks.ContainsKey($_.id) -and $script:checks[$_.id]}|ForEach-Object{$_.id})
}
function Counts {
 if($null -eq $script:state){return};$ids=@($script:state.config.programs|Where-Object{$script:checks.ContainsKey($_.id) -and $script:checks[$_.id]}|ForEach-Object{$_.id});$visible=@($programGrid.Rows|ForEach-Object{$_.Tag});$hidden=@($ids|Where-Object{$visible -notcontains $_}).Count
 $counts.Text=('کل: {0}  |  نمایان: {1}  |  تیک‌خورده: {2}  |  تیک‌خوردهٔ پنهان با فیلتر: {3}' -f @($script:state.config.programs).Count,$programGrid.Rows.Count,$ids.Count,$hidden)
}
function RenderPrograms {
 $script:rendering=$true
 try{
  $programGrid.Rows.Clear();if($null -eq $script:state){return};$query=$filter.Text.Trim()
  foreach($item in $script:state.config.programs){
   if($query -and $item.path.IndexOf($query,[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
   $picked=$script:checks.ContainsKey($item.id) -and $script:checks[$item.id]
   $i=$programGrid.Rows.Add([bool]$picked,[IO.Path]::GetFileName($item.path),$item.path,$item.sha256.Substring(0,12),[string]$item.enabled);$programGrid.Rows[$i].Tag=$item.id;$programGrid.Rows[$i].Cells['hash'].ToolTipText=$item.sha256
  }
 }finally{$script:rendering=$false};Counts
}
$programGrid.Add_CurrentCellDirtyStateChanged({if($programGrid.IsCurrentCellDirty){[void]$programGrid.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit)}})
$programGrid.Add_CellValueChanged({param($sender,$e) if(-not $script:rendering -and $e.RowIndex -ge 0 -and $e.ColumnIndex -eq 0){$row=$programGrid.Rows[$e.RowIndex];if($null -ne $row.Tag){$script:checks[[string]$row.Tag]=[bool]$row.Cells['pick'].Value;Counts}}})
$filter.Add_TextChanged({if($null -ne $script:state){[void](CheckedIds);RenderPrograms}})
$selectVisible.Add_Click({foreach($row in $programGrid.Rows){$script:checks[[string]$row.Tag]=$true};RenderPrograms})
$clearVisible.Add_Click({foreach($row in $programGrid.Rows){$script:checks[[string]$row.Tag]=$false};RenderPrograms})
$clearAll.Add_Click({$script:checks=@{};RenderPrograms})
function Generation{if($null -eq $script:state){throw 'configuration_not_loaded'};return [int]$script:state.config.generation}
function RenderState($s,[bool]$Editor){
 $script:state=$s;$known=@($s.config.programs|ForEach-Object{$_.id});foreach($id in @($script:checks.Keys)){if($known -notcontains $id){$script:checks.Remove($id)}};RenderPrograms
 if($Editor){$mode.SelectedItem=[string]$s.config.mode;$whitelist.Lines=@($s.config.whitelist)}
 $map=@{};foreach($item in $s.config.programs){$map[$item.id]=$item.path};$blackGrid.Rows.Clear()
 foreach($entry in $s.config.blacklist){$i=$blackGrid.Rows.Add($entry.target,$entry.protocol,$entry.port,(@($entry.program_ids|ForEach-Object{$map[$_]}) -join '; '));$blackGrid.Rows[$i].Tag=$entry.id}
 $apply.Enabled=($null -eq $script:job -and $s.config.mode -ceq 'blacklist_only')
}
function AssertSaved {
 if([string]$mode.SelectedItem -cne $script:state.config.mode -or (@($whitelist.Lines|Where-Object{$_.Trim()}) -join "`n") -cne (@($script:state.config.whitelist) -join "`n")){throw 'ابتدا سیاست وایت‌لیست/حالت را ذخیره کنید.'}
}
function SetBusy([bool]$Busy){
 foreach($v in @($hostRead,$hostSink,$hostRemove,$hostDomains,$hostFilter,$historyReload,$historyOpen,$historyExport,$stageObserved,$baselineStart,$baselineHistory,$dnsTrace)){$v.Enabled=-not $Busy}
 foreach($v in @($add,$remove,$observe,$reload,$save,$preview,$importBlack,$importWhite,$addEntry,$deleteEntry,$mode,$whitelist,$programGrid,$blackGrid,$filter,$selectVisible,$clearVisible,$clearAll,$target,$proto,$port,$duration,$apply,$restore,$nativeStatus,$copyPath)){$v.Enabled=-not $Busy}
 $stop.Enabled=($Busy -and $script:job.action -in @('monitor_record','baseline_record'));$monitorStop.Enabled=$stop.Enabled;$popupStop.Enabled=$stop.Enabled
 if(-not $Busy -and $null -ne $script:state){$apply.Enabled=($script:state.config.mode -ceq 'blacklist_only')}
 if(-not $Busy){$stageObserved.Enabled=($null -ne $script:liveFrame)}
 Set-EvidenceControls
}
function BeginOp([string]$Action,$Payload){
 if($null -ne $script:ptrJob -and $Action -in @('native_prepare','native_apply_blacklist','native_restore')){throw 'ابتدا PTR را پایان دهید یا متوقف کنید.'}
 if($null -ne $script:job){throw 'operation_already_running'}
 $id=[guid]::NewGuid().ToString('N');$folder=Join-Path $root ('private-state/jobs/'+$id);$null=New-Item -ItemType Directory -Path $folder -Force
 $request=Join-Path $folder 'request.json';$response=Join-Path $folder 'response.json'
 [IO.File]::WriteAllText($request,(ConvertTo-Json -InputObject @{action=$Action;payload=$Payload} -Depth 24),(New-Object Text.UTF8Encoding($false)))
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=Join-Path $root 'runtime/python.exe';$info.Arguments='-I "'+(Join-Path $PSScriptRoot 'desktop_cli.py')+'" --request "'+$request+'" --response "'+$response+'"'
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $proc=New-Object Diagnostics.Process;$proc.StartInfo=$info;[void]$proc.Start()
 $script:job=@{action=$Action;process=$proc;folder=$folder;response=$response};SetBusy $true
 $status.Text='در حال انجام: '+$Action+' — تا پایان عملیات صبر کنید.'
}
function TryOp([scriptblock]$Body){try{& $Body}catch{$status.Text='خطا: '+$_.Exception.Message;[void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'Unified Firewall','OK','Warning')}}
function ConfirmText([string]$Title,[string]$Explanation,[string]$Expected){
 $dialog=New-Object Windows.Forms.Form;$dialog.Text=$Title;$dialog.Size=New-Object Drawing.Size(760,510);$dialog.MinimumSize=New-Object Drawing.Size(620,400);$dialog.StartPosition='CenterParent';$dialog.Font=$form.Font;$dialog.AutoScaleMode='Dpi';$dialog.RightToLeft='Yes'
 $v=Stack $dialog 3;$v.RowStyles[0].SizeType='Percent';$v.RowStyles[0].Height=100;$v.RowStyles[2].SizeType='AutoSize'
 $text=TextBox 600;$text.Multiline=$true;$text.ReadOnly=$true;$text.ScrollBars='Both';$text.WordWrap=$false;$text.Dock='Fill';$text.Text=$Explanation;$v.Controls.Add($text,0,0)
 $typed=TextBox 600;$typed.Dock='Fill';$v.Controls.Add($typed,0,1)
 $buttons=Flow;$cancel=Button 'انصراف';$cancel.DialogResult='Cancel';$ok=Button 'تأیید دقیق';$ok.Enabled=$false;$ok.DialogResult='OK';$buttons.Controls.Add($cancel);$buttons.Controls.Add($ok);$v.Controls.Add($buttons,0,2)
 $typed.Tag=@{expected=$Expected;button=$ok};$typed.Add_TextChanged({param($sender,$e) $sender.Tag.button.Enabled=($sender.Text -ceq $sender.Tag.expected)})
 $dialog.CancelButton=$cancel;$dialog.AcceptButton=$ok
 try{return ($dialog.ShowDialog($form) -eq 'OK' -and $typed.Text -ceq $Expected)}finally{$dialog.Dispose()}
}
$add.Add_Click({TryOp {$dialog=New-Object Windows.Forms.OpenFileDialog;$dialog.Filter='Executable files (*.exe)|*.exe';$dialog.Multiselect=$true;try{if($dialog.ShowDialog() -eq 'OK'){BeginOp 'register' @{generation=(Generation);paths=@($dialog.FileNames)}}}finally{$dialog.Dispose()}}})
$remove.Add_Click({TryOp {$ids=CheckedIds;if($ids.Count -eq 0){throw 'ابتدا EXEها را تیک بزنید.'};if([Windows.Forms.MessageBox]::Show(('حذف تنظیمات {0} برنامه، شامل تیک‌های پنهان؟ قواعد فعال ویندوز حذف نمی‌شوند.' -f $ids.Count),'حذف تنظیمات','YesNo','Warning') -eq 'Yes'){BeginOp 'remove_programs' @{generation=(Generation);program_ids=$ids}}}})
$reload.Add_Click({TryOp {if([Windows.Forms.MessageBox]::Show('تنظیمات ذخیره‌شده دوباره خوانده شوند؟ ویرایش ذخیره‌نشده کنار گذاشته می‌شود.','بازخوانی','YesNo') -eq 'Yes'){BeginOp 'load' @{}}}})
$save.Add_Click({TryOp {BeginOp 'configure' @{generation=(Generation);mode=[string]$mode.SelectedItem;whitelist=@($whitelist.Lines|Where-Object{$_.Trim()})}}})
$preview.Add_Click({TryOp {AssertSaved;BeginOp 'preview' @{}}})
$addEntry.Add_Click({TryOp {$ids=CheckedIds;if($ids.Count -eq 0){throw 'ابتدا EXEها را در زبانهٔ برنامه‌ها تیک بزنید.'};BeginOp 'add_blacklist' @{generation=(Generation);program_ids=$ids;target=$target.Text;protocol=[string]$proto.SelectedItem;port=[int]$port.Value}}})
$deleteEntry.Add_Click({TryOp {$ids=@($blackGrid.SelectedRows|ForEach-Object{$_.Tag});if($ids.Count -eq 0){throw 'ردیف‌های بلک‌لیست را انتخاب کنید.'};if([Windows.Forms.MessageBox]::Show(('حذف {0} ردیف از تنظیمات؟ قواعد فعال تغییر نمی‌کنند.' -f $ids.Count),'حذف قواعد تنظیمات','YesNo','Warning') -eq 'Yes'){BeginOp 'delete_blacklist' @{generation=(Generation);entry_ids=$ids}}}})
$observe.Add_Click({TryOp {$ids=CheckedIds;if($ids.Count -eq 0){throw 'ابتدا EXEها را تیک بزنید.'};$script:liveFrame=$null;$script:liveRevision=-1;$script:liveSeen=@{};$script:popupSeen=@{};$script:domainMainSeen=@{};$script:domainPopupSeen=@{};$script:liveCapture=$null;$script:liveFinal=$false;$liveGrid.Rows.Clear();$popupGrid.Rows.Clear();$domainMain.Rows.Clear();$domainPopup.Rows.Clear();$liveStatus.Text='در حال بررسی EXEها؛ هنوز نمونهٔ موفق نداریم.';$popupStatus.Text=$liveStatus.Text;if($dnsTrace.Checked -and [Windows.Forms.MessageBox]::Show('برای DNS زنده یک نشست موقت DNS-Client ETW آغاز می‌شود؛ Administrator لازم است. فقط رویدادهای EXEهای انتخابی نگه داشته می‌شوند. audit، کانال رویداد، فایروال و hosts تغییر نمی‌کنند. تأیید؟','رصد زنده DNS','YesNo','Question') -ne 'Yes'){return};BeginOp 'monitor_record' @{program_ids=$ids;seconds=@(30,60,120,300,0)[$duration.SelectedIndex];dns_etw_consent=[bool]$dnsTrace.Checked};$tabs.SelectedTab=$monitorTab;if(-not $livePopup.Visible){$livePopup.Show($form)}}})
function Request-MonitorStop {
 if($null -ne $script:job -and $script:job.action -in @('monitor_record','baseline_record')){[IO.File]::WriteAllText((Join-Path $script:job.folder 'stop.txt'),'stop');$status.Text='توقف رصد درخواست شد؛ منتظر پایان خواندن جاری باشید.'}
}
$stop.Add_Click({TryOp {Request-MonitorStop}})
$copyPath.Add_Click({TryOp {if($null -eq $programGrid.CurrentRow){throw 'یک ردیف انتخاب کنید.'};[Windows.Forms.Clipboard]::SetText([string]$programGrid.CurrentRow.Cells['path'].Value)}})
foreach($pair in @(@($importBlack,'import_blacklist'),@($importWhite,'import_whitelist'))){$pair[0].Tag=[string]$pair[1];$pair[0].Add_Click({param($sender,$e) TryOp {$dialog=New-Object Windows.Forms.OpenFileDialog;$dialog.Filter='JSON (*.json)|*.json';try{if($dialog.ShowDialog() -eq 'OK'){BeginOp ([string]$sender.Tag) @{generation=(Generation);path=$dialog.FileName}}}finally{$dialog.Dispose()}}})}
$apply.Add_Click({TryOp {
 AssertSaved;$script:legacyAck=''
 if(@($script:state.config.legacy_imports).Count -gt 0){if(-not (ConfirmText 'توقف و بازیابی ابزارهای قدیمی' "فقط پس از توقف و Restore ابزارهای قبلی، عبارت زیر را تایپ کنید. قواعد قدیمی خودکار پذیرفته یا حذف نمی‌شوند.`r`nOLD TOOLS RESTORED" 'OLD TOOLS RESTORED')){return};$script:legacyAck='OLD TOOLS RESTORED'}
 BeginOp 'native_prepare' @{generation=(Generation);legacy_ack=$script:legacyAck}
}})
$restore.Add_Click({TryOp {if(ConfirmText 'Restore قواعد ثبت‌شده' "فقط قواعد بدون تغییر ثبت‌شده در ژورنال محافظت‌شده حذف می‌شوند. قاعدهٔ تغییرکرده به‌زور حذف نمی‌شود. به دسترسی Administrator نیاز است.`r`nبرای ادامه دقیقاً تایپ کنید:`r`nRESTORE" 'RESTORE'){BeginOp 'native_restore' @{confirmation='RESTORE'}}}})
$nativeStatus.Add_Click({TryOp {BeginOp 'native_status' @{}}})
$reports.Add_Click({TryOp {$folder=Join-Path $root 'private-state';$null=New-Item -ItemType Directory -Path $folder -Force;[void][Diagnostics.Process]::Start('explorer.exe',('"'+$folder+'"'))}})

# Monitoring and hosts are separate scopes; shared mutex/native sequencing are unchanged.
. (Join-Path $PSScriptRoot 'live-model.ps1')
$script:liveFrame=$null;$script:liveRevision=-1;$script:liveSeen=@{};$script:popupSeen=@{};$script:domainMainSeen=@{};$script:domainPopupSeen=@{};$script:liveCapture=$null;$script:liveFinal=$false;$script:hostsView=$null;$script:hostsPending=$null
$monitorTab=Tab '۵  رصد زنده و سابقه';$hostsTab=Tab '۶  دامنه‌ها / hosts'
$m=Stack $monitorTab 5
$liveStatus=Label 'رصد شروع نشده است. در برنامه‌ها EXEها را تیک بزنید و «شروع رصد زنده TCP / DNS» را بزنید.';$m.Controls.Add($liveStatus,0,0)
$mb=Flow;$showPopup=Button 'نمایش پنجرهٔ زنده';$historyReload=Button 'سابقهٔ رصد';$stageObserved=Button 'ثبت مقصد انتخابی در تنظیمات'
$liveFilter=TextBox 190;$mb.Controls.Add((Label 'فیلتر مقصد / برنامه'));$mb.Controls.Add($liveFilter)
$onlyPresent=New-Object Windows.Forms.CheckBox;$onlyPresent.Text='فقط حاضر در آخرین نمونه';$onlyPresent.AutoSize=$true;$mb.Controls.Add($onlyPresent)
foreach($v in @($showPopup,$historyReload,$stageObserved)){$mb.Controls.Add($v)};$m.Controls.Add($mb,0,1)
function New-MonitorGrid {
 $v=Grid @(@('program','برنامه / PID'),@('destination','مقصد TCP'),@('presence','آخرین نمونه'),@('samples','نمونه'),@('states','حالت‌های ثبت‌شده'),@('first','اولین مشاهده UTC'),@('last','آخرین مشاهده UTC'))
 $v.ReadOnly=$true;$v.RightToLeft='No';$v.AutoSizeRowsMode='None';$v.RowTemplate.Height=32;$v.Columns['program'].FillWeight=120;$v.Columns['destination'].FillWeight=140;$v.Columns['first'].FillWeight=150;$v.Columns['last'].FillWeight=150;$v.Columns['samples'].FillWeight=45
 return $v
}
$liveGrid=New-MonitorGrid;$m.Controls.Add($liveGrid,0,2)
$hb=Flow;$historyOpen=Button 'بازکردن سابقهٔ انتخابی';$historyExport=Button 'خروجی ZIP سابقهٔ انتخابی'
foreach($v in @($historyOpen,$historyExport,(Label 'گزارش خصوصی است؛ خروجی IP، پورت، زمان و هش دارد. مسیر کامل EXE در ZIP حذف می‌شود.'))){$hb.Controls.Add($v)};$m.Controls.Add($hb,0,3)
$historyGrid=Grid @(@('time','شروع UTC'),@('programs','EXEها'),@('records','ردیف'),@('samples','نمونهٔ موفق'),@('errors','خطای خواندن'),@('limited','سقف داده'))
$historyGrid.ReadOnly=$true;$historyGrid.RightToLeft='No';$m.Controls.Add($historyGrid,0,4)
$m.RowStyles[2].SizeType='Percent';$m.RowStyles[2].Height=70;$m.RowStyles[4].Height=30
$livePopup=New-Object Windows.Forms.Form;$livePopup.Text='Unified Firewall / رصد زنده TCP';$livePopup.Size=New-Object Drawing.Size(1060,610);$livePopup.MinimumSize=New-Object Drawing.Size(740,440);$livePopup.Font=$form.Font;$livePopup.AutoScaleMode='Dpi';$livePopup.RightToLeft='Yes';$livePopup.RightToLeftLayout=$true;$livePopup.StartPosition='CenterParent';$livePopup.BackColor=[Drawing.Color]::White
$pv=Stack $livePopup 4;$popupStatus=Label 'منتظر نخستین نمونهٔ موفق…';$pv.Controls.Add($popupStatus,0,0)
$popupOptions=Flow
$pin=New-Object Windows.Forms.CheckBox;$pin.Text='همیشه روی پنجره‌ها';$pin.AutoSize=$true;$pin.Checked=$true;$livePopup.TopMost=$true
$pause=New-Object Windows.Forms.CheckBox;$pause.Text='مکث نمایش (ثبت ادامه دارد)';$pause.AutoSize=$true
$follow=New-Object Windows.Forms.CheckBox;$follow.Text='دنبال‌کردن جدیدها';$follow.AutoSize=$true;$follow.Checked=$true
$flash=New-Object Windows.Forms.CheckBox;$flash.Text='چشمک پس‌زمینهٔ فعالیت';$flash.AutoSize=$true;$flash.Checked=$true
$popupHide=Button 'پنهان‌کردن';$popupStop=Button 'توقف ثبت'
foreach($v in @($pin,$pause,$follow,$flash,$popupHide,$popupStop)){$popupOptions.Controls.Add($v)};$pv.Controls.Add($popupOptions,0,1)
$popupGrid=New-MonitorGrid;$pv.Controls.Add($popupGrid,0,2);$pv.RowStyles[2].SizeType='Percent';$pv.RowStyles[2].Height=100;$pv.RowStyles[3].SizeType='AutoSize'
$pv.Controls.Add((Label 'پالس فقط تغییر نمونهٔ TCP است؛ نه اثبات ارسال بسته یا موفقیت Block. بستن این پنجره، ثبت را متوقف نمی‌کند.'),0,3)
$livePopup.Add_FormClosing({param($sender,$e) if($e.CloseReason -eq [Windows.Forms.CloseReason]::UserClosing -and -not $script:closing){$e.Cancel=$true;$livePopup.Hide()}})
$pin.Add_CheckedChanged({$livePopup.TopMost=$pin.Checked});$popupHide.Add_Click({$livePopup.Hide()})
$popupStop.Add_Click({TryOp {Request-MonitorStop}});$showPopup.Add_Click({if(-not $livePopup.Visible){$livePopup.Show($form)};$livePopup.BringToFront();Render-Popup})
function Read-LiveFile([string]$Path){
 $f=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
 try{
  if($f.Length -gt 16777216){throw 'live_frame_too_large'}
  $reader=New-Object IO.StreamReader($f,(New-Object Text.UTF8Encoding($false)),$true)
  try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
 }finally{$f.Dispose()}
 $value=ConvertFrom-Json -InputObject $text
 if($value.schema -cnotin @('unified-live-monitor-1','unified-new-process-monitor-1') -or $value.capture_id -cnotmatch '^[a-f0-9]{32}$' -or @($value.endpoints).Count -gt 5000){throw 'invalid_live_frame'}
 if($value.schema -ceq 'unified-new-process-monitor-1' -and (@($value.processes).Count -gt 2000 -or @($value.programs).Count -gt 512)){throw 'invalid_baseline_live_limits'}
 return $value
}
function Live-StatusText($Frame){
 $age=([DateTime]::UtcNow-[DateTime]::Parse([string]$Frame.published_utc).ToUniversalTime()).TotalSeconds
 $mode=if($Frame.status -ceq 'interrupted'){'ثبت ناقص/متوقف؛ وضعیت فعلی نامعلوم است.'}elseif($Frame.status -ceq 'finished'){'ثبت پایان یافت؛ حضور مربوط به آخرین نمونه است.'}elseif($age -gt 4){'هشدار: قاب قدیمی؛ وضعیت جاری نامعلوم است.'}elseif(-not $Frame.ready){'هنوز نمونهٔ موفق نداریم؛ خروجی خالی معتبر نیست.'}elseif(-not $Frame.last_sample_ok){'آخرین خواندن خطا داشت؛ حضور نامعلوم.'}else{'آماده و در حال نمونه‌برداری TCP'}
 $extra=''
 if($Frame.PSObject.Properties.Name -contains 'event_evidence'){
  $extra=' | DNS / Sysmon: '+$Frame.event_evidence.streams.dns.status+' | WFP: '+$Frame.event_evidence.streams.wfp.status+' | شواهد ناقص: '+$Frame.event_evidence.truncated
  if($Frame.event_evidence.PSObject.Properties.Name -contains 'dns_trace'){$d=$Frame.event_evidence.dns_trace;$extra+=' | DNS زنده: '+$d.status+' / '+$d.error_code+' | رویداد منتخب: '+$d.selected_events+' | ازدست‌رفته: '+$d.queue_dropped+' | پاکسازی لازم: '+$d.cleanup_required}
 }else{$extra=' | شواهد DNS/WFP در این ثبت جمع‌آوری نشده است.'}
 if($Frame.schema -ceq 'unified-new-process-monitor-1'){$extra+=' | خط مبنا آماده از '+$Frame.baseline_utc+' | قدیمی‌های کنارگذاشته: '+$Frame.baseline_existing_count+' | فرایند تازه: '+@($Frame.processes).Count+' | بدون تغییر شبکه/تنظیمات'}
 if($Frame.PSObject.Properties.Name -contains 'block_inventory'){$extra+=' | snapshot قواعد: '+$Frame.block_inventory.checked_utc+' / '+$Frame.block_inventory.reason}
 return ('{0} | ردیف: {1} (نمایش حداکثر ۲۰۰۰) | موفق: {2} | خطا: {3} | خطای انتشار: {4} | سقف ثبت: {5} | سن قاب: {6:N1}s | خواندن‌ناپذیر فرایند: {7}' -f $mode,@($Frame.endpoints).Count,$Frame.successful_samples,$Frame.query_errors,$Frame.publication_errors,$Frame.truncated,$age,$Frame.unreadable_process_instances)+$extra
}
function Update-LiveView {
 if($null -ne $script:job -and $script:job.action -in @('monitor_record','baseline_record')){
  $path=Join-Path $script:job.folder 'live.json'
  try{
   if([IO.File]::Exists($path)){$frame=Read-LiveFile $path;if([int]$frame.revision -gt $script:liveRevision){Accept-LiveFrame $frame}}
  }catch{$liveStatus.Text='قاب قابل خواندن نیست؛ دادهٔ نمایش‌داده‌شده قدیمی و وضعیت جاری نامعلوم است.';$popupStatus.Text=$liveStatus.Text;return}
 }
 if($null -ne $script:liveFrame){$liveStatus.Text=Live-StatusText $script:liveFrame;if($livePopup.Visible){$popupStatus.Text=$liveStatus.Text+$(if($pause.Checked -and -not $script:liveFinal){' | مکث نمایش؛ ثبت ادامه دارد.'}else{''})}}
}
$pause.Add_CheckedChanged({Render-Popup});$flash.Add_CheckedChanged({Expire-LivePulses})
$liveFilter.Add_TextChanged({if($null -ne $script:liveFrame){Render-LiveGrid $liveGrid $script:liveFrame $script:liveSeen $false $false $true}})
$onlyPresent.Add_CheckedChanged({if($null -ne $script:liveFrame){Render-LiveGrid $liveGrid $script:liveFrame $script:liveSeen $false $false $true}})
function Render-History($History){
 $historyGrid.Rows.Clear();foreach($c in $History.captures){$i=$historyGrid.Rows.Add($c.started_utc,$c.program_count,$c.records,$c.successful_samples,$c.query_errors,$c.truncated);$historyGrid.Rows[$i].Tag=$c.capture_id}
 $status.Text='سابقهٔ محلی؛ حداکثر ۲۰۰ مورد. قدیمی‌ترهای نمایش‌نداده: '+$History.older_not_listed+' | خراب/ناخوانا: '+$History.invalid_or_unreadable
}
function Selected-Capture {
 if($historyGrid.SelectedRows.Count -ne 1){throw 'یک سابقه را انتخاب کنید.'}
 return [string]$historyGrid.SelectedRows[0].Tag
}
$historyReload.Add_Click({TryOp {BeginOp 'monitor_history' @{}}})
$historyOpen.Add_Click({TryOp {$id=Selected-Capture;$script:liveSeen=@{};$script:popupSeen=@{};$script:domainMainSeen=@{};$script:domainPopupSeen=@{};BeginOp $(if($script:historyMode -ceq 'baseline'){'baseline_open'}else{'monitor_open'}) @{capture_id=$id}}})
$historyExport.Add_Click({TryOp {$id=Selected-Capture;if([Windows.Forms.MessageBox]::Show('ZIP خصوصی است: IP، دامنه، پورت، زمان و شناسهٔ فرایند باقی می‌مانند؛ ثبت انتخابی هش EXE هم دارد. مسیر کامل EXE حذف می‌شود؛ ناشناس‌سازی کامل نیست. فقط خروجی محلی ساخته شود؟','خروجی خصوصی','YesNo','Warning') -eq 'Yes'){BeginOp $(if($script:historyMode -ceq 'baseline'){'baseline_export'}else{'monitor_export'}) @{capture_id=$id}}}})
$stageObserved.Add_Click({TryOp {Prefill-Observed $liveGrid 'endpoint' 'blacklist'}})
# Hosts names are global OS configuration, not per-program whitelist/blacklist rules.
$h=Stack $hostsTab 5
$h.Controls.Add((Label 'hosts سراسری است: روی همهٔ برنامه‌ها اثر دارد و وایت‌لیست آن را خنثی نمی‌کند. هر نام دقیق جداست؛ زیردامنه و wildcard خودکار نیست. تغییر فایل ≠ اثبات قطع اتصال.'),0,0)
$hbar=Flow;$hostRead=Button 'بازخوانی hosts';$hostFilter=TextBox 240;$hbar.Controls.Add($hostRead);$hbar.Controls.Add((Label 'جست‌وجوی نگاشت'));$hbar.Controls.Add($hostFilter);$h.Controls.Add($hbar,0,1)
$hostsGrid=Grid @(@('domain','نام دقیق دامنه'),@('addresses','نگاشت IP'),@('kind','نوع نگاشت'),@('lines','شمارهٔ خط'))
$hostsGrid.ReadOnly=$true;$hostsGrid.RightToLeft='No';$hostsGrid.Columns['domain'].FillWeight=160;$hostsGrid.Columns['addresses'].FillWeight=200;$h.Controls.Add($hostsGrid,0,2)
$hostEdit=New-Object Windows.Forms.TableLayoutPanel;$hostEdit.ColumnCount=1;$hostEdit.RowCount=3;$hostEdit.AutoSize=$true;$hostEdit.Dock='Fill'
$hostEdit.Controls.Add((Label 'هر خط فقط یک دامنه، بدون https:// یا مسیر. برای حذف، نام‌ها را صریح وارد کنید. افزودن، نگاشت قبلی همان نام را با 0.0.0.0 و :: جایگزین می‌کند.'),0,0)
$hostDomains=TextBox 600;$hostDomains.Multiline=$true;$hostDomains.Height=75;$hostDomains.Dock='Fill';$hostDomains.ScrollBars='Vertical';$hostDomains.Font=New-Object Drawing.Font('Consolas',11);$hostEdit.Controls.Add($hostDomains,0,1)
$hostButtons=Flow;$hostSink=Button 'پیش‌نمایش مسدودسازی دامنه‌ها';$hostRemove=Button 'پیش‌نمایش حذف نگاشت‌ها';foreach($v in @($hostSink,$hostRemove)){$hostButtons.Controls.Add($v)};$hostEdit.Controls.Add($hostButtons,0,2);$h.Controls.Add($hostEdit,0,3)
$hostsSummary=Label 'ابتدا hosts را بازخوانی کنید. نوشتن فقط با Administrator، پیش‌نمایش، تأیید جداگانه و پشتیبان انجام می‌شود. هیچ DNS flush یا تغییر خودکار فایروال انجام نمی‌شود.';$h.Controls.Add($hostsSummary,0,4)
$h.RowStyles[2].SizeType='Percent';$h.RowStyles[2].Height=100;$h.RowStyles[4].SizeType='AutoSize'
function Render-Hosts($Hosts){
 $script:hostsView=$Hosts;$hostsGrid.Rows.Clear()
 foreach($r in $Hosts.entries){if($hostFilter.Text.Trim() -and ($r.domain+' '+($r.addresses -join ' ')).IndexOf($hostFilter.Text.Trim(),[StringComparison]::OrdinalIgnoreCase) -lt 0){continue};[void]$hostsGrid.Rows.Add($r.domain,($r.addresses -join ', '),$r.mapping_kind,($r.lines -join ', '))}
 $hostsSummary.Text=('دامنه‌ها: {0} | خطوط نامعتبر: {1} | نمایش ناقص: {2} | SHA256: {3}' -f @($Hosts.entries).Count,$Hosts.invalid_items,$Hosts.truncated,$Hosts.sha256)
}
$hostRead.Add_Click({TryOp {BeginOp 'hosts_read' @{}}})
$hostFilter.Add_TextChanged({if($null -ne $script:hostsView){Render-Hosts $script:hostsView}})
foreach($pair in @(@($hostSink,'sink'),@($hostRemove,'remove'))){$pair[0].Tag=$pair[1];$pair[0].Add_Click({param($sender,$e) TryOp {
 if(-not $hostDomains.Text.Trim()){throw 'نام دقیق دامنه‌ها را وارد کنید.'}
 $script:hostsPending=@{domains=$hostDomains.Text;operation=[string]$sender.Tag};BeginOp 'hosts_prepare' $script:hostsPending
}})}

. (Join-Path $PSScriptRoot 'ui-evidence.ps1')
. (Join-Path $PSScriptRoot 'ui-baseline.ps1')
. (Join-Path $PSScriptRoot 'ui-layout.ps1')
. (Join-Path $PSScriptRoot 'ui-context.ps1')
$timer=New-Object Windows.Forms.Timer;$timer.Interval=250
$timer.Add_Tick({
 Update-LiveView;Expire-LivePulses;Update-Ptr
 if($null -eq $script:job -or -not $script:job.process.HasExited){return};$j=$script:job;$prepared=$null;$hostsPrepared=$null
 try{
  if(-not (Test-Path -LiteralPath $j.response)){throw 'backend_no_response; برای عملیات Native وضعیت/ژورنال را بررسی کنید؛ دوباره Apply نکنید.'}
  $r=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($j.response));$text=ConvertTo-Json -InputObject $r -Depth 32
  if($text.Length -gt 400000){$text=$text.Substring(0,400000)+"`r`n[Display truncated; full JSON retained in response.json.]"};$output.Text=$text
  if(-not $r.ok){if([string]$r.error -match 'run_Open_Lab_as_administrator_explicitly'){throw 'پنجره را ببندید؛ Start.cmd را با Run as administrator دوباره باز کنید. هیچ ارتقای خودکار دسترسی انجام نمی‌شود.'};throw ([string]$r.error+' | '+$j.response)}
  if($r.PSObject.Properties.Name -contains 'state'){RenderState $r.state ($j.action -in @('load','configure','import_whitelist'))}
  $status.Text='انجام شد: '+$j.action+' | '+$j.response
  if($r.PSObject.Properties.Name -contains 'native_ok'){
   if(-not $r.native_ok){throw ('Native operation failed; inspect details/journal; do not retry Apply. '+$j.response)}
   if($j.action -ceq 'native_apply_blacklist'){$status.Text='بلک‌لیست LAB ثبت شد؛ حفاظت جامع تأیید نشده. برای تغییر یا حذف قواعد، Restore.'}
   elseif($j.action -ceq 'native_restore'){$status.Text='درخواست Restore موفق گزارش شد؛ جزئیات نشست در گزارش محفوظ است.'}
  }
  if($j.action -ceq 'native_prepare'){$prepared=$r.preparation}
  if($j.action -in @('monitor_record','monitor_open','baseline_record','baseline_open')){$script:liveFinal=$true;Accept-LiveFrame $r.capture;$script:liveCapture=$r.capture.capture_id;$tabs.SelectedTab=$monitorTab}
  if($j.action -in @('monitor_history','baseline_history')){$script:historyMode=if($j.action -ceq 'baseline_history'){'baseline'}else{'selected'};Render-History $r.history;$tabs.SelectedTab=$historyTab}
  if($j.action -in @('monitor_export','baseline_export')){$status.Text='خروجی خصوصی، بدون مسیر کامل EXE: '+$r.export_file;[void][Diagnostics.Process]::Start('explorer.exe',('/select,"'+$r.export_file+'"'))}
  if($j.action -ceq 'hosts_read'){Render-Hosts $r.hosts;$tabs.SelectedTab=$hostsTab}
  if($j.action -ceq 'hosts_prepare'){$hostsPrepared=$r.hosts_plan}
  if($j.action -ceq 'hosts_apply'){$script:hostsView=$null;$hostsGrid.Rows.Clear();$hostsSummary.Text='عملیات پایان یافت؛ برای وضعیت فعلی بازخوانی کنید. نتیجه در جزئیات است. پشتیبان: private-state\hosts-backups';$tabs.SelectedTab=$hostsTab}

  if($j.action -notin @('load','monitor_record','monitor_history','monitor_open','baseline_record','baseline_history','baseline_open','hosts_read','hosts_prepare','hosts_apply')){$tabs.SelectedTab=$detailTab}
  if($j.action -ne 'preview'){$detailHint.Text='جزئیات آخرین عملیات؛ فایل کامل JSON در پوشهٔ گزارش‌هاست. رصد TCP نمونه‌برداری است، نه ضبط همهٔ بسته‌ها. گزارش‌ها خصوصی‌اند.'}
  if($j.action -ceq 'preview'){$detailHint.Text='پیش‌نمایش: overlaps تعارض‌ها و تقدم Block را توضیح می‌دهد. activation_allowed=false مربوط به محدودیت انتشار است؛ مسیر دستی فقط blacklist_only LAB است.'}
  if($j.action -in @('monitor_record','baseline_record') -and ($r.capture.query_errors -gt 0 -or $r.capture.successful_samples -eq 0)){$status.Text='رصد ناقص/خطای خواندن؛ خروجی خالی به معنی نبود ترافیک نیست. '+$j.response}
 }catch{
  if($j.action -in @('monitor_record','baseline_record') -and $null -eq $script:liveFrame){$liveStatus.Text='رصد ناموفق بود؛ هنوز نمونهٔ معتبری نداریم.';$popupStatus.Text=$liveStatus.Text}
  if($j.action -in @('monitor_record','baseline_record') -and $null -ne $script:liveFrame){
   $script:liveFrame.status='interrupted';$script:liveFrame.last_sample_ok=$false
   foreach($row in $script:liveFrame.endpoints){$row.presence='unknown'}
   $script:liveFinal=$true;$script:liveCapture=$null;Accept-LiveFrame $script:liveFrame
  }
  $status.Text='خطا: '+$_.Exception.Message;$tabs.SelectedTab=$detailTab
 }
 finally{$j.process.Dispose();$script:job=$null;SetBusy $false}
 if($script:closing){if($null -eq $script:ptrJob){$form.Close()};return}
 if($null -ne $hostsPrepared){TryOp {
  $lines=@('SYSTEM-WIDE HOSTS / NOT PER EXE','این تغییر روی همهٔ برنامه‌ها و همهٔ اتصال‌ها اثر می‌گذارد، نه فقط EXE تیک‌خورده.', 'وایت‌لیست نمی‌تواند hosts را خنثی کند. زیردامنه‌ها خودکار پوشش داده نمی‌شوند.', 'حذف نگاشت، تمام نگاشت‌های همان نام را حذف می‌کند؛ پشتیبان محلی نگه داشته می‌شود.', 'ممکن است ورود، به‌روزرسانی، سایت یا VPN وابسته به این نام‌ها مختل شود.', 'کش DNS پاک نمی‌شود؛ اتصال موجود و DNS داخلی بعضی برنامه‌ها ممکن است این فایل را دور بزنند.',(ConvertTo-Json -InputObject $hostsPrepared -Depth 12),'','I ACCEPT SYSTEM WIDE HOSTS CHANGES')
  if(ConfirmText 'تأیید جداگانهٔ hosts سراسری' ($lines -join "`r`n") 'I ACCEPT SYSTEM WIDE HOSTS CHANGES'){
   BeginOp 'hosts_apply' @{domains=$script:hostsPending.domains;operation=$script:hostsPending.operation;expected_sha256=[string]$hostsPrepared.expected_sha256;plan_digest=[string]$hostsPrepared.plan_digest;confirmation='I ACCEPT SYSTEM WIDE HOSTS CHANGES'}
  }
 }}
 if($null -ne $prepared){TryOp {
  $rangeAck='';$loginAck=''
  if(@($prepared.additional_risks.network_ranges).Count -gt 0){
   if(-not (ConfirmText 'تأیید اضافهٔ بازهٔ شبکه' ((ConvertTo-Json -InputObject $prepared.additional_risks.network_ranges -Depth 8)+"`r`nاین قواعد چندین IP را پوشش می‌دهند و می‌توانند سرویس‌های دیگر را هم قطع کنند.`r`nI ACCEPT NETWORK RANGE RISK") 'I ACCEPT NETWORK RANGE RISK')){return};$rangeAck='I ACCEPT NETWORK RANGE RISK'
  }
  if(@($prepared.additional_risks.known_login_endpoint_entry_ids).Count -gt 0){
   if(-not (ConfirmText 'تأیید اضافهٔ خطر ورود' "طرح شامل مقصد ورود شناخته‌شدهٔ نسخهٔ قبلی است و می‌تواند ورود را مختل کند. این تشخیص فهرست کامل همهٔ سرویس‌های حیاتی نیست.`r`nI ACCEPT LOGIN DISRUPTION RISK" 'I ACCEPT LOGIN DISRUPTION RISK')){return};$loginAck='I ACCEPT LOGIN DISRUPTION RISK'
  }
  $lines=@('BLACKLIST ONLY / LAB — not a kill-switch','اعمال روی کل تنظیمات است، نه فقط EXEهای تیک‌خورده.',('Rules: '+$prepared.rule_count),('Generation: '+$prepared.generation),('Plan SHA256: '+$prepared.plan_digest),'')
  foreach($item in $prepared.programs){$lines+=@($item.path,('SHA256: '+$item.sha256),'')};$lines+=@('هشدار: CIDR/بازه چندین مقصد را می‌پوشاند و ممکن است ورود، به‌روزرسانی یا VPN را مختل کند؛ فقط پس از بررسی دامنهٔ دقیق ادامه دهید.','EXACT RULES / مقصد، برنامه، پروتکل و پورت:',(ConvertTo-Json -InputObject @($prepared.rules) -Depth 16),'');$lines+=@('ویرایش بعدی قواعد فعال را تغییر نمی‌دهد. بستن برنامه Restore نیست.','برای ادامه دقیقاً عبارت زیر را وارد کنید:','I ACCEPT LAB NETWORK CHANGES')
  if(ConfirmText 'تأیید اعمال واقعی بلک‌لیست' ($lines -join "`r`n") 'I ACCEPT LAB NETWORK CHANGES'){BeginOp 'native_apply_blacklist' @{generation=[int]$prepared.generation;plan_digest=[string]$prepared.plan_digest;legacy_ack=$script:legacyAck;range_confirmation=$rangeAck;login_confirmation=$loginAck;confirmation='I ACCEPT LAB NETWORK CHANGES'}}
 }}
})
$form.Add_FormClosing({param($sender,$e)
 if($null -ne $script:job){
  $e.Cancel=$true
  if($script:job.action -in @('monitor_record','baseline_record')){$script:closing=$true;[IO.File]::WriteAllText((Join-Path $script:job.folder 'stop.txt'),'stop');Stop-Ptr;$status.Text='توقف رصد/PTR درخواست شد؛ پس از پایان خواندن بسته می‌شود.'}
  else{$status.Text='تا پایان عملیات صبر کنید. بستن اجباری، بازیابی قواعد را تضمین نمی‌کند.'}
 }elseif($null -ne $script:ptrJob){$e.Cancel=$true;$script:closing=$true;Stop-Ptr;$status.Text='پس از پایان PTR بسته می‌شود.'}
})
function WrapLabels {foreach($label in $script:wrapLabels){if($null -ne $label.Parent){$width=[Math]::Max(96,[Math]::Min($main.ClientSize.Width-36,$label.Parent.ClientSize.Width-24));if($label.MaximumSize.Width -ne $width){$label.MaximumSize=New-Object Drawing.Size($width,0)}}}}
$form.Add_Resize({WrapLabels});$tabs.Add_SelectedIndexChanged({WrapLabels});$form.Add_Shown({WrapLabels})
try{$timer.Start();BeginOp 'load' @{};[void]$form.ShowDialog()}finally{$timer.Stop();$timer.Dispose();if($held){$mutex.ReleaseMutex()};$mutex.Dispose();$tip.Dispose();foreach($menu in $script:observedMenus){$menu.Dispose()};$livePopup.Dispose();$form.Dispose()}
