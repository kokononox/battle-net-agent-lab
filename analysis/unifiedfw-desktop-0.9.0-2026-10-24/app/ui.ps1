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
$form.Text='Unified Firewall Desktop 0.9.0 RC / LAB'
$form.Size=New-Object Drawing.Size(1240,860);$form.MinimumSize=New-Object Drawing.Size(920,680)
$form.StartPosition='CenterScreen';$form.Font=New-Object Drawing.Font('Tahoma',10)
$form.AutoScaleMode='Dpi';$form.RightToLeft='Yes';$form.RightToLeftLayout=$true
$form.BackColor=[Drawing.ColorTranslator]::FromHtml('#F6F8FB');$form.ForeColor=$ink
function Stack($Parent,[int]$Rows){
 $v=New-Object Windows.Forms.TableLayoutPanel;$v.Dock='Fill';$v.ColumnCount=1;$v.RowCount=$Rows;$v.Padding=New-Object Windows.Forms.Padding(8)
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
$edition=Label '0.9.0 RC • Windows x64 • LAB';$edition.ForeColor=$blue;$header.Controls.Add($edition);$main.Controls.Add($header,0,0)
$notice=Label 'بلک‌لیست چند EXE + پیش‌نمایش وایت‌لیست | وایت‌لیست سراسری فعال نمی‌شود؛ Kill-switch پیاده نشده است. این نسخه تأیید حفاظت جامع ندارد.'
$notice.BackColor=[Drawing.ColorTranslator]::FromHtml('#FFF4D8');$notice.ForeColor=[Drawing.ColorTranslator]::FromHtml('#725010');$notice.Padding=New-Object Windows.Forms.Padding(8);$notice.Dock='Fill';$main.Controls.Add($notice,0,1)
$tabs=New-Object Windows.Forms.TabControl;$tabs.Dock='Fill';$main.Controls.Add($tabs,0,2)
$programTab=Tab '۱  برنامه‌ها و رصد';$blackTab=Tab '۲  بلک‌لیست';$policyTab=Tab '۳  وایت‌لیست و سیاست';$detailTab=Tab '۴  جزئیات و گزارش'
$p=Stack $programTab 4
$p.Controls.Add((Label 'تیک‌ها برای رصد / افزودن بلک‌لیست / حذف تنظیمات هستند؛ انتخاب ردیف یا تیک، کلید فعال‌سازی حفاظت نیست.'),0,0)
$bar=Flow;$filter=TextBox 270;$bar.Controls.Add((Label 'جست‌وجوی نام یا مسیر'));$bar.Controls.Add($filter)
$selectVisible=Button 'تیک همهٔ نمایان';$clearVisible=Button 'پاک‌کردن تیک نمایان';$clearAll=Button 'پاک‌کردن همهٔ تیک‌ها'
foreach($v in @($selectVisible,$clearVisible,$clearAll)){$bar.Controls.Add($v)};$p.Controls.Add($bar,0,1)
$pb=Flow;$add=Button 'انتخاب چند EXE';$remove=Button 'حذف تیک‌خورده‌ها';$observe=Button 'رصد TCP تیک‌خورده‌ها';$stop=Button 'توقف رصد';$copyPath=Button 'کپی مسیر ردیف';$reload=Button 'بازخوانی'
$duration=New-Object Windows.Forms.NumericUpDown;$duration.Minimum=1;$duration.Maximum=120;$duration.Value=30;$duration.Width=65;$duration.Margin=New-Object Windows.Forms.Padding(5,9,5,5)
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
 foreach($v in @($add,$remove,$observe,$reload,$save,$preview,$importBlack,$importWhite,$addEntry,$deleteEntry,$mode,$whitelist,$programGrid,$blackGrid,$filter,$selectVisible,$clearVisible,$clearAll,$target,$proto,$port,$duration,$apply,$restore,$nativeStatus,$copyPath)){$v.Enabled=-not $Busy}
 $stop.Enabled=($Busy -and $script:job.action -ceq 'observe')
 if(-not $Busy -and $null -ne $script:state){$apply.Enabled=($script:state.config.mode -ceq 'blacklist_only')}
}
function BeginOp([string]$Action,$Payload){
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
$observe.Add_Click({TryOp {$ids=CheckedIds;if($ids.Count -eq 0){throw 'ابتدا EXEها را تیک بزنید.'};BeginOp 'observe' @{program_ids=$ids;seconds=[int]$duration.Value}}})
$stop.Add_Click({TryOp {if($null -ne $script:job -and $script:job.action -ceq 'observe'){[IO.File]::WriteAllText((Join-Path $script:job.folder 'stop.txt'),'stop');$status.Text='توقف رصد درخواست شد؛ منتظر پایان خواندن جاری باشید.'}}})
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
$timer=New-Object Windows.Forms.Timer;$timer.Interval=250
$timer.Add_Tick({
 if($null -eq $script:job -or -not $script:job.process.HasExited){return};$j=$script:job;$prepared=$null
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
  if($j.action -ne 'load'){$tabs.SelectedTab=$detailTab}
  if($j.action -ne 'preview'){$detailHint.Text='جزئیات آخرین عملیات؛ فایل کامل JSON در پوشهٔ گزارش‌هاست. رصد TCP نمونه‌برداری است، نه ضبط همهٔ بسته‌ها. گزارش‌ها خصوصی‌اند.'}
  if($j.action -ceq 'preview'){$detailHint.Text='پیش‌نمایش: overlaps تعارض‌ها و تقدم Block را توضیح می‌دهد. activation_allowed=false مربوط به محدودیت انتشار است؛ مسیر دستی فقط blacklist_only LAB است.'}
  if($j.action -ceq 'observe' -and ($r.observation.query_errors -gt 0 -or $r.observation.successful_samples -eq 0)){$status.Text='رصد ناقص/خطای خواندن؛ خروجی خالی به معنی نبود ترافیک نیست. '+$j.response}
 }catch{$status.Text='خطا: '+$_.Exception.Message;$tabs.SelectedTab=$detailTab}
 finally{$j.process.Dispose();$script:job=$null;SetBusy $false}
 if($script:closing){$form.Close();return}
 if($null -ne $prepared){TryOp {
  $lines=@('BLACKLIST ONLY / LAB — not a kill-switch','اعمال روی کل تنظیمات است، نه فقط EXEهای تیک‌خورده.',('Rules: '+$prepared.rule_count),('Generation: '+$prepared.generation),('Plan SHA256: '+$prepared.plan_digest),'')
  foreach($item in $prepared.programs){$lines+=@($item.path,('SHA256: '+$item.sha256),'')};$lines+=@('EXACT RULES / مقصد، برنامه، پروتکل و پورت:',(ConvertTo-Json -InputObject @($prepared.rules) -Depth 16),'');$lines+=@('ویرایش بعدی قواعد فعال را تغییر نمی‌دهد. بستن برنامه Restore نیست.','برای ادامه دقیقاً عبارت زیر را وارد کنید:','I ACCEPT LAB NETWORK CHANGES')
  if(ConfirmText 'تأیید اعمال واقعی بلک‌لیست' ($lines -join "`r`n") 'I ACCEPT LAB NETWORK CHANGES'){BeginOp 'native_apply_blacklist' @{generation=[int]$prepared.generation;plan_digest=[string]$prepared.plan_digest;legacy_ack=$script:legacyAck;confirmation='I ACCEPT LAB NETWORK CHANGES'}}
 }}
})
$form.Add_FormClosing({param($sender,$e)
 if($null -ne $script:job){$e.Cancel=$true;if($script:job.action -ceq 'observe'){$script:closing=$true;[IO.File]::WriteAllText((Join-Path $script:job.folder 'stop.txt'),'stop');$status.Text='رصد متوقف می‌شود؛ سپس پنجره بسته خواهد شد.'}else{$status.Text='تا پایان عملیات صبر کنید. بستن اجباری، بازیابی قواعد را تضمین نمی‌کند.'}}
})
function WrapLabels {foreach($label in $script:wrapLabels){if($null -ne $label.Parent){$width=[Math]::Max(240,[Math]::Min($main.ClientSize.Width-36,$label.Parent.ClientSize.Width-24));if($label.MaximumSize.Width -ne $width){$label.MaximumSize=New-Object Drawing.Size($width,0)}}}}
$form.Add_Resize({WrapLabels});$tabs.Add_SelectedIndexChanged({WrapLabels});$form.Add_Shown({WrapLabels})
try{$timer.Start();BeginOp 'load' @{};[void]$form.ShowDialog()}finally{$timer.Stop();$timer.Dispose();if($held){$mutex.ReleaseMutex()};$mutex.Dispose();$form.Dispose()}
