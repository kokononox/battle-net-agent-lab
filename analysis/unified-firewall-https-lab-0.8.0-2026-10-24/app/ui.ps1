# Windows-only preview/observation interface. All mutation controls are disabled.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$root=Split-Path $PSScriptRoot -Parent
$mutex=New-Object Threading.Mutex($false,'Local\UnifiedFWPreview060')
$held=$false;try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
if(-not $held){[Windows.Forms.MessageBox]::Show('Another preview window is open.');exit 1}
$script:state=$null;$script:job=$null;$script:closing=$false
$form=New-Object Windows.Forms.Form
$form.Text='Unified Firewall 0.8.0 LAB — Policy editor / TCP observer'
$form.Size=New-Object Drawing.Size(1120,850);$form.MinimumSize=New-Object Drawing.Size(980,720)
$form.StartPosition='CenterScreen';$form.Font=New-Object Drawing.Font('Tahoma',10)
$layout=New-Object Windows.Forms.TableLayoutPanel;$layout.Dock='Fill';$layout.ColumnCount=1;$layout.RowCount=4
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,70)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,55)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,35)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,45)))
$form.Controls.Add($layout)
$banner=New-Object Windows.Forms.Label;$banner.Dock='Fill';$banner.RightToLeft='Yes';$banner.ForeColor=[Drawing.Color]::DarkRed
$banner.Text='نسخهٔ توسعه‌ای: انتخاب چند EXE، تنظیم سیاست مشترک، پیش‌نمایش تعارض‌ها و رصد TCP. در این پنجره قواعد اعمال نمی‌شوند؛ مسیر واقعی Apply/Restore فقط در کنسول LAB با تأیید صریح است. ویرایش تنظیمات قواعد فعال را تغییر نمی‌دهد: ابتدا Restore سپس Apply. حفاظت بیرون VPN پیاده نشده است.'
$layout.Controls.Add($banner,0,0)
$tabs=New-Object Windows.Forms.TabControl;$tabs.Dock='Fill';$layout.Controls.Add($tabs,0,1)
function PanelTab([string]$Name){$t=New-Object Windows.Forms.TabPage;$t.Text=$Name;$t.Padding=New-Object Windows.Forms.Padding(8);[void]$tabs.TabPages.Add($t);return $t}
function MakeButton([string]$Text){$b=New-Object Windows.Forms.Button;$b.Text=$Text;$b.AutoSize=$true;$b.MinimumSize=New-Object Drawing.Size(130,34);return $b}
function MakeFlow{$f=New-Object Windows.Forms.FlowLayoutPanel;$f.Dock='Fill';$f.AutoScroll=$true;return $f}
$programTab=PanelTab '۱. برنامه‌ها / رصد';$policyTab=PanelTab '۲. سیاست مشترک';$blackTab=PanelTab '۳. بلک‌لیست'
$progLayout=New-Object Windows.Forms.TableLayoutPanel;$progLayout.Dock='Fill';$progLayout.RowCount=3;$progLayout.ColumnCount=1
[void]$progLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,30)))
[void]$progLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
[void]$progLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,90)))
$programTab.Controls.Add($progLayout)
$hint=New-Object Windows.Forms.Label;$hint.Dock='Fill';$hint.Text='تیک‌ها فقط هدفِ افزودن بلک‌لیست / رصد / حذف را انتخاب می‌کنند؛ کلید روشن‌وخاموش سیاست نیستند.';$hint.RightToLeft='Yes';$progLayout.Controls.Add($hint,0,0)
$programs=New-Object Windows.Forms.CheckedListBox;$programs.Dock='Fill';$programs.CheckOnClick=$true;$programs.HorizontalScrollbar=$true;$progLayout.Controls.Add($programs,0,1)
$pb=MakeFlow;$progLayout.Controls.Add($pb,0,2)
$add=MakeButton 'انتخاب چند EXE';$remove=MakeButton 'حذف تیک‌خورده‌ها';$observe=MakeButton 'رصد تیک‌خورده‌ها';$stop=MakeButton 'توقف رصد';$reload=MakeButton 'بازخوانی'
$duration=New-Object Windows.Forms.NumericUpDown;$duration.Minimum=1;$duration.Maximum=120;$duration.Value=30;$duration.Width=65
foreach($c in @($add,$remove,$observe,$duration,$stop,$reload)){$pb.Controls.Add($c)}
$polLayout=New-Object Windows.Forms.TableLayoutPanel;$polLayout.Dock='Fill';$polLayout.ColumnCount=1;$polLayout.RowCount=3
[void]$polLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,42)))
[void]$polLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
[void]$polLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,85)))
$policyTab.Controls.Add($polLayout)
$mode=New-Object Windows.Forms.ComboBox;$mode.DropDownStyle='DropDownList';$mode.Width=260
[void]$mode.Items.AddRange(@('blacklist_only','vpn_allowlist','full_isolation'));$mode.SelectedIndex=0
$modeBar=MakeFlow;$modeBar.Controls.Add($mode);$whHint=New-Object Windows.Forms.Label;$whHint.AutoSize=$true;$whHint.Text='هر خط: IP، CIDR یا بازه؛ روی همهٔ تونل‌ها. دامنه فعلاً پذیرفته نمی‌شود.';$modeBar.Controls.Add($whHint);$polLayout.Controls.Add($modeBar,0,0)
$whitelist=New-Object Windows.Forms.TextBox;$whitelist.Multiline=$true;$whitelist.ScrollBars='Vertical';$whitelist.Dock='Fill';$whitelist.Font=New-Object Drawing.Font('Consolas',11)
$polLayout.Controls.Add($whitelist,0,1)
$polButtons=MakeFlow;$save=MakeButton 'ذخیرهٔ تنظیمات';$preview=MakeButton 'پیش‌نمایش همهٔ قواعد';$importBlack=MakeButton 'ورود settings بلک‌لیست';$importWhite=MakeButton 'ورود config وایت‌لیست'
$apply=MakeButton 'Apply — غیرفعال';$restore=MakeButton 'Restore — غیرفعال';$apply.Enabled=$false;$restore.Enabled=$false
$labHelp=MakeButton 'راهنمای آزمون ویندوز'
foreach($c in @($save,$preview,$importBlack,$importWhite,$apply,$restore,$labHelp)){$polButtons.Controls.Add($c)}
$polLayout.Controls.Add($polButtons,0,2)
$bl=New-Object Windows.Forms.TableLayoutPanel;$bl.Dock='Fill';$bl.RowCount=3;$bl.ColumnCount=1
[void]$bl.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,42)))
[void]$bl.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
[void]$bl.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,85)))
$blackTab.Controls.Add($bl)
$entryBar=MakeFlow;$target=New-Object Windows.Forms.TextBox;$target.Width=310
$target.Text='8.8.8.8';$proto=New-Object Windows.Forms.ComboBox;$proto.DropDownStyle='DropDownList';[void]$proto.Items.AddRange(@('TCP','UDP'));$proto.SelectedIndex=0;$proto.Width=80
$port=New-Object Windows.Forms.NumericUpDown;$port.Minimum=1;$port.Maximum=65535;$port.Value=443;$port.Width=90
$addEntry=MakeButton 'افزودن برای EXEهای تیک‌خورده'
foreach($c in @($target,$proto,$port,$addEntry)){$entryBar.Controls.Add($c)};$bl.Controls.Add($entryBar,0,0)
$grid=New-Object Windows.Forms.DataGridView;$grid.Dock='Fill';$grid.ReadOnly=$true;$grid.AllowUserToAddRows=$false;$grid.AllowUserToDeleteRows=$false;$grid.SelectionMode='FullRowSelect';$grid.MultiSelect=$true;$grid.AutoSizeColumnsMode='Fill'
foreach($pair in @(@('target','مقصد'),@('protocol','پروتکل'),@('port','پورت'),@('programs','مسیر برنامه‌ها'))){$col=New-Object Windows.Forms.DataGridViewTextBoxColumn;$col.Name=$pair[0];$col.HeaderText=$pair[1];[void]$grid.Columns.Add($col)}
$bl.Controls.Add($grid,0,1)
$bb=MakeFlow;$deleteEntry=MakeButton 'حذف ردیف‌های انتخابی';$testFlow=MakeButton 'توضیح تصمیم برای یک EXE';$iface=New-Object Windows.Forms.ComboBox;$iface.DropDownStyle='DropDownList';[void]$iface.Items.AddRange(@('vpn','outside','unknown'));$iface.SelectedIndex=0;$iface.Width=100
foreach($c in @($deleteEntry,$testFlow,$iface)){$bb.Controls.Add($c)};$bl.Controls.Add($bb,0,2)
$status=New-Object Windows.Forms.Label;$status.Dock='Fill';$status.Text='Loading...';$layout.Controls.Add($status,0,2)
$output=New-Object Windows.Forms.TextBox;$output.Multiline=$true;$output.ReadOnly=$true;$output.ScrollBars='Both';$output.WordWrap=$false;$output.Dock='Fill';$output.Font=New-Object Drawing.Font('Consolas',10);$layout.Controls.Add($output,0,3)
$script:programRows=@()
function CheckedIds{return ,@($programs.CheckedIndices|ForEach-Object{$script:programRows[[int]$_].id})}
function Generation{if($null -eq $script:state){throw 'configuration_not_loaded'};return [int]$script:state.config.generation}
function RenderState($s,[bool]$Editor){
 $checked=@(CheckedIds);$script:state=$s;$script:programRows=@($s.config.programs);$programs.Items.Clear()
 foreach($p in $script:programRows){$index=$programs.Items.Add($p.path+' | SHA256 '+$p.sha256.Substring(0,12));$programs.SetItemChecked($index,($checked -contains $p.id))}
 if($Editor){$mode.SelectedItem=[string]$s.config.mode;$whitelist.Lines=@($s.config.whitelist)}
 $map=@{};foreach($p in $s.config.programs){$map[$p.id]=$p.path};$grid.Rows.Clear()
 foreach($e in $s.config.blacklist){$i=$grid.Rows.Add($e.target,$e.protocol,$e.port,(@($e.program_ids|ForEach-Object{$map[$_]}) -join '; '));$grid.Rows[$i].Tag=$e.id}
}
function SetBusy([bool]$Busy){foreach($c in @($add,$remove,$observe,$reload,$save,$preview,$importBlack,$importWhite,$addEntry,$deleteEntry,$testFlow,$mode,$whitelist,$programs)){$c.Enabled=-not $Busy};$stop.Enabled=($Busy -and $script:job.action -ceq 'observe')}
function BeginOp([string]$Action,$Payload){
 if($null -ne $script:job){return}
 $id=[guid]::NewGuid().ToString('N');$job=Join-Path $root ('private-state/jobs/'+$id);$null=New-Item -ItemType Directory -Path $job -Force
 $request=Join-Path $job 'request.json';$response=Join-Path $job 'response.json'
 [IO.File]::WriteAllText($request,(ConvertTo-Json -InputObject @{action=$Action;payload=$Payload} -Depth 16),(New-Object Text.UTF8Encoding($false)))
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=Join-Path $root 'runtime/python.exe';$info.Arguments='-I "'+(Join-Path $PSScriptRoot 'cli.py')+'" --request "'+$request+'" --response "'+$response+'"'
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardError=$true
 $proc=New-Object Diagnostics.Process;$proc.StartInfo=$info
 [void]$proc.Start();$script:job=@{action=$Action;process=$proc;folder=$job;response=$response};SetBusy $true;$status.Text=$Action+' — working (no firewall changes)'
}
function TryOp([scriptblock]$Body){try{& $Body}catch{$status.Text='Error: '+$_.Exception.Message}}
$add.Add_Click({TryOp {$d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='Executable files (*.exe)|*.exe';$d.Multiselect=$true;if($d.ShowDialog() -eq 'OK'){BeginOp 'register' @{generation=(Generation);paths=@($d.FileNames)}}}})
$remove.Add_Click({TryOp {$ids=CheckedIds;if($ids.Count -eq 0){throw 'tick_programs_first'};if([Windows.Forms.MessageBox]::Show('Remove these programs and their configuration references? No Windows rule will be removed.','Remove configuration only','YesNo','Warning') -eq 'Yes'){BeginOp 'remove_programs' @{generation=(Generation);program_ids=$ids}}}})
$reload.Add_Click({TryOp {if([Windows.Forms.MessageBox]::Show('Reload saved settings? Unsaved whitelist editor changes will be discarded.','Reload','YesNo') -eq 'Yes'){BeginOp 'load' @{}}}})
$save.Add_Click({TryOp {BeginOp 'configure' @{generation=(Generation);mode=[string]$mode.SelectedItem;whitelist=@($whitelist.Lines|Where-Object{$_.Trim()})}}})
$preview.Add_Click({TryOp {if([string]$mode.SelectedItem -cne $script:state.config.mode -or (@($whitelist.Lines|Where-Object{$_.Trim()}) -join "`n") -cne (@($script:state.config.whitelist) -join "`n")){throw 'save_policy_editor_first'};BeginOp 'preview' @{}}})
$addEntry.Add_Click({TryOp {$ids=CheckedIds;if($ids.Count -eq 0){throw 'tick_programs_first'};BeginOp 'add_blacklist' @{generation=(Generation);program_ids=$ids;target=$target.Text;protocol=[string]$proto.SelectedItem;port=[int]$port.Value}}})
$deleteEntry.Add_Click({TryOp {$ids=@($grid.SelectedRows|ForEach-Object{$_.Tag});if($ids.Count -eq 0){throw 'select_blacklist_rows_first'};BeginOp 'delete_blacklist' @{generation=(Generation);entry_ids=$ids}}})
$testFlow.Add_Click({TryOp {$ids=CheckedIds;if($ids.Count -ne 1){throw 'tick_exactly_one_program_for_decision'};BeginOp 'decision' @{program_id=$ids[0];address=$target.Text;protocol=[string]$proto.SelectedItem;port=[int]$port.Value;interface=[string]$iface.SelectedItem}}})
$observe.Add_Click({TryOp {$ids=CheckedIds;if($ids.Count -eq 0){throw 'tick_programs_first'};BeginOp 'observe' @{program_ids=$ids;seconds=[int]$duration.Value}}})
$stop.Add_Click({TryOp {if($null -ne $script:job -and $script:job.action -ceq 'observe'){[IO.File]::WriteAllText((Join-Path $script:job.folder 'stop.txt'),'stop');$status.Text='Stop requested; waiting for the current read to finish...'}}})
foreach($pair in @(@($importBlack,'import_blacklist'),@($importWhite,'import_whitelist'))){
 $button=$pair[0];$action=[string]$pair[1]
 $button.Tag=$action
 $button.Add_Click({param($sender,$eventArgs) TryOp {$d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='JSON (*.json)|*.json';if($d.ShowDialog() -eq 'OK'){BeginOp ([string]$sender.Tag) @{generation=(Generation);path=$d.FileName}}}})
}
$labHelp.Add_Click({[void][Windows.Forms.MessageBox]::Show('ابتدا Coexistence-Preflight.cmd را با Run as administrator اجرا کنید؛ فقط مسیر مقصد و وضعیت را می‌خواند و قاعده یا اتصال آزمایشی نمی‌سازد. مقصد آزمایش باید تحت کنترل شما و روی IP متفاوت از IP سرور VPN، با مسیر SSTP باشد. Coexistence-Test.cmd فقط دو EXE بسته را روی یک IP و پورت می‌آزماید. وایت‌لیست سراسری و full_isolation فعال نیستند. برای بازیابی نشست ثبت‌شده Open-Lab.cmd و RESTORE موجود است.','Windows LAB — not production','OK','Warning')})
$timer=New-Object Windows.Forms.Timer;$timer.Interval=250
$timer.Add_Tick({
 if($null -eq $script:job -or -not $script:job.process.HasExited){return}
 $j=$script:job
 try{
  if(-not (Test-Path -LiteralPath $j.response)){$err=$j.process.StandardError.ReadToEnd();throw ('backend_no_response: '+$err.Substring(0,[Math]::Min(400,$err.Length)))}
  $r=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($j.response))
  if(-not $r.ok){throw [string]$r.error}
  if($r.PSObject.Properties.Name -contains 'state'){RenderState $r.state ($j.action -in @('load','configure','import_whitelist'))}
  $text=ConvertTo-Json -InputObject $r -Depth 24
  if($text.Length -gt 400000){$text=$text.Substring(0,400000)+"`r`n[Display truncated; complete JSON remains in the result file.]"}
  $output.Text=$text;$status.Text='Completed: '+$j.action+' | '+$j.response
  if($j.action -ceq 'observe' -and ($r.observation.query_errors -gt 0 -or $r.observation.successful_samples -eq 0)){$status.Text='Observation incomplete / read errors; do not interpret empty rows as no traffic. '+$j.response}
 }catch{$status.Text='Error: '+$_.Exception.Message}
 finally{$j.process.Dispose();$script:job=$null;SetBusy $false;if($script:closing){$form.Close()}}
})
$form.Add_FormClosing({param($sender,$eventArgs)
 if($null -ne $script:job){$eventArgs.Cancel=$true;if($script:job.action -ceq 'observe'){$script:closing=$true;[IO.File]::WriteAllText((Join-Path $script:job.folder 'stop.txt'),'stop');$status.Text='Stopping observation before closing...'}else{$status.Text='Wait for the local configuration operation to finish.'}}
})
try{$timer.Start();BeginOp 'load' @{};[void]$form.ShowDialog()}finally{$timer.Stop();$timer.Dispose();if($held){$mutex.ReleaseMutex()};$mutex.Dispose();$form.Dispose()}
