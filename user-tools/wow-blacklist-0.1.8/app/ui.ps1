$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$root=$env:WOW_BL_ROOT;$private=Join-Path $root 'private-state';[void][IO.Directory]::CreateDirectory($private)
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-model.ps1'))))
$script:job=$null;$script:closeAfterObserve=$false;$script:reselected=$false;$script:observed=@();$script:actual=@{};$script:actualAt='';$script:loading=$false;$script:dirty=$false;$script:ptr=@{};$script:closeAfterLookup=$false;$script:observationSnapshot=$null;$script:observationProgram='';$script:observedChecks=@{};$script:renderingObserved=$false;$script:observationTruncated=$false;$script:resetObservedChecks=$false;$script:syncingObservedChecks=$false;$script:captureId='';$script:stageEdits=@{};$script:annotationsDirty=$false;$script:syncingStages=$false;$script:observationHistorical=$false;$script:historyNeedsRefresh=$true
$form=New-Object Windows.Forms.Form
$form.Text='WoW Blacklist · 0.1.8';$form.ClientSize=New-Object Drawing.Size(1240,960);$form.MinimumSize=New-Object Drawing.Size(1000,800);$form.StartPosition='CenterScreen';$form.BackColor=[Drawing.Color]::White;$form.Font=New-Object Drawing.Font('Tahoma',10.5);$form.AutoScaleMode='Dpi'
$layout=New-Object Windows.Forms.TableLayoutPanel;$layout.Dock='Fill';$layout.AutoScroll=$true;$layout.Padding=New-Object Windows.Forms.Padding(16);$layout.ColumnCount=1;$layout.RowCount=10
foreach($height in @(40,58,44,52,-1,82,108,40,108,56)){
 $style=if($height -eq -1){New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)}else{New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$height)}
 [void]$layout.RowStyles.Add($style)
}
$form.Controls.Add($layout)
function Label([string]$value){$c=New-Object Windows.Forms.Label;$c.Text=$value;$c.Dock='Fill';$c.TextAlign='MiddleRight';$c.RightToLeft='Yes';return $c}
function Button([string]$value){$c=New-Object Windows.Forms.Button;$c.Text=$value;$c.AutoSize=$true;$c.MinimumSize=New-Object Drawing.Size(130,44);$c.FlatStyle='Flat';$c.Margin=New-Object Windows.Forms.Padding(4);return $c}
function Flow {$p=New-Object Windows.Forms.FlowLayoutPanel;$p.Dock='Fill';$p.FlowDirection='RightToLeft';$p.AutoScroll=$true;return $p}
function Grid {
 $g=New-Object Windows.Forms.DataGridView;$g.Dock='Fill';$g.ReadOnly=$true;$g.AllowUserToAddRows=$false;$g.AllowUserToDeleteRows=$false;$g.RowHeadersVisible=$false;$g.MultiSelect=$true;$g.SelectionMode='FullRowSelect';$g.BackgroundColor=[Drawing.Color]::White;$g.BorderStyle='FixedSingle';$g.AutoSizeColumnsMode='Fill';$g.RightToLeft='No';$g.EnableHeadersVisualStyles=$false;$g.ColumnHeadersDefaultCellStyle.BackColor=[Drawing.Color]::FromArgb(240,239,237);$g.ColumnHeadersHeightSizeMode='DisableResizing';$g.ColumnHeadersHeight=38;$g.RowTemplate.Height=44;$g.AlternatingRowsDefaultCellStyle.BackColor=[Drawing.Color]::FromArgb(249,248,247);$g.DefaultCellStyle.Font=New-Object Drawing.Font('Tahoma',10);$g.DefaultCellStyle.SelectionBackColor=[Drawing.Color]::FromArgb(229,242,252);$g.DefaultCellStyle.SelectionForeColor=[Drawing.Color]::FromArgb(44,44,43);return $g
}
function Column($g,[string]$name,[string]$caption,[int]$weight){$c=New-Object Windows.Forms.DataGridViewTextBoxColumn;$c.Name=$name;$c.HeaderText=$caption;$c.FillWeight=$weight;$c.MinimumWidth=64;$c.SortMode='Automatic';[void]$g.Columns.Add($c)}
$heading=Label 'فهرست سیاه — رصد با شواهد و نمایش hosts';$heading.Font=New-Object Drawing.Font('Tahoma',17,[Drawing.FontStyle]::Bold);$layout.Controls.Add($heading,0,0)
$warning=Label 'قوانین پس از بستن پنجره و ری‌استارت باقی می‌مانند. حذف یک ردیف ابتدا فقط فهرست را تغییر می‌دهد؛ «اعمال تغییرات» یا «حذف انتخاب‌ها و اعمال» فایروال را به‌روزرسانی می‌کند.';$warning.BackColor=[Drawing.Color]::FromArgb(255,241,223);$layout.Controls.Add($warning,0,1)
$programRow=New-Object Windows.Forms.TableLayoutPanel;$programRow.Dock='Fill';$programRow.ColumnCount=2;[void]$programRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100)));[void]$programRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,180)))
$program=New-Object Windows.Forms.TextBox;$program.ReadOnly=$true;$program.Dock='Fill';$program.RightToLeft='No';$program.Margin=New-Object Windows.Forms.Padding(4,10,8,0);$program.AccessibleName='Selected Wow.exe path';$pick=Button 'انتخاب Wow.exe';$programRow.Controls.Add($program,0,0);$programRow.Controls.Add($pick,1,0);$layout.Controls.Add($programRow,0,2)
$captureRow=Flow;$captureRow.WrapContents=$false;$observe=Button 'رصد مقصدهای TCP';$stop=Button 'توقف رصد / شناسایی';$stop.Enabled=$false
$duration=New-Object Windows.Forms.ComboBox;$duration.DropDownStyle='DropDownList';$duration.Width=80;$duration.Margin=New-Object Windows.Forms.Padding(8,12,8,0);[void]$duration.Items.AddRange(@('60','120','300','تا توقف'));$duration.SelectedItem='120'
$note=New-Object Windows.Forms.Label;$note.Text='ثانیه؛ رصد فقط TCP است، نه محتوای بسته‌ها';$note.AutoSize=$true;$note.Margin=New-Object Windows.Forms.Padding(8,14,8,0)
$liveEnabled=New-Object Windows.Forms.CheckBox;$liveEnabled.Text='پاپ‌آپ زنده';$liveEnabled.Checked=$true;$liveEnabled.AutoSize=$true;$liveEnabled.Margin=New-Object Windows.Forms.Padding(8,14,8,0);$liveOpen=Button 'نمایش مانیتور زنده'
$analysisExport=Button 'خروجی تحلیلی رصدها';$captureRow.Controls.AddRange(@($observe,$stop,$duration,$liveEnabled,$liveOpen,$analysisExport));$layout.Controls.Add($captureRow,0,3)
$tabs=New-Object Windows.Forms.TabControl;$tabs.Dock='Fill';$tabs.MinimumSize=New-Object Drawing.Size(0,260);$tabs.Font=New-Object Drawing.Font('Tahoma',11)
$blackTab=New-Object Windows.Forms.TabPage;$blackTab.Text='لیست سیاه';$blackTab.Padding=New-Object Windows.Forms.Padding(6)
$obsTab=New-Object Windows.Forms.TabPage;$obsTab.Text='رصد اصلی';$obsTab.Padding=New-Object Windows.Forms.Padding(6)
$coveredTab=New-Object Windows.Forms.TabPage;$coveredTab.Text='زیر پوشش Block';$coveredTab.Padding=New-Object Windows.Forms.Padding(6)
$hostsTab=New-Object Windows.Forms.TabPage;$hostsTab.Text='فایل hosts — ویرایش تأییدشده';$hostsTab.Padding=New-Object Windows.Forms.Padding(6)
$historyTab=New-Object Windows.Forms.TabPage;$historyTab.Text='ضبط‌ها و خروجی تحلیلی';$historyTab.Padding=New-Object Windows.Forms.Padding(6)
[void]$tabs.TabPages.Add($historyTab);[void]$tabs.TabPages.Add($blackTab);[void]$tabs.TabPages.Add($obsTab);[void]$tabs.TabPages.Add($coveredTab);[void]$tabs.TabPages.Add($hostsTab);$tabs.SelectedTab=$blackTab;$layout.Controls.Add($tabs,0,4)
$black=Grid;$black.AccessibleName='Blacklist table: IP, port, protocol, rule status and reason'
Column $black 'ip' 'IP / CIDR' 24;Column $black 'port' 'Port' 9;Column $black 'protocol' 'Protocol' 10;Column $black 'hostname' 'نام میزبان / PTR' 24;Column $black 'ptrstate' 'وضعیت PTR' 16;Column $black 'state' 'وضعیت قانون' 22;Column $black 'reason' 'شرح / مبنای انتخاب' 35
$black.Columns['ip'].MinimumWidth=190;$black.Columns['state'].MinimumWidth=170;$black.Columns['reason'].DefaultCellStyle.Alignment='MiddleRight';$black.Columns['state'].DefaultCellStyle.Alignment='MiddleRight';$black.ShowCellToolTips=$true
$black.Columns['ip'].DefaultCellStyle.Font=New-Object Drawing.Font('Consolas',11);$black.Columns['port'].ValueType=[int]
$delcol=New-Object Windows.Forms.DataGridViewButtonColumn;$delcol.Name='remove';$delcol.HeaderText='حذف تکی';$delcol.Text='حذف';$delcol.UseColumnTextForButtonValue=$true;$delcol.FillWeight=10;$delcol.MinimumWidth=72;[void]$black.Columns.Add($delcol);$blackTab.Controls.Add($black)
$found=Grid;$found.AccessibleName='Observed TCP endpoints; choose rows then add';$found.MultiSelect=$true
$check=New-Object Windows.Forms.DataGridViewCheckBoxColumn;$check.Name='choose';$check.HeaderText='انتخاب';$check.FillWeight=10;$check.MinimumWidth=70;[void]$found.Columns.Add($check);$found.ReadOnly=$false
Column $found 'ip' 'IP' 30;Column $found 'port' 'Port' 10;Column $found 'protocol' 'Protocol' 12;Column $found 'hostname' 'نام میزبان / PTR' 24;Column $found 'ptrstate' 'وضعیت PTR' 16;Column $found 'samples' 'دفعات مشاهده' 20;Column $found 'fresh' 'فرایند تازه' 18
Column $found 'history' 'مقصد تازه / قدیمی' 24
Column $found 'tcpstate' 'حالت‌های TCP دیده‌شده' 20;Column $found 'pid' 'PID' 8;Column $found 'coverage' 'مبنای تفکیک Block' 20
foreach($c in $found.Columns){if($c.Name -ne 'choose'){$c.ReadOnly=$true}}
$stageColumn=New-Object Windows.Forms.DataGridViewButtonColumn;$stageColumn.Name='stage';$stageColumn.HeaderText='مرحله‌ها؛ کلیک برای انتخاب';$stageColumn.ReadOnly=$false;$stageColumn.FlatStyle='Flat';[void]$found.Columns.Add($stageColumn)
$covered=Grid;$covered.ReadOnly=$false;$covered.EditMode='EditOnEnter';$covered.AccessibleName='Observed destinations matching verified owned Block specifications; not packet-drop evidence'
foreach($c in $found.Columns){[void]$covered.Columns.Add($c.Clone())}
$coveredLayout=New-Object Windows.Forms.TableLayoutPanel;$coveredLayout.Dock='Fill';$coveredLayout.RowCount=2;$coveredLayout.ColumnCount=1;[void]$coveredLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,48)));[void]$coveredLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)));$coveredNotice=Label 'فقط تطابق مشخصات Block در زمان بررسی؛ نه اثبات افت بسته. فیلتر فرایند تازه در تب رصد اصلی روی این تب هم اثر دارد.';$coveredNotice.Font=New-Object Drawing.Font('Tahoma',9);$coveredLayout.Controls.Add($coveredNotice,0,0);$coveredLayout.Controls.Add($covered,0,1);$coveredTab.Controls.Add($coveredLayout)
$obsLayout=New-Object Windows.Forms.TableLayoutPanel;$obsLayout.Dock='Fill';$obsLayout.RowCount=3;$obsLayout.ColumnCount=1
[void]$obsLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,108)));[void]$obsLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)));[void]$obsLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,68)))
$obsFilters=Flow;$obsFilters.WrapContents=$true
$onlyFresh=New-Object Windows.Forms.CheckBox;$onlyFresh.Text='فقط فرایند تازه';$onlyFresh.Checked=$false;$onlyFresh.AutoSize=$true;$onlyFresh.RightToLeft='Yes';$onlyFresh.Margin=New-Object Windows.Forms.Padding(8,14,8,0)
$hideCovered=New-Object Windows.Forms.CheckBox;$hideCovered.Text='پنهان‌کردن موارد زیر پوشش Block';$hideCovered.Checked=$false;$hideCovered.AutoSize=$true;$hideCovered.RightToLeft='Yes';$hideCovered.Margin=New-Object Windows.Forms.Padding(8,14,8,0)
$reclassify=Button 'بازبینی تفکیک Block';$bulkStage=New-Object Windows.Forms.ComboBox;$bulkStage.DropDownStyle='DropDownList';$bulkStage.Width=140;$bulkStage.Margin=New-Object Windows.Forms.Padding(8,12,8,0);[void]$bulkStage.Items.AddRange(@('نامشخص','لانچ برنامه','ورود','داشبورد','محیط بازی','چند مرحله'));$bulkStage.SelectedIndex=0;$setSelectedStage=Button 'مرحله برای انتخاب‌ها';$saveAnnotations=Button 'ذخیرهٔ برچسب‌ها';$obsFilters.Controls.AddRange(@($onlyFresh,$hideCovered,$reclassify,$setSelectedStage,$saveAnnotations))
$obsSummary=Label 'پس از پیام آمادگی، بازی را تازه اجرا کن. رصد فقط متادیتای TCP است، نه اثبات افت بسته.';$obsSummary.Font=New-Object Drawing.Font('Tahoma',9)
$obsLayout.Controls.Add($obsFilters,0,0);$obsLayout.Controls.Add($found,0,1);$obsLayout.Controls.Add($obsSummary,0,2);$obsTab.Controls.Add($obsLayout)
$hostsLayout=New-Object Windows.Forms.TableLayoutPanel;$hostsLayout.Dock='Fill';$hostsLayout.ColumnCount=1;$hostsLayout.RowCount=3
[void]$hostsLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,52)));[void]$hostsLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)));[void]$hostsLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,80)))
$hostsRead=Button 'خواندن فایل hosts';$hostsTop=Flow;$hostsTop.Controls.Add($hostsRead)
$hostsGrid=Grid;$hostsGrid.AccessibleName='Read-only Windows hosts mappings; no game activity attribution';$hostsGrid.AutoSizeColumnsMode='None'
Column $hostsGrid 'domain' 'دامنهٔ ثبت‌شده' 30;Column $hostsGrid 'addresses' 'آدرس نگاشت' 24;Column $hostsGrid 'kind' 'نوع ثبت / محدودیت استنباط' 34;Column $hostsGrid 'lines' 'خط‌های فایل' 12
$hostsGrid.Columns['domain'].Width=250;$hostsGrid.Columns['addresses'].Width=260;$hostsGrid.Columns['kind'].Width=360;$hostsGrid.Columns['lines'].Width=140
$hostsSummary=Label 'ابتدا hosts را بخوان؛ افزودن/ویرایش/حذف تنها پس از تأیید و با پشتیبان اعمال می‌شود. تغییر سراسری است، نه فقط Wow.';$hostsSummary.Font=New-Object Drawing.Font('Tahoma',9)
$hostsLayout.Controls.Add($hostsTop,0,0);$hostsLayout.Controls.Add($hostsGrid,0,1);$hostsLayout.Controls.Add($hostsSummary,0,2);$hostsTab.Controls.Add($hostsLayout)

$historyLayout=New-Object Windows.Forms.TableLayoutPanel;$historyLayout.Dock='Fill';$historyLayout.ColumnCount=1;$historyLayout.RowCount=3
[void]$historyLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,52)));[void]$historyLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)));[void]$historyLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,80)))
$historyRefresh=Button 'خواندن تاریخچه';$historyLoad=Button 'بازکردن ضبط انتخابی';$historyExport=Button 'خروجی ضبط‌های انتخابی';$historyButtons=Flow;$historyButtons.WrapContents=$false;$historyButtons.Controls.AddRange(@($historyExport,$historyLoad,$historyRefresh))
$historyGrid=Grid;$historyGrid.AutoSizeColumnsMode='None';$historyGrid.AccessibleName='Saved capture history; multi-select records for a shareable analysis ZIP'
Column $historyGrid 'when' 'شروع ضبط UTC' 30;Column $historyGrid 'id' 'شناسه' 10;Column $historyGrid 'records' 'رکوردها' 10;Column $historyGrid 'annotated' 'مرحلهٔ مشخص‌شده' 15;Column $historyGrid 'hash' 'Hash بازی' 15;Column $historyGrid 'truncated' 'ضبط ناقص' 10;Column $historyGrid 'labels' 'وضعیت برچسب‌ها' 20
$historyGrid.Columns['when'].Width=250;$historyGrid.Columns['id'].Width=100;$historyGrid.Columns['records'].Width=90;$historyGrid.Columns['annotated'].Width=150;$historyGrid.Columns['hash'].Width=130;$historyGrid.Columns['truncated'].Width=100;$historyGrid.Columns['labels'].Width=240
$historySummary=Label 'تاریخچه هنوز خوانده نشده است. ضبط‌ها از output خوانده می‌شوند؛ برچسب مرحله دستی است، نه تشخیص خودکار.';$historySummary.Font=New-Object Drawing.Font('Tahoma',9)
$historyLayout.Controls.Add($historyButtons,0,0);$historyLayout.Controls.Add($historyGrid,0,1);$historyLayout.Controls.Add($historySummary,0,2);$historyTab.Controls.Add($historyLayout)
foreach($grid in @($black,$found,$covered)){$grid.AutoSizeColumnsMode='None';$grid.Columns['ip'].Width=190;$grid.Columns['port'].Width=68;$grid.Columns['protocol'].Width=78;$grid.Columns['hostname'].Width=220;$grid.Columns['ptrstate'].Width=145;$grid.Columns['hostname'].DefaultCellStyle.Font=New-Object Drawing.Font('Consolas',10)}
$black.Columns['state'].Width=180;$black.Columns['reason'].Width=230;$black.Columns['remove'].Width=80
foreach($grid in @($found,$covered)){$grid.Columns['choose'].Width=70;$grid.Columns['samples'].Width=100;$grid.Columns['fresh'].Width=120;$grid.Columns['tcpstate'].Width=180;$grid.Columns['pid'].Width=72;$grid.Columns['coverage'].Width=260;$grid.Columns['stage'].Width=360;$grid.Columns['history'].Width=200;$order=@('choose','ip','port','protocol','stage','history','tcpstate','pid','fresh','hostname','ptrstate','samples','coverage');for($i=0;$i -lt $order.Count;$i++){$grid.Columns[$order[$i]].DisplayIndex=$i}}
$details=New-Object Windows.Forms.TextBox;$details.Multiline=$true;$details.ReadOnly=$true;$details.Dock='Fill';$details.ScrollBars='Vertical';$details.RightToLeft='No';$details.Text='برای جزئیات یک ردیف را انتخاب کن. PTR دامنهٔ واقعی اتصال را ثابت نمی‌کند.';$details.BackColor=[Drawing.Color]::FromArgb(249,248,247);$layout.Controls.Add($details,0,5)
$listActions=Flow;$listActions.WrapContents=$true
$delete=Button 'حذف انتخاب‌ها';$deleteApply=Button 'حذف انتخاب‌ها و اعمال';$addFound=Button 'افزودن رصدشده‌ها';$import=Button 'بارگذاری TXT';$manual=Button 'افزودن IP تکی';$range=Button 'افزودن آسان رنج';$lookupSelected=Button 'شناسایی نام انتخاب‌ها';$lookupAll=Button 'شناسایی نام همهٔ این تب';$lookupFresh=Button 'استعلام تازهٔ انتخاب‌ها';$export=Button 'خروجی TXT';$listActions.Controls.AddRange(@($manual,$range,$import,$addFound,$delete,$deleteApply,$lookupSelected,$lookupAll,$lookupFresh));$layout.Controls.Add($listActions,0,6)
$consent=New-Object Windows.Forms.CheckBox;$consent.Text='با اعمال فهرست فعلی و باقی‌ماندن قواعد پس از بستن برنامه موافقم.';$consent.Dock='Fill';$consent.RightToLeft='Yes';$layout.Controls.Add($consent,0,7)
$actions=Flow;$actions.WrapContents=$true
$apply=Button 'اعمال تغییرات';$apply.BackColor=[Drawing.Color]::FromArgb(23,104,176);$apply.ForeColor=[Drawing.Color]::White
$applyClose=Button 'اعمال و بستن';$restore=Button 'بازگردانی همه';$restore.ForeColor=[Drawing.Color]::FromArgb(168,52,41);$save=Button 'فقط ذخیرهٔ لیست';$refresh=Button 'بررسی وضعیت';$exit=Button 'بستن'
$actions.Controls.AddRange(@($apply,$applyClose,$restore,$save,$export,$refresh,$exit));$layout.Controls.Add($actions,0,8)
$status=Label 'در حال خواندن وضعیت…';$layout.Controls.Add($status,0,9)
$script:controls=@($pick,$observe,$duration,$analysisExport,$tabs,$delete,$deleteApply,$addFound,$import,$manual,$range,$lookupSelected,$lookupAll,$lookupFresh,$export,$consent,$apply,$applyClose,$restore,$save,$refresh,$exit)
function Enabled([bool]$v){foreach($c in $script:controls){$c.Enabled=$v};$stop.Enabled=(!$v -and $script:job -and $script:job.Action -in @('observe','lookup'));if(Get-Command Set-LiveBusy -ErrorAction SilentlyContinue){Set-LiveBusy}}
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-range.ps1'))))
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-observation.ps1'))))
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-analysis.ps1'))))
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-live.ps1'))))
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-tools.ps1'))))
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $root 'app/ui-session.ps1'))))
$compareHistory=Button 'مقایسهٔ دو ضبط';$historyButtons.Controls.Add($compareHistory);$compareHistory.Add_Click({Start-CaptureComparison})
function PtrState($e) {
 if($e.ip.Contains('/')){return 'رنج؛ IP تکی لازم است'}
 if(!$script:ptr.ContainsKey([string]$e.ip)){return 'بررسی نشده'}
 $p=$script:ptr[[string]$e.ip];$label=switch($p.status){'found'{'نام پیدا شد'};'no_ptr'{'PTR ندارد'};'timeout'{'مهلت تمام شد'};default{'خطای DNS'}}
 if($p.stale -or [double]$p.expires_utc -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()){$label+=' (قدیمی)'};return $label
}
function PtrName($e) {if($script:ptr.ContainsKey([string]$e.ip)){return @($script:ptr[[string]$e.ip].names) -join ', '};return ''}
function ReadNames($rows) {
 foreach($p in @($rows)){if($p -and $p.ip){$script:ptr[[string]$p.ip]=$p}}
 foreach($grid in @($black,$found,$covered,$script:liveGrid,$script:liveEvidenceGrid)){if(!$grid){continue};foreach($row in $grid.Rows){if(!$row.Tag.ip){continue};$row.Cells['hostname'].Value=PtrName $row.Tag;$row.Cells['ptrstate'].Value=PtrState $row.Tag;$row.Cells['hostname'].ToolTipText=PtrName $row.Tag}}
}
function PtrDetail($e) {
 $text='PTR: '+(PtrState $e)+' | '+(PtrName $e)
 if($script:ptr.ContainsKey([string]$e.ip)){$p=$script:ptr[[string]$e.ip];$utc=([DateTimeOffset]::FromUnixTimeSeconds([long]$p.checked_utc)).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss');$text+=' | UTC: '+$utc}
 return $text+[Environment]::NewLine+'نام PTR فقط نام ثبت‌شده برای IP است؛ دامنهٔ واقعی، مالکیت و نقش سرویس را ثابت نمی‌کند.'
}
function LookupNames([bool]$all,[bool]$force=$false) {
 $grid=Active-TcpGrid;if(!$grid){$status.Text='برای PTR یک تب IP را انتخاب کن؛ نام‌های hosts نیاز به Reverse DNS ندارند.';return}
 $rows=if($all){@($grid.Rows)}elseif($grid -ne $black){@($grid.Rows | Where-Object {$_.Selected -or $_.Cells['choose'].Value -eq $true})}else{@($grid.SelectedRows)}
 if(!$rows.Count){$status.Text='ابتدا ردیف‌های موردنظر را انتخاب کن.';return}
 $items=@();$seen=@{};$rangeCount=0
 foreach($row in $rows){$e=$row.Tag;if($e.ip.Contains('/')){$rangeCount++;continue};if(!$seen.ContainsKey([string]$e.ip)){$seen[[string]$e.ip]=$true;$items+=$e}}
 if(!$items.Count){$status.Text='رنج دامنهٔ واحد ندارد؛ IP تکی را از تب رصد انتخاب کن.';return}
 if($items.Count -gt 100){$status.Text='هر بار حداکثر ۱۰۰ IP یکتا؛ تعداد کمتری را انتخاب کن.';return}
 $status.Text='درخواست PTR از DNS سیستم؛ بدون تغییر فایروال.'
 BeginOp 'lookup' @{text=(Ui-Text $items);force=$force}
}
function Entries {return @($black.Rows|ForEach-Object {$_.Tag})}
function Reason($e){if($e.ip.Contains('/')){return 'رنج CIDR؛ تمام آدرس‌های این زیرشبکه روی پورت مشخص'};if((Ui-Key $e) -eq '37.244.29.11|3724|TCP'){return 'هشدار: قبلاً ورود را مختل کرد'};if((Ui-Key $e) -in $script:seedKeys){return 'تست گروه ده‌تایی: کاربر مشکل ندید؛ نقش سرویس نامشخص'};return 'افزوده‌شده به فهرست؛ نقش سرویس تأیید نشده'}
function State($e){$key=Ui-Key $e;if(!$script:actual.ContainsKey($key)){return 'هنوز بررسی نشده'};$a=$script:actual[$key];if($a.persistent_verified -and $a.active_verified){return 'قانون تأییدشده در دو store'};if(!$a.persistent_present -and !$a.active_present){return 'قانونی برای این ردیف نیست'};return 'ناقص / ناسازگار؛ بررسی لازم'}
function ShowRows($entries,[bool]$dirty){$parsed=@(Ui-Parse (Ui-Text $entries));$script:loading=$true;$black.Rows.Clear();foreach($e in $parsed){$i=$black.Rows.Add($e.ip,[int]$e.port,$e.protocol,(PtrName $e),(PtrState $e),(State $e),(Reason $e),'حذف');$black.Rows[$i].Tag=$e;$black.Rows[$i].Cells['hostname'].ToolTipText=PtrName $e};$script:loading=$false;$script:dirty=$dirty;$consent.Checked=$false;$blackTab.Text='لیست سیاه ('+$black.Rows.Count+')'+$(if($dirty){' *'}else{''})}
function DetailText($e){
 $key=Ui-Key $e;$specific='وضعیت ردیفی هنوز بررسی نشده'
 if($script:actual.ContainsKey($key)){$a=$script:actual[$key];$specific='PersistentStore: present='+[string]$a.persistent_present+', verified='+[string]$a.persistent_verified+' | ActiveStore: present='+[string]$a.active_present+', verified='+[string]$a.active_verified}
 return (Ui-Text @($e))+' — '+(Reason $e)+[Environment]::NewLine+$specific+[Environment]::NewLine+'فقط خروجی Wow.exe انتخابی | آخرین بررسی: '+$script:actualAt+' | نقش سرویس و اثر پینگ تأیید نشده است.'+[Environment]::NewLine+(PtrDetail $e)
}
function ReadActual($actual){$script:actual=@{};$script:actualAt=[DateTime]::Now.ToString('HH:mm:ss');foreach($e in @($actual.entries)){if($e){$script:actual[(Ui-Key $e)]=$e}};foreach($row in $black.Rows){$row.Cells['state'].Value=State $row.Tag};if($black.SelectedRows.Count){$details.Text=DetailText $black.SelectedRows[0].Tag}}
function Payload {return @{program=$program.Text;text=(Ui-Text (Entries));program_reselected=$script:reselected;persistent_consent=$consent.Checked}}
function BeginOp([string]$action,$payload,[bool]$closeOnSuccess=$false,[string]$copyExportTo=''){
 if($script:job -or $script:ptrJob){$status.Text='ابتدا عملیات جاری یا PTR را تمام کن.';return}
 $id=[Guid]::NewGuid().ToString('N');$request=Join-Path $private ('job-'+$id+'.request.json');$result=Join-Path $private ('job-'+$id+'.result.json')
 [IO.File]::WriteAllText($request,(@{action=$action;payload=$payload}|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
 $psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=Join-Path $root 'runtime\python.exe';$psi.Arguments='-I "'+(Join-Path $root 'app\backend.py')+'" "'+$request+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=$root
 try{$process=[Diagnostics.Process]::Start($psi)}catch{$status.Text='اجرای عملیات شروع نشد؛ موفقیت فرض نکن.';return}
 $script:job=@{Id=$id;Action=$action;Process=$process;Live=(Join-Path $private ('job-'+$id+'.live.json'));LiveLabels=(Join-Path $private ('job-'+$id+'.live-labels.json'));Phases=(Join-Path $private ('job-'+$id+'.phase.json'));Result=$result;Stop=(Join-Path $private ('job-'+$id+'.stop'));Ready=(Join-Path $private ('job-'+$id+'.ready'));ReadySeen=$false;ExportTarget=$copyExportTo;Program=[string]$payload.program;Progress=(Join-Path $private ('job-'+$id+'.progress.json'));CloseOnSuccess=$closeOnSuccess};if($action -eq 'observe'){Start-LiveCapture $script:job};Enabled $false
 $status.Text=if($action -eq 'observe'){'در حال آماده‌سازی رصد؛ منتظر پیام آمادگی بمان.'}elseif($action -eq 'lookup'){'در حال شناسایی PTR از DNS سیستم؛ فایروال و جدول ویرایش تغییر نمی‌کنند.'}else{'در حال اجرا؛ برای تأیید نتیجه منتظر بمان.'};$timer.Start()
}
function ApplyList([bool]$closeWindow){
 if(!$consent.Checked){$status.Text='ابتدا رضایت اعمال پایدارِ فهرست فعلی را تیک بزن.';return}
 $p=Payload
 if(!$p.text){if([Windows.Forms.MessageBox]::Show('لیست خالی است؛ همهٔ قواعد همین نصب حذف و لیست خالی ذخیره شود؟','بازگردانی فهرست خالی','YesNo','Warning') -ne 'Yes'){return};$p.empty_restore_consent=$true}
 $ranges=@(Entries | Where-Object {$_.ip.Contains('/')})
 if($ranges.Count){
  $summary=(@($ranges|ForEach-Object {Ui-Text @($_)}) -join [Environment]::NewLine)
  if([Windows.Forms.MessageBox]::Show('انسداد رنج تمام IPهای داخل زیرشبکه را فقط برای Wow.exe و پورت/پروتکل درج‌شده دربرمی‌گیرد. 2.0.0.0/8 شامل 16,777,216 آدرس است و می‌تواند ورود/دانلود را مختل کند. این رنج‌ها اعمال شوند؟'+[Environment]::NewLine+$summary,'تأیید جداگانهٔ انسداد رنج','YesNo','Warning') -ne 'Yes'){return};$p.range_consent=$true
 }
 if((Entries | Where-Object {(Ui-Contains $_ '37.244.29.11') -and $_.port -eq 3724 -and $_.protocol -eq 'TCP'})){
  if([Windows.Forms.MessageBox]::Show('این مقصد قبلاً ورود را مختل کرد. با این حال اعمال شود؟','هشدار مقصد ورود','YesNo','Warning') -ne 'Yes'){return};$p.critical_consent=$true
 }
 BeginOp 'apply' $p $closeWindow
}
$timer=New-Object Windows.Forms.Timer;$timer.Interval=250
$timer.Add_Tick({
 if(!$script:job){$timer.Stop();return};$j=$script:job
 if($j.Action -eq 'observe' -and !$j.ReadySeen -and (Test-Path -LiteralPath $j.Ready)){$j.ReadySeen=$true;$status.Text='رصد آماده است؛ بازی قبلی را ببند و دوباره اجرا کن تا فرایند تازه ثبت شود. قواعد فعلی تغییر نمی‌کنند.'}
 if($j.Action -eq 'lookup' -and (Test-Path -LiteralPath $j.Progress)){try{$progress=[IO.File]::ReadAllText($j.Progress)|ConvertFrom-Json;$status.Text='شناسایی PTR: '+$progress.done+' از '+$progress.total+' IP؛ بدون تغییر فایروال.'}catch{}}
 if($j.Action -eq 'observe'){Poll-LiveCapture $j}
 if(!$j.Process.HasExited){return};$timer.Stop();$script:job=$null;Enabled $true;$stop.Enabled=($null -ne $script:ptrJob)
 try{
  $r=[IO.File]::ReadAllText($j.Result)|ConvertFrom-Json
  if(!$r.ok -and $j.Action -eq 'lookup'){$status.Text='شناسایی نام انجام نشد؛ فایروال و ویرایش‌ها تغییر نکردند. '+$r.error;if($script:closeAfterLookup){$script:closeAfterLookup=$false;$form.Close()};return}
  if(!$r.ok -and $j.Action -eq 'observe'){Fail-LiveCapture}
  if(!$r.ok -and $j.Action -eq 'hosts_apply'){$status.Text='اعمال/بازخوانی hosts تأیید نشد: '+$r.error+'؛ وضعیت فایل را دوباره بخوان و پشتیبان private-state/hosts-backups را بررسی کن. هیچ تغییر فایروالی انجام نشده.';return}
  if(!$r.ok -and $j.Action -in @('hosts','observe','classify_observation','history','load_observation','annotate_observation','export_analysis','hosts_apply','delete_records','delete_captures','compare_captures')){$status.Text='خواندن/رصد تأیید نشد: '+$r.error+'؛ هیچ تغییر فایروالی در این عملیات انجام نشد.';if($script:closeAfterObserve){$script:closeAfterObserve=$false;$form.Close()};return}
  if(!$r.ok){if($j.Action -in @('apply','restore')){Invalidate-ObservationClassification};$script:actual=@{};foreach($row in $black.Rows){$row.Cells['state'].Value='نتیجه نامشخص؛ بررسی / بازگردانی'};$status.Text='تأیید نشد: '+$r.error+'؛ ممکن است قوانین جزئی مانده باشند. از بازگردانی استفاده کن.';return}
  if($j.Action -eq 'delete_captures'){Show-CaptureHistory $r.history;Clear-DeletedCapture $r.history;$status.Text='ضبط‌های انتخابی به سطل محلی منتقل شدند؛ فایروال و hosts تغییر نکردند.';return}
  if($j.Action -eq 'delete_records'){Accept-CaptureReport $r.observation $script:observationHistorical;try{Load-LiveHistory $r.observation}catch{Write-UiDiagnostic 'deleted_popup' $_};$status.Text='رکوردها از فهرست و خروجی‌های بعدی حذف شدند؛ فایل خام محلی حفظ شده است.';if($script:closeAfterObserve){$script:closeAfterObserve=$false;$form.Close()};return}
  if($j.Action -eq 'compare_captures'){$status.Text='مقایسه آماده است؛ ندیدن دوبارهٔ مقصد، موفقیت بلاک را ثابت نمی‌کند.';Show-CaptureComparison $r.comparison ([string]$r.comparison_text);return}
  if($j.Action -eq 'history'){Show-CaptureHistory $r.history;$status.Text='تاریخچه خوانده شد؛ برای برچسب‌گذاری یک ضبط را باز کن، یا چند ضبط را برای خروجی انتخاب کن.';return}
  if($j.Action -eq 'annotate_observation'){
   if($r.annotation.capture_id -eq $script:captureId){$script:annotationsDirty=$false;Update-AnnotationIndicator}
   $script:historyNeedsRefresh=$true;$status.Text='برچسب‌های دستی ذخیره شدند؛ فایل خام رصد، بلک‌لیست و فایروال تغییر نکردند.';if($script:closeAfterObserve){$script:closeAfterObserve=$false;$form.Close()};return
  }
  if($j.Action -eq 'export_analysis'){Complete-AnalysisExport $r.export $j;return}
  if($j.Action -eq 'lookup'){
   ReadNames $r.lookup.entries
   $status.Text='شناسایی PTR: '+$r.lookup.completed+' از '+$r.lookup.requested+' IP؛ '+$(if($r.lookup.cancelled){'متوقف شد؛ نتایج تکمیل‌شده نگه داشته شدند.'}else{'نتایج در جدول و ptr-cache.json ذخیره شدند.'})+' دامنهٔ واقعی اتصال تأیید نشده است.'
   $active=Active-TcpGrid;if($active -and $active.SelectedRows.Count){if($active -eq $black){$details.Text=DetailText $active.SelectedRows[0].Tag}else{$details.Text=Observed-Detail $active.SelectedRows[0].Tag}}
   if($script:closeAfterLookup){$script:closeAfterLookup=$false;$form.Close()};return
  }
  if($r.lookup_cache){ReadNames $r.lookup_cache}
  if($j.Action -in @('hosts','hosts_apply')){
   Show-Hosts $r.hosts;$tabs.SelectedTab=$hostsTab;$status.Text=$(if($j.Action -eq 'hosts_apply'){'hosts اعمال و بازخوانی شد؛ پشتیبان در private-state/hosts-backups است. کش DNS خودکار پاک نشد؛ نتیجه روی بازی تضمین نشده.'}else{'hosts خوانده شد؛ برای تغییر از افزودن/ویرایش/حذف استفاده کن.'});return
  }
  if($j.Action -in @('observe','classify_observation','load_observation')){
   # Canonical saved report reaches the main model BEFORE any popup rendering.
   if($j.Action -in @('observe','load_observation')){Accept-CaptureReport $r.observation ($j.Action -eq 'load_observation');$script:observationProgram=$(if($j.Action -eq 'observe'){$j.Program}else{''})}
   else{foreach($row in @($r.observation.endpoints)){$old=@($script:observed|Where-Object {$_.record_id -eq $row.record_id}|Select-Object -First 1);if($old.Count -and $old[0].context){$row|Add-Member NoteProperty context $old[0].context -Force;if($old[0].phase_context){$row|Add-Member NoteProperty phase_context $old[0].phase_context -Force}}};$script:observed=@($r.observation.endpoints);$script:observationSnapshot=$r.observation.block_snapshot;Show-ObservedRows}
   $tabs.SelectedTab=$obsTab;$status.Text='رکوردهای ذخیره‌شده منتقل شدند؛ مرحله‌های همین ضبط و سابقهٔ ضبط‌های دیگر جدا نمایش داده می‌شوند.'
   try{if($j.Action -eq 'observe'){Finish-LiveCapture $r.observation}elseif($j.Action -eq 'load_observation'){Load-LiveHistory $r.observation}}catch{Write-UiDiagnostic 'popup_finalize' $_;$status.Text+=' نمایش نهایی پاپ‌آپ خطا داشت؛ رکورد اصلی در تاریخچه ذخیره است.'}
   if($j.Action -eq 'observe' -and (Finalize-LiveEdits $r.observation)){return}
   if($script:closeAfterObserve){$script:closeAfterObserve=$false;$form.Close()};return
  }
  if($r.config){$program.Text=[string]$r.config.program;ShowRows @(Ui-Parse ([string]$r.config.text)) $false;$script:reselected=$false}
  if($j.Action -eq 'apply'){
   $rows=@(Entries);$verified=@(foreach($e in $rows){[pscustomobject]@{ip=$e.ip;port=$e.port;protocol=$e.protocol;persistent_present=$true;active_present=$true;persistent_verified=$true;active_verified=$true}});ReadActual @{entries=$verified}
   $status.Text='تغییرات اعمال و در دو store تأیید شد؛ '+$rows.Count+' قانون. پنجره باز است؛ می‌توانی ردیف بعدی را حذف و دوباره اعمال کنی.'
  }elseif($j.Action -eq 'restore'){
   $rows=@(foreach($e in (Entries)){[pscustomobject]@{ip=$e.ip;port=$e.port;protocol=$e.protocol;persistent_present=$false;active_present=$false;persistent_verified=$false;active_verified=$false}});ReadActual @{entries=$rows};$status.Text='تمام قواعد همین نصب حذف شدند؛ لیست برای استفادهٔ بعدی نگه داشته شد. پنجره باز است.'
  }elseif($j.Action -eq 'save'){$status.Text='TXT ذخیره شد: private-state\blacklist.txt؛ فایروال تغییر نکرد.'
  }else{ReadActual $r.actual;$status.Text='بررسی '+$script:actualAt+' | پایدار: '+$r.actual.persistent_count+' | فعال: '+$r.actual.active_count+' | * یعنی تغییر ذخیره‌نشده؛ وضعیت قانون، اثبات افت بسته نیست.'}
  if($j.Action -in @('apply','restore')){Invalidate-ObservationClassification}
  if($r.settings_preserved){$status.Text='قواعد همین نصب حذف شدند؛ فایل تنظیمات یا TXT نامعتبر است و دست‌نخورده ماند. پیش از بارگذاری دوباره آن را اصلاح کن.'}
  if($j.CloseOnSuccess){$form.Close()}
 }catch{Write-UiDiagnostic ('result_'+$j.Action) $_;if($j.Action -eq 'observe'){Fail-LiveCapture};if($j.Action -in @('apply','restore')){Invalidate-ObservationClassification};if($j.Action -in @('hosts','observe','classify_observation','history','load_observation','annotate_observation','export_analysis','hosts_apply','delete_records','delete_captures','compare_captures')){$status.Text='نتیجهٔ خواندن/رصد دریافت نشد؛ این عملیات فایروال را تغییر نمی‌دهد.'}elseif($j.Action -eq 'lookup'){$status.Text='نتیجهٔ شناسایی نام خوانده نشد؛ فایروال و ویرایش‌های جدول تغییر نکردند.'}else{$status.Text='نتیجه خوانده نشد؛ موفقیت فرض نکن. Restore.cmd در همین پوشه موجود است.'}}
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
foreach($grid in @($found,$covered)){$grid.Add_SelectionChanged({param($sender,$e) if(!$script:renderingObserved -and $sender.SelectedRows.Count -and $sender.SelectedRows[0].Tag){$details.Text=Observed-Detail $sender.SelectedRows[0].Tag}});$grid.Add_CurrentCellDirtyStateChanged({param($sender,$e) if($sender.IsCurrentCellDirty){[void]$sender.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit)}})}
foreach($grid in @($found,$covered)){$grid.Add_CellValueChanged({param($sender,$e) if($e.RowIndex -ge 0 -and $e.ColumnIndex -eq $sender.Columns['choose'].Index){Sync-ObservedCheck $sender $e.RowIndex}})}
foreach($grid in @($found,$covered)){
 $grid.Add_CellContentClick({param($sender,$e) if($e.RowIndex -ge 0 -and $e.ColumnIndex -eq $sender.Columns['stage'].Index){Edit-MainStages @($sender.Rows[$e.RowIndex])}})
}
$saveAnnotations.Add_Click({Save-CaptureAnnotations})
$setSelectedStage.Add_Click({$grid=Active-TcpGrid;if(!$grid -or $grid -eq $black){return};Edit-MainStages @($grid.Rows|Where-Object {$_.Selected -or $_.Cells['choose'].Value -eq $true})})
$analysisExport.Add_Click({Start-AnalysisExport})
$historyExport.Add_Click({Start-AnalysisExport $true});$historyRefresh.Add_Click({BeginOp 'history' @{}});$historyLoad.Add_Click({Open-SelectedCapture})
$historyGrid.Add_CellDoubleClick({param($sender,$e) if($e.RowIndex -ge 0){Open-SelectedCapture}})
$tabs.Add_SelectedIndexChanged({if($tabs.SelectedTab -eq $historyTab -and $script:historyNeedsRefresh -and !$script:job){BeginOp 'history' @{}}})
$hostsGrid.Add_SelectionChanged({if($hostsGrid.SelectedRows.Count -and $hostsGrid.SelectedRows[0].Tag){$h=$hostsGrid.SelectedRows[0].Tag;$details.Text=$h.domain+' → '+(@($h.addresses) -join ', ')+[Environment]::NewLine+(Hosts-Label $h.mapping_kind)+' | خطوط: '+(@($h.lines) -join ', ')+[Environment]::NewLine+'این فقط ثبت در hosts است؛ نه اثبات تلاش بازی یا موفقیت مسدودسازی. IPv4/IPv6، کش و روش نام‌گشایی برنامه می‌توانند نتیجه را تغییر دهند.'}})
$found.Add_CurrentCellDirtyStateChanged({if($found.IsCurrentCellDirty){[void]$found.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit)}})
$delete.Add_Click({if($tabs.SelectedTab -eq $historyTab){Delete-SelectedCaptures;return};if($tabs.SelectedTab -in @($obsTab,$coveredTab)){Delete-MainRecords;return};if($tabs.SelectedTab -eq $hostsTab){$hostsDelete.PerformClick();return};RemoveKeys @($black.SelectedRows|ForEach-Object {Ui-Key $_.Tag}) $false})
$deleteApply.Add_Click({if($tabs.SelectedTab -ne $blackTab){$tabs.SelectedTab=$blackTab;return};RemoveKeys @($black.SelectedRows|ForEach-Object {Ui-Key $_.Tag}) $true})
$black.Add_KeyDown({param($sender,$e) if($e.KeyCode -eq 'Delete'){RemoveKeys @($black.SelectedRows|ForEach-Object {Ui-Key $_.Tag}) $false;$e.Handled=$true}})
$pick.Add_Click({$d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='World of Warcraft (Wow.exe)|Wow.exe';if($d.ShowDialog() -eq 'OK'){$program.Text=$d.FileName;$script:reselected=$true;Invalidate-ObservationClassification;$consent.Checked=$false;$script:actual=@{};foreach($row in $black.Rows){$row.Cells['state'].Value='مسیر عوض شد؛ بررسی لازم'}};$d.Dispose()})
$import.Add_Click({$d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='Text list (*.txt)|*.txt';if($d.ShowDialog() -eq 'OK'){try{if((Get-Item -LiteralPath $d.FileName).Length -gt 30000){throw 'too_large'};$entries=@(Ui-Parse ([IO.File]::ReadAllText($d.FileName)));ShowRows $entries $true;$status.Text='فایل در جدول بارگذاری شد؛ هنوز اعمال نشده است.'}catch{$status.Text='لیست معتبر نیست؛ هر خط IP یا CIDR:Port TCP/UDP، حداکثر ۱۰۰ ردیف. فهرست قبلی تغییر نکرد.'}};$d.Dispose()})
$range.Add_Click({$preview=Show-RangeWizard;if($preview){try{ShowRows @(Ui-Parse ((Ui-Text (Entries))+[Environment]::NewLine+$preview.text)) $true;$tabs.SelectedTab=$blackTab;$status.Text=$preview.address_count+' آدرس در '+$preview.rule_count+' ردیف به جدول اضافه شد؛ هنوز ذخیره یا مسدود نشده است.'}catch{$status.Text='فهرست مجموعاً از ۱۰۰ ردیف بیشتر می‌شود؛ بازه را کوچک‌تر کن. جدول تغییر نکرد.'}}})
$lookupSelected.Add_Click({LookupNames $false})
$lookupAll.Add_Click({LookupNames $true})
$lookupFresh.Add_Click({LookupNames $false $true})
$manual.Add_Click({
 $d=New-Object Windows.Forms.Form;$d.Text='افزودن IP تکی / ورود مستقیم';$d.ClientSize=New-Object Drawing.Size(520,160);$d.StartPosition='CenterParent';$d.Font=$form.Font
 $l=New-Object Windows.Forms.Label;$l.Text='نمونه: 2.19.198.11:80 TCP؛ برای بازه از فرم رنج استفاده کن';$l.SetBounds(16,16,488,28)
 $input=New-Object Windows.Forms.TextBox;$input.SetBounds(16,50,488,30);$input.RightToLeft='No';$input.Font=New-Object Drawing.Font('Consolas',11)
 $ok=Button 'افزودن';$ok.SetBounds(360,98,144,44);$ok.DialogResult='OK';$d.Controls.AddRange(@($l,$input,$ok));$d.AcceptButton=$ok
 if($d.ShowDialog($form) -eq 'OK'){try{$entries=@(Ui-Parse ((Ui-Text (Entries))+[Environment]::NewLine+$input.Text));ShowRows $entries $true;$status.Text='مقصد به لیست اضافه شد؛ هنوز اعمال نشده است.'}catch{$status.Text='IP یا CIDR معتبر با آدرس شبکه لازم است؛ نمونه: 2.0.0.0/8:80 TCP. لیست تغییر نکرد.'}};$d.Dispose()
})
$addFound.Add_Click({
 if($tabs.SelectedTab -notin @($obsTab,$coveredTab)){$status.Text='برای افزودن، ابتدا یکی از تب‌های رصد را انتخاب کن.';return}
 $grid=Active-TcpGrid;$lines=New-Object Collections.Generic.List[string];$lines.Add((Ui-Text (Entries)))
 foreach($row in $grid.Rows){if($row.Cells['choose'].Value -eq $true){$lines.Add((Ui-Text @($row.Tag)))}}
 try{ShowRows @(Ui-Parse ($lines -join [Environment]::NewLine)) $true;$tabs.SelectedTab=$blackTab;$status.Text='انتخاب‌های همین تب فقط به لیست اضافه شدند؛ هنوز ذخیره یا مسدود نشده‌اند.'}catch{$status.Text='حداکثر ۱۰۰ ردیف مجاز است؛ لیست قبلی تغییر نکرد.'}
})
$onlyFresh.Add_CheckedChanged({Show-ObservedRows});$hideCovered.Add_CheckedChanged({Show-ObservedRows})
$reclassify.Add_Click({if(!$script:observed.Count){$status.Text='ابتدا رصد بگیر.';return};if($program.Text -ine $script:observationProgram){$status.Text='مسیر بازی تغییر کرده؛ برای این مسیر رصد تازه بگیر.';return};Remember-ObservedChecks;BeginOp 'classify_observation' @{program=$script:observationProgram;endpoints=(Observation-PayloadRows)}})
$hostsRead.Add_Click({BeginOp 'hosts' @{}})
$observe.Add_Click({if(!(Can-SwitchCapture)){return};if(!$program.Text){$status.Text='ابتدا Wow.exe را انتخاب کن.';return};BeginOp 'observe' @{program=$program.Text;seconds=$(if($duration.SelectedItem -eq 'تا توقف'){0}else{[int]$duration.SelectedItem})}})
$liveOpen.Add_Click({Open-LiveWindow});$liveEnabled.Add_CheckedChanged({if($liveEnabled.Checked -and $script:job -and $script:job.Action -eq 'observe'){Open-LiveWindow}elseif(!$liveEnabled.Checked -and $script:liveForm){$script:liveForm.Hide()}})
$stop.Add_Click({Request-RecordingStop})
$export.Add_Click({$d=New-Object Windows.Forms.SaveFileDialog;$d.Filter='Text list (*.txt)|*.txt';$d.FileName='blacklist.txt';$d.OverwritePrompt=$true;if($d.ShowDialog() -eq 'OK'){try{[IO.File]::WriteAllText($d.FileName,(Ui-Text (Entries)),(New-Object Text.UTF8Encoding($false)));$status.Text='خروجی TXT از جدول فعلی ذخیره شد؛ فایروال و لیست اصلی تغییر نکردند.'}catch{$status.Text='ذخیرهٔ خروجی TXT ناموفق بود.'}};$d.Dispose()})
$save.Add_Click({BeginOp 'save' (Payload)})
$refresh.Add_Click({BeginOp 'status' (Payload)})
$apply.Add_Click({ApplyList $false});$applyClose.Add_Click({ApplyList $true})
$restore.Add_Click({if([Windows.Forms.MessageBox]::Show('تمام قواعد همین نصب حذف شوند؟ لیست می‌ماند و پنجره بسته نمی‌شود.','بازگردانی','YesNo','Warning') -eq 'Yes'){BeginOp 'restore' @{}}})
$exit.Add_Click({$form.Close()})
$form.Add_FormClosing({param($sender,$e)
 if($script:ptrJob){$e.Cancel=$true;if($script:job -and $script:job.Action -eq 'observe'){$script:closeAfterObserve=$true;Request-RecordingStop};[IO.File]::WriteAllText($script:ptrJob.Stop,'stop');$status.Text='PTR در حال توقف است؛ پس از پایان دوباره بستن را بزن.';return}
 if($script:job){$e.Cancel=$true;if($script:job.Action -eq 'observe'){$script:closeAfterObserve=$true;Request-RecordingStop;$status.Text='پس از پایان رصد بسته می‌شود؛ قواعد موجود باقی می‌مانند.'}elseif($script:job.Action -eq 'lookup'){$script:closeAfterLookup=$true;[IO.File]::WriteAllText($script:job.Stop,'stop');$status.Text='پس از توقف استعلام‌های جاری بسته می‌شود؛ فایروال تغییر نمی‌کند.'}else{$status.Text='تا پایان عملیات منتظر بمان؛ نتیجه هنوز تأیید نشده است.'};return}
 Commit-ObservationEdits
 if($script:annotationsDirty){if([Windows.Forms.MessageBox]::Show('برچسب‌های مرحلهٔ مشاهده ذخیره نشده‌اند. بدون ذخیره بسته شود؟ فایل خام رصد حفظ می‌شود.','برچسب‌های ذخیره‌نشده','YesNo','Warning') -ne 'Yes'){$e.Cancel=$true;return}}
 if($script:dirty){if([Windows.Forms.MessageBox]::Show('تغییرات فهرست ذخیره/اعمال نشده‌اند. با این حال پنجره بسته شود؟ قواعد فعلی باقی می‌مانند.','تغییرات ذخیره‌نشده','YesNo','Warning') -ne 'Yes'){$e.Cancel=$true}}
})
$form.Add_Shown({BeginOp 'load' @{}})
[void]$form.ShowDialog();$timer.Dispose();$ptrTimer.Dispose();if($script:liveForm){$script:liveForm.Dispose()};$form.Dispose()
