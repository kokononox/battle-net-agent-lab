# Contextual workspaces. Sidebar navigation only; draft edits never apply Windows rules.
. (Join-Path $PSScriptRoot 'workspace-model.ps1')
$script:ipDraft=@();$script:ipDirty=$false;$script:ipGeneration=-1;$script:ipSavedFingerprint=''
$script:hostDraft=@();$script:hostDirty=$false;$script:hostRevision=0;$script:hostLoaded=$false;$script:hostLoadAttempted=$false
$script:workspaceButtons=New-Object Collections.Generic.List[object]
function Local-Button([string]$Text){$v=Button $Text;$script:workspaceButtons.Add($v);return $v}
function Local-Control($Panel,$Control){
 $Control.Dock='None';$Control.MaximumSize=New-Object Drawing.Size(0,0);$Control.Margin=New-Object Windows.Forms.Padding(4)
 if($Control -is [Windows.Forms.Button]){$Control.MinimumSize=New-Object Drawing.Size(125,38);$Control.AutoSize=$true;$Control.Width=155}
 elseif($Control -is [Windows.Forms.TextBox]){$Control.Width=210}
 elseif($Control -is [Windows.Forms.Label]){$Control.MaximumSize=New-Object Drawing.Size(650,0)}
 $Panel.Controls.Add($Control)
}
function Local-Page($Page,[string]$Note,$Content,$Controls){
 $Page.Controls.Clear();$layout=Stack $Page 3
 $layout.Controls.Add((Label $Note),0,0);$tools=Flow
 foreach($v in @($Controls)){Local-Control $tools $v}
 $layout.Controls.Add($tools,0,1);$layout.Controls.Add($Content,0,2);return $layout
}
function Nested-Tab($Parent,[string]$Caption){$v=New-Object Windows.Forms.TabPage;$v.Text=$Caption;$v.BackColor=[Drawing.Color]::White;[void]$Parent.TabPages.Add($v);return $v}
function Draft-Selection($Grid){if($Grid.SelectedRows.Count -ne 1){throw 'فقط یک ردیف را انتخاب کنید.'};return $Grid.SelectedRows[0].Tag}
function Render-Drafts {
 if($null -eq $script:state){return}
 $map=@{};foreach($p in @($script:state.config.programs)){$map[$p.id]=$p.path}
 $ipDraftGrid.Rows.Clear()
 foreach($r in @($script:ipDraft)){
  $paths=@($r.program_ids|ForEach-Object{if($map.ContainsKey($_)){$map[$_]}else{'EXE حذف شده: '+$_}})-join '; '
  $valid=(@($r.program_ids).Count -gt 0 -and $r.protocol -cin @('TCP','UDP') -and $r.port -ge 1)
  if(-not $paths){$paths='ابتدا EXE را ثبت و در ویرایش انتخاب کنید: '+$r.source_path}
  $i=$ipDraftGrid.Rows.Add($r.target,$r.protocol,$r.port,$paths,$(if($valid){'ذخیره/اعتبارسنجی لازم'}else{'ناقص؛ ویرایش لازم'}));$ipDraftGrid.Rows[$i].Tag=$r
 }
 foreach($grid in @($hostDraftGrid,$blackDomainGrid)){
  $grid.Rows.Clear();foreach($r in @($script:hostDraft)){$i=$grid.Rows.Add($r.domain,$(if($r.operation -ceq 'sink'){'مسدودسازی: 0.0.0.0 + ::'}else{'حذف تمام نگاشت‌های این نام'}));$grid.Rows[$i].Tag=$r}
 }
 $ipDraftStatus.Text=('IP: {0} ردیف | {1} | ذخیره ≠ Apply' -f $script:ipDraft.Count,$(if($script:ipDirty){'پیش‌نویس ذخیره‌نشده'}else{'همسان با تنظیمات ذخیره‌شده'}))
 foreach($v in @($hostDraftStatus,$blackDomainStatus)){$v.Text=('hosts سراسری: {0} نام | {1} | ذخیرهٔ محلی ≠ تغییر ویندوز' -f $script:hostDraft.Count,$(if(-not $script:hostLoaded){'ذخیرهٔ محلی هنوز بارگذاری نشده'}elseif($script:hostDirty){'پیش‌نویس ذخیره‌نشده'}else{'ذخیرهٔ محلی خوانده شد'}))}
}
function Workspace-State($State,[string]$Action){
 $fingerprint=ConvertTo-Json -InputObject @($State.config.blacklist) -Depth 12 -Compress
 if(-not $script:ipDirty -or $Action -ceq 'workspace_blacklist_save'){
  $script:ipDraft=@($State.config.blacklist|ForEach-Object{New-IPDraftRow @($_.program_ids) $_.target $_.protocol $_.port '' $_.id});$script:ipDirty=$false;$script:ipGeneration=[int]$State.config.generation;$script:ipSavedFingerprint=$fingerprint
 }elseif($fingerprint -ceq $script:ipSavedFingerprint){$script:ipGeneration=[int]$State.config.generation}
 # A conflicting imported/changed blacklist keeps the draft's old generation: saving must fail, never silently replace it.
 Render-Drafts
}
function Set-WorkspaceBusy([bool]$Busy){foreach($v in $script:workspaceButtons){$v.Enabled=(-not $Busy)} }
function Stage-ObservedDraft($Row,$Choice){
 if($null -ne $script:job -and $script:job.action -notin @('monitor_record','baseline_record')){throw 'تا پایان عملیات جاری صبر کنید؛ چیزی به پیش‌نویس اضافه نشد.'}
 if($Choice.type -ceq 'domain'){
  $n=New-HostDraftRow $Choice.value 'sink'
  if(@($script:hostDraft|Where-Object{$_.domain -ieq $n.domain -and $_.operation -cne 'sink'}).Count -gt 0){if([Windows.Forms.MessageBox]::Show('این نام قبلاً برای حذف نگاشت در پیش‌نویس است؛ با مسدودسازی جایگزین شود؟ هنوز ذخیره نمی‌شود.','تعارض پیش‌نویس دامنه','YesNo','Warning') -ne 'Yes'){return}}
  $script:hostDraft=Merge-HostDraft $script:hostDraft $n;$script:hostDirty=$true
  $tabs.SelectedTab=$blackTab;$blackSections.SelectedTab=$blackDomainTab
 }else{
  if($null -eq $script:state){throw 'تنظیمات هنوز خوانده نشده است.'}
  $n=Observed-IPDraft $Row $Choice.value @($script:state.config.programs);$script:ipDraft=Merge-IPDraft $script:ipDraft @($n);$script:ipDirty=$true
  $tabs.SelectedTab=$blackTab;$blackSections.SelectedTab=$ipDraftTab
 }
 Render-Drafts;$form.BringToFront();$livePopup.Hide();$status.Text='به جدول پیش‌نویس منتقل شد؛ هیچ ذخیره یا Apply انجام نشد. در IP، EXE/پروتکل/پورت ناقص را ویرایش کنید؛ ذخیره بعداً.'
}
function Edit-HostDraft($Grid,[bool]$Actual=$false,[bool]$DeleteActual=$false){
 $old=$null;if($null -ne $Grid){$old=Draft-Selection $Grid}
 if($DeleteActual){
  if([Windows.Forms.MessageBox]::Show(('حذف تمام نگاشت‌های '+$old.domain+' فقط به پیش‌نویس اضافه شود؟ اعمال واقعی بعداً و جداگانه است.'),'پیش‌نویس حذف نگاشت','YesNo','Warning') -ne 'Yes'){return}
  $n=New-HostDraftRow $old.domain 'remove'
 }else{
  $dialog=New-Object Windows.Forms.Form;$dialog.Text='دامنه / پیش‌نویس hosts سراسری';$dialog.Size=New-Object Drawing.Size(680,300);$dialog.StartPosition='CenterParent';$dialog.Font=$form.Font;$dialog.AutoScaleMode='Dpi';$dialog.RightToLeft='Yes'
  $v=Stack $dialog 4;$v.RowStyles[3].SizeType='AutoSize';$v.Controls.Add((Label 'یک نام دقیق؛ نگاشت Block دوگانه یا حذف تمام نگاشت‌های همان نام. Save / Apply خودکار نیست.'),0,0)
  $name=TextBox 520;$name.Dock='Top';if($null -ne $old){$name.Text=$old.domain};$v.Controls.Add($name,0,1)
  $operation=New-Object Windows.Forms.ComboBox;$operation.DropDownStyle='DropDownList';$operation.Dock='Top';[void]$operation.Items.AddRange(@('مسدودسازی نام با 0.0.0.0 و ::','حذف تمام نگاشت‌های نام'));$operation.SelectedIndex=0
  if(-not $Actual -and $null -ne $old -and $old.operation -ceq 'remove'){$operation.SelectedIndex=1};$v.Controls.Add($operation,0,2)
  $bar=Flow;$ok=Button 'فقط ثبت در پیش‌نویس';$ok.DialogResult='OK';$cancel=Button 'لغو';$cancel.DialogResult='Cancel';$bar.Controls.Add($ok);$bar.Controls.Add($cancel);$v.Controls.Add($bar,0,3);$dialog.AcceptButton=$ok;$dialog.CancelButton=$cancel
  Prepare-Dialog $dialog
  try{if($dialog.ShowDialog($form) -ne 'OK'){return};$id=if($null -ne $old -and -not $Actual){$old.id}else{''};$n=New-HostDraftRow $name.Text @('sink','remove')[$operation.SelectedIndex] $id}finally{$dialog.Dispose()}
 }
 $next=@($script:hostDraft)
 if($Actual -and $n.domain -ine $old.domain){
  if([Windows.Forms.MessageBox]::Show(('تغییر نام در فایل واقعی: حذف نگاشت‌های '+$old.domain+' و '+$n.operation+' برای '+$n.domain+' به پیش‌نویس افزوده شود؟'),'دو تغییر سراسری در پیش‌نویس','YesNo','Warning') -ne 'Yes'){return}
  $next=Merge-HostDraft $next (New-HostDraftRow $old.domain 'remove')
 }
 $next=Merge-HostDraft $next $n;$script:hostDraft=$next;$script:hostDirty=$true;Render-Drafts
 if($Actual){$hostSections.SelectedTab=$hostDraftTab;$tabs.SelectedTab=$hostsTab}
}
function Delete-HostDraft($Grid){
 $ids=@($Grid.SelectedRows|ForEach-Object{$_.Tag.id});if(-not $ids.Count){throw 'ردیف‌های پیش‌نویس را انتخاب کنید.'}
 $script:hostDraft=@($script:hostDraft|Where-Object{$ids -cnotcontains $_.id});$script:hostDirty=$true;Render-Drafts
}
function Save-HostDraft {if(-not $script:hostLoaded){throw 'ابتدا «خواندن ذخیرهٔ محلی» را بزنید؛ پیش‌نویس جاری حفظ می‌شود.'};BeginOp 'workspace_hosts_save' @{revision=$script:hostRevision;rows=@($script:hostDraft)}}
function Preview-HostDraft {
 if(-not $script:hostLoaded -or $script:hostDirty){throw 'ابتدا پیش‌نویس hosts را محلی ذخیره کنید. ذخیره هیچ تغییری روی ویندوز نمی‌دهد.'}
 if(-not $script:hostDraft.Count){throw 'پیش‌نویس خالی است؛ فایل واقعی hosts دست نمی‌خورد.'}
 $script:hostsPending=@{rows=@($script:hostDraft)};BeginOp 'workspace_hosts_prepare' $script:hostsPending
}
function Edit-IPDraft($Old=$null){
 $dialog=New-Object Windows.Forms.Form;$dialog.Text='IP / CIDR / بازه — فقط پیش‌نویس';$dialog.Size=New-Object Drawing.Size(760,460);$dialog.StartPosition='CenterParent';$dialog.Font=$form.Font;$dialog.AutoScaleMode='Dpi';$dialog.RightToLeft='Yes'
 $v=Stack $dialog 5;$v.RowStyles[4].SizeType='AutoSize';$v.RowStyles[3].SizeType='Percent';$v.RowStyles[3].Height=100
 $v.Controls.Add((Label 'EXEهای دقیق را انتخاب کنید. مقصد فقط IP/CIDR/بازه است، نه دامنه یا مسیر EXE. اعتبارسنجی کامل هنگام ذخیره انجام می‌شود.'),0,0)
 $value=TextBox 600;$value.Dock='Top';if($null -ne $Old){$value.Text=$Old.target};$v.Controls.Add($value,0,1)
 $bar=Flow;$protocol=New-Object Windows.Forms.ComboBox;$protocol.DropDownStyle='DropDownList';[void]$protocol.Items.AddRange(@('انتخاب پروتکل','TCP','UDP'));$protocol.SelectedIndex=0
 $number=New-Object Windows.Forms.NumericUpDown;$number.Minimum=0;$number.Maximum=65535;$number.Width=100
 if($null -ne $Old){if($Old.protocol -cin @('TCP','UDP')){$protocol.SelectedItem=$Old.protocol};$number.Value=$Old.port}
 foreach($c in @((Label 'پروتکل'),$protocol,(Label 'پورت؛ صفر = هنوز مشخص نشده'),$number)){Local-Control $bar $c};$v.Controls.Add($bar,0,2)
 $list=New-Object Windows.Forms.CheckedListBox;$list.Dock='Fill';$list.CheckOnClick=$true;$list.RightToLeft='No';$programs=@($script:state.config.programs);$ids=if($null -ne $Old){@($Old.program_ids)}else{@(CheckedIds)}
 foreach($p in $programs){[void]$list.Items.Add($p.path,($ids -contains $p.id))};$v.Controls.Add($list,0,3)
 $buttons=Flow;$ok=Button 'فقط ثبت در پیش‌نویس';$ok.DialogResult='OK';$cancel=Button 'لغو';$cancel.DialogResult='Cancel';$buttons.Controls.Add($ok);$buttons.Controls.Add($cancel);$v.Controls.Add($buttons,0,4);$dialog.AcceptButton=$ok;$dialog.CancelButton=$cancel
 Prepare-Dialog $dialog
 try{
  if($dialog.ShowDialog($form) -ne 'OK'){return};$selected=@($list.CheckedIndices|ForEach-Object{$programs[[int]$_].id})
  if(-not $selected.Count -or $protocol.SelectedIndex -eq 0 -or $number.Value -lt 1){throw 'EXE، پروتکل و پورت معتبر لازم است؛ پیش‌نویس قبلی حفظ شد.'}
  $source='';$id='';if($null -ne $Old){$id=$Old.id;$source=$Old.source_path}
  if($source -and ($selected.Count -ne 1 -or @($programs|Where-Object{$_.id -ceq $selected[0] -and $_.path -ieq $source}).Count -ne 1)){throw 'ردیف رصدشده باید به همان EXE دقیق متصل باشد؛ ابتدا انتقال EXE به برنامه‌ها را انجام دهید.'}
  $n=New-IPDraftRow $selected $value.Text ([string]$protocol.SelectedItem) ([int]$number.Value) $source $id
  $script:ipDraft=Merge-IPDraft $script:ipDraft @($n);$script:ipDirty=$true;Render-Drafts
 }finally{$dialog.Dispose()}
 $tabs.SelectedTab=$blackTab;$blackSections.SelectedTab=$ipDraftTab
}
function Open-RangeBuilder($Seed=$null){
 if($null -ne $script:job){throw 'ابتدا ثبت جاری را با توقف ثبت عادی پایان دهید؛ سپس بازهٔ پورت را پیش‌نمایش کنید.'}
 $ids=if($null -ne $Seed){@($Seed.program_ids)}else{@(CheckedIds)};if(-not $ids.Count){throw 'ابتدا EXEهای موردنظر را در برنامه‌ها تیک بزنید.'}
 $dialog=New-Object Windows.Forms.Form;$dialog.Text='رنج IP و پورت مقصد — فقط پیش‌نمایش';$dialog.Size=New-Object Drawing.Size(820,600);$dialog.StartPosition='CenterParent';$dialog.Font=$form.Font;$dialog.AutoScaleMode='Dpi';$dialog.RightToLeft='Yes'
 $v=Stack $dialog 7;$v.RowStyles[6].SizeType='AutoSize';$v.RowStyles[3].SizeType='Percent';$v.RowStyles[3].Height=100
 $v.Controls.Add((Label 'پورت از/تا شامل هر دو انتهاست؛ TCP و UDP جدا انتخاب می‌شوند. هر IP/شبکه × هر پورت یک ردیف است؛ سقف کل پیش‌نویس ۲۵۶ است. هیچ بخشی از بازهٔ بیش از سقف اعمال نمی‌شود.'),0,0)
 $kind=New-Object Windows.Forms.ComboBox;$kind.DropDownStyle='DropDownList';$kind.Dock='Top';[void]$kind.Items.AddRange(@('پیشوند IP / wildcard انتهایی','از IP تا IP','CIDR / یک IP','فهرست IP دقیق — هر خط یک آدرس'));$kind.SelectedIndex=2;$v.Controls.Add($kind,0,1)
 $binding=Label $(if($null -ne $Seed){'فقط EXE رصدشده: '+$Seed.path}else{'EXE تیک‌خورده: '+$ids.Count+' — Apply بعدی روی کل تنظیمات ذخیره‌شده است.'});$v.Controls.Add($binding,0,2)
 $first=TextBox 650;$first.Multiline=$true;$first.ScrollBars='Vertical';$first.Dock='Fill';$first.MinimumSize=New-Object Drawing.Size(0,80);$first.AccessibleName='IP / CIDR / فهرست IP دقیق';$v.Controls.Add($first,0,3)
 $lastBar=Flow;$lastLabel=Label 'انتهای IP (فقط حالت از IP تا IP)';$last=TextBox 340;$last.Enabled=$false;$lastBar.Controls.Add($lastLabel);$lastBar.Controls.Add($last);$v.Controls.Add($lastBar,0,4)
 $kind.Tag=$last;$kind.Add_SelectedIndexChanged({param($sender,$e)$sender.Tag.Enabled=($sender.SelectedIndex -eq 1)})
 $bar=Flow;$protocol=New-Object Windows.Forms.ComboBox;$protocol.DropDownStyle='DropDownList';[void]$protocol.Items.AddRange(@('انتخاب پروتکل','TCP','UDP'));$protocol.SelectedIndex=0
 $number=New-Object Windows.Forms.NumericUpDown;$number.Minimum=1;$number.Maximum=65535;$number.Value=443;$number.Width=100;$number.RightToLeft='No'
 $endPort=New-Object Windows.Forms.NumericUpDown;$endPort.Minimum=1;$endPort.Maximum=65535;$endPort.Value=443;$endPort.Width=100;$endPort.RightToLeft='No'
 foreach($c in @((Label 'پروتکل مقصد'),$protocol,(Label 'پورت از'),$number,(Label 'تا (شامل)'),$endPort)){Local-Control $bar $c};$v.Controls.Add($bar,0,5)
 if($null -ne $Seed){$kind.SelectedIndex=3;$first.Text=($Seed.ips -join "`r`n");if($Seed.protocol){$protocol.SelectedItem=$Seed.protocol};if($Seed.port -ge 1 -and $Seed.port -le 65535){$number.Value=$Seed.port;$endPort.Value=$Seed.port}}
 $buttons=Flow;$ok=Button 'پیش‌نمایش دقیق IP × پورت';$ok.DialogResult='OK';$cancel=Button 'لغو';$cancel.DialogResult='Cancel';$buttons.Controls.Add($ok);$buttons.Controls.Add($cancel);$v.Controls.Add($buttons,0,6);$dialog.AcceptButton=$ok;$dialog.CancelButton=$cancel
 try{
  Prepare-Dialog $dialog
  if($dialog.ShowDialog($form) -ne 'OK'){return}
  if($protocol.SelectedIndex -eq 0 -or $endPort.Value -lt $number.Value){throw 'پروتکل را انتخاب کنید و پایان پورت را کوچک‌تر از شروع نگذارید.'}
  $payload=@{mode=@('pattern','between','cidr','targets')[$kind.SelectedIndex];value=$first.Text;last=$last.Text;protocol=[string]$protocol.SelectedItem;port=[int]$number.Value;port_end=[int]$endPort.Value;row_budget=[Math]::Max(0,256-$script:ipDraft.Count);program_count=$ids.Count}
  BeginOp 'workspace_range_preview' $payload;$script:job.range_program_ids=$ids;$script:job.range_source_path=$(if($null -ne $Seed){[string]$Seed.path}else{''})
 }finally{$dialog.Dispose()}
}
function Accept-RangeDraft($Preview,$Ids,[string]$SourcePath=''){
 $note='پروتکل: '+$Preview.entries[0].protocol+"`r`nپورت مقصد از "+$Preview.port_first+' تا '+$Preview.port_last+' (شامل هر دو انتها)'+"`r`nتعداد پورت: "+$Preview.port_count+"`r`nابتدای IP: "+$Preview.first_ip+"`r`nانتهای IP: "+$Preview.last_ip+"`r`nتعداد آدرس: "+$Preview.address_count+$(if($Preview.destination_set_not_contiguous){' — فقط IPهای فهرست؛ فاصله‌ها مسدود نمی‌شوند.'}else{''})+"`r`nردیف جدید: "+$Preview.rule_count+"`r`nحداکثر قواعد این دسته: "+$Preview.native_rule_upper_bound+"`r`nEXE: "+@($Ids).Count+"`r`n"+$SourcePath+"`r`n"+$Preview.text+"`r`nممکن است ورود یا اتصال بازی قطع شود. فقط به پیش‌نویس اضافه شود؟ هنوز ذخیره/Apply نمی‌شود."
 if([Windows.Forms.MessageBox]::Show($note,'بازبینی دقیق بازهٔ پورت مقصد','YesNo','Warning') -ne 'Yes'){return}
 $new=@($Preview.entries|ForEach-Object{New-IPDraftRow $Ids $_.ip $_.protocol $_.port $SourcePath});$next=Merge-IPDraft $script:ipDraft $new
 $bound=0;foreach($row in @($next)){$bound+=@($row.program_ids).Count};if($bound -gt 1024){throw 'مجموع قواعد بالقوه بیش از ۱۰۲۴ است؛ بازه/EXEها را محدود کنید. پیش‌نویس قبلی حفظ شد.'}
 $script:ipDraft=$next;$script:ipDirty=$true;Render-Drafts;$tabs.SelectedTab=$blackTab;$blackSections.SelectedTab=$ipDraftTab
}
# Remove the former expanding tool panels from navigation. Controls are reparented, never disposed.
foreach($entry in $script:menuEntries){$script:desktopNavigationPanel.Controls.Remove($entry.tools);$entry.tools.Visible=$false}
function Update-VerticalMenu {
 foreach($entry in $script:menuEntries){$active=($tabs.SelectedTab -eq $entry.page);$entry.tools.Visible=$false;$entry.button.BackColor=if($active){$blue}else{[Drawing.Color]::White};$entry.button.ForeColor=if($active){[Drawing.Color]::White}else{$ink}}
}
$programDraft=Local-Button 'افزودن IP برای EXEهای تیک‌خورده';$programDraft.Add_Click({TryOp {Edit-IPDraft}})
$programTab.Controls.Clear();$programLayout=Stack $programTab 4
$programPrimary=Flow;foreach($c in @($add,$observe,$baselineStart,$stop,$duration,$dnsTrace)){Local-Control $programPrimary $c};$programLayout.Controls.Add($programPrimary,0,0)
$programSearch=Flow;Local-Control $programSearch $filter;$filter.AccessibleName='جست‌وجوی نام یا مسیر EXE';$tip.SetToolTip($filter,'جست‌وجوی نام یا مسیر EXE')
$programAdvancedToggle=Button 'انتخاب‌ها / مدیریت EXE';Local-Control $programSearch $programAdvancedToggle;$programLayout.Controls.Add($programSearch,0,1)
$programAdvanced=Flow;$programAdvanced.Visible=$false;foreach($c in @($remove,$reload,$selectVisible,$clearVisible,$clearAll,$copyPath,$programDraft)){Local-Control $programAdvanced $c};$programLayout.Controls.Add($programAdvanced,0,2)
$programAdvancedToggle.Tag=$programAdvanced;$programAdvancedToggle.Add_Click({param($sender,$e)$sender.Tag.Visible=-not $sender.Tag.Visible});$programLayout.Controls.Add($programGrid,0,3)
$counts.Dock='Fill';$counts.MaximumSize=New-Object Drawing.Size(0,0);$counts.AutoSize=$true;$footer.Controls.Add($counts,0,0)
$null=Local-Page $policyTab 'IP/CIDR/بازه در هر خط. Block صریح مقدم است؛ دامنه در وایت‌لیست پشتیبانی نمی‌شود. فعال‌سازی سراسری و Kill-switch موجود نیست.' $whitelist @($mode,$save,$preview,$importBlack,$importWhite)
$null=Local-Page $detailTab 'جزئیات عملیات و گزارش‌های خصوصی؛ خطا یا ناشناخته به معنی آزادبودن اتصال نیست.' $output @()
$null=Local-Page $historyTab 'سوابق منتخب یا خط مبنا را بخوانید، سپس یک ثبت را باز یا ZIP خصوصی تهیه کنید.' $historyGrid @($historyReload,$baselineHistory,$historyOpen,$historyExport)
# Live controls near the live table; optional PTR/cleanup lives in a collapsible section.
$monitorTab.Controls.Clear();$monitorLayout=Stack $monitorTab 4;$monitorLayout.RowStyles[3].SizeType='Percent';$monitorLayout.RowStyles[3].Height=100
$monitorPrimary=Flow;foreach($c in @($liveFilter,$onlyPresent,$monitorStop,$showPopup,$transferPrograms,$stageObserved,$liveDetails)){Local-Control $monitorPrimary $c};$monitorLayout.Controls.Add($monitorPrimary,0,0)
$liveStatus.Dock='Fill';$liveStatus.MaximumSize=New-Object Drawing.Size(0,0);$liveStatus.Height=42;$monitorLayout.Controls.Add($liveStatus,0,1)
$advanced=Flow;$advanced.Visible=$false;foreach($c in @($ptrPick,$ptrAll,$ptrStop,$ptrForce,$dnsCleanup)){Local-Control $advanced $c};$monitorLayout.Controls.Add($advanced,0,2)
$advancedToggle=Button 'PTR / ابزار پیشرفته';Local-Control $monitorPrimary $advancedToggle;$advancedToggle.Tag=$advanced;$advancedToggle.Add_Click({param($sender,$e)$sender.Tag.Visible=-not $sender.Tag.Visible})
$monitorLayout.Controls.Add($mainLiveTabs,0,3)
# Clear labels instead of a menu that grows with every tool. Recovery remains pinned on the right.
$blackTab.Controls.Clear();$blackSections=New-Object Windows.Forms.TabControl;$blackSections.Dock='Fill';$blackSections.RightToLeft='Yes';$blackTab.Controls.Add($blackSections)
$ipDraftTab=Nested-Tab $blackSections 'IP / رنج — پیش‌نویس';$savedIPTab=Nested-Tab $blackSections 'IP ذخیره‌شده';$blackDomainTab=Nested-Tab $blackSections 'دامنه — پیش‌نویس hosts'
$ipDraftGrid=Grid @(@('target','IP / CIDR / بازه'),@('protocol','پروتکل'),@('port','پورت'),@('programs','EXE دقیق'),@('status','وضعیت پیش‌نویس'));$ipDraftGrid.ReadOnly=$true;$ipDraftGrid.RightToLeft='No';$ipDraftGrid.Columns['programs'].FillWeight=240
$ipNew=Local-Button 'افزودن IP';$ipEdit=Local-Button 'ویرایش ردیف';$ipDelete=Local-Button 'حذف از پیش‌نویس';$rangeAdd=Local-Button 'رنج IP / پورت';$ipSave=Local-Button 'ذخیرهٔ بلک‌لیست';$ipRevert=Local-Button 'بازگشت به ذخیره‌شده';$ipDraftStatus=Label ''
$ipPanel=Local-Page $ipDraftTab 'ویرایش در جدول موقت است. IP رصدشده به همان EXE متصل می‌شود؛ برای DNS، پورت/پروتکل حدس زده نمی‌شود.' $ipDraftGrid @($ipNew,$ipEdit,$ipDelete,$rangeAdd,$ipSave,$ipRevert);$ipPanel.Controls.Remove($ipPanel.GetControlFromPosition(0,0));$ipPanel.Controls.Add($ipDraftStatus,0,0)
$ipNew.Add_Click({TryOp {Edit-IPDraft}});$ipEdit.Add_Click({TryOp {Edit-IPDraft (Draft-Selection $ipDraftGrid)}})
$ipDelete.Add_Click({TryOp {$ids=@($ipDraftGrid.SelectedRows|ForEach-Object{$_.Tag.id});if(-not $ids.Count){throw 'ردیف را انتخاب کنید.'};$script:ipDraft=@($script:ipDraft|Where-Object{$ids -cnotcontains $_.id});$script:ipDirty=$true;Render-Drafts}})
$ipSave.Add_Click({TryOp {BeginOp 'workspace_blacklist_save' @{generation=$script:ipGeneration;rows=(Export-IPDraft $script:ipDraft)}}})
$ipRevert.Add_Click({TryOp {if([Windows.Forms.MessageBox]::Show('پیش‌نویس IP کنار گذاشته شود و تنظیمات فعلی دوباره خوانده شود؟','بازگشت','YesNo') -eq 'Yes'){$script:ipDirty=$false;BeginOp 'load' @{}}}})
$rangeAdd.Add_Click({TryOp {Open-RangeBuilder}})
$null=Local-Page $savedIPTab 'تنظیمات ذخیره‌شده؛ برای تغییر قواعد فعال ابتدا Restore نسخهٔ فعال و سپس Apply. Apply فقط حالت blacklist_only LAB است.' $blackGrid @($apply)
# Shared domain draft appears in both Blacklist and Hosts; never diverges into unrelated input boxes.
$blackDomainGrid=Grid @(@('domain','نام دقیق دامنه'),@('operation','عملیات برنامه‌ریزی‌شده'));$blackDomainGrid.ReadOnly=$true;$blackDomainGrid.RightToLeft='No'
$hostsTab.Controls.Clear();$hostSections=New-Object Windows.Forms.TabControl;$hostSections.Dock='Fill';$hostsTab.Controls.Add($hostSections)
$hostDraftTab=Nested-Tab $hostSections 'پیش‌نویس محلی';$hostActualTab=Nested-Tab $hostSections 'فایل واقعی Windows'
$hostDraftGrid=Grid @(@('domain','نام دقیق دامنه'),@('operation','عملیات برنامه‌ریزی‌شده'));$hostDraftGrid.ReadOnly=$true;$hostDraftGrid.RightToLeft='No'
$hostDraftStatus=Label '';$blackDomainStatus=Label ''
foreach($item in @(@($hostDraftTab,$hostDraftGrid,$hostDraftStatus),@($blackDomainTab,$blackDomainGrid,$blackDomainStatus))){
 $page=$item[0];$grid=$item[1];$label=$item[2]
 $new=Local-Button 'افزودن دامنه';$edit=Local-Button 'ویرایش ردیف';$delete=Local-Button 'حذف از پیش‌نویس';$saveDraft=Local-Button 'ذخیرهٔ محلی hosts';$loadDraft=Local-Button 'خواندن ذخیرهٔ محلی';$previewDraft=Local-Button 'پیش‌نمایش / اعمال hosts'
 $new.Add_Click({TryOp {Edit-HostDraft $null}});$edit.Tag=$grid;$edit.Add_Click({param($sender,$e)TryOp {Edit-HostDraft $sender.Tag}});$delete.Tag=$grid;$delete.Add_Click({param($sender,$e)TryOp {Delete-HostDraft $sender.Tag}})
 $saveDraft.Add_Click({TryOp {Save-HostDraft}});$previewDraft.Add_Click({TryOp {Preview-HostDraft}})
 $loadDraft.Add_Click({TryOp {if($script:hostDirty -and $script:hostLoaded){if([Windows.Forms.MessageBox]::Show('پیش‌نویس دامنه کنار گذاشته و ذخیرهٔ محلی خوانده شود؟','بازخوانی','YesNo') -ne 'Yes'){return};$script:hostDirty=$false};BeginOp 'workspace_hosts_load' @{}}})
 $panel=Local-Page $page '' $grid @($new,$edit,$delete,$saveDraft,$loadDraft,$previewDraft);$panel.Controls.Remove($panel.GetControlFromPosition(0,0));$panel.Controls.Add($label,0,0)
}
$actualEdit=Local-Button 'ویرایش نام → پیش‌نویس';$actualDelete=Local-Button 'حذف نگاشت → پیش‌نویس';$actualEdit.Add_Click({TryOp {Edit-HostDraft $hostsGrid $true}});$actualDelete.Add_Click({TryOp {Edit-HostDraft $hostsGrid $true $true}})
$null=Local-Page $hostActualTab 'این جدول فایل واقعی ویندوز است. تغییر/حذف ابتدا به پیش‌نویس می‌رود؛ ذخیرهٔ محلی، سپس پیش‌نمایش و تأیید تایپی سراسری لازم است.' $hostsGrid @($hostRead,$hostFilter,$actualEdit,$actualDelete)
$hostsSummary.MaximumSize=New-Object Drawing.Size(0,0);$hostsSummary.AutoSize=$false;$hostsSummary.AutoEllipsis=$true;$hostsSummary.Height=34
$hostsSummary.Add_MouseEnter({$tip.SetToolTip($hostsSummary,$hostsSummary.Text)})
# Titles are deliberately short; explanatory safety text remains available in global help/preview.
$stageObserved.Text='مقصد → پیش‌نویس بلک‌لیست'
foreach($menuItem in $script:observedMenus){$menuItem.Items[0].Text='بلک‌لیست ← جدول پیش‌نویس (ذخیره بعداً)';$menuItem.Items[0].ToolTipText='دامنه به جدول hosts مشترک؛ IP به جدول موقت با EXE/پورت واقعی. هیچ ذخیره یا Apply انجام نمی‌شود.'}
$hostRead.Text='خواندن فایل واقعی hosts';$save.Text='ذخیرهٔ سیاست';$workspace.ColumnStyles[1].Width=270
$form.Add_FormClosing({param($sender,$e)if(-not $e.Cancel -and ($script:ipDirty -or $script:hostDirty)){if([Windows.Forms.MessageBox]::Show('پیش‌نویس ذخیره‌نشده دارید. بدون ذخیره بسته شود؟ قواعد فعال Restore نمی‌شوند.','بستن پیش‌نویس','YesNo','Warning') -ne 'Yes'){$e.Cancel=$true;$script:closing=$false}}})
Update-VerticalMenu
