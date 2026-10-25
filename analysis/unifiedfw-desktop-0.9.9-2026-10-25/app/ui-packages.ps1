# One top-level row per normalized domain, with opt-in route-level batch staging.
. (Join-Path $PSScriptRoot 'package-model.ps1')
$packageTab=New-Object Windows.Forms.TabPage;$packageTab.Text='بسته‌های فعالیت / مدیریت یکجا';$packageTab.BackColor=[Drawing.Color]::White;[void]$mainLiveTabs.TabPages.Add($packageTab)
$packageLayout=Stack $packageTab 3
$packageNote=Label 'یک بسته برای هر نام DNS، با حفظ EXEها و مسیرها. فقط فعالیت‌های ثبت‌شده؛ تلمتری نامِ فعالیت است، نه الزاماً یک فرایند مستقل. DNS/نام مشترک IP، اثبات نام همین سوکت نیست. پالس کل ردیف: زرد DNS؛ قرمز منع WFP یا پاسخ تهی/محلی (ستون جدا)؛ آبی فقط نمونه TCP، نه تحویل درخواست.';$packageLayout.Controls.Add($packageNote,0,0)
$packageTools=Flow;$packageManage=Button 'بستهٔ منتخب: تیک مسیرها / انتقال یکجا';$packageTools.Controls.Add($packageManage);$packageLayout.Controls.Add($packageTools,0,1)
$packageGrid=Grid @(@('label','بسته / فعالیت'),@('paths','برنامه‌های دقیق'),@('routes','مسیرهای ثبت‌شده'),@('dns','رویداد DNS'),@('sink','پاسخ تهی/محلی'),@('deny','منع WFP'),@('tcp','نمونه TCP'))
$packageGrid.ReadOnly=$true;$packageGrid.MultiSelect=$false;$packageGrid.RightToLeft='No';$packageGrid.Columns['label'].FillWeight=240;$packageGrid.Columns['paths'].FillWeight=220;$packageLayout.Controls.Add($packageGrid,0,2)
$script:packageSeen=@{};$script:packageCapture=''
function Render-ActivityPackages($Frame,[bool]$Pulse=$true){
 $capture=if($Frame.PSObject.Properties.Name -contains 'capture_id'){[string]$Frame.capture_id}else{''};if($capture -cne $script:packageCapture){$script:packageSeen=@{};$script:packageCapture=$capture}
 $selected='';if($packageGrid.SelectedRows.Count -eq 1){$selected=[string]$packageGrid.SelectedRows[0].Tag.key}
 $packageGrid.SuspendLayout();try{
  $existing=@{};foreach($row in $packageGrid.Rows){$existing[[string]$row.Tag.key]=$row};$visible=@{}
  foreach($p in @(Get-ActivityPackages $Frame|Sort-Object label)){
   if($liveFilter.Text.Trim() -and ($p.label+' '+($p.paths -join ' ')).IndexOf($liveFilter.Text.Trim(),[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
   $visible[$p.key]=$true
   if($existing.ContainsKey($p.key)){$row=$existing[$p.key]}else{$i=$packageGrid.Rows.Add();$row=$packageGrid.Rows[$i]}
   $row.Tag=$p;$row.Cells['label'].Value=$p.label;$row.Cells['paths'].Value=(@($p.paths|ForEach-Object{[IO.Path]::GetFileName($_)}) -join '; ');$row.Cells['routes'].Value=$p.routes.Count;$row.Cells['dns'].Value=$p.dns_count;$row.Cells['sink'].Value=$p.sink_count;$row.Cells['deny'].Value=$p.denied_count;$row.Cells['tcp'].Value=$p.tcp_samples;$row.Cells['paths'].ToolTipText=$p.paths -join "`r`n"
   $row.DefaultCellStyle.BackColor=[Drawing.ColorTranslator]::FromHtml($(if($p.denied_count -gt 0){'#FCE9E7'}elseif($p.sink_count -gt 0){'#FFF1DC'}else{'#FFFFFF'}))
   $base=$row.DefaultCellStyle.BackColor;$row.DefaultCellStyle.SelectionBackColor=$base;$row.DefaultCellStyle.SelectionForeColor=[Drawing.Color]::Black
   $kind=Get-PackagePulse $script:packageSeen[$p.key] $p;$script:packageSeen[$p.key]=$p
   $active=$row.Cells['label'].Tag;if($null -ne $active -and $active.until -gt [DateTime]::UtcNow -and $flash.Checked -and -not $script:liveFinal){$row.DefaultCellStyle.BackColor=$active.color;$row.DefaultCellStyle.SelectionBackColor=$active.color}
   if($Pulse -and $flash.Checked -and -not $script:liveFinal -and $kind -cne 'none'){$row.DefaultCellStyle.BackColor=[Drawing.ColorTranslator]::FromHtml((Get-EvidencePulseColor $kind));$row.DefaultCellStyle.SelectionBackColor=$row.DefaultCellStyle.BackColor;$row.Cells['label'].Tag=[pscustomobject]@{until=[DateTime]::UtcNow.AddSeconds(1.6);base=$base;color=$row.DefaultCellStyle.BackColor}}
  }
  for($i=$packageGrid.Rows.Count-1;$i -ge 0;$i--){if(-not $visible.ContainsKey([string]$packageGrid.Rows[$i].Tag.key)){$packageGrid.Rows.RemoveAt($i)}}
  $packageGrid.ClearSelection();foreach($row in $packageGrid.Rows){if($row.Tag.key -ceq $selected){$row.Selected=$true}}
  $packageTab.Text='بسته‌های فعالیت ('+$packageGrid.Rows.Count+')'
 }finally{$packageGrid.ResumeLayout()}
}
function Manage-ActivityPackage {
 if($null -ne $script:job -and $script:job.action -notin @('monitor_record','baseline_record')){throw 'تا پایان عملیات جاری صبر کنید؛ هیچ پیش‌نویسی تغییر نکرد.'}
 if($packageGrid.SelectedRows.Count -ne 1){throw 'یک بسته را انتخاب کنید.'};if($null -eq $script:state){throw 'تنظیمات هنوز خوانده نشده است.'}
 $p=$packageGrid.SelectedRows[0].Tag
 $d=New-Object Windows.Forms.Form;$d.Text='مدیریت یکجای بسته: '+$p.label;$d.Size=New-Object Drawing.Size(1050,650);$d.Font=$form.Font;$d.RightToLeft='Yes';$d.StartPosition='CenterParent'
 $layout=Stack $d 5;$layout.RowStyles[2].SizeType='Percent';$layout.RowStyles[2].Height=100;$layout.RowStyles[4].SizeType='AutoSize'
 $layout.Controls.Add((Label 'ردیف اصلی یکی است؛ این‌ها مسیرهای همان بسته‌اند، نه فرایند تکراری. انتخاب همه فقط مسیرهای ثبت‌شده را پوشش می‌دهد، نه آدرسها/روش‌های ناشناخته و آینده. وایت‌لیست فعلی سراسری است؛ hosts هم سراسری و نام دقیق است، نه مخصوص EXE.'),0,0)
 $tools=Flow;$all=Button 'تیک همهٔ مسیرها';$none=Button 'برداشتن همهٔ تیک‌ها';$tools.Controls.Add($all);$tools.Controls.Add($none);$layout.Controls.Add($tools,0,1)
 $pick=New-Object Windows.Forms.CheckedListBox;$pick.Dock='Fill';$pick.CheckOnClick=$true;$pick.RightToLeft='No';$pick.HorizontalScrollbar=$true
 foreach($r in $p.routes){$transport=if($r.protocol){$r.protocol+':'+$r.port}else{'DNS answer: transport UNKNOWN'};[void]$pick.Items.Add(($r.program_path+' | '+$r.ip+' | '+$transport+' | '+($r.identities.Keys -join ';')),$false)}
 $all.Tag=$pick;$none.Tag=$pick;$all.Add_Click({param($sender,$e)for($i=0;$i -lt $sender.Tag.Items.Count;$i++){$sender.Tag.SetItemChecked($i,$true)}});$none.Add_Click({param($sender,$e)for($i=0;$i -lt $sender.Tag.Items.Count;$i++){$sender.Tag.SetItemChecked($i,$false)}})
 $layout.Controls.Add($pick,0,2)
 $transportBar=Flow;$unknown=New-Object Windows.Forms.ComboBox;$unknown.DropDownStyle='DropDownList';[void]$unknown.Items.AddRange(@('برای مسیر DNS انتخاب کنید','TCP','UDP','Any'));$unknown.SelectedIndex=0
 $first=New-Object Windows.Forms.NumericUpDown;$first.Minimum=0;$first.Maximum=65535;$last=New-Object Windows.Forms.NumericUpDown;$last.Minimum=0;$last.Maximum=65535;$first.Tag=$last;$first.Add_ValueChanged({param($sender,$e)if($sender.Tag.Value -lt $sender.Value){$sender.Tag.Value=$sender.Value}})
 foreach($c in @((Label 'فقط برای IP پاسخ DNS با پورت نامعلوم'),$unknown,(Label 'پورت از'),$first,(Label 'تا'),$last,(Label 'Any در بلک‌لیست = TCP+UDP همه پورت‌ها؛ در وایت‌لیست = همه پروتکل‌ها'))){Local-Control $transportBar $c};$layout.Controls.Add($transportBar,0,3)
 $buttons=Flow;$black=Button 'مسیرهای تیک‌خورده → بلک‌لیست';$black.DialogResult='Yes';$white=Button 'مسیرهای تیک‌خورده → وایت‌لیست';$white.DialogResult='No';$hostButton=Button 'خود نام دامنه → hosts';$hostButton.DialogResult='Retry';$hostButton.Enabled=[bool]$p.domain;$cancel=Button 'لغو';$cancel.DialogResult='Cancel'
 foreach($c in @($black,$white,$hostButton,$cancel)){$buttons.Controls.Add($c)};$layout.Controls.Add($buttons,0,4);$d.CancelButton=$cancel;$d.AcceptButton=$cancel
 try{
  Prepare-Dialog $d;$answer=$d.ShowDialog($form);if($answer -notin @('Yes','No','Retry')){return}
  $routes=@($pick.CheckedIndices|ForEach-Object{$p.routes[[int]$_]});$action=switch($answer){'Yes'{'blacklist'};'No'{'whitelist'};'Retry'{'hosts'}}
  $plan=New-PackageTransferPlan $p $routes @($script:state.config.programs) $action $(if($unknown.SelectedIndex -gt 0){[string]$unknown.SelectedItem}else{''}) ([int]$first.Value) ([int]$last.Value)
  # Compute all merges before assigning any draft. No partial UI staging on failure.
  $newBlack=Merge-IPDraft $script:ipDraft $plan.black;$newWhite=Merge-WhitelistDraft ([string]$whitelist.Text) $plan.white;$newHosts=@($script:hostDraft)
  foreach($h in $plan.hosts){$old=@($newHosts|Where-Object{$_.domain -ieq $h.domain -and $_.operation -cne 'sink'});if($old.Count){throw 'نام در پیش‌نویس حذف است؛ ابتدا تعارض را در hosts حل کنید.'};$newHosts=Merge-HostDraft $newHosts $h}
  $review='بسته: '+$p.label+"`r`nIP/پورت بلک‌لیست: "+$plan.black.Count+"`r`nمجوز وایت‌لیست سراسری: "+$plan.white.Count+"`r`nhosts سراسری: "+$plan.hosts.Count+"`r`nفقط انتقال به پیش‌نویس؛ نه ذخیره و نه Apply. آدرس آینده پوشش داده نشده؛ IP مشترک ممکن است سرویس دیگری را هم شامل شود. ادامه؟"
  if([Windows.Forms.MessageBox]::Show($review,'مرور انتقال یکجای بسته','YesNo','Warning','Button2') -ne 'Yes'){return}
  if($plan.black.Count){$script:ipDraft=$newBlack;$script:ipDirty=$true;$tabs.SelectedTab=$blackTab;$blackSections.SelectedTab=$ipDraftTab}
  if($plan.white.Count){$whitelist.Text=$newWhite;$tabs.SelectedTab=$policyTab}
  if($plan.hosts.Count){$script:hostDraft=$newHosts;$script:hostDirty=$true;$tabs.SelectedTab=$blackTab;$blackSections.SelectedTab=$blackDomainTab}
  Render-Drafts;$status.Text='بسته به‌صورت یکجا به پیش‌نویس منتقل شد؛ ذخیره و اعمال جداست. هویت EXEها حفظ شد و هیچ مجوز/انسداد آینده‌ای حدس زده نشد.'
 }finally{$d.Dispose()}
}
$packageManage.Add_Click({TryOp {Manage-ActivityPackage}});$packageGrid.Add_CellDoubleClick({param($sender,$e)if($e.RowIndex -ge 0){TryOp {Manage-ActivityPackage}}})
$mainLiveTabs.SelectedTab=$packageTab

function Expire-PackagePulses {
 foreach($row in $packageGrid.Rows){$pulse=$row.Cells['label'].Tag;if($null -ne $pulse -and ([DateTime]::UtcNow -ge $pulse.until -or -not $flash.Checked)){$row.DefaultCellStyle.BackColor=$pulse.base;$row.DefaultCellStyle.SelectionBackColor=$pulse.base;$row.Cells['label'].Tag=$null}}
}
$liveFilter.Add_TextChanged({if($null -ne $script:liveFrame){Render-ActivityPackages $script:liveFrame $false}})
