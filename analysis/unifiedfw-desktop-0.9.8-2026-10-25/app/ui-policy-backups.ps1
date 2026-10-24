# Backups/defaults change only local settings. Native Restore remains explicit and separate.
function Get-PolicyUIDraft {
 return @{ip_rows=(Export-IPDraft $script:ipDraft);whitelist_text=[string]$whitelist.Text;mode=[string]$mode.SelectedItem}
}
function Reset-PolicySettings([string]$Scope){
 $name=if($Scope -ceq 'blacklist'){'بلک‌لیست IP'}else{'وایت‌لیست'}
 $detail=if($Scope -ceq 'whitelist'){'وایت‌لیست خالی و حالت ذخیره‌شده به blacklist_only برمی‌گردد؛ بلک‌لیست حفظ می‌شود.'}else{'فقط فهرست ذخیره‌شدهٔ بلک‌لیست IP خالی می‌شود؛ EXEها و وایت‌لیست حفظ می‌شوند.'}
 $message=$detail+"`r`nقبل از تغییر، تنظیمات فعلی و پیش‌نویس‌های روی صفحه پشتیبان و با بازخوانی تأیید می‌شوند. شکست پشتیبان‌گیری تغییر را متوقف می‌کند.`r`nاین دکمه فایروال ویندوز، hosts، Audit و قواعد فعال را Restore نمی‌کند. برای رفع قواعد فعال از Restore قواعد ثبت‌شده استفاده کنید؛ تنظیمات خالی به معنی رفع انسداد فعال نیست."
 if(ConfirmText ('پیش‌فرض تنظیمات '+$name) $message 'RESET POLICY SETTINGS'){BeginOp 'workspace_policy_defaults' @{scope=$Scope;generation=(Generation);confirmation='RESET POLICY SETTINGS';ui_snapshot=(Get-PolicyUIDraft)}}
}
function Start-PolicyBackupList([string]$Scope){BeginOp 'workspace_policy_backup_list' @{};$script:job.backup_scope=$Scope}
function Show-PolicyBackupList($Backups,[string]$Scope){
 if(@($Backups.items).Count -eq 0){$status.Text='پشتیبان معتبر برای همین مالک پیدا نشد؛ اولین ذخیرهٔ تغییرات، پشتیبان قبل از تغییر می‌سازد. فایل نامعتبر/مالک دیگر: '+$Backups.invalid_or_other_owner;return}
 $dialog=New-Object Windows.Forms.Form;$dialog.Text='بازیابی تنظیمات '+$(if($Scope -ceq 'blacklist'){'بلک‌لیست'}else{'وایت‌لیست'});$dialog.Font=$form.Font;$dialog.AutoScaleMode='Dpi';$dialog.StartPosition='CenterParent';$dialog.Size=New-Object Drawing.Size(940,560);$dialog.MinimumSize=New-Object Drawing.Size(650,400);$dialog.RightToLeft='Yes'
 $layout=Stack $dialog 3;$layout.RowStyles[0].SizeType='AutoSize';$layout.RowStyles[1].SizeType='Percent';$layout.RowStyles[1].Height=100;$layout.RowStyles[2].SizeType='AutoSize'
 $layout.Controls.Add((Label 'یک پشتیبان را انتخاب کنید. فقط تنظیمات همین بخش بازیابی می‌شود؛ قواعد فعال تغییر نمی‌کنند. قبل از بازیابی هم از وضعیت فعلی پشتیبان گرفته می‌شود. پیش‌نویس ذخیره‌نشدهٔ پشتیبان، در صورت وجود، جدا به صفحه برمی‌گردد.'),0,0)
 $grid=Grid @(@('utc','زمان UTC'),@('generation','نسل'),@('black','تعداد بلک‌لیست'),@('white','تعداد وایت‌لیست'),@('draft','پیش‌نویس صفحه'),@('reason','دلیل پشتیبان'));$grid.ReadOnly=$true;$grid.MultiSelect=$false;$grid.RightToLeft='No'
 foreach($b in @($Backups.items)){$i=$grid.Rows.Add($b.created_utc,$b.generation,$b.blacklist_count,$b.whitelist_count,$b.has_unsaved_UI,$b.reason);$grid.Rows[$i].Tag=$b}
 $layout.Controls.Add($grid,0,1);$buttons=Flow;$ok=Button 'بازیابی بخش منتخب';$ok.DialogResult='OK';$cancel=Button 'انصراف';$cancel.DialogResult='Cancel';$buttons.Controls.Add($ok);$buttons.Controls.Add($cancel);$layout.Controls.Add($buttons,0,2);$dialog.AcceptButton=$cancel;$dialog.CancelButton=$cancel
 Prepare-Dialog $dialog
 try{
  $grid.ClearSelection();if($dialog.ShowDialog($form) -ne 'OK'){return};if($grid.SelectedRows.Count -ne 1){throw 'یک ردیف پشتیبان را انتخاب کنید؛ چیزی تغییر نکرد.'};$b=$grid.SelectedRows[0].Tag
  if(ConfirmText 'بازیابی تنظیمات از پشتیبان' ('بخش: '+$Scope+"`r`nزمان: "+$b.created_utc+"`r`nشناسه: "+$b.id+"`r`nنسل قدیمی دوباره استفاده نمی‌شود؛ نسل تازه ثبت می‌شود. owner، EXEهای فعلی و بخش دیگر حفظ می‌شوند. قواعد فعال و hosts تغییر نمی‌کنند. وضعیت فعلی قبل از تغییر پشتیبان می‌شود.") 'RESTORE POLICY SETTINGS'){
   BeginOp 'workspace_policy_backup_restore' @{scope=$Scope;generation=(Generation);backup_id=[string]$b.id;confirmation='RESTORE POLICY SETTINGS';ui_snapshot=(Get-PolicyUIDraft)}
  }
 }finally{$dialog.Dispose()}
}
function Accept-PolicySettingsResult($Result){
 $x=$Result.policy_settings_result
 if($x.operation -ceq 'restore_backup' -and $null -ne $x.restored_UI){
  if($x.scope -ceq 'blacklist'){$script:ipDraft=@($x.restored_UI.ip_rows|ForEach-Object{New-IPDraftRow @($_.program_ids) $_.target $_.protocol $_.port $_.source_path});$script:ipDirty=$true;Render-Drafts}
  else{$whitelist.Text=[string]$x.restored_UI.whitelist_text;$mode.SelectedItem=[string]$x.restored_UI.mode}
 }
 $status.Text='تنظیمات '+$x.scope+' '+$(if($x.operation -ceq 'defaults'){'به پیش‌فرض برگشت'}else{'از پشتیبان بازیابی شد'})+'؛ پشتیبان قبل از تغییر: '+$x.prechange_backup_id+' | فقط تنظیمات؛ قواعد فعال Restore نشدند.'
 if($x.scope -ceq 'blacklist'){$tabs.SelectedTab=$blackTab;$blackSections.SelectedTab=$ipDraftTab}else{$tabs.SelectedTab=$policyTab}
}
foreach($pair in @(@($ipPanel.GetControlFromPosition(0,1),'blacklist'),@($policyTab.Controls[0].GetControlFromPosition(0,1),'whitelist'))){
 $defaults=Local-Button 'پیش‌فرض تنظیمات';$defaults.Tag=[string]$pair[1];$defaults.Add_Click({param($sender,$e)TryOp {Reset-PolicySettings ([string]$sender.Tag)}})
 $backups=Local-Button 'پشتیبان‌ها / بازیابی تنظیمات';$backups.Tag=[string]$pair[1];$backups.Add_Click({param($sender,$e)TryOp {Start-PolicyBackupList ([string]$sender.Tag)}})
 Local-Control $pair[0] $defaults;Local-Control $pair[0] $backups
 $tip.SetToolTip($defaults,'پشتیبان تأییدشده قبل از تغییر؛ تنظیمات همین بخش، نه بازنشانی فایروال ویندوز.')
}
