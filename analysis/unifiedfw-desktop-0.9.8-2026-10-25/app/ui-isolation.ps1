# Whitelist range editor and explicit system-wide SSTP isolation controls.
function Open-WhiteRange([bool]$Edit=$false){
 $original=[string]$whitelist.Text;$lines=@($whitelist.Lines);$index=-1;$seed=''
 if($Edit){$index=$whitelist.GetLineFromCharIndex($whitelist.SelectionStart);if($index -ge $lines.Count -or -not $lines[$index].Trim()){throw 'نشانگر را در خط موردنظر وایت‌لیست قرار دهید.'};$seed=$lines[$index].Trim()}
 $d=New-Object Windows.Forms.Form;$d.Text='بازهٔ IP و پورت وایت‌لیست — فقط پیش‌نویس';$d.Size=New-Object Drawing.Size(800,540);$d.Font=$form.Font;$d.StartPosition='CenterParent';$d.RightToLeft='Yes'
 $v=Stack $d 7;$v.RowStyles[2].SizeType='Percent';$v.RowStyles[2].Height=100
 $v.Controls.Add((Label 'فقط IP، CIDR یا بازه؛ دامنه Resolve نمی‌شود. Any یعنی همهٔ پروتکل‌ها و پورت‌ها و نیاز به بازبینی دارد. ذخیره و اعمال واقعی دو مرحلهٔ جدا هستند.'),0,0)
 $kind=New-Object Windows.Forms.ComboBox;$kind.DropDownStyle='DropDownList';[void]$kind.Items.AddRange(@('پیشوند / wildcard','از IP تا IP','CIDR / IP','فهرست IP دقیق'));$kind.SelectedIndex=2;$v.Controls.Add($kind,0,1)
 $value=TextBox 600;$value.Multiline=$true;$value.Dock='Fill';$value.ScrollBars='Vertical';$v.Controls.Add($value,0,2)
 $last=TextBox 600;$last.AccessibleName='انتهای IP در حالت از / تا';$v.Controls.Add($last,0,3)
 $bar=Flow;$protoWhite=New-Object Windows.Forms.ComboBox;$protoWhite.DropDownStyle='DropDownList';[void]$protoWhite.Items.AddRange(@('TCP','UDP','Any'));$protoWhite.SelectedIndex=0
 $start=New-Object Windows.Forms.NumericUpDown;$start.Minimum=0;$start.Maximum=65535;$start.Value=443
 $end=New-Object Windows.Forms.NumericUpDown;$end.Minimum=0;$end.Maximum=65535;$end.Value=443
 foreach($c in @((Label 'پروتکل'),$protoWhite,(Label 'پورت از'),$start,(Label 'تا'),$end)){Local-Control $bar $c};$v.Controls.Add($bar,0,4)
 $v.Controls.Add((Label 'در حالت Any مقدار پورت نادیده گرفته می‌شود؛ فقط داخل تونل مجاز خواهد بود. ویرایش، خط قبلی را پس از پذیرش پیش‌نمایش جایگزین می‌کند.'),0,5)
 if($seed){$parts=$seed.Split('|');$value.Text=$parts[0];if($parts[0].Contains('-')){$ip=$parts[0].Split('-');$kind.SelectedIndex=1;$value.Text=$ip[0];$last.Text=$ip[1]};if($parts.Count -eq 1){$protoWhite.SelectedItem='Any'}else{$protoWhite.SelectedItem=$parts[1];if($parts[2] -ne '*'){$ports=$parts[2].Split('-');$start.Value=[int]$ports[0];$end.Value=[int]$ports[-1]}}}
 $buttons=Flow;$ok=Button 'پیش‌نمایش';$ok.DialogResult='OK';$cancel=Button 'لغو';$cancel.DialogResult='Cancel';$buttons.Controls.Add($ok);$buttons.Controls.Add($cancel);$v.Controls.Add($buttons,0,6);$d.CancelButton=$cancel;$d.AcceptButton=$ok
 try{Prepare-Dialog $d;if($d.ShowDialog($form) -ne 'OK'){return};$any=([string]$protoWhite.SelectedItem -ceq 'Any')
  BeginOp 'workspace_whitelist_range_preview' @{mode=@('pattern','between','cidr','targets')[$kind.SelectedIndex];value=$value.Text;last=$last.Text;protocol=[string]$protoWhite.SelectedItem;port=$(if($any){0}else{[int]$start.Value});port_end=$(if($any){0}else{[int]$end.Value})}
  $script:job.white_original=$original;$script:job.white_index=$index
 }finally{$d.Dispose()}
}
function Accept-WhiteRange($Preview,$Job){
 if([string]$whitelist.Text -cne [string]$Job.white_original){throw 'پیش‌نویس در حین پیش‌نمایش تغییر کرد؛ چیزی جایگزین نشد.'}
 $rules=@($Preview.rules);$message=($rules -join "`r`n")+"`r`nفقط پیش‌نویس؛ نه ذخیره و نه اعمال روی فایروال. بازه/همهٔ پورت‌ها را بررسی کنید."
 if([Windows.Forms.MessageBox]::Show($message,'بازبینی وایت‌لیست','YesNo','Warning','Button2') -ne 'Yes'){return}
 $result=@();$lines=@($whitelist.Lines);for($i=0;$i -lt $lines.Count;$i++){if($i -eq [int]$Job.white_index){$result+= $rules}else{$result+=$lines[$i]}};if([int]$Job.white_index -lt 0){$result+=$rules}
 $whitelist.Lines=@($result|Where-Object{$_.Trim()}|Select-Object -Unique);$tabs.SelectedTab=$policyTab;$status.Text='پیش‌نویس وایت‌لیست به‌روز شد؛ ابتدا ذخیره، سپس بررسی و اعمال ایزولیشن.'
}
function Confirm-IsolationPlan($Plan){
 $message=@('تغییر سراسری ویندوز؛ Administrator لازم است. ممکن است تمام اینترنت قطع شود.','قبل از تغییر، تنظیمات و تصویر قواعد محلی پشتیبان می‌شوند. Allowهای خروجی محلی غیرفعال و خروجی پیش‌فرض هر سه پروفایل Block می‌شود.','اجازه‌ها: فقط IP/پورت وایت‌لیست داخل رابط دقیق SSTP، انتقال SSTP سرویس SstpSvc به IPهای تأییدشده و DNS فقط داخل همان رابط. DHCP و DNS بیرون تونل خودکار آزاد نمی‌شوند.','Task محافظ با SYSTEM ثبت می‌شود؛ با بستن رابط حفاظت پایدار می‌ماند. Allow محلی تازه پس از ثبت تصویر غیرفعال می‌شود؛ این پایش زمان‌بندی‌شده تضمین اتمی در برابر مدیر/GPO نیست.','تغییر نام/رابط/سرور VPN خودکار دسترسی را گسترش نمی‌دهد؛ باید دوباره بررسی و اعمال کنید. اتصال مجدد ممکن است به دلیل DNS/DHCP محدود شود.','Blockهای دیگران و hosts دست‌نخورده می‌مانند؛ وایت‌لیست آن‌ها را دور نمی‌زند.','برنامهٔ قدیمی و بلک‌لیست Native فعال باید ابتدا با ابزار خودش Restore شود.','تنظیمات پیش‌فرض، ایزولیشن فعال را خاموش نمی‌کند. فقط «بازیابی ایزولیشن» یا Isolation-Recovery.cmd تغییرات ثبت‌شده را برمی‌گرداند.','تست نشت روی دستگاه شما انجام نشده است.',(ConvertTo-Json -InputObject $Plan.review -Depth 10)) -join "`r`n"
 if(ConfirmText 'اعمال واقعی فول ایزولیشن SSTP — LAB' $message 'APPLY ISOLATION'){
  BeginOp 'isolation_apply' @{generation=[int]$Plan.generation;review_digest=[string]$Plan.review_digest;confirmation='APPLY ISOLATION'}
 }
}
function Accept-IsolationResult($Result){
 $x=$Result.isolation_status
 $status.Text='ایزولیشن: '+$x.phase+' | '+$x.health+' | پیکربندی بررسی‌شده: '+$x.configuration_verified+' | بدون تأیید تست نشت؛ جزئیات را بخوانید.'
 if($x.PSObject.Properties.Name -contains 'settings_match_active' -and -not $x.settings_match_active){$status.Text+=' | تنظیمات ذخیره‌شده با سیاست فعال یکسان نیست؛ ذخیره به معنی اعمال نیست.'}
 $tabs.SelectedTab=$policyTab
}
$whiteTools=$policyTab.Controls[0].GetControlFromPosition(0,1)
$whiteAdd=Local-Button 'افزودن بازهٔ IP / پورت';$whiteAdd.Add_Click({TryOp {Open-WhiteRange}})
$whiteEdit=Local-Button 'ویرایش / تبدیل خط به بازه';$whiteEdit.Add_Click({TryOp {Open-WhiteRange $true}})
$isoApply=Local-Button 'بررسی و اعمال فول ایزولیشن / کیل‌سوییچ';$isoApply.Add_Click({TryOp {AssertSaved;BeginOp 'isolation_prepare' @{generation=(Generation)}}})
$isoStatus=Local-Button 'وضعیت ایزولیشن / محافظ';$isoStatus.Add_Click({TryOp {BeginOp 'isolation_status' @{}}})
$isoRestore=Local-Button 'بازیابی ایزولیشن';$isoRestore.Add_Click({TryOp {if(ConfirmText 'بازیابی ایزولیشن' 'Task محافظ متوقف می‌شود؛ فقط قواعد و فیلدهای ثبت‌شده و بدون تغییر به وضعیت قبل برمی‌گردند. حفاظت ایزولیشن برداشته می‌شود. تعارض/تغییر خارجی بازیابی را متوقف می‌کند؛ تنظیمات و hosts پاک نمی‌شوند.' 'RESTORE ISOLATION'){BeginOp 'isolation_restore' @{confirmation='RESTORE ISOLATION'}}}})
foreach($c in @($whiteAdd,$whiteEdit,$isoApply,$isoStatus,$isoRestore)){Local-Control $whiteTools $c}
