# Default review contains plain-language outcomes, never JSON. Technical data stays opt-in.
$policyReviewTab=Tab 'بررسی سادهٔ سیاست';$null=New-MenuEntry $policyReviewTab 'بررسی سیاست / مشکل‌ها'
$reviewLayout=Stack $policyReviewTab 4;$reviewLayout.RowStyles[2].SizeType='Percent';$reviewLayout.RowStyles[2].Height=100;$reviewLayout.RowStyles[3].SizeType='AutoSize'
$reviewHeadline=Label 'هنوز بررسی انجام نشده است.';$reviewHeadline.Font=New-Object Drawing.Font('Tahoma',13,[Drawing.FontStyle]::Bold)
$reviewSummary=Label 'این صفحه فقط بررسی می‌کند؛ هیچ قاعده‌ای اعمال نمی‌شود.'
$reviewIssues=Grid @(@('level','نوع'),@('title','مشکل / نکته'),@('detail','کدام مورد و چه اثری؟'),@('fix','برای رفع یا ادامه چه کنید؟'));$reviewIssues.ReadOnly=$true;$reviewIssues.MultiSelect=$false;$reviewIssues.RightToLeft='Yes';$reviewIssues.Columns['level'].FillWeight=55;$reviewIssues.Columns['title'].FillWeight=125;$reviewIssues.Columns['detail'].FillWeight=220;$reviewIssues.Columns['fix'].FillWeight=240;$reviewIssues.DefaultCellStyle.WrapMode='True';$reviewIssues.AutoSizeRowsMode='AllCells'
$reviewButtons=Flow;$reviewBack=Button 'ویرایش سیاست / وایت‌لیست';$reviewAgain=Button 'بررسی دوباره';$reviewTechnical=Button 'جزئیات فنی — اختیاری'
foreach($c in @($reviewBack,$reviewAgain,$reviewTechnical)){$reviewButtons.Controls.Add($c)}
$reviewLayout.Controls.Add($reviewHeadline,0,0);$reviewLayout.Controls.Add($reviewSummary,0,1);$reviewLayout.Controls.Add($reviewIssues,0,2);$reviewLayout.Controls.Add($reviewButtons,0,3)
function Accept-PolicyReview($Review){
 $reviewHeadline.Text=[string]$Review.headline;$reviewSummary.Text=$Review.mode_label+' | وایت‌لیست: '+$Review.whitelist_count+' | بلک‌لیست: '+$Review.blacklist_count+' | فقط بررسی؛ هنوز اعمال نشده. این نتیجه در زمان بررسی است، نه تضمین اتصال یا نبود نشتی.'
 $reviewIssues.Rows.Clear()
 foreach($x in @($Review.issues)){
  $label=switch([string]$x.severity){'error'{'نیاز به رفع'};'warning'{'هشدار'};'notice'{'توضیح تقدم'};default{'اطلاع'}}
  $i=$reviewIssues.Rows.Add($label,$x.title,$x.detail,$x.fix);$row=$reviewIssues.Rows[$i];$row.DefaultCellStyle.BackColor=[Drawing.ColorTranslator]::FromHtml($(if($x.severity -ceq 'error'){'#FCE9E7'}elseif($x.severity -ceq 'warning'){'#FFF1DC'}else{'#F2F5F8'}))
 }
 $reviewHeadline.ForeColor=[Drawing.ColorTranslator]::FromHtml($(if(@($Review.issues|Where-Object{$_.severity -ceq 'error'}).Count){'#A12721'}else{'#725010'}));$reviewIssues.ClearSelection();$tabs.SelectedTab=$policyReviewTab;$status.Text=$Review.headline+' — فقط بررسی، بدون تغییر ویندوز.'
}
function Show-PolicyReviewFailure {
 $reviewHeadline.Text='بررسی کامل نشد؛ فعلاً اعمال نکنید.';$reviewSummary.Text='وضعیت حفاظت از این خطا مشخص نمی‌شود. هیچ موفقیت یا نبود مشکل تأیید نشده است.';$reviewIssues.Rows.Clear();[void]$reviewIssues.Rows.Add('نیاز به بررسی','خواندن نتیجه ناموفق بود','تنظیمات یا پاسخ بررسی کامل خوانده نشد.','تنظیمات را بازخوانی کنید؛ اگر مشکل باقی بود جزئیات فنی را برای بررسی نگه دارید.');$tabs.SelectedTab=$policyReviewTab
}
$reviewBack.Add_Click({$tabs.SelectedTab=$policyTab})
$reviewAgain.Add_Click({TryOp {AssertSaved;BeginOp 'policy_review' @{}}})
$reviewTechnical.Add_Click({$tabs.SelectedTab=$detailTab})
Update-VerticalMenu

function Mark-PolicyReviewStale {
 $reviewHeadline.Text='تنظیمات روی صفحه تغییر کرده؛ بررسی قبلی برای این ویرایش معتبر نیست.';$reviewHeadline.ForeColor=[Drawing.ColorTranslator]::FromHtml('#725010')
 if(Get-Variable killState -ErrorAction SilentlyContinue){$killState.Text='ویرایش روی صفحه هنوز اعمال نشده؛ وضعیت قبلی را به روش/لیست جدید نسبت ندهید. برای تطبیق، ذخیره و دوباره وضعیت را بررسی کنید.';$killState.ForeColor=[Drawing.ColorTranslator]::FromHtml('#8A4B00')}
}
$whitelist.Add_TextChanged({Mark-PolicyReviewStale})
