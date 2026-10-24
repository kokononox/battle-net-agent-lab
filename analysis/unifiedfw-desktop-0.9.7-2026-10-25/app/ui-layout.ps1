# Presentation-only reparenting. Existing controls, callbacks, confirmations and backend actions are retained.
# Explicit LTR shell places the menu on the physical right; text controls retain their own RTL/LTR.
$script:menuEntries=New-Object Collections.Generic.List[object]
function New-VerticalTools {
 $v=New-Object Windows.Forms.FlowLayoutPanel;$v.FlowDirection='TopDown';$v.WrapContents=$false;$v.AutoSize=$true;$v.AutoSizeMode='GrowAndShrink';$v.Width=236;$v.Margin=New-Object Windows.Forms.Padding(0,0,0,8);$v.Padding=New-Object Windows.Forms.Padding(6);$v.BackColor=[Drawing.ColorTranslator]::FromHtml('#F0F4F9');return $v
}
function Add-ToolControl($Panel,$Control){
 if($null -eq $Control){return}
 $Control.Dock='None';$Control.Margin=New-Object Windows.Forms.Padding(4,4,4,6)
 if($Control -is [Windows.Forms.Label]){$Control.MaximumSize=New-Object Drawing.Size(212,0);$Control.AutoSize=$true;$Control.RightToLeft='Yes'}
 elseif($Control -is [Windows.Forms.Button]){$Control.AutoSize=$true;$Control.MinimumSize=New-Object Drawing.Size(212,40);$Control.MaximumSize=New-Object Drawing.Size(212,0);$Control.Width=212;$Control.TextAlign='MiddleCenter'}
 elseif($Control -is [Windows.Forms.CheckBox]){$Control.AutoSize=$true;$Control.MaximumSize=New-Object Drawing.Size(212,0);$Control.RightToLeft='Yes'}
 else{$Control.Width=212}
 $Panel.Controls.Add($Control)
}
function Move-FlowControls($Source,$Target){
 foreach($c in @($Source.Controls)){Add-ToolControl $Target $c}
 if($null -ne $Source.Parent){$Source.Parent.Controls.Remove($Source)}
}
function Move-Cell($Table,[int]$Row,$Target){$c=$Table.GetControlFromPosition(0,$Row);if($null -ne $c){Add-ToolControl $Target $c}}
function Maximize-TableRow($Table,[int]$Row){
 for($i=0;$i -lt $Table.RowStyles.Count;$i++){$Table.RowStyles[$i].SizeType='AutoSize';$Table.RowStyles[$i].Height=0}
 $Table.RowStyles[$Row].SizeType='Percent';$Table.RowStyles[$Row].Height=100
}
$workspace=New-Object Windows.Forms.TableLayoutPanel;$workspace.Dock='Fill';$workspace.ColumnCount=2;$workspace.RowCount=1;$workspace.RightToLeft='No'
[void]$workspace.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100)))
[void]$workspace.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,284)))
[void]$workspace.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
$workspace.Controls.Add($tabs,0,0);$main.Controls.Add($workspace,0,2)
$tabs.Appearance='FlatButtons';$tabs.ItemSize=New-Object Drawing.Size(1,1);$tabs.SizeMode='Fixed';$tabs.Multiline=$true
$sidebarHost=New-Object Windows.Forms.TableLayoutPanel;$sidebarHost.Dock='Fill';$sidebarHost.ColumnCount=1;$sidebarHost.RowCount=2;$sidebarHost.RightToLeft='Yes';$sidebarHost.Padding=New-Object Windows.Forms.Padding(8,0,0,0)
[void]$sidebarHost.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
[void]$sidebarHost.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::AutoSize)))
$script:desktopNavigationPanel=New-Object Windows.Forms.FlowLayoutPanel;$script:desktopNavigationPanel.Dock='Fill';$script:desktopNavigationPanel.FlowDirection='TopDown';$script:desktopNavigationPanel.WrapContents=$false;$script:desktopNavigationPanel.AutoScroll=$true;$script:desktopNavigationPanel.BackColor=[Drawing.Color]::White;$script:desktopNavigationPanel.Padding=New-Object Windows.Forms.Padding(4)
$sidebarHost.Controls.Add($script:desktopNavigationPanel,0,0);$workspace.Controls.Add($sidebarHost,1,0)
$historyTab=Tab 'سوابق رصد';$historyPanel=Stack $historyTab 1;$historyPanel.Controls.Add($historyGrid,0,0)
function New-MenuEntry($Page,[string]$Caption){
 $button=Button $Caption;$button.AutoSize=$false;$button.Size=New-Object Drawing.Size(236,44);$button.MinimumSize=New-Object Drawing.Size(236,44);$button.TextAlign='MiddleRight';$button.Tag=$Page;$button.RightToLeft='Yes'
 $tools=New-VerticalTools;$tools.Visible=$false;$script:desktopNavigationPanel.Controls.Add($button);$script:desktopNavigationPanel.Controls.Add($tools)
 $script:menuEntries.Add([pscustomobject]@{page=$Page;button=$button;tools=$tools})
 $button.Add_Click({param($sender,$e)$tabs.SelectedTab=$sender.Tag})
 return $tools
}
$programTools=New-MenuEntry $programTab 'برنامه‌ها / شروع رصد'
$monitorTools=New-MenuEntry $monitorTab 'رصد زنده / IP و دامنه'
$historyTools=New-MenuEntry $historyTab 'سوابق رصد'
$blackTools=New-MenuEntry $blackTab 'بلک‌لیست'
$hostTools=New-MenuEntry $hostsTab 'دامنه‌ها / hosts'
$policyTools=New-MenuEntry $policyTab 'وایت‌لیست و سیاست'
$detailTools=New-MenuEntry $detailTab 'جزئیات و گزارش'
# Give the tables all available center height. Tools and explanatory text live in the right menu.
Move-Cell $p 0 $programTools;Add-ToolControl $programTools $counts;Move-FlowControls $pb $programTools;Move-FlowControls $bar $programTools;Maximize-TableRow $p 3
Move-Cell $b 0 $blackTools;Move-FlowControls $bb $blackTools;Add-ToolControl $blackTools $apply;Maximize-TableRow $b 2
Move-Cell $pol 0 $policyTools;Move-FlowControls $polBar $policyTools;Move-FlowControls $polButtons $policyTools;Maximize-TableRow $pol 3
Move-Cell $d 0 $detailTools;Maximize-TableRow $d 1
Move-FlowControls $mb $monitorTools;Move-Cell $m 0 $monitorTools;Add-ToolControl $historyTools $historyReload;Add-ToolControl $historyTools $baselineHistory;Move-FlowControls $hb $historyTools;Maximize-TableRow $m 2
Move-Cell $h 0 $hostTools;Move-FlowControls $hbar $hostTools
Move-Cell $hostEdit 0 $hostTools;Add-ToolControl $hostTools $hostDomains;$hostDomains.Height=110;Move-FlowControls $hostButtons $hostTools
if($null -ne $hostEdit.Parent){$hostEdit.Parent.Controls.Remove($hostEdit)}
Add-ToolControl $hostTools $hostsSummary;Maximize-TableRow $h 2
# Recovery stays visible below the scrollable menu. It is not hidden under the current section.
$recoveryTools=New-VerticalTools;$recoveryTools.BackColor=[Drawing.ColorTranslator]::FromHtml('#EAF0F7')
Add-ToolControl $recoveryTools $restore;Add-ToolControl $recoveryTools $nativeStatus;Add-ToolControl $recoveryTools $reports;$sidebarHost.Controls.Add($recoveryTools,0,1)
if($null -ne $actions.Parent){$actions.Parent.Controls.Remove($actions)}
$helpToggle=Button 'RC / محدودیت‌ها و راهنمای ایمنی';$helpToggle.AutoSize=$false;$helpToggle.Size=New-Object Drawing.Size(236,44);$script:desktopNavigationPanel.Controls.Add($helpToggle)
$helpTools=New-VerticalTools;Add-ToolControl $helpTools $notice;Add-ToolControl $helpTools $scope;$helpTools.Visible=$false;$script:desktopNavigationPanel.Controls.Add($helpTools)
$helpToggle.Add_Click({$helpTools.Visible=-not $helpTools.Visible})
function Update-VerticalMenu {
 $script:desktopNavigationPanel.SuspendLayout();try{foreach($entry in $script:menuEntries){$active=($tabs.SelectedTab -eq $entry.page);$entry.tools.Visible=$active;$entry.button.BackColor=if($active){$blue}else{[Drawing.Color]::White};$entry.button.ForeColor=if($active){[Drawing.Color]::White}else{$ink}}}finally{$script:desktopNavigationPanel.ResumeLayout()}
}
$tabs.Add_SelectedIndexChanged({Update-VerticalMenu})
$title.Font=New-Object Drawing.Font('Tahoma',13,[Drawing.FontStyle]::Bold)
$status.AutoSize=$false;$status.AutoEllipsis=$true;$status.Dock='Fill';$status.Height=30;$status.MinimumSize=New-Object Drawing.Size(400,30)
$footer.RowStyles.Clear();$footer.AutoSize=$true
$tip=New-Object Windows.Forms.ToolTip;$status.Add_MouseEnter({$tip.SetToolTip($status,$status.Text)})
# Popup also gets a narrow right-side vertical tool area; the list no longer loses height to wrapping buttons.
$popupHost=New-Object Windows.Forms.TableLayoutPanel;$popupHost.Dock='Fill';$popupHost.RightToLeft='No';$popupHost.ColumnCount=2;$popupHost.RowCount=1
[void]$popupHost.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100)))
[void]$popupHost.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,252)))
[void]$popupHost.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
$popupHost.Controls.Add($pv,0,0);$livePopup.Controls.Add($popupHost)
$popupMenu=New-Object Windows.Forms.Panel;$popupMenu.Dock='Fill';$popupMenu.AutoScroll=$true;$popupMenu.RightToLeft='Yes';$popupHost.Controls.Add($popupMenu,1,0)
$popupTools=New-VerticalTools;$popupTools.Dock='Top';$popupMenu.Controls.Add($popupTools)
Add-ToolControl $popupTools $popupStatus;Move-FlowControls $popupOptions $popupTools;Add-ToolControl $popupTools $evidenceLegend;Maximize-TableRow $pv 2
$livePopup.MinimumSize=New-Object Drawing.Size(900,520);$livePopup.Size=New-Object Drawing.Size(1240,740)
Update-VerticalMenu

# Keep live diagnostics inspectable without allowing a long status paragraph to bury the controls.
foreach($v in @($liveStatus,$popupStatus)){$v.AutoSize=$false;$v.Size=New-Object Drawing.Size(212,100);$v.AutoEllipsis=$true}
$liveDetails=Button 'جزئیات کامل وضعیت زنده';Add-ToolControl $monitorTools $liveDetails
$liveDetails.Add_Click({if($null -ne $script:liveFrame){[void][Windows.Forms.MessageBox]::Show((Live-StatusText $script:liveFrame),'جزئیات رصد','OK','Information')}})
# Keep arithmetic separate from constructor argument lists: Windows PowerShell otherwise treats
# "$area.Left+8,$area.Top+8" as an array addition and throws during Form.Shown.
function Set-WindowBoundsForArea($Window,$Area){
 if($Area.Width -le 0 -or $Area.Height -le 0){throw 'invalid_window_working_area'}
 [int]$minimumWidth=[Math]::Max(1,[Math]::Min(900,([int]$Area.Width-24)))
 [int]$minimumHeight=[Math]::Max(1,[Math]::Min(620,([int]$Area.Height-24)))
 $Window.MinimumSize=New-Object -TypeName System.Drawing.Size -ArgumentList @($minimumWidth,$minimumHeight)
 if($Window.Width -gt $Area.Width -or $Window.Height -gt $Area.Height){
  [int]$width=[Math]::Max(1,[Math]::Min([int]$Window.Width,([int]$Area.Width-16)))
  [int]$height=[Math]::Max(1,[Math]::Min([int]$Window.Height,([int]$Area.Height-16)))
  [int]$left=([int]$Area.Left+8);[int]$top=([int]$Area.Top+8)
  $Window.Size=New-Object -TypeName System.Drawing.Size -ArgumentList @($width,$height)
  $Window.Location=New-Object -TypeName System.Drawing.Point -ArgumentList @($left,$top)
 }
}
function Fit-WorkingArea($Window){
 $area=[Windows.Forms.Screen]::FromControl($Window).WorkingArea
 Set-WindowBoundsForArea $Window $area
}
$form.Add_Shown({Fit-WorkingArea $form});$livePopup.Add_Shown({Fit-WorkingArea $livePopup})

# Discovery filters are created by ui-baseline; attach only after tool panels exist.
Add-ToolControl $monitorTools $processActivityFilter
Add-ToolControl $popupTools $popupActivityFilter
