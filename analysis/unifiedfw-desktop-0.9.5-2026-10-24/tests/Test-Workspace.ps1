param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
. (Join-Path $Root 'app/workspace-model.ps1')
$a=New-HostDraftRow 'A.EXAMPLE.' 'sink';Check ($a.domain -ceq 'a.example') 'host-normalized';Check ($a.id -match '^[a-f0-9]{32}$') 'host-stable-id'
$rows=Merge-HostDraft @() $a;Check ($rows.Count -eq 1) 'single-array-retained';$rows=Merge-HostDraft $rows (New-HostDraftRow 'a.example' 'sink');Check ($rows.Count -eq 1) 'host-no-duplicate'
$b=New-HostDraftRow 'b.example' 'remove';$rows=Merge-HostDraft $rows $b;Check ($rows.Count -eq 2) 'host-add';$rows=Merge-HostDraft $rows (New-HostDraftRow 'c.example' 'sink' $b.id);Check ($rows.Count -eq 2 -and $rows[1].domain -ceq 'c.example') 'host-edit-by-id'
$rows=Merge-HostDraft $rows (New-HostDraftRow 'a.example' 'remove' $b.id);Check ($rows.Count -eq 1 -and $rows[0].operation -ceq 'remove') 'host-edit-dedup-merges'
foreach($name in @('https://a.example','*.a.example','a.example b.example','localhost','a.example/path')){$failed=$false;try{New-HostDraftRow $name 'sink'}catch{$failed=$true};Check $failed ('host-invalid-'+$name)}
$big=@(1..500|ForEach-Object{New-HostDraftRow ('d'+$_+'.example') 'sink'});$failed=$false;try{Merge-HostDraft $big (New-HostDraftRow 'overflow.example' 'sink')}catch{$failed=$true};Check $failed 'host-limit-no-partial-write';Check ($big.Count -eq 500) 'host-input-not-mutated'
$p=[pscustomobject]@{id='p1';path='C:\Apps\Game.exe'};$observed=[pscustomobject]@{program_path='c:\apps\GAME.exe';remote_ip='8.8.8.8';protocol='TCP';remote_port=5224}
$n=Observed-IPDraft $observed '8.8.8.8' @($p);Check ($n.program_ids.Count -eq 1 -and $n.program_ids[0] -ceq 'p1') 'exact-casefold-path-binding';Check ($n.port -eq 5224 -and $n.protocol -ceq 'TCP') 'observed-transport-not-guessed'
$dns=[pscustomobject]@{program_path='C:\Apps\Game.exe';domain='a.example'};$n=Observed-IPDraft $dns '1.1.1.1' @($p);Check ($n.port -eq 0 -and $n.protocol -ceq '') 'DNS-answer-transport-unknown'
$unknown=[pscustomobject]@{program_path='C:\Other\Game.exe';remote_port=443;protocol='TCP'};$n=Observed-IPDraft $unknown '1.1.1.1' @($p);Check ($n.program_ids.Count -eq 0) 'same-filename-other-path-not-bound';Check ($n.source_path -ceq $unknown.program_path) 'unregistered-source-path-kept'
$ip=New-IPDraftRow @('p1') '8.8.8.8' 'TCP' 443;$list=Merge-IPDraft @() @($ip);Check ($list.Count -eq 1) 'IP-array-retained';$list=Merge-IPDraft $list @((New-IPDraftRow @('p1') '8.8.8.8' 'TCP' 443));Check ($list.Count -eq 1) 'IP-dedup'
$list=Merge-IPDraft $list @((New-IPDraftRow @('p1') '1.1.1.1' 'UDP' 53 '' $ip.id));Check ($list.Count -eq 1 -and $list[0].target -ceq '1.1.1.1') 'IP-edit-by-id'
$payload=Export-IPDraft $list;Check ($payload.Count -eq 1 -and $payload[0].Keys.Count -eq 5 -and -not $payload[0].ContainsKey('id')) 'export-no-UI-id';Check ($payload[0].program_ids -is [array]) 'export-program-array'
$rows=@(1..256|ForEach-Object{New-IPDraftRow @('p1') ('8.8.'+[Math]::Floor($_/255)+'.'+($_%255)) 'TCP' 443});$failed=$false;try{Merge-IPDraft $rows @((New-IPDraftRow @('p1') '1.1.1.1' 'TCP' 443))}catch{$failed=$true};Check $failed 'IP-limit';Check ($rows.Count -eq 256) 'IP-input-not-mutated'
# Real Stage-ObservedDraft function, fake controls and state. No WinForms/native APIs are loaded.
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-workspace.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in @('Stage-ObservedDraft','Workspace-State')){$f=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq $name},$true);Invoke-Expression $f.Extent.Text}
$script:state=[pscustomobject]@{config=[pscustomobject]@{programs=@($p);blacklist=@();generation=1}};$script:ipDraft=@();$script:ipDirty=$false;$script:hostDraft=@();$script:hostDirty=$false;$script:job=[pscustomobject]@{action='baseline_record'}
$tabs=[pscustomobject]@{SelectedTab=$null};$blackTab='black';$blackSections=[pscustomobject]@{SelectedTab=$null};$ipDraftTab='ip';$blackDomainTab='domain';$status=[pscustomobject]@{Text=''}
$form=[pscustomobject]@{};$form|Add-Member ScriptMethod BringToFront {}; $livePopup=[pscustomobject]@{};$livePopup|Add-Member ScriptMethod Hide {};function Render-Drafts {$script:checks++}
Stage-ObservedDraft $observed ([pscustomobject]@{type='ip';value='8.8.8.8'});Check ($script:ipDraft.Count -eq 1 -and $script:ipDirty -and $blackSections.SelectedTab -ceq 'ip') 'observed-IP-stages-table';Check ($script:job.action -ceq 'baseline_record') 'recording-continues'
Stage-ObservedDraft $dns ([pscustomobject]@{type='domain';value='a.example'});Check ($script:hostDraft.Count -eq 1 -and $script:hostDirty -and $blackSections.SelectedTab -ceq 'domain') 'observed-domain-shared-host-table'
$script:job.action='workspace_blacklist_save';$failed=$false;try{Stage-ObservedDraft $observed ([pscustomobject]@{type='ip';value='9.9.9.9'})}catch{$failed=$true};Check $failed 'no-staging-during-save';Check ($script:ipDraft.Count -eq 1) 'busy-no-draft-loss'
$script:job=$null;$script:ipSavedFingerprint=ConvertTo-Json -InputObject @() -Depth 12 -Compress;$script:ipGeneration=1
Workspace-State $script:state 'register';Check ($script:ipDraft.Count -eq 1 -and $script:ipDirty) 'own-registration-preserves-unsaved-draft'
$script:state.config.generation=2;Workspace-State $script:state 'configure';Check ($script:ipGeneration -eq 2) 'unchanged-blacklist-advances-generation'
$script:state.config.blacklist=@([pscustomobject]@{id='stored';program_ids=@('p1');target='9.9.9.9';protocol='TCP';port=443});$script:state.config.generation=3;Workspace-State $script:state 'import_blacklist';Check ($script:ipGeneration -eq 2 -and $script:ipDraft[0].target -ceq '8.8.8.8') 'changed-blacklist-stale-generation-preserved'
Workspace-State $script:state 'workspace_blacklist_save';Check (-not $script:ipDirty -and $script:ipDraft[0].target -ceq '9.9.9.9' -and $script:ipGeneration -eq 3) 'successful-save-refreshes-draft'
$text=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-workspace.ps1'));Check ($text.Contains('$menu.Controls.Remove($entry.tools)')) 'navigation-only-sidebar';Check ($text.Contains('$script:hostDirty') -and $text.Contains('Preview-HostDraft')) 'save-before-host-preview'
$result=@{suite='workspace-drafts-model-and-routing';passed=$true;assertions=$script:checks;environment='PowerShell 7 Linux; pure models + AST functions + fake controls';Windows_GUI_tested=$false;settings_written=$false;firewall_or_hosts_changed=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/workspace-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
