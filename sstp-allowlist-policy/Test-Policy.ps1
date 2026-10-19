param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')
$script:checks=0
function Check($Ok) { if (-not $Ok) { throw ('policy_fixture_'+($script:checks+1)) };$script:checks++ }
function Reject([scriptblock]$Block) { $rejected=$false;try { & $Block | Out-Null } catch { $rejected=$true };Check $rejected }
$receipt=[ordered]@{schema='sstp-allowlist-policy-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$false;checks=0;error_code=$null;network_changed=$false;dns_queried=$false;resident_program_created=$false;enforcement_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
try {
    Check ((PolicyDomain 'LEVEL3.BLIZZARD.COM.') -ceq 'level3.blizzard.com')
    Reject { PolicyDomain 'https://level3.blizzard.com' }
    Reject { PolicyDomain '*.blizzard.com' }
    Reject { PolicyDomain 'level3.blizzard.com:443' }
    Reject { PolicyDomain '127.0.0.1' }
    Reject { PolicyIp '0.0.0.0/0' }
    Reject { PolicyIp '::/0' }
    Reject { PolicyIp '127.0.0.1' }
    Reject { PolicyIp 'fe80::1' }
    Check ((PolicyIp '1.1.1.1') -ceq '1.1.1.1')
    $c=[pscustomobject]@{schema='sstp-allowlist-config-1';domains=@('level3.blizzard.com');ip_addresses=@()}
    $c=PolicyConfig $c;Check ($c.domains.Count -eq 1)
    $added=EditPolicyConfig $c Add 'example.com';Check ($added.domains.Count -eq 2)
    $same=EditPolicyConfig $added Add 'EXAMPLE.COM';Check ($same.domains.Count -eq 2)
    $removed=EditPolicyConfig $same Remove 'example.com';Check ($removed.domains.Count -eq 1)
    $ipadded=EditPolicyConfig $c Add '1.1.1.1';Check ($ipadded.ip_addresses.Count -eq 1)
    Reject { EditPolicyConfig $c Remove 'level3.blizzard.com' }
    Reject { PolicyConfig ([pscustomobject]@{schema=$c.schema;domains=$c.domains;ip_addresses=@();allow_all=$true}) }
    Reject { PolicyConfig ([pscustomobject]@{schema=$c.schema;domains='level3.blizzard.com';ip_addresses=@()}) }
    $h=[pscustomobject]@{name='holand';scope='User';tunnel_type='Sstp';connected=$false}
    $active=[pscustomobject]@{name='other-active';scope='User';tunnel_type='Sstp';connected=$true}
    $wire=[pscustomobject]@{name='not-sstp';scope='User';tunnel_type='Ikev2';connected=$true}
    Check ((SelectPolicyVpn @($h,$active,$wire)).name -ceq 'other-active')
    Check ((SelectPolicyVpn @($h,$wire)).name -ceq 'holand')
    $available=[pscustomobject]@{name='another';scope='User';tunnel_type='Sstp';connected=$false}
    Check ((SelectPolicyVpn @($h,$available)).name -ceq 'holand')
    $active2=[pscustomobject]@{name='second-active';scope='AllUser';tunnel_type='Sstp';connected=$true}
    Reject { SelectPolicyVpn @($active,$active2) }
    Reject { SelectPolicyVpn @($h,([pscustomobject]@{name='holand';scope='AllUser';tunnel_type='Sstp';connected=$false})) }
    Check ((SelectPolicyVpn @($h,$active) 'holand').name -ceq 'holand')
    $map=[ordered]@{'level3.blizzard.com'=@('1.1.1.1','8.8.8.8')}
    $plan=NewPolicyPlan $c @($h,$active) $map @('9.9.9.9') @('10.0.0.53')
    Check ($plan.allow_target_ips.Count -eq 2)
    Check ($plan.default_for_other_destinations -ceq 'deny' -and $plan.on_disconnect -ceq 'deny')
    Check (-not $plan.dns_outside_tunnel_allowed -and -not $plan.ordinary_lan_allowed)
    Check (-not $plan.resident_process_required -and -not $plan.custom_resident_service_required -and -not $plan.recurring_task_required)
    Check (-not $plan.automatic_expiry -and $plan.persist_across_reboot)
    Check (-not $plan.auto_connect -and -not $plan.ready_for_user_apply -and -not $plan.enforcement_tested)
    Check ($plan.vpn_transport_remote_port -eq 443 -and $plan.vpn_transport_service -ceq 'SstpSvc')
    Reject { NewPolicyPlan $c @($h) ([ordered]@{}) @('9.9.9.9') }
    Reject { NewPolicyPlan $c @($h) ([ordered]@{'level3.blizzard.com'=@()}) @('9.9.9.9') }
    Reject { NewPolicyPlan $c @($h) $map @() }
    Reject { NewPolicyPlan $c @($h) $map @('0.0.0.0/0') }
    if ($script:checks -ne 35) { throw 'policy_fixture_count' }
    $receipt.passed=$true
} catch { $receipt.error_code='policy_fixture_failed';if ($_.Exception.Message -cmatch '^policy_[a-z_0-9]{1,80}$') { $receipt.error_code=$_.Exception.Message } }
finally {
    $receipt.checks=$script:checks
    if ($OutputPath) { [IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 4),(New-Object Text.UTF8Encoding($false))) }
}
if (-not $receipt.passed) { exit 1 }
