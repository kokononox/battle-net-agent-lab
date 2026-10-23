# Executes only the actual status helper with a mocked native WPR command.
$ErrorActionPreference='Stop'
$out=Join-Path $PSScriptRoot '../reports/status-test-temp'
New-Item -ItemType Directory -Path $out -Force | Out-Null
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Run-Control.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$f=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-InstanceState'},$true)
if (-not $f) { throw 'Actual status helper not found.' }
Invoke-Expression $f.Extent.Text
function Invoke-Wpr {
    param([string[]]$Arguments,[string]$LogName)
    $script:FakeText | Out-File (Join-Path $out $LogName) -Encoding utf8
    return $script:FakeCode
}
$real=Get-Content (Join-Path $PSScriptRoot '../reports/status-inactive-fixture.txt') -Raw
$tests=@(
    @{name='Real returned text, zero exit';text=$real;code=0;want='Inactive'},
    @{name='Explicit inactive, nonzero exit';text='WPR is not recording';code=-984076288;want='Inactive'},
    @{name='Official no-profile wording';text='There are no trace profiles running.';code=0;want='Inactive'},
    @{name='Explicit active and success';text='WPR recording is in progress...';code=0;want='Active'},
    @{name='Active words but error exit';text='WPR recording is in progress...';code=1;want='Unknown'},
    @{name='Zero exit alone is not active';text='';code=0;want='Unknown'},
    @{name='Unrecognized text';text='Some other diagnostic message';code=0;want='Unknown'}
)
$results=@()
foreach ($test in $tests) {
    $script:FakeText=$test.text; $script:FakeCode=$test.code
    $got=Get-InstanceState -Instance 'mock-session' -LogName 'mock-status.txt'
    if ($got -ne $test.want) { throw ('Regression failed: '+$test.name+' got '+$got) }
    $results+=@([ordered]@{test=$test.name;expected=$test.want;actual=$got;passed=$true})
}
# Compile the actual loopback C# source, but do NOT execute it or start any trace.
$scriptText=Get-Content (Join-Path $PSScriptRoot 'Run-Control.ps1') -Raw
$m=[regex]::Match($scriptText,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@")
if (-not $m.Success) { throw 'Loopback C# not found.' }
Add-Type -TypeDefinition $m.Groups[1].Value
[ordered]@{runtime=$PSVersionTable.PSVersion.ToString();platform=[Environment]::OSVersion.Platform.ToString();powershell_ast_errors=0;actual_helper_tests=$results;csharp_compiled=$true;loopback_run=$false;native_wpr_invoked=$false;windows_target_execution_tested=$false} | ConvertTo-Json -Depth 8 | Out-File (Join-Path $PSScriptRoot '../reports/status-regression.json') -Encoding utf8
Write-Host 'PASS: actual status helper, 7 fixtures; PowerShell AST; C# compilation. No native WPR or Windows execution.'
