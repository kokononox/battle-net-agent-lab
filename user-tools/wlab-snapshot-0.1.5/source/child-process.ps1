# Own-process launcher. No PowerShell Start-Process ExitCode wrapper and no event callbacks.
# Process.Start owns the native handle from creation. Stream bytes are copied by .NET Tasks.
function Get-WLabExitClassification($code){
if($null -eq $code -or $code -isnot [int]){return 'unknown'}
if($code -eq 0){return 'succeeded'}
return 'failed'
}
function Start-WLabChild($file,[string[]]$arguments,$prefix){
$stdout=$prefix+'.stdout.txt';$stderr=$prefix+'.stderr.txt'
$utf8=[Text.UTF8Encoding]::new($false)
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=$file;$info.Arguments=$arguments -join ' '
$info.UseShellExecute=$false;$info.CreateNoWindow=$true
$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
$p=New-Object Diagnostics.Process;$p.StartInfo=$info
$o=$null;$e=$null
try{
$o=[IO.File]::Open($stdout,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$e=[IO.File]::Open($stderr,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
if(!$p.Start()){throw 'Process.Start returned false'}
$nativeHandle=$p.Handle
$outTask=$p.StandardOutput.BaseStream.CopyToAsync($o)
$errTask=$p.StandardError.BaseStream.CopyToAsync($e)
return [pscustomobject]@{Process=$p;Pid=$p.Id;OutTask=$outTask;ErrTask=$errTask;OutStream=$o;ErrStream=$e;Stdout=$stdout;Stderr=$stderr;ResultPath=($prefix+'.result.json');Completed=$false;Result=$null;NativeHandleAcquired=($nativeHandle -ne [IntPtr]::Zero)}
}catch{
if($null -ne $o){$o.Dispose()};if($null -ne $e){$e.Dispose()}
$p.Dispose();throw
}
}
function Test-WLabChildExited($job){
if($job.Completed){return $true}
return $job.Process.HasExited
}
function Complete-WLabChild($job){
if($job.Completed){return $job.Result}
if(!$job.Process.HasExited){throw 'Child process has not exited'}
$job.Process.WaitForExit()
$code=$null;$codeError=$null
try{$code=$job.Process.ExitCode}catch{$codeError=$_.Exception.Message}
$state=Get-WLabExitClassification $code
$streamError=$null;$drained=$false
try{
$tasks=[Threading.Tasks.Task[]]@($job.OutTask,$job.ErrTask)
$drained=[Threading.Tasks.Task]::WaitAll($tasks,2000)
if(!$drained){$streamError='stdout/stderr drain not confirmed within 2 seconds; file handles remain until process cleanup'}
}catch{$streamError=$_.Exception.Message}
if($drained){
try{$job.OutStream.Flush();$job.ErrStream.Flush()}catch{$streamError=$_.Exception.Message}
$job.OutStream.Dispose();$job.ErrStream.Dispose();$job.Process.Dispose()
}
$result=[pscustomobject]@{status=$state;exit_code=$code;exit_code_error=$codeError;child_pid=$job.Pid;native_handle_acquired=$job.NativeHandleAcquired;stdio_drained=$drained;stdio_error=$streamError;source='owned System.Diagnostics.Process.Start handle';completed_utc=[DateTime]::UtcNow.ToString('o')}
[IO.File]::WriteAllText($job.ResultPath,($result|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
$job.Result=$result;$job.Completed=$true
return $result
}
function Invoke-WLabChildSelfTest($exe,$out){
$results=New-Object 'Collections.Generic.List[object]'
foreach($expected in @(0,7)){
$name=if($expected -eq 0){'probe-zero'}else{'probe-seven'}
$job=Start-WLabChild $exe @('--child-probe',([string]$expected)) (Join-Path $out $name)
if(!$job.Process.WaitForExit(5000)){
# Only this newly created probe child may be stopped; never Wow or a capture worker.
try{$job.Process.Kill();[void]$job.Process.WaitForExit(1000)}catch{}
throw ('Owned child probe timed out: '+$expected)
}
$r=Complete-WLabChild $job
$expectedState=if($expected -eq 0){'succeeded'}else{'failed'}
$text=[IO.File]::ReadAllText($job.Stdout)
$err=[IO.File]::ReadAllText($job.Stderr)
$ok=($r.status -eq $expectedState -and $r.exit_code -eq $expected -and $r.stdio_drained -and $text.Contains('WLAB-CHILD-PROBE '+$expected) -and $err.Contains('WLAB-CHILD-STDERR '+$expected))
$results.Add([pscustomobject]@{expected_exit_code=$expected;actual_exit_code=$r.exit_code;status=$r.status;passed=$ok})
if(!$ok){throw ('Child exit-code/logging self-test failed: '+$expected)}
}
return $results.ToArray()
}
