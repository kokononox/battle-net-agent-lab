# Windows PowerShell 5.1, x64. No downloads, debugger, game access, or upload.
$ErrorActionPreference = 'Stop'
$base = $PSScriptRoot
$out = Join-Path $base ('RESULT-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path $out | Out-Null
$status = [ordered]@{tool='WLab-ETW-Diagnostic-0.1.3'; started_utc=[DateTime]::UtcNow.ToString('o'); stack_presence_verified=$false; game_accessed=$false; cases=@(); error=$null}
$wpr = Join-Path $env:windir 'System32\wpr.exe'
$oldTemp=$env:TEMP; $oldTmp=$env:TMP
function Invoke-Wpr {
    param([string[]]$Arguments, [string]$LogName)
    $savePreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $text = & $wpr @Arguments 2>&1
        $code = $LASTEXITCODE
        $text | Out-File (Join-Path $out $LogName) -Encoding utf8
        return [int]$code
    } finally { $ErrorActionPreference = $savePreference }
}
function Get-InstanceState {
    param([string]$Instance, [string]$LogName)
    $code=Invoke-Wpr -Arguments @('-status','-instancename',$Instance) -LogName $LogName
    $text=Get-Content -LiteralPath (Join-Path $out $LogName) -Raw
    if ($text -match '(?im)^\s*(WPR is not recording|There are no trace profiles running)[.\s]*$') { return 'Inactive' }
    if ($code -eq 0 -and $text -match '(?im)^\s*WPR recording is in progress') { return 'Active' }
    return 'Unknown'
}
function Module-Snapshot {
    $items = @()
    foreach ($m in [Diagnostics.Process]::GetCurrentProcess().Modules) {
        $items += [ordered]@{ name=$m.ModuleName; base=('0x{0:X}' -f $m.BaseAddress.ToInt64()); size=$m.ModuleMemorySize; path=$m.FileName }
    }
    return $items
}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run Windows PowerShell as administrator, then run this script again.' }
    if ([IntPtr]::Size -ne 8) { throw 'Use 64-bit Windows PowerShell.' }
    if (Get-Process -Name 'Wow','WowB','WowT','WowClassic' -ErrorAction SilentlyContinue) { throw 'Close the game manually first. This control must not run while the game is open.' }
    if (-not (Test-Path $wpr)) { throw 'Built-in wpr.exe not found.' }
    $root = [IO.Path]::GetPathRoot($out)
    $drive = New-Object IO.DriveInfo($root)
    if ($drive.AvailableFreeSpace -lt 256MB) { throw 'At least 256 MiB free is required on the output drive. Extract this package to another local drive.' }
    $temp = Join-Path $out 'temp'
    New-Item -ItemType Directory -Path $temp | Out-Null
    $env:TEMP = $temp; $env:TMP = $temp
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json | Out-File (Join-Path $out 'os.json') -Encoding utf8
    $profile = Join-Path $base 'Control.wprp'
    $code=Invoke-Wpr -Arguments @('-profiles',$profile) -LogName 'profile-check.txt'
    if ($code -ne 0) { throw ('Profile validation failed: '+$code) }
    if (-not ('WLabEtwLoopbackControl' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
public static class WLabEtwLoopbackControl {
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Dictionary<string, object> Run() {
        TcpListener listener = null;
        Socket sender = null, receiver = null;
        var result = new Dictionary<string, object>();
        var writes = new List<Dictionary<string, object>>();
        result["pid"] = Process.GetCurrentProcess().Id;
        result["qpc_frequency"] = Stopwatch.Frequency;
        result["started_utc"] = DateTime.UtcNow.ToString("o");
        try {
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start(1);
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            sender.SendTimeout=2000; sender.ReceiveTimeout=2000; sender.NoDelay=true;
            sender.Connect(IPAddress.Loopback, port);
            receiver = listener.AcceptSocket();
            receiver.ReceiveTimeout=2000;
            result["client_local"] = sender.LocalEndPoint.ToString();
            result["client_remote"] = sender.RemoteEndPoint.ToString();
            result["server_local"] = receiver.LocalEndPoint.ToString();
            int total=0;
            foreach(int length in new int[] {64,128,256}) {
                byte[] data = new byte[length];
                for(int i=0;i<data.Length;i++) data[i]=(byte)(i%251);
                int sent=0;
                while(sent<length) {
                    long before=Stopwatch.GetTimestamp();
                    int n=sender.Send(data,sent,length-sent,SocketFlags.None);
                    long after=Stopwatch.GetTimestamp();
                    if(n<=0) throw new Exception("Zero-length send progress");
                    writes.Add(new Dictionary<string,object>{{"requested",length-sent},{"returned",n},{"qpc_before",before},{"qpc_after",after}});
                    sent+=n;
                }
                byte[] read = new byte[length]; int got=0;
                while(got<length) {
                    int n=receiver.Receive(read,got,length-got,SocketFlags.None);
                    if(n<=0) throw new Exception("Unexpected EOF");
                    got+=n;
                }
                for(int i=0;i<length;i++) if(read[i]!=data[i]) throw new Exception("Loopback payload mismatch");
                total+=got;
                System.Threading.Thread.Sleep(200);
            }
            result["verified_received_bytes"] = total;
            result["writes"] = writes;
            result["finished_utc"] = DateTime.UtcNow.ToString("o");
            return result;
        } finally {
            if(sender!=null) sender.Dispose();
            if(receiver!=null) receiver.Dispose();
            if(listener!=null) listener.Stop();
        }
    }
}
'@
    }
    $prior=Get-InstanceState -Instance 'WLabControl_50923003541345798cfb63e4cf451a01' -LogName 'previous-failed-instance-status.txt'
    $status.prior_instance_state=$prior
    if ($prior -eq 'Active') { throw 'Previous control is recording; preserve this report and use its exact recovery name.' }
    if ($prior -eq 'Unknown') { throw 'Previous WPR status is unrecognized, not proof of recording. Preserve the status log.' }
    Module-Snapshot | ConvertTo-Json -Depth 5 | Out-File (Join-Path $out 'modules-before.json') -Encoding utf8
    $tests = @('AFD_Paged_NoStack','AFD_Paged_Stack','AFD_NonPaged_NoStack','AFD_NonPaged_Stack','Sockets_Paged_NoStack','Sockets_Paged_Stack')
    foreach ($name in $tests) {
        $instance='WLabDiag_'+[Guid]::NewGuid().ToString('N')
        $begin=Get-Date
        $started=$false
        $r=[ordered]@{name=$name; instance=$instance; start_exit=$null; stop_exit=$null; loopback_verified=$false; trace_saved=$false; stack_presence_verified=$false; error=$null}
        Write-Host ('Testing: '+$name)
        @(('wpr -status -instancename '+$instance),('wpr -cancel -instancename '+$instance)) | Out-File (Join-Path $out ($name+'-RECOVERY.txt')) -Encoding utf8
        try {
            $code=Invoke-Wpr -Arguments @('-start',($profile+'!'+$name+'.Verbose'),'-recordtempto',$temp,'-instancename',$instance) -LogName ($name+'-start.txt')
            $r.start_exit=$code
            if ($code -ne 0) { throw ('Provider enable failed: '+$code) }
            $started=$true
            Start-Sleep -Milliseconds 200
            $control=[WLabEtwLoopbackControl]::Run()
            $control | ConvertTo-Json -Depth 8 | Out-File (Join-Path $out ($name+'-control.json')) -Encoding utf8
            $r.loopback_verified=($control['verified_received_bytes'] -eq 448)
            if (-not $r.loopback_verified) { throw 'Loopback byte verification failed.' }
            Start-Sleep -Milliseconds 200
        } catch { $r.error=$_.Exception.Message }
        finally {
            if ($started) {
                $null=Invoke-Wpr -Arguments @('-status','-instancename',$instance) -LogName ($name+'-status.txt')
                $etl=Join-Path $out ($name+'.etl')
                $stop=Invoke-Wpr -Arguments @('-stop',$etl,'-skipPdbGen','-instancename',$instance) -LogName ($name+'-stop.txt')
                $r.stop_exit=$stop
                $r.trace_saved=($stop -eq 0 -and (Test-Path $etl))
            }
            # Check and cancel ONLY this unique instance, including partial-start failure.
            $state=Get-InstanceState -Instance $instance -LogName ($name+'-cleanup-status.txt')
            $r.cleanup_state_before=$state
            if ($state -ne 'Inactive') {
                $r.cancel_exit=Invoke-Wpr -Arguments @('-cancel','-instancename',$instance) -LogName ($name+'-cancel-own.txt')
                $state=Get-InstanceState -Instance $instance -LogName ($name+'-cleanup-after.txt')
                if ($state -ne 'Inactive') { $status.error='Own-session cleanup is unconfirmed. Stop further tests and inspect recovery/status files.' }
            }
            $r.cleanup_state_after=$state
            # Time-window event-log candidates are NOT automatically attributed to this test.
            try {
                $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-EventTracing/Admin';StartTime=$begin;EndTime=(Get-Date)} -MaxEvents 32 -ErrorAction Stop)
                @('<Events>')+@($events | ForEach-Object {$_.ToXml()})+@('</Events>') | Out-File (Join-Path $out ($name+'-etw-admin-candidates.xml')) -Encoding utf8
            } catch { $_.Exception.Message | Out-File (Join-Path $out ($name+'-eventlog-note.txt')) -Encoding utf8 }
            $status.cases+=@($r)
            $status | ConvertTo-Json -Depth 8 | Out-File (Join-Path $out 'STATUS.json') -Encoding utf8
        }
        if ($status.error) { break }
    }
    Module-Snapshot | ConvertTo-Json -Depth 5 | Out-File (Join-Path $out 'modules-after.json') -Encoding utf8
} catch { $status.error=$_.Exception.Message; Write-Host $status.error }
finally {
    $env:TEMP=$oldTemp; $env:TMP=$oldTmp
    $status.finished_utc=[DateTime]::UtcNow.ToString('o')
    $status.etl_excluded=@()
    $send=@(Get-ChildItem -LiteralPath $out -File | Where-Object {$_.Extension -in '.txt','.json','.xml'} | ForEach-Object {$_.FullName})
    $total=0
    foreach ($f in @(Get-ChildItem -LiteralPath $out -Filter '*.etl' -File)) {
        if ($total+$f.Length -le 64MB) { $send+=@($f.FullName); $total+=$f.Length }
        else { $status.etl_excluded+=@($f.Name) }
    }
    $status | ConvertTo-Json -Depth 8 | Out-File (Join-Path $out 'STATUS.json') -Encoding utf8
    if ($send -notcontains (Join-Path $out 'STATUS.json')) { $send+=@(Join-Path $out 'STATUS.json') }
    try { $zip=Join-Path $out 'READY-TO-SEND.zip'; Compress-Archive -LiteralPath $send -DestinationPath $zip; Write-Host ('Send: '+$zip) }
    catch { Write-Host ('ZIP failed. Keep folder: '+$out) }
    Write-Host 'Provider enable or loopback success is NOT proof of useful stack capture.'
}
