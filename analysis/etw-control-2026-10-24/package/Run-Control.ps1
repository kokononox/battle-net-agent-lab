# Windows PowerShell 5.1, x64. No downloads, debugger, game access, or upload.
$ErrorActionPreference = 'Stop'
$base = $PSScriptRoot
$out = Join-Path $base ('RESULT-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path $out | Out-Null
$instance = 'WLabControl_' + [Guid]::NewGuid().ToString('N')
$status = [ordered]@{ tool='WLab-ETW-Control-0.1'; instance=$instance; started_utc=[DateTime]::UtcNow.ToString('o'); control_success=$false; start_succeeded=$false; stop_exit_code=$null; trace_saved=$false; stack_presence_verified=$false; game_accessed=$false; error=$null }
$started = $false
$wpr = Join-Path $env:windir 'System32\wpr.exe'
$oldTemp = $env:TEMP; $oldTmp = $env:TMP
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
    @('Only the unique session below belongs to this test.', ('wpr -status -instancename ' + $instance), ('wpr -cancel -instancename ' + $instance)) | Out-File (Join-Path $out 'SESSION-RECOVERY.txt') -Encoding utf8
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json | Out-File (Join-Path $out 'os.json') -Encoding utf8
    Get-Item $wpr | ForEach-Object { $_.VersionInfo | Select-Object FileVersion,ProductVersion } | ConvertTo-Json | Out-File (Join-Path $out 'wpr-version.json') -Encoding utf8
    $profile = Join-Path $base 'Control.wprp'
    $check = Invoke-Wpr -Arguments @('-profiles',$profile) -LogName 'profile-check.txt'
    if ($check -ne 0) { throw ('WPR profile validation failed: ' + $check) }
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
    Module-Snapshot | ConvertTo-Json -Depth 5 | Out-File (Join-Path $out 'modules-before.json') -Encoding utf8
    $code = Invoke-Wpr -Arguments @('-start',($profile+'!WLabControl.Verbose'),'-recordtempto',$temp,'-instancename',$instance) -LogName 'start.txt'
    if ($code -ne 0) { throw ('WPR start failed: ' + $code + '. No stop/cancel will target any other session.') }
    $started = $true; $status.start_succeeded=$true
    Start-Sleep -Milliseconds 300
    $control = [WLabEtwLoopbackControl]::Run()
    $control | ConvertTo-Json -Depth 8 | Out-File (Join-Path $out 'control.json') -Encoding utf8
    if ($control['verified_received_bytes'] -ne 448) { throw 'Control byte verification failed.' }
    $status.control_success=$true
    Start-Sleep -Milliseconds 300
    Module-Snapshot | ConvertTo-Json -Depth 5 | Out-File (Join-Path $out 'modules-after.json') -Encoding utf8
} catch {
    $status.error = $_.Exception.Message
    Write-Host ('Result: ' + $status.error)
} finally {
    if ($started) {
        $null = Invoke-Wpr -Arguments @('-status','-instancename',$instance) -LogName 'trace-status.txt'
        $etl = Join-Path $out 'control.etl'
        $stop = Invoke-Wpr -Arguments @('-stop',$etl,'-skipPdbGen','-instancename',$instance) -LogName 'stop.txt'
        $status.stop_exit_code = $stop
        if ($stop -eq 0 -and (Test-Path $etl)) { $status.trace_saved=$true }
        if ($stop -ne 0) {
            $null = Invoke-Wpr -Arguments @('-cancel','-instancename',$instance) -LogName 'cancel-own-session.txt'
        }
    }
    $env:TEMP=$oldTemp; $env:TMP=$oldTmp
    $status.finished_utc=[DateTime]::UtcNow.ToString('o')
    if (Test-Path (Join-Path $out 'control.etl')) { $status.etl_bytes=(Get-Item (Join-Path $out 'control.etl')).Length }
    $status | ConvertTo-Json -Depth 6 | Out-File (Join-Path $out 'STATUS.json') -Encoding utf8
    # Include the ETL only below 64 MiB. This is a packaging gate, not a hard bound on merged ETL/temp size.
    $send = @(Get-ChildItem -LiteralPath $out -File | Where-Object { $_.Extension -in '.txt','.json' -or ($_.Name -eq 'control.etl' -and $_.Length -le 64MB) } | ForEach-Object { $_.FullName })
    try {
        $zip = Join-Path $out 'READY-TO-SEND.zip'
        Compress-Archive -LiteralPath $send -DestinationPath $zip
        Write-Host ('Send: ' + $zip)
    } catch { Write-Host ('ZIP failed; keep result folder: ' + $out) }
    Write-Host 'A saved ETL or successful loopback is NOT proof that useful call stacks were captured.'
}
