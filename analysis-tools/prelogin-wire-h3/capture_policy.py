"""Disable performance-only LSO on disposable hosted runner, before qualification.
No changes to TLS, firewall, security tools, packet parser, game or user machine.
"""
import json
import os
from pathlib import Path
import subprocess

SCRIPT=r'''
$ErrorActionPreference = 'Stop'
$before = @(Get-NetAdapterLso -ErrorAction Stop)
if ($before.Count -lt 1 -or $before.Count -gt 32) { throw 'adapter_count' }
$enabled = @($before | Where-Object { $_.IPv4Enabled -or $_.IPv6Enabled }).Count
$before | Disable-NetAdapterLso -Confirm:$false -ErrorAction Stop
Start-Sleep -Seconds 3
$after = @(Get-NetAdapterLso -ErrorAction Stop)
if ($after.Count -ne $before.Count) { throw 'adapter_changed' }
if (@(Compare-Object @($before.Name | Sort-Object) @($after.Name | Sort-Object)).Count -ne 0) { throw 'adapter_changed' }
if (@($after | Where-Object { $_.IPv4Enabled -or $_.IPv6Enabled }).Count -ne 0) { throw 'lso_still_enabled' }
@{method='disable_netadapter_lso';adapter_count=$after.Count;previously_enabled_count=$enabled;verified_disabled=$true} | ConvertTo-Json -Compress
'''

def validate(policy):
    if type(policy) is not dict or set(policy)!={'method','adapter_count','previously_enabled_count','verified_disabled'}:raise ValueError('capture_policy_keys')
    if policy['method']!='disable_netadapter_lso' or policy['verified_disabled'] is not True:raise ValueError('capture_policy_method')
    a=policy['adapter_count'];b=policy['previously_enabled_count']
    if type(a) is not int or type(b) is not int or not 1<=a<=32 or not 0<=b<=a:raise ValueError('capture_policy_count')
    return policy

def configure(env):
    exe=Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'
    result=subprocess.run([str(exe),'-NoLogo','-NoProfile','-NonInteractive','-Command',SCRIPT],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=75,check=False)
    if result.returncode!=0 or len(result.stdout)>4096:raise RuntimeError('capture_policy_failed')
    return validate(json.loads(result.stdout.decode('utf-8-sig')))
