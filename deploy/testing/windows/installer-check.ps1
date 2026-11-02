# Installs the agent with the real install.ps1 from a running installer-stub,
# checks it runs and reports, then runs -Uninstall and checks nothing is left.
# CI runs this on windows-latest.
#
#   powershell -ExecutionPolicy Bypass -File installer-check.ps1 -Stub http://127.0.0.1:8099
param([Parameter(Mandatory)][string]$Stub)
$ErrorActionPreference = 'Stop'
function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }

Write-Host '== install'
$script = Invoke-RestMethod "$Stub/install.ps1"
& ([scriptblock]::Create($script)) -Key 'pg_ci_install_key' -Tags 'ci,windows'

Write-Host '== checks'
& "$env:ProgramFiles\Sentinel\sentinel-agent.exe" version
$svc = Get-Service sentinel-agent -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') { Fail 'service is not running' }
if (-not (Get-ScheduledTask -TaskName 'Sentinel agent update' -ErrorAction SilentlyContinue)) { Fail 'no update task' }
$deadline = (Get-Date).AddSeconds(60)
while ((Invoke-RestMethod "$Stub/pushes") -eq 0) {
    if ((Get-Date) -gt $deadline) { Fail 'the agent sent no metrics in 60 s' }
    Start-Sleep -Seconds 1
}
Write-Host "agent reported (pushes: $(Invoke-RestMethod "$Stub/pushes"))"

Write-Host '== uninstall'
& ([scriptblock]::Create($script)) -Uninstall
Start-Sleep -Seconds 2
if (Get-Service sentinel-agent -ErrorAction SilentlyContinue) { Fail 'service left behind' }
if (Get-ScheduledTask -TaskName 'Sentinel agent update' -ErrorAction SilentlyContinue) { Fail 'update task left behind' }
if (Get-Process sentinel-agent -ErrorAction SilentlyContinue) { Fail 'agent process left behind' }
foreach ($p in "$env:ProgramFiles\Sentinel", "$env:ProgramData\Sentinel") {
    if (Test-Path $p) { Fail "$p left behind" }
}
Write-Host 'PASS on windows'
