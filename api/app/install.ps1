# Sentinel agent installer for Windows (Server 2016+ / Windows 10+), run as Administrator:
#   & ([scriptblock]::Create((irm __DOWNLOAD_URL__/install.ps1))) -Key <install key> [-Tags web,production]
#   & ([scriptblock]::Create((irm __DOWNLOAD_URL__/install.ps1))) -Uninstall [-KeepConfig]
#
# Served by the Sentinel API with the URLs below filled in from its config.
param([string]$Key = '', [string]$Tags = '', [switch]$Uninstall, [switch]$KeepConfig)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # makes Invoke-WebRequest much faster
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$DownloadUrl = '__DOWNLOAD_URL__'
$IngestUrl = '__INGEST_URL__'
$Version = '__AGENT_VERSION__'

$ServiceName = 'sentinel-agent'
$InstallDir = Join-Path $env:ProgramFiles 'Sentinel'
$Bin = Join-Path $InstallDir 'sentinel-agent.exe'
$StateDir = Join-Path $env:ProgramData 'Sentinel'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'sentinel: run this in an elevated (Administrator) PowerShell'
}

# Everything the install below creates. The server stays listed in Sentinel
# (as not reporting) until it's removed there.
if ($Uninstall) {
    foreach ($task in 'Sentinel agent update', 'Sentinel agent watchdog') {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    }
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $InstallDir
    if ($KeepConfig) {
        Get-ChildItem $StateDir -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'conf' } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StateDir
    }
    Write-Host 'Sentinel agent removed. The server stays listed in Sentinel as not reporting until you remove it there.'
    return
}
if (-not $Key) { throw 'sentinel: -Key <install key> is required (or -Uninstall)' }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$asset = "sentinel-agent-windows-$arch.exe"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("sentinel-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading $asset ($Version)..."
    Invoke-WebRequest -UseBasicParsing "$DownloadUrl/agent/$Version/$asset" -OutFile (Join-Path $tmp $asset)
    # Saved to a file and read as text: Windows PowerShell 5.1 hands back
    # .Content as raw bytes when the server sends application/octet-stream.
    Invoke-WebRequest -UseBasicParsing "$DownloadUrl/agent/$Version/$asset.sha256" -OutFile (Join-Path $tmp "$asset.sha256")
    $expected = ((Get-Content -Raw (Join-Path $tmp "$asset.sha256")).Trim() -split '\s+')[0]
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash
    if ($actual -ne $expected.ToUpper()) { throw "sentinel: checksum mismatch for $asset" }

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing -and $existing.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item (Join-Path $tmp $asset) $Bin -Force
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# State (including the host token): SYSTEM and Administrators full control,
# the LocalService account the agent runs as can modify, nobody else.
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
& icacls $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null

# Plugin and action files: Administrators write them, the agent only reads.
$ConfigDir = Join-Path $StateDir 'conf'
New-Item -ItemType Directory -Force -Path (Join-Path $ConfigDir 'plugins.d') | Out-Null
& icacls $ConfigDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null

# Windows PowerShell drops empty arguments to native programs, so --tags is
# only passed when there are tags.
$registerArgs = @('register', '--url', $IngestUrl, '--key', $Key, '--state-dir', $StateDir)
if ($Tags) { $registerArgs += @('--tags', $Tags) }
& $Bin @registerArgs
if ($LASTEXITCODE -ne 0) { throw 'sentinel: registration failed' }

$binPath = "`"$Bin`" run --state-dir `"$StateDir`""
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    & sc.exe config $ServiceName binPath= $binPath start= auto obj= 'NT AUTHORITY\LocalService' | Out-Null
} else {
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'Sentinel agent' `
        -Description 'Collects server metrics for Sentinel.' -StartupType Automatic | Out-Null
    & sc.exe config $ServiceName obj= 'NT AUTHORITY\LocalService' | Out-Null
}
# Restart automatically if it ever exits.
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null
Start-Service -Name $ServiceName

# Hourly self-update check as SYSTEM (the agent itself can't replace its
# binary); it only downloads when a new version is advertised.
$action = New-ScheduledTaskAction -Execute $Bin -Argument "update --state-dir `"$StateDir`" --restart $ServiceName"
$trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes((Get-Random -Minimum 5 -Maximum 60))) `
    -RepetitionInterval (New-TimeSpan -Hours 1)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName 'Sentinel agent update' -Action $action -Trigger $trigger -Settings $settings `
    -User 'SYSTEM' -RunLevel Highest -Force | Out-Null

# Watchdog: the service manager restarts the agent after a crash, not after
# Stop-Service; this starts it again within 5 minutes. To stop the agent for
# good, disable the 'Sentinel agent watchdog' task too.
$wdAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `"if ((Get-Service $ServiceName).Status -ne 'Running') { Start-Service $ServiceName }`""
$wdTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName 'Sentinel agent watchdog' -Action $wdAction -Trigger $wdTrigger -Settings $settings `
    -User 'SYSTEM' -RunLevel Highest -Force | Out-Null

Write-Host 'Sentinel agent installed and running.'
