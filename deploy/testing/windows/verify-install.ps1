# Runs the real Windows installer, then checks what it set up. Used against
# the test VM: powershell -ExecutionPolicy Bypass -File verify-install.ps1 -Api <url> -Key <install key>
param([string]$Api, [string]$Key)
$ErrorActionPreference = 'Stop'

& ([scriptblock]::Create((Invoke-RestMethod "$Api/install.ps1"))) -Key $Key

Start-Sleep -Seconds 3
$svc = Get-CimInstance Win32_Service -Filter "Name='pulsegrid-agent'"
"--- service: state=$($svc.State) start=$($svc.StartMode) account=$($svc.StartName)"
"--- binary:  $(& 'C:\Program Files\Pulsegrid\pulsegrid-agent.exe' version)"
"--- process: $((Get-Process pulsegrid-agent).Id)"
"--- state dir ACL:"
(Get-Acl 'C:\ProgramData\Pulsegrid').Access | ForEach-Object { "    $($_.IdentityReference) $($_.FileSystemRights)" }
"--- files: $((Get-ChildItem 'C:\ProgramData\Pulsegrid' -Name) -join ', ')"
$task = Get-ScheduledTask -TaskName 'Pulsegrid agent update'
"--- update task: $($task.State) as $($task.Principal.UserId), runs: $($task.Actions[0].Execute) $($task.Actions[0].Arguments)"
"--- recovery: $((& sc.exe qfailure pulsegrid-agent) -match 'RESTART' | Select-Object -First 1)"
