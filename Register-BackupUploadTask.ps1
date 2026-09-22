<#
.SYNOPSIS
    Registers the uploader as a Windows Scheduled Task.

.DESCRIPTION
    Creates a task that runs the uploader on a repeating interval under a
    service account, with the working directory pinned to this folder so the
    relative state/, logs/ and secrets/ paths resolve correctly.

    Run this elevated. The account you specify must:
      * have "Log on as a batch job" rights,
      * be able to read the backup folder,
      * be the SAME account used to create the DPAPI secret file.

.EXAMPLE
    .\Register-BackupUploadTask.ps1 -TaskName 'SQL Backup to Azure' `
        -ConfigFile .\config.json -RepeatMinutes 30 -RunAsUser 'CONTOSO\svc_sqlbackup'
#>
[CmdletBinding()]
param(
    [string]$TaskName = 'SQL Backup Upload to Azure',
    [string]$ConfigFile = '.\config.json',
    [string]$ScriptArguments,
    [int]$RepeatMinutes = 30,
    [string]$StartTime = '00:05',
    [string]$RunAsUser,
    [switch]$RunAsSystem,
    [int]$ExecutionTimeLimitHours = 12
)

$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$target     = Join-Path $scriptRoot 'Upload-SqlBackupsToAzure.ps1'
if (-not (Test-Path -LiteralPath $target)) { throw "Uploader not found: $target" }

$argList = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $target
if ($ScriptArguments) {
    $argList += ' ' + $ScriptArguments
} else {
    $cfg = if ([System.IO.Path]::IsPathRooted($ConfigFile)) { $ConfigFile } else { Join-Path $scriptRoot (Split-Path -Leaf $ConfigFile) }
    $argList += ' -ConfigFile "{0}"' -f $cfg
}

$action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') `
    -Argument $argList -WorkingDirectory $scriptRoot

$trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($StartTime))
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At ([datetime]::Parse($StartTime)) `
    -RepetitionInterval (New-TimeSpan -Minutes $RepeatMinutes) `
    -RepetitionDuration (New-TimeSpan -Hours 24)).Repetition

$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 10) `
    -ExecutionTimeLimit (New-TimeSpan -Hours $ExecutionTimeLimitHours)

if ($RunAsSystem) {
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
} elseif ($RunAsUser) {
    $cred = Get-Credential -UserName $RunAsUser -Message "Password for $RunAsUser (stored by Task Scheduler)"
    $principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Password -RunLevel Highest
} else {
    throw 'Specify -RunAsUser <domain\account> or -RunAsSystem.'
}

$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Description 'Copies SQL Server backup files to Azure Blob Storage (AzCopy-free uploader).'

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

if ($RunAsSystem) {
    Register-ScheduledTask -TaskName $TaskName -InputObject $task | Out-Null
} else {
    Register-ScheduledTask -TaskName $TaskName -InputObject $task `
        -User $cred.UserName -Password $cred.GetNetworkCredential().Password | Out-Null
}

Write-Host "Registered scheduled task '$TaskName'" -ForegroundColor Green
Write-Host "  runs every $RepeatMinutes minutes"
Write-Host "  command: powershell.exe $argList"
Write-Host "  working dir: $scriptRoot"
Write-Host ''
Write-Host 'Note: if you used a DPAPI secret file, create it while logged on as that same account:' -ForegroundColor Yellow
Write-Host '  .\New-SecretFile.ps1 -Path .\secrets\sas.txt' -ForegroundColor Yellow
