<#
.SYNOPSIS
    Stores a SAS token or storage account key in a DPAPI-encrypted file.

.DESCRIPTION
    The resulting file can only be decrypted by the SAME Windows account on the
    SAME machine that created it. Run this while logged on as (or using
    runas /user:) the account the scheduled task will run under - otherwise the
    task will not be able to read it.

.EXAMPLE
    .\New-SecretFile.ps1 -Path .\secrets\sas.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$Value
)

$ErrorActionPreference = 'Stop'

$dir = Split-Path -Parent $Path
if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

if ($Value) {
    $secure = ConvertTo-SecureString -String $Value -AsPlainText -Force
} else {
    Write-Host 'Paste the SAS token (starting with "sv=" or "?sv=") or the account key.' -ForegroundColor Cyan
    $secure = Read-Host -Prompt 'Secret' -AsSecureString
}

ConvertFrom-SecureString -SecureString $secure | Set-Content -LiteralPath $Path -Encoding UTF8

# Lock the file down to the current account + SYSTEM + Administrators.
try {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
    foreach ($id in @("$env:USERDOMAIN\$env:USERNAME", 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        try {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
        } catch { }
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
} catch {
    Write-Warning "Secret written but ACL hardening failed: $($_.Exception.Message)"
}

Write-Host "Secret written to $Path" -ForegroundColor Green
Write-Host 'Readable only by the account that created it, on this machine.' -ForegroundColor Yellow
