<#
.SYNOPSIS
    Copies SQL Server backup files from a Windows server to Azure Blob Storage
    without AzCopy, the Az modules, or any other external dependency.

.DESCRIPTION
    Built for the failure modes that make AzCopy unreliable on backup volumes:

      * Chunked block-blob upload (Put Block / Put Block List) so a 500 GB .bak
        is never one long fragile HTTP request.
      * True resume: uncommitted blocks already accepted by Azure are detected
        and skipped, so a re-run after a network drop restarts mid-file, not
        from zero.
      * Per-block Content-MD5 validated by the storage service, so silent
        corruption in transit is rejected rather than committed.
      * Exponential backoff with jitter on 408/429/5xx and on socket errors.
      * Skips files that SQL Server is still writing (age + size-stability +
        share-lock checks) instead of uploading a truncated backup.
      * Idempotent: a state ledger plus a remote size check means re-running the
        job never re-uploads what already landed.
      * Corporate proxy and TLS 1.2 handled explicitly.

.EXAMPLE
    .\Upload-SqlBackupsToAzure.ps1 -SourcePath 'E:\SQLBackups' -Recurse `
        -AccountName 'stgsqlbackups' -Container 'sqlbackups' `
        -SecretFile '.\secrets\sas.txt' -AccessTier Cool

.EXAMPLE
    .\Upload-SqlBackupsToAzure.ps1 -ConfigFile .\config.json

.NOTES
    Exit codes: 0 = everything uploaded/verified, 1 = one or more files failed,
                2 = fatal error (config, auth, container).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # ---- source ------------------------------------------------------------
    [string[]]$SourcePath,
    [string[]]$Filter = @('*.bak', '*.trn', '*.dif'),
    [switch]$Recurse,
    [int]$MinAgeSeconds = 60,
    [int]$StabilityCheckSeconds = 5,
    [int]$MaxFileAgeDays = 0,          # 0 = no limit; else skip files older than this

    # ---- destination -------------------------------------------------------
    [string]$AccountName,
    [string]$Container,
    [string]$BlobPrefix,               # defaults to the computer name
    [switch]$DatePartition,            # insert yyyy/MM/dd into the blob path
    [switch]$FlattenNames,             # ignore source folder structure
    [ValidateSet('', 'Hot', 'Cool', 'Cold', 'Archive')][string]$AccessTier = '',
    [switch]$CreateContainer,

    # ---- auth --------------------------------------------------------------
    [string]$SasToken,
    [string]$AccountKey,
    [string]$ConnectionString,
    [string]$SecretFile,               # DPAPI-encrypted SAS/key (see New-SecretFile.ps1)
    [ValidateSet('Sas', 'Key')][string]$SecretType = 'Sas',
    [string]$BlobEndpoint,
    [string]$EndpointSuffix = 'core.windows.net',
    [string]$ProxyUri,
    [switch]$NoProxy,

    # ---- transfer tuning ---------------------------------------------------
    [ValidateRange(1, 4000)][int]$BlockSizeMB = 64,
    [ValidateRange(1, 32)][int]$Concurrency = 4,
    [int]$MaxRetries = 6,
    [int]$TimeoutSec = 900,
    [double]$MaxMBps = 0,              # 0 = unthrottled
    [switch]$VerifyMd5,                # full-file MD5 (extra local read pass)
    [switch]$NoResume,

    # ---- post-actions ------------------------------------------------------
    [switch]$DeleteSourceAfterUpload,
    [string]$MoveToPathAfterUpload,
    [int]$DeleteSourceOlderThanDays = 0,

    # ---- plumbing ----------------------------------------------------------
    [string]$ConfigFile,
    [string]$StatePath,
    [string]$LogPath,
    [switch]$ListOnly
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

#region ----------------------------------------------------------- config + setup

if ($ConfigFile) {
    if (-not (Test-Path -LiteralPath $ConfigFile)) { throw "Config file not found: $ConfigFile" }
    $cfg = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
    foreach ($p in $cfg.PSObject.Properties) {
        # explicit command-line arguments always win over the config file
        if ($PSBoundParameters.ContainsKey($p.Name)) { continue }
        if (-not (Get-Variable -Name $p.Name -Scope 0 -ErrorAction SilentlyContinue)) { continue }
        $val = $p.Value
        if ($val -is [System.Management.Automation.PSCustomObject]) { continue }
        Set-Variable -Name $p.Name -Value $val -Scope 0
    }
}

if (-not $StatePath) { $StatePath = Join-Path $scriptRoot 'state' }
if (-not $LogPath)   { $LogPath   = Join-Path $scriptRoot 'logs' }

# Preflight the working directories BEFORE anything else. A scheduled task running
# as a service account that cannot write its own bookkeeping files is the single
# most common "it works interactively but fails at 2am" failure - and it must fail
# loudly, naming the account and the path, not with a bare "access denied".
function Assert-WritableDirectory {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Purpose)

    $who = "$env:USERDOMAIN\$env:USERNAME"
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        $probe = Join-Path $Path ('.writeprobe_{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($probe, 'probe')
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
    } catch {
        Write-Host ''
        Write-Host "FATAL: cannot write to the $Purpose directory." -ForegroundColor Red
        Write-Host "  path    : $Path"
        Write-Host "  account : $who"
        Write-Host "  error   : $($_.Exception.Message)"
        Write-Host ''
        Write-Host 'Fix one of these:' -ForegroundColor Yellow
        Write-Host "  * grant Modify on '$Path' to $who"
        Write-Host "  * point -$Purpose`Path at a directory the service account owns, e.g. C:\ProgramData\SqlBackupUpload\$Purpose"
        Write-Host '  * if this runs as a scheduled task, confirm the account has "Log on as a batch job"'
        Write-Host ''
        exit 2
    }
}

Assert-WritableDirectory -Path $StatePath -Purpose 'State'
Assert-WritableDirectory -Path $LogPath   -Purpose 'Log'

$logFile = Join-Path $LogPath ('upload_{0:yyyyMMdd}.log' -f (Get-Date))
$script:logWriteWarned = $false

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO'
    )
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1,-5}] {2}' -f (Get-Date), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
    try {
        Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Never lose the log silently - say so once, keep running.
        if (-not $script:logWriteWarned) {
            $script:logWriteWarned = $true
            Write-Host "WARNING: cannot write to $logFile ($($_.Exception.Message)). Console output only." -ForegroundColor Yellow
        }
    }
}

$modulePath = Join-Path $scriptRoot 'modules\AzBlobRest.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) { throw "Module not found: $modulePath" }
Import-Module $modulePath -Force -DisableNameChecking

#endregion

#region ------------------------------------------------------------------- helpers

function Resolve-Secret {
    if ($ConnectionString) {
        $parsed = ConvertFrom-AzStorageConnectionString -ConnectionString $ConnectionString
        if (-not $AccountName) { $script:AccountName = $parsed.AccountName }
        if ($parsed.BlobEndpoint -and -not $BlobEndpoint) { $script:BlobEndpoint = $parsed.BlobEndpoint }
        return @{ Sas = $parsed.SasToken; Key = $parsed.AccountKey }
    }
    if ($SecretFile) {
        if (-not (Test-Path -LiteralPath $SecretFile)) { throw "Secret file not found: $SecretFile" }
        $sec = Get-Content -LiteralPath $SecretFile -Raw | ConvertTo-SecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ($SecretType -eq 'Key') { return @{ Sas = $null; Key = $plain } }
        return @{ Sas = $plain; Key = $null }
    }
    @{ Sas = $SasToken; Key = $AccountKey }
}

function Test-FileReady {
    <#
        A backup that SQL Server is still writing must never be uploaded.
        Three independent checks: minimum age, size stability, and an exclusive
        open (which fails while the writer holds the file).
    #>
    param([Parameter(Mandatory)][System.IO.FileInfo]$File)

    if ($MinAgeSeconds -gt 0) {
        $age = (Get-Date) - $File.LastWriteTime
        if ($age.TotalSeconds -lt $MinAgeSeconds) {
            return @{ Ready = $false; Reason = ('last written {0:N0}s ago (< {1}s)' -f $age.TotalSeconds, $MinAgeSeconds) }
        }
    }

    if ($StabilityCheckSeconds -gt 0) {
        $before = $File.Length
        Start-Sleep -Seconds $StabilityCheckSeconds
        $File.Refresh()
        if ($File.Length -ne $before) {
            return @{ Ready = $false; Reason = 'file size still growing' }
        }
    }

    try {
        $fs = [System.IO.File]::Open($File.FullName, 'Open', 'Read', 'None')
        $fs.Dispose()
    } catch {
        return @{ Ready = $false; Reason = 'file is locked by another process' }
    }

    @{ Ready = $true; Reason = $null }
}

function Get-BlobNameFor {
    param([Parameter(Mandatory)][System.IO.FileInfo]$File, [Parameter(Mandatory)][string]$Root)

    $parts = @()
    if ($BlobPrefix) { $parts += $BlobPrefix.Trim('/') }
    if ($DatePartition) { $parts += ('{0:yyyy/MM/dd}' -f $File.LastWriteTime) }

    if ($FlattenNames) {
        $parts += $File.Name
    } else {
        $rel = $File.FullName.Substring($Root.Length).TrimStart('\', '/')
        $parts += ($rel -replace '\\', '/')
    }
    ($parts | Where-Object { $_ }) -join '/'
}

function Get-StateFilePath {
    param([Parameter(Mandatory)][string]$BlobName)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $h = ($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($BlobName)) |
              ForEach-Object { $_.ToString('x2') }) -join ''
    } finally { $md5.Dispose() }
    Join-Path $StatePath "$h.json"
}

function Read-State {
    param([Parameter(Mandatory)][string]$BlobName)
    $p = Get-StateFilePath -BlobName $BlobName
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { Get-Content -LiteralPath $p -Raw | ConvertFrom-Json } catch { $null }
}

function Write-State {
    param([Parameter(Mandatory)][string]$BlobName, [Parameter(Mandatory)][hashtable]$State)
    $p = Get-StateFilePath -BlobName $BlobName
    ($State | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $p -Encoding UTF8
}

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1TB) { return '{0:N2} TB' -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return '{0:N2} MB' -f ($Bytes / 1MB) }
    '{0:N0} KB' -f ($Bytes / 1KB)
}

#endregion

#region -------------------------------------------------------------- block worker

# Runs inside each runspace. Reads its own byte range straight from disk so the
# read is parallel too, then PUTs it as a single block.
$blockWorker = {
    param($Context, $Container, $BlobName, $FilePath, $Offset, $Length,
          $BlockId, $MaxRetries, $TimeoutSec, $ThrottleBytesPerSec)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $buffer = New-Object byte[] $Length
        $fs = [System.IO.File]::Open($FilePath, 'Open', 'Read', 'ReadWrite')
        try {
            [void]$fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
            $read = 0
            while ($read -lt $Length) {
                $n = $fs.Read($buffer, $read, $Length - $read)
                if ($n -le 0) { break }
                $read += $n
            }
        } finally { $fs.Dispose() }

        if ($read -ne $Length) { throw "short read: expected $Length bytes, got $read" }

        Send-AzBlobBlock -Context $Context -Container $Container -BlobName $BlobName `
            -BlockId $BlockId -Data $buffer -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec | Out-Null

        if ($ThrottleBytesPerSec -gt 0) {
            $target = $Length / $ThrottleBytesPerSec
            $sleep  = [int](($target - $sw.Elapsed.TotalSeconds) * 1000)
            if ($sleep -gt 0) { Start-Sleep -Milliseconds $sleep }
        }

        [pscustomobject]@{ BlockId = $BlockId; Ok = $true; Bytes = $Length; Error = $null }
    } catch {
        [pscustomobject]@{ BlockId = $BlockId; Ok = $false; Bytes = 0; Error = $_.Exception.Message }
    }
}

function Send-FileToBlob {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][System.IO.FileInfo]$File,
        [Parameter(Mandatory)][string]$BlobName
    )

    $blockSize  = $BlockSizeMB * 1MB
    $totalBytes = $File.Length
    $blockCount = [int][Math]::Max(1, [Math]::Ceiling($totalBytes / $blockSize))

    if ($blockCount -gt 50000) {
        throw ("$($File.Name) needs $blockCount blocks (max 50000). " +
               "Raise -BlockSizeMB to at least $([Math]::Ceiling($totalBytes / 50000 / 1MB)).")
    }

    $blockIds = @(0..($blockCount - 1) | ForEach-Object { New-AzBlockId -Index $_ })

    # ---- resume: which blocks did Azure already accept? --------------------
    $alreadyUploaded = @{}
    if (-not $NoResume) {
        $state = Read-State -BlobName $BlobName
        $sameFile = $state -and
                    $state.SourceLength -eq $totalBytes -and
                    $state.SourceLastWriteUtc -eq $File.LastWriteTimeUtc.ToString('o') -and
                    $state.BlockSize -eq $blockSize
        if ($sameFile) {
            $uncommitted = Get-AzBlobUncommittedBlocks -Context $Context -Container $Container -BlobName $BlobName
            for ($i = 0; $i -lt $blockCount; $i++) {
                $expected = if ($i -eq $blockCount - 1) { $totalBytes - ($i * $blockSize) } else { $blockSize }
                if ($uncommitted.ContainsKey($blockIds[$i]) -and $uncommitted[$blockIds[$i]] -eq $expected) {
                    $alreadyUploaded[$i] = $true
                }
            }
            if ($alreadyUploaded.Count) {
                Write-Log ("  resuming: $($alreadyUploaded.Count)/$blockCount blocks already in Azure") 'INFO'
            }
        }
    }

    Write-State -BlobName $BlobName -State @{
        SourcePath         = $File.FullName
        SourceLength       = $totalBytes
        SourceLastWriteUtc = $File.LastWriteTimeUtc.ToString('o')
        BlockSize          = $blockSize
        BlockCount         = $blockCount
        Status             = 'InProgress'
        StartedUtc         = [DateTime]::UtcNow.ToString('o')
    }

    $throttle = if ($MaxMBps -gt 0) { [long](($MaxMBps * 1MB) / $Concurrency) } else { 0 }

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $iss.ImportPSModule($modulePath)
    $pool = [runspacefactory]::CreateRunspacePool(1, $Concurrency, $iss, $Host)
    $pool.Open()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $pending = New-Object System.Collections.ArrayList
    $sentBytes = 0L
    $skippedBytes = 0L
    $done = 0
    $failures = @()
    $next = 0
    $maxInFlight = [Math]::Max(2, $Concurrency * 2)

    try {
        while ($done -lt $blockCount) {

            while ($next -lt $blockCount -and $pending.Count -lt $maxInFlight) {
                $i = $next; $next++
                $offset = [long]$i * $blockSize
                $len = [int][Math]::Min($blockSize, $totalBytes - $offset)

                if ($alreadyUploaded.ContainsKey($i)) {
                    $done++; $skippedBytes += $len
                    continue
                }

                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddScript($blockWorker).AddArgument($Context).AddArgument($Container).
                    AddArgument($BlobName).AddArgument($File.FullName).AddArgument($offset).
                    AddArgument($len).AddArgument($blockIds[$i]).AddArgument($MaxRetries).
                    AddArgument($TimeoutSec).AddArgument($throttle)
                [void]$pending.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Index = $i; Length = $len })
            }

            if ($pending.Count -eq 0) { continue }

            $completed = @($pending | Where-Object { $_.Handle.IsCompleted })
            if ($completed.Count -eq 0) { Start-Sleep -Milliseconds 200; continue }

            foreach ($job in $completed) {
                try { $res = $job.PS.EndInvoke($job.Handle) } catch { $res = $null }
                $out = if ($res) { @($res)[-1] } else { $null }
                $job.PS.Dispose()
                [void]$pending.Remove($job)
                $done++

                if ($out -and $out.Ok) {
                    $sentBytes += $out.Bytes
                } else {
                    $msg = if ($out) { $out.Error } else { 'worker produced no result' }
                    $failures += "block $($job.Index): $msg"
                }
            }

            $moved = $sentBytes + $skippedBytes
            $pct = [int](($moved / [double]$totalBytes) * 100)
            $mbps = if ($sw.Elapsed.TotalSeconds -gt 0) { ($sentBytes / 1MB) / $sw.Elapsed.TotalSeconds } else { 0 }
            Write-Progress -Activity "Uploading $($File.Name)" `
                -Status ('{0}% - {1} of {2} - {3:N1} MB/s - {4} failed' -f $pct, (Format-Bytes $moved), (Format-Bytes $totalBytes), $mbps, $failures.Count) `
                -PercentComplete ([Math]::Min($pct, 100))

            if ($failures.Count -gt 0) { break }
        }
    } finally {
        foreach ($job in @($pending)) {
            try { $job.PS.Stop(); $job.PS.Dispose() } catch { }
        }
        $pool.Close(); $pool.Dispose()
        Write-Progress -Activity "Uploading $($File.Name)" -Completed
    }

    if ($failures.Count -gt 0) {
        $detail = ($failures | Select-Object -First 3) -join '; '
        throw "upload failed after retries -> $detail"
    }

    # ---- commit ------------------------------------------------------------
    $fileMd5 = $null
    if ($VerifyMd5) {
        Write-Log '  computing file MD5 for the commit record...'
        $fileMd5 = Get-FileMd5Base64 -Path $File.FullName
    }

    $meta = @{
        source_host = $env:COMPUTERNAME
        source_path = ($File.FullName -replace '[^\x20-\x7E]', '')
        source_mtime_utc = $File.LastWriteTimeUtc.ToString('o')
    }

    Complete-AzBlobBlockList -Context $Context -Container $Container -BlobName $BlobName `
        -BlockIds $blockIds -BlobContentMD5 $fileMd5 -AccessTier $AccessTier `
        -Metadata $meta -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec | Out-Null

    # ---- verify ------------------------------------------------------------
    $props = Get-AzBlobProperties -Context $Context -Container $Container -BlobName $BlobName
    if (-not $props) { throw 'blob not found after commit' }
    if ($props.Length -ne $totalBytes) {
        throw "size mismatch after commit: local $totalBytes vs blob $($props.Length)"
    }
    if ($fileMd5 -and $props.ContentMD5 -and $props.ContentMD5 -ne $fileMd5) {
        throw 'MD5 mismatch after commit'
    }

    Write-State -BlobName $BlobName -State @{
        SourcePath         = $File.FullName
        SourceLength       = $totalBytes
        SourceLastWriteUtc = $File.LastWriteTimeUtc.ToString('o')
        BlockSize          = $blockSize
        BlockCount         = $blockCount
        Status             = 'Completed'
        CompletedUtc       = [DateTime]::UtcNow.ToString('o')
        Md5                = $fileMd5
    }

    [pscustomobject]@{
        Bytes        = $totalBytes
        SentBytes    = $sentBytes
        ResumedBytes = $skippedBytes
        Seconds      = $sw.Elapsed.TotalSeconds
    }
}

#endregion

#region ---------------------------------------------------------------------- main

$summary = [pscustomobject]@{
    Uploaded = 0; Skipped = 0; Failed = 0; BytesSent = 0L; Started = Get-Date
}

Write-Log '============================================================'
Write-Log "SQL backup -> Azure Blob upload starting on $env:COMPUTERNAME"

try {
    if (-not $SourcePath -or $SourcePath.Count -eq 0) { throw 'Specify -SourcePath (or set it in -ConfigFile).' }
    if (-not $Container) { throw 'Specify -Container.' }

    $secret = Resolve-Secret
    if (-not $AccountName) { throw 'Specify -AccountName.' }
    if (-not $secret.Sas -and -not $secret.Key) { throw 'No credential supplied (-SasToken, -AccountKey, -SecretFile or -ConnectionString).' }
    if (-not $BlobPrefix) { $BlobPrefix = $env:COMPUTERNAME }

    $ctxArgs = @{
        AccountName    = $AccountName
        EndpointSuffix = $EndpointSuffix
    }
    if ($secret.Sas)  { $ctxArgs['SasToken']     = $secret.Sas }
    if ($secret.Key)  { $ctxArgs['AccountKey']   = $secret.Key }
    if ($BlobEndpoint){ $ctxArgs['BlobEndpoint'] = $BlobEndpoint }
    if ($ProxyUri)    { $ctxArgs['ProxyUri']     = $ProxyUri }
    if ($NoProxy)     { $ctxArgs['NoProxy']      = $true }
    $ctx = New-AzBlobContext @ctxArgs

    Write-Log "Destination: $($ctx.BlobEndpoint)/$Container/$BlobPrefix"
    Write-Log ("Auth: {0} | blocks: {1} MB | concurrency: {2} | tier: {3}" -f
        $(if ($secret.Sas) { 'SAS' } else { 'SharedKey' }), $BlockSizeMB, $Concurrency,
        $(if ($AccessTier) { $AccessTier } else { 'account default' }))

    if ($ListOnly) {
        Write-Log 'ListOnly: skipping container check and all uploads'
    }
    elseif (-not (Test-AzBlobContainer -Context $ctx -Container $Container)) {
        if ($CreateContainer) {
            New-AzBlobContainer -Context $ctx -Container $Container | Out-Null
            Write-Log "Created container '$Container'" 'OK'
        } else {
            throw "Container '$Container' not found (or the SAS lacks list permission). Use -CreateContainer to create it."
        }
    }

    # ---- enumerate ---------------------------------------------------------
    $candidates = New-Object System.Collections.ArrayList
    foreach ($root in $SourcePath) {
        if (-not (Test-Path -LiteralPath $root)) { Write-Log "Source path not found: $root" 'WARN'; continue }
        $rootFull = (Resolve-Path -LiteralPath $root).ProviderPath.TrimEnd('\')

        $gci = @{ LiteralPath = $rootFull; File = $true; ErrorAction = 'SilentlyContinue' }
        if ($Recurse) { $gci['Recurse'] = $true }

        foreach ($f in (Get-ChildItem @gci)) {
            $name = $f.Name
            $match = $false
            foreach ($pattern in $Filter) { if ($name -like $pattern) { $match = $true; break } }
            if ($match) { [void]$candidates.Add([pscustomobject]@{ File = $f; Root = $rootFull }) }
        }
    }

    $candidates = @($candidates | Sort-Object { $_.File.LastWriteTime })
    Write-Log "Found $($candidates.Count) candidate file(s)"

    foreach ($c in $candidates) {
        $file = $c.File
        $blob = Get-BlobNameFor -File $file -Root $c.Root

        if ($MaxFileAgeDays -gt 0 -and $file.LastWriteTime -lt (Get-Date).AddDays(-$MaxFileAgeDays)) {
            Write-Log "SKIP $($file.Name) - older than $MaxFileAgeDays days"; $summary.Skipped++; continue
        }

        if ($ListOnly) {
            Write-Log ("WOULD UPLOAD {0} ({1}) -> {2}" -f $file.Name, (Format-Bytes $file.Length), $blob)
            $summary.Skipped++; continue
        }

        # already there?
        $state = Read-State -BlobName $blob
        if ($state -and $state.Status -eq 'Completed' -and
            $state.SourceLength -eq $file.Length -and
            $state.SourceLastWriteUtc -eq $file.LastWriteTimeUtc.ToString('o')) {
            $props = Get-AzBlobProperties -Context $ctx -Container $Container -BlobName $blob
            if ($props -and $props.Length -eq $file.Length) {
                Write-Log "SKIP $($file.Name) - already uploaded and verified"
                $summary.Skipped++
                if ($DeleteSourceAfterUpload -and $PSCmdlet.ShouldProcess($file.FullName, 'Delete (already verified in Azure)')) {
                    Remove-Item -LiteralPath $file.FullName -Force
                    Write-Log '  source file deleted (previously verified)'
                }
                continue
            }
        }

        $ready = Test-FileReady -File $file
        if (-not $ready.Ready) {
            Write-Log "SKIP $($file.Name) - $($ready.Reason)" 'WARN'; $summary.Skipped++; continue
        }

        if (-not $PSCmdlet.ShouldProcess($file.FullName, "Upload to $Container/$blob")) {
            $summary.Skipped++; continue
        }

        Write-Log ("UPLOAD {0} ({1}) -> {2}" -f $file.Name, (Format-Bytes $file.Length), $blob)
        try {
            $r = Send-FileToBlob -Context $ctx -File $file -BlobName $blob
            $mbps = if ($r.Seconds -gt 0) { ($r.SentBytes / 1MB) / $r.Seconds } else { 0 }
            Write-Log ("  done in {0:N0}s at {1:N1} MB/s{2}" -f $r.Seconds, $mbps,
                $(if ($r.ResumedBytes -gt 0) { " (resumed $(Format-Bytes $r.ResumedBytes))" } else { '' })) 'OK'
            $summary.Uploaded++
            $summary.BytesSent += $r.SentBytes

            if ($MoveToPathAfterUpload) {
                if (-not (Test-Path -LiteralPath $MoveToPathAfterUpload)) {
                    New-Item -ItemType Directory -Path $MoveToPathAfterUpload -Force | Out-Null
                }
                Move-Item -LiteralPath $file.FullName -Destination (Join-Path $MoveToPathAfterUpload $file.Name) -Force
                Write-Log "  moved source to $MoveToPathAfterUpload"
            } elseif ($DeleteSourceAfterUpload) {
                Remove-Item -LiteralPath $file.FullName -Force
                Write-Log '  source file deleted (upload verified)'
            }
        } catch {
            Write-Log "  FAILED $($file.Name): $($_.Exception.Message)" 'ERROR'
            $summary.Failed++
        }
    }

    # ---- optional source retention sweep -----------------------------------
    if ($DeleteSourceOlderThanDays -gt 0) {
        $cutoff = (Get-Date).AddDays(-$DeleteSourceOlderThanDays)
        foreach ($c in $candidates) {
            $file = $c.File
            if (-not (Test-Path -LiteralPath $file.FullName)) { continue }
            if ($file.LastWriteTime -ge $cutoff) { continue }
            $blob = Get-BlobNameFor -File $file -Root $c.Root
            $props = Get-AzBlobProperties -Context $ctx -Container $Container -BlobName $blob
            if ($props -and $props.Length -eq $file.Length) {
                if ($PSCmdlet.ShouldProcess($file.FullName, 'Delete (retention, verified in Azure)')) {
                    Remove-Item -LiteralPath $file.FullName -Force
                    Write-Log "RETENTION removed $($file.Name) (verified in Azure)"
                }
            }
        }
    }
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" 'ERROR'
    Write-Log '============================================================'
    exit 2
}

$elapsed = (Get-Date) - $summary.Started
Write-Log ("Summary: {0} uploaded, {1} skipped, {2} failed, {3} sent in {4:hh\:mm\:ss}" -f
    $summary.Uploaded, $summary.Skipped, $summary.Failed, (Format-Bytes $summary.BytesSent), $elapsed) `
    $(if ($summary.Failed) { 'WARN' } else { 'OK' })
Write-Log '============================================================'

exit $(if ($summary.Failed -gt 0) { 1 } else { 0 })

#endregion
