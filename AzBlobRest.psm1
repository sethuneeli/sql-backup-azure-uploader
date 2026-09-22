<#
    AzBlobRest.psm1
    Dependency-free Azure Blob Storage REST client for Windows PowerShell 5.1.
    No AzCopy, no Az modules, no .NET SDK required.

    Implements the block-blob upload path that large SQL backups need:
      Put Block         - chunked upload, per-block Content-MD5 validated by Azure
      Get Block List    - lists uncommitted blocks, enabling resume after a failure
      Put Block List    - commits the blob
      Get Blob Properties - post-upload verification
#>

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# TLS 1.2+. PS 5.1 still negotiates TLS 1.0 first on some builds, which is a very
# common cause of "connection was forcibly closed" failures against Azure Storage.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 12288 } catch { }
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::DefaultConnectionLimit = 64

$script:ApiVersion = '2021-12-02'

#region ------------------------------------------------------------------ context

function ConvertFrom-AzStorageConnectionString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConnectionString)

    $h = @{}
    foreach ($part in $ConnectionString.Split(';')) {
        if (-not $part) { continue }
        $i = $part.IndexOf('=')
        if ($i -lt 1) { continue }
        $h[$part.Substring(0, $i).Trim()] = $part.Substring($i + 1).Trim()
    }
    [pscustomobject]@{
        AccountName    = $h['AccountName']
        AccountKey     = $h['AccountKey']
        SasToken       = $h['SharedAccessSignature']
        BlobEndpoint   = $h['BlobEndpoint']
        EndpointSuffix = $(if ($h['EndpointSuffix']) { $h['EndpointSuffix'] } else { 'core.windows.net' })
    }
}

function New-AzBlobContext {
    <#
        .SYNOPSIS
        Creates the connection/auth context used by every other function in this module.
        Supports SAS token auth or Shared Key (account key) auth.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [string]$AccountKey,
        [string]$SasToken,
        [string]$BlobEndpoint,
        [string]$EndpointSuffix = 'core.windows.net',
        [string]$ProxyUri,
        [switch]$NoProxy
    )

    if (-not $AccountKey -and -not $SasToken) {
        throw 'New-AzBlobContext: supply either -AccountKey or -SasToken.'
    }
    if (-not $BlobEndpoint) { $BlobEndpoint = "https://$AccountName.blob.$EndpointSuffix" }

    [pscustomobject]@{
        AccountName  = $AccountName
        AccountKey   = $AccountKey
        SasToken     = $(if ($SasToken) { $SasToken.TrimStart('?') } else { $null })
        BlobEndpoint = $BlobEndpoint.TrimEnd('/')
        ProxyUri     = $ProxyUri
        NoProxy      = [bool]$NoProxy
    }
}

function New-AzBlobPath {
    <# Builds "/container/blob/name" with every segment properly escaped. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Container,
        [string]$BlobName
    )
    $p = '/' + [Uri]::EscapeDataString($Container)
    if ($BlobName) {
        foreach ($s in ($BlobName.Trim('/').Split('/') | Where-Object { $_ -ne '' })) {
            $p += '/' + [Uri]::EscapeDataString($s)
        }
    }
    $p
}

#endregion

#region ------------------------------------------------------------------ signing

function Get-AzCanonicalizedResource {
    param([Parameter(Mandatory)][uri]$Uri, [Parameter(Mandatory)][string]$AccountName)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('/').Append($AccountName).Append($Uri.AbsolutePath)

    if ($Uri.Query -and $Uri.Query.Length -gt 1) {
        $q = [System.Web.HttpUtility]::ParseQueryString($Uri.Query)
        foreach ($key in ($q.AllKeys | Where-Object { $_ } | Sort-Object)) {
            $vals = ($q.GetValues($key) | Sort-Object) -join ','
            [void]$sb.Append("`n").Append($key.ToLowerInvariant()).Append(':').Append($vals)
        }
    }
    $sb.ToString()
}

function Get-AzSharedKeyAuthHeader {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][string]$AccountKey,
        [long]$ContentLength = 0
    )

    $canonHeaders = (
        $Headers.GetEnumerator() |
            Where-Object { $_.Key.ToLowerInvariant().StartsWith('x-ms-') } |
            ForEach-Object { '{0}:{1}' -f $_.Key.ToLowerInvariant(), (([string]$_.Value) -replace "`r?`n", ' ').Trim() } |
            Sort-Object
    ) -join "`n"

    $canonResource = Get-AzCanonicalizedResource -Uri $Uri -AccountName $AccountName

    $get = { param($n) if ($Headers.ContainsKey($n)) { [string]$Headers[$n] } else { '' } }

    $stringToSign = @(
        $Method.ToUpperInvariant()
        (& $get 'Content-Encoding')
        (& $get 'Content-Language')
        $(if ($ContentLength -gt 0) { [string]$ContentLength } else { '' })
        (& $get 'Content-MD5')
        (& $get 'Content-Type')
        ''    # Date - we always use x-ms-date instead
        ''    # If-Modified-Since
        ''    # If-Match
        ''    # If-None-Match
        ''    # If-Unmodified-Since
        ''    # Range
        $canonHeaders
        $canonResource
    ) -join "`n"

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Convert]::FromBase64String($AccountKey)
    $sig = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign)))
    $hmac.Dispose()

    'SharedKey {0}:{1}' -f $AccountName, $sig
}

#endregion

#region ---------------------------------------------------------------- transport

function Invoke-AzBlobRest {
    <#
        .SYNOPSIS
        Performs a single REST call. Never throws on HTTP errors - always returns a
        result object so the retry layer can inspect StatusCode / ErrorCode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$ResourcePath,
        [string]$Query,
        [byte[]]$Body,
        [hashtable]$Headers,
        [string]$ContentType,
        [string]$ContentMD5,
        [int]$TimeoutSec = 900
    )

    $h = @{}
    if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }

    $h['x-ms-version'] = $script:ApiVersion
    $h['x-ms-date']    = [DateTime]::UtcNow.ToString('R', [Globalization.CultureInfo]::InvariantCulture)
    if ($ContentType) { $h['Content-Type'] = $ContentType }
    if ($ContentMD5)  { $h['Content-MD5']  = $ContentMD5 }

    $q = @()
    if ($Query)            { $q += $Query.TrimStart('?') }
    if ($Context.SasToken) { $q += $Context.SasToken }
    $qs = if ($q.Count) { '?' + ($q -join '&') } else { '' }

    $uri = [uri]($Context.BlobEndpoint + $ResourcePath + $qs)
    $len = if ($Body) { [long]$Body.Length } else { 0L }

    if (-not $Context.SasToken) {
        $h['Authorization'] = Get-AzSharedKeyAuthHeader -Method $Method -Uri $uri -Headers $h `
            -AccountName $Context.AccountName -AccountKey $Context.AccountKey -ContentLength $len
    }

    $result = [pscustomobject]@{
        Success    = $false
        StatusCode = 0
        ErrorCode  = $null
        Message    = $null
        Headers    = @{}
        Content    = $null
    }

    try {
        $req = [System.Net.HttpWebRequest]::Create($uri)
        $req.Method           = $Method.ToUpperInvariant()
        $req.Timeout          = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $req.KeepAlive        = $true
        $req.AllowWriteStreamBuffering = $false
        $req.UserAgent        = 'SqlBackupBlobUploader/1.0'
        $req.ServicePoint.ConnectionLimit = 64

        if ($Context.NoProxy) {
            $req.Proxy = $null
        } elseif ($Context.ProxyUri) {
            $p = New-Object System.Net.WebProxy($Context.ProxyUri, $true)
            $p.UseDefaultCredentials = $true
            $req.Proxy = $p
        } else {
            $sp = [System.Net.WebRequest]::GetSystemWebProxy()
            $sp.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            $req.Proxy = $sp
        }

        foreach ($k in $h.Keys) {
            if ($k.ToLowerInvariant() -eq 'content-type') { $req.ContentType = [string]$h[$k] }
            else { $req.Headers[$k] = [string]$h[$k] }
        }

        if ($len -gt 0) {
            $req.ContentLength = $len
            $rs = $req.GetRequestStream()
            try { $rs.Write($Body, 0, $Body.Length); $rs.Flush() } finally { $rs.Dispose() }
        } elseif ($req.Method -eq 'PUT' -or $req.Method -eq 'POST') {
            $req.ContentLength = 0
        }

        $resp = $req.GetResponse()
        try {
            $result.StatusCode = [int]$resp.StatusCode
            foreach ($k in $resp.Headers.AllKeys) { $result.Headers[$k] = $resp.Headers[$k] }
            if ($req.Method -ne 'HEAD') {
                $stream = $resp.GetResponseStream()
                if ($stream) {
                    $sr = New-Object System.IO.StreamReader($stream)
                    try { $result.Content = $sr.ReadToEnd() } finally { $sr.Dispose() }
                }
            }
            $result.Success = $true
        } finally { $resp.Dispose() }
    }
    catch [System.Net.WebException] {
        $we = $_.Exception
        $result.Message = $we.Message
        if ($we.Response) {
            try {
                $result.StatusCode = [int]$we.Response.StatusCode
                foreach ($k in $we.Response.Headers.AllKeys) { $result.Headers[$k] = $we.Response.Headers[$k] }
                $result.ErrorCode = $we.Response.Headers['x-ms-error-code']
                $es = $we.Response.GetResponseStream()
                if ($es) {
                    $sr = New-Object System.IO.StreamReader($es)
                    try { $result.Content = $sr.ReadToEnd() } finally { $sr.Dispose() }
                }
            } catch { }
            try { $we.Response.Dispose() } catch { }
        }
        if (-not $result.ErrorCode -and $result.Content -and $result.Content -match '<Code>([^<]+)</Code>') {
            $result.ErrorCode = $Matches[1]
        }
    }
    catch {
        $result.Message = $_.Exception.Message
    }

    $result
}

function Invoke-AzBlobRestWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Request,
        [int]$MaxRetries = 6,
        [int]$InitialBackoffMs = 1500,
        [scriptblock]$OnRetry
    )

    $retryable = @(0, 408, 429, 500, 502, 503, 504)
    $attempt = 0
    while ($true) {
        $r = Invoke-AzBlobRest @Request
        if ($r.Success) { return $r }
        if (($retryable -notcontains $r.StatusCode) -or $attempt -ge $MaxRetries) { return $r }

        $attempt++
        $delay = [int][Math]::Min($InitialBackoffMs * [Math]::Pow(2, $attempt - 1), 60000)
        $delay += Get-Random -Minimum 0 -Maximum 1000
        if ($OnRetry) { & $OnRetry $attempt $r $delay }
        Start-Sleep -Milliseconds $delay
    }
}

function Format-AzBlobError {
    <# Turns a failed result into a message that names the actual problem. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    if ($Result.StatusCode -eq 0) {
        return "no HTTP response (network, DNS, proxy or TLS failure) - $($Result.Message)"
    }

    $detail = $Result.Message
    if ($Result.Content -and $Result.Content -match '<Message>([^<]+)</Message>') {
        $detail = ($Matches[1] -split "`n")[0].Trim()
    }

    $hint = switch ($Result.ErrorCode) {
        'AuthenticationFailed'            { ' [check SAS validity and system clock skew vs Azure]' }
        'AuthorizationPermissionMismatch' { " [SAS needs 'c' and 'w'; must be container-scoped (sr=c)]" }
        'AuthorizationFailure'            { ' [storage account firewall may be blocking this host]' }
        'ContainerNotFound'               { ' [wrong container name, or the SAS cannot see it]' }
        'Md5Mismatch'                     { ' [data altered in transit - suspect a TLS-inspecting proxy]' }
        'InvalidBlockList'                { ' [uncommitted blocks expired after 7 days; re-run to re-upload]' }
        'BlobImmutableDueToPolicy'        { ' [immutability/legal hold prevents overwriting this blob]' }
        default                           { '' }
    }

    "HTTP $($Result.StatusCode) $($Result.ErrorCode) - $detail$hint"
}

#endregion

#region ----------------------------------------------------------------- blob ops

function Test-AzBlobContainer {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Container)

    $r = Invoke-AzBlobRest -Method GET -Context $Context `
        -ResourcePath (New-AzBlobPath -Container $Container) -Query 'restype=container&comp=metadata'
    if ($r.Success) { return $true }
    if ($r.StatusCode -eq 404) { return $false }
    throw "Container check failed: $(Format-AzBlobError $r)"
}

function New-AzBlobContainer {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Container)

    $r = Invoke-AzBlobRest -Method PUT -Context $Context `
        -ResourcePath (New-AzBlobPath -Container $Container) -Query 'restype=container'
    if ($r.Success -or $r.ErrorCode -eq 'ContainerAlreadyExists') { return $true }
    throw "Create container failed: $(Format-AzBlobError $r)"
}

function Get-AzBlobProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$BlobName
    )
    $r = Invoke-AzBlobRest -Method HEAD -Context $Context `
        -ResourcePath (New-AzBlobPath -Container $Container -BlobName $BlobName)
    if ($r.StatusCode -eq 404) { return $null }
    if (-not $r.Success) {
        throw "Get blob properties failed: $(Format-AzBlobError $r)"
    }
    [pscustomobject]@{
        Length       = [long]$r.Headers['Content-Length']
        ContentMD5   = $r.Headers['Content-MD5']
        LastModified = $r.Headers['Last-Modified']
        BlobType     = $r.Headers['x-ms-blob-type']
        AccessTier   = $r.Headers['x-ms-access-tier']
    }
}

function Get-AzBlobUncommittedBlocks {
    <# Returns a hashtable of blockId -> size for blocks left by an interrupted run. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$BlobName
    )
    $map = @{}
    $r = Invoke-AzBlobRest -Method GET -Context $Context `
        -ResourcePath (New-AzBlobPath -Container $Container -BlobName $BlobName) `
        -Query 'comp=blocklist&blocklisttype=uncommitted'

    if (-not $r.Success -or -not $r.Content) { return $map }
    try {
        $xml = [xml]$r.Content
        foreach ($n in $xml.SelectNodes('//UncommittedBlocks/Block')) { $map[$n.Name] = [long]$n.Size }
    } catch { }
    $map
}

function New-AzBlockId {
    param([Parameter(Mandatory)][int]$Index)
    # Fixed-width id: every block id within a blob must be the same length.
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(('blk-{0:D8}' -f $Index)))
}

function Send-AzBlobBlock {
    <# Uploads one block with a Content-MD5 that Azure validates on arrival. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$BlobName,
        [Parameter(Mandatory)][string]$BlockId,
        [Parameter(Mandatory)][byte[]]$Data,
        [int]$Length = -1,
        [int]$MaxRetries = 6,
        [int]$TimeoutSec = 900,
        [scriptblock]$OnRetry
    )

    if ($Length -lt 0) { $Length = $Data.Length }
    if ($Length -ne $Data.Length) {
        $trimmed = New-Object byte[] $Length
        [Array]::Copy($Data, 0, $trimmed, 0, $Length)
        $Data = $trimmed
    }

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $hash = [Convert]::ToBase64String($md5.ComputeHash($Data)) } finally { $md5.Dispose() }

    $req = @{
        Method       = 'PUT'
        Context      = $Context
        ResourcePath = (New-AzBlobPath -Container $Container -BlobName $BlobName)
        Query        = 'comp=block&blockid=' + [Uri]::EscapeDataString($BlockId)
        Body         = $Data
        ContentMD5   = $hash
        TimeoutSec   = $TimeoutSec
    }
    $r = Invoke-AzBlobRestWithRetry -Request $req -MaxRetries $MaxRetries -OnRetry $OnRetry
    if (-not $r.Success) {
        throw "Put Block '$BlockId' failed: $(Format-AzBlobError $r)"
    }
    $true
}

function Complete-AzBlobBlockList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$BlobName,
        [Parameter(Mandatory)][string[]]$BlockIds,
        [string]$ContentType = 'application/octet-stream',
        [string]$BlobContentMD5,
        [ValidateSet('', 'Hot', 'Cool', 'Cold', 'Archive')][string]$AccessTier = '',
        [hashtable]$Metadata,
        [int]$MaxRetries = 6,
        [int]$TimeoutSec = 900
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<?xml version="1.0" encoding="utf-8"?><BlockList>')
    foreach ($id in $BlockIds) { [void]$sb.Append('<Latest>').Append($id).Append('</Latest>') }
    [void]$sb.Append('</BlockList>')
    $body = [Text.Encoding]::UTF8.GetBytes($sb.ToString())

    $headers = @{ 'x-ms-blob-content-type' = $ContentType }
    if ($BlobContentMD5) { $headers['x-ms-blob-content-md5'] = $BlobContentMD5 }
    if ($AccessTier)     { $headers['x-ms-access-tier']      = $AccessTier }
    if ($Metadata) { foreach ($k in $Metadata.Keys) { $headers["x-ms-meta-$k"] = [string]$Metadata[$k] } }

    $req = @{
        Method       = 'PUT'
        Context      = $Context
        ResourcePath = (New-AzBlobPath -Container $Container -BlobName $BlobName)
        Query        = 'comp=blocklist'
        Body         = $body
        Headers      = $headers
        ContentType  = 'application/xml'
        TimeoutSec   = $TimeoutSec
    }
    $r = Invoke-AzBlobRestWithRetry -Request $req -MaxRetries $MaxRetries
    if (-not $r.Success) {
        throw "Put Block List failed: $(Format-AzBlobError $r)"
    }
    $true
}

function Remove-AzBlob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$BlobName
    )
    $r = Invoke-AzBlobRest -Method DELETE -Context $Context `
        -ResourcePath (New-AzBlobPath -Container $Container -BlobName $BlobName)
    ($r.Success -or $r.StatusCode -eq 404)
}

function Get-FileMd5Base64 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { [Convert]::ToBase64String($md5.ComputeHash($fs)) }
    finally { $fs.Dispose(); $md5.Dispose() }
}

#endregion

Export-ModuleMember -Function *-*
