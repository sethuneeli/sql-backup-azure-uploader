<#
.SYNOPSIS
    Diagnoses why backup uploads to Azure Blob Storage are failing.

.DESCRIPTION
    Runs the checks that explain the overwhelming majority of AzCopy/REST
    failures on an on-prem SQL Server:

      1. DNS resolution of the storage endpoint (split-brain / private endpoint)
      2. TCP 443 reachability and TLS handshake (inspection proxies, TLS 1.0)
      3. Certificate chain issuer (TLS-intercepting firewall)
      4. Proxy configuration actually in effect for this account
      5. System clock skew vs Azure (Shared Key auth fails past ~15 minutes)
      6. SAS token expiry / permissions / start time
      7. Container reachability, and a real 8 MB round-trip upload + delete

.EXAMPLE
    .\Test-AzureBlobConnectivity.ps1 -AccountName stgsqlbackups -Container sqlbackups -SecretFile .\secrets\sas.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AccountName,
    [Parameter(Mandatory)][string]$Container,
    [string]$SasToken,
    [string]$AccountKey,
    [string]$SecretFile,
    [ValidateSet('Sas', 'Key')][string]$SecretType = 'Sas',
    [string]$EndpointSuffix = 'core.windows.net',
    [string]$BlobEndpoint,
    [string]$ProxyUri,
    [switch]$NoProxy,
    [switch]$SkipUploadTest
)

$ErrorActionPreference = 'Continue'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $scriptRoot 'modules\AzBlobRest.psm1') -Force -DisableNameChecking

$pass = 0; $fail = 0; $warn = 0
function Result {
    param([string]$Name, [ValidateSet('PASS', 'FAIL', 'WARN')][string]$Status, [string]$Detail)
    $color = @{ PASS = 'Green'; FAIL = 'Red'; WARN = 'Yellow' }[$Status]
    Write-Host ('[{0}] {1}' -f $Status, $Name) -ForegroundColor $color
    if ($Detail) { Write-Host ('       {0}' -f $Detail) -ForegroundColor DarkGray }
    switch ($Status) { 'PASS' { $script:pass++ } 'FAIL' { $script:fail++ } 'WARN' { $script:warn++ } }
}

$host_ = if ($BlobEndpoint) { ([uri]$BlobEndpoint).Host } else { "$AccountName.blob.$EndpointSuffix" }
Write-Host "`nAzure Blob connectivity diagnostics for $host_`n" -ForegroundColor Cyan

# ---- 1. DNS ----------------------------------------------------------------
try {
    $ips = [System.Net.Dns]::GetHostAddresses($host_) | ForEach-Object { $_.IPAddressToString }
    $priv = $ips | Where-Object { $_ -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' }
    Result 'DNS resolution' 'PASS' ("$host_ -> " + ($ips -join ', ') +
        $(if ($priv) { '  (private IP - resolving via Private Endpoint)' } else { '' }))
} catch {
    Result 'DNS resolution' 'FAIL' $_.Exception.Message
}

# ---- 2/3. TCP + TLS + certificate ------------------------------------------
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $iar = $tcp.BeginConnect($host_, 443, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(10000)) { throw 'timed out after 10s' }
    $tcp.EndConnect($iar)
    Result 'TCP 443 reachable' 'PASS' "connected to $host_`:443"

    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
    $ssl.AuthenticateAsClient($host_)
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
    Result 'TLS handshake' 'PASS' "protocol: $($ssl.SslProtocol)"

    if ($cert.Issuer -match 'Microsoft|DigiCert|Baltimore|GlobalSign|Entrust') {
        Result 'Server certificate' 'PASS' "issuer: $($cert.Issuer)"
    } else {
        Result 'Server certificate' 'WARN' ("issuer: $($cert.Issuer) - looks like a TLS-inspecting proxy. " +
            'This breaks many storage clients; ask the network team to bypass inspection for *.blob.core.windows.net.')
    }
    $ssl.Dispose(); $tcp.Close()
} catch {
    Result 'TCP/TLS to storage endpoint' 'FAIL' $_.Exception.Message
}

# ---- 4. Proxy --------------------------------------------------------------
try {
    $sys = [System.Net.WebRequest]::GetSystemWebProxy()
    $target = [uri]("https://$host_/")
    if ($ProxyUri) {
        Result 'Proxy' 'PASS' "explicit -ProxyUri $ProxyUri"
    } elseif ($NoProxy) {
        Result 'Proxy' 'PASS' 'bypassed (-NoProxy)'
    } elseif ($sys.IsBypassed($target)) {
        Result 'Proxy' 'PASS' 'direct connection (no proxy for this host)'
    } else {
        Result 'Proxy' 'WARN' ("system proxy in use: " + $sys.GetProxy($target) +
            ' - proxies frequently time out on multi-GB uploads. Consider a bypass rule for *.blob.core.windows.net.')
    }
} catch { Result 'Proxy' 'WARN' $_.Exception.Message }

# ---- 5. Clock skew ---------------------------------------------------------
try {
    $req = [System.Net.HttpWebRequest]::Create("https://$host_/?comp=list")
    $req.Method = 'GET'; $req.Timeout = 15000
    try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response }
    $serverDate = [datetime]::Parse($resp.Headers['Date']).ToUniversalTime()
    $skew = [Math]::Abs(((Get-Date).ToUniversalTime() - $serverDate).TotalSeconds)
    if ($skew -lt 300) {
        Result 'Clock skew' 'PASS' ('{0:N0}s vs Azure' -f $skew)
    } else {
        Result 'Clock skew' 'FAIL' ('{0:N0}s vs Azure - Shared Key auth rejects requests beyond ~15 min. Fix time sync (w32tm /resync).' -f $skew)
    }
    $resp.Dispose()
} catch { Result 'Clock skew' 'WARN' $_.Exception.Message }

# ---- 6. Credential ---------------------------------------------------------
if ($SecretFile -and (Test-Path -LiteralPath $SecretFile)) {
    try {
        $sec = Get-Content -LiteralPath $SecretFile -Raw | ConvertTo-SecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ($SecretType -eq 'Key') { $AccountKey = $plain } else { $SasToken = $plain }
        Result 'Secret file' 'PASS' "decrypted $SecretFile as $env:USERDOMAIN\$env:USERNAME"
    } catch {
        Result 'Secret file' 'FAIL' ("cannot decrypt - DPAPI secrets only open for the account that created them. " +
            "Re-run New-SecretFile.ps1 as the scheduled-task account. ($($_.Exception.Message))")
    }
}

if ($SasToken) {
    $sas = $SasToken.TrimStart('?')
    $kv = @{}
    foreach ($pair in $sas.Split('&')) {
        $i = $pair.IndexOf('=')
        if ($i -gt 0) { $kv[$pair.Substring(0, $i)] = [uri]::UnescapeDataString($pair.Substring($i + 1)) }
    }
    if ($kv['se']) {
        $exp = [datetime]::Parse($kv['se']).ToUniversalTime()
        $left = $exp - (Get-Date).ToUniversalTime()
        if ($left.TotalMinutes -le 0) {
            Result 'SAS expiry' 'FAIL' "expired at $($exp.ToString('u'))"
        } elseif ($left.TotalHours -lt 24) {
            Result 'SAS expiry' 'WARN' ("expires in {0:N1}h ($($exp.ToString('u'))). A SAS that expires mid-transfer is a classic AzCopy failure." -f $left.TotalHours)
        } else {
            Result 'SAS expiry' 'PASS' ("valid for {0:N1} more days" -f $left.TotalDays)
        }
    }
    if ($kv['st']) {
        $start = [datetime]::Parse($kv['st']).ToUniversalTime()
        if ($start -gt (Get-Date).ToUniversalTime()) {
            Result 'SAS start time' 'FAIL' "not valid until $($start.ToString('u'))"
        }
    }
    if ($kv['sp']) {
        $missing = @('c', 'w', 'r') | Where-Object { $kv['sp'].IndexOf($_) -lt 0 }
        if ($missing) {
            Result 'SAS permissions' 'WARN' ("sp=$($kv['sp']) - missing '$($missing -join "','")'. " +
                "Uploads need c (create) and w (write); r (read) is required for the post-upload size check.")
        } else {
            Result 'SAS permissions' 'PASS' "sp=$($kv['sp'])"
        }
    }
    if ($kv['sr'] -and $kv['sr'] -eq 'b') {
        Result 'SAS scope' 'WARN' "sr=b is a single-blob SAS; a container SAS (sr=c) is required to upload many files."
    }
}

# ---- 7. Live round trip ----------------------------------------------------
if (-not $SasToken -and -not $AccountKey) {
    Result 'Live API test' 'WARN' 'no credential supplied - skipped'
} else {
    try {
        $ctxArgs = @{ AccountName = $AccountName; EndpointSuffix = $EndpointSuffix }
        if ($SasToken)    { $ctxArgs['SasToken']     = $SasToken }
        if ($AccountKey)  { $ctxArgs['AccountKey']   = $AccountKey }
        if ($BlobEndpoint){ $ctxArgs['BlobEndpoint'] = $BlobEndpoint }
        if ($ProxyUri)    { $ctxArgs['ProxyUri']     = $ProxyUri }
        if ($NoProxy)     { $ctxArgs['NoProxy']      = $true }
        $ctx = New-AzBlobContext @ctxArgs

        if (Test-AzBlobContainer -Context $ctx -Container $Container) {
            Result 'Container access' 'PASS' "$Container is reachable"
        } else {
            Result 'Container access' 'FAIL' "$Container not found (or the SAS cannot see it)"
        }

        if (-not $SkipUploadTest) {
            $blob = "_connectivity-test/$env:COMPUTERNAME-$(Get-Date -Format yyyyMMddHHmmss).tmp"
            $data = New-Object byte[] (8MB)
            (New-Object Random).NextBytes($data)

            $sw = [Diagnostics.Stopwatch]::StartNew()
            $id = New-AzBlockId -Index 0
            Send-AzBlobBlock -Context $ctx -Container $Container -BlobName $blob -BlockId $id -Data $data -MaxRetries 2 | Out-Null
            Complete-AzBlobBlockList -Context $ctx -Container $Container -BlobName $blob -BlockIds @($id) -MaxRetries 2 | Out-Null
            $sw.Stop()

            $props = Get-AzBlobProperties -Context $ctx -Container $Container -BlobName $blob
            if ($props -and $props.Length -eq 8MB) {
                Result 'Live 8 MB upload' 'PASS' ('{0:N1} MB/s round trip' -f (8 / $sw.Elapsed.TotalSeconds))
            } else {
                Result 'Live 8 MB upload' 'FAIL' 'blob missing or wrong size after commit'
            }
            Remove-AzBlob -Context $ctx -Container $Container -BlobName $blob | Out-Null
        }
    } catch {
        Result 'Live API test' 'FAIL' $_.Exception.Message
    }
}

Write-Host ("`n{0} passed, {1} warnings, {2} failed`n" -f $pass, $warn, $fail) -ForegroundColor Cyan
exit $(if ($fail -gt 0) { 1 } else { 0 })
