# SQL Server backups to Azure Blob Storage — without AzCopy

A dependency-free PowerShell replacement for AzCopy, built for the one job AzCopy
most often fails at on a database server: moving large `.bak` / `.trn` files from
an on-prem Windows box to Azure Blob Storage, unattended, every night.

No AzCopy. No `Az.*` modules. No .NET SDK. Windows PowerShell 5.1 and TLS to
`*.blob.core.windows.net` are the only requirements.

---

## Read this first: you may not need to copy files at all

If SQL Server itself can reach Azure over 443, `BACKUP ... TO URL` writes the
backup straight into blob storage. There is no local `.bak` and therefore no copy
job to fail. That is the more reliable design, and it is what `sql/BackupToUrl.sql`
sets up — a container-scoped SAS credential, compressed, checksummed, striped
across four URLs for parallel throughput.

Use the PowerShell uploader in this folder when you can't do that:

- a third-party backup product (Veeam, Commvault, Ola Hallengren to disk) owns the backup
- you need a local copy on disk for restore-time SLAs
- SQL Server 2012 or older, or a version without block-blob `TO URL` support
- the SQL Server service account has no outbound internet, but a file server does

Both approaches can coexist: back up to disk for fast local restores, then ship
the file to Azure with the uploader for offsite retention.

---

## Why AzCopy fails on backup volumes, and what this does instead

| What goes wrong with AzCopy | What this uploader does |
|---|---|
| SAS expires partway through a multi-hour transfer, and the whole file restarts | Re-run picks up mid-file: blocks already accepted by Azure are detected via *Get Block List (uncommitted)* and skipped. Refresh the SAS, re-run, done |
| A single long HTTP request dies on a flaky WAN and the transfer restarts from 0% | The file is split into blocks (64 MB default). One dropped block costs one block, not the file |
| `.azcopy` job-plan files silently fill the system drive | No plan files. State is a few hundred bytes of JSON per blob in `state\` |
| Uploads a backup SQL Server is still writing, producing an unrestorable blob | Three independent readiness checks — minimum age, size stability, and an exclusive open that fails while the writer holds the file |
| Corporate TLS-inspection proxy breaks the transfer with an opaque error | Proxy is explicit (`-ProxyUri` / `-NoProxy`, system proxy with default credentials otherwise), and `Test-AzureBlobConnectivity.ps1` names the intercepting issuer |
| Transient 500/503/429 aborts the run | Exponential backoff with jitter on 408/429/5xx and socket errors, per block |
| Silent corruption in transit | Every block carries a `Content-MD5` that the storage service validates and rejects on mismatch. Size is re-verified after commit; `-VerifyMd5` adds a whole-file hash |
| Version drift — AzCopy v8 vs v10 flags, `azcopy login` token expiry | Nothing to install or update. One `.psm1` calling the documented REST API |

---

## Files

| Path | What it is |
|---|---|
| `Upload-SqlBackupsToAzure.ps1` | The uploader. Run it by hand or from Task Scheduler |
| `modules\AzBlobRest.psm1` | Blob REST client: Shared Key signing, retries, block upload, commit, verify |
| `Test-AzureBlobConnectivity.ps1` | Diagnostic. Run this first when something fails |
| `New-SecretFile.ps1` | Stores the SAS/key DPAPI-encrypted so it never sits in a script or config in plain text |
| `Register-BackupUploadTask.ps1` | Registers the scheduled task with sane settings |
| `config.sample.json` | Copy to `config.json` and edit |
| `sql\BackupToUrl.sql` | The `BACKUP TO URL` alternative, with troubleshooting notes |
| `tests\Invoke-Tests.ps1` | Offline end-to-end test suite (see below) |

---

## Setup

**1. Create a container SAS** with `racwdl`, HTTPS only, and a long expiry.

```bash
az storage container generate-sas --account-name stgsqlbackups --name sqlbackups --permissions racwdl --expiry 2027-12-31T23:59Z --https-only -o tsv
```

**2. Store it encrypted**, logged on as the account the scheduled task will use.
DPAPI ties the file to that account on that machine — creating it as yourself and
running the task as a service account is the single most common setup mistake.

```bash
powershell -File ".\New-SecretFile.ps1" -Path ".\secrets\sas.txt"
```

**3. Prove the path works** before scheduling anything.

```bash
powershell -File ".\Test-AzureBlobConnectivity.ps1" -AccountName stgsqlbackups -Container sqlbackups -SecretFile ".\secrets\sas.txt"
```

It checks DNS, TCP 443, the TLS protocol, the certificate issuer, the effective
proxy, clock skew against Azure, SAS expiry/permissions/scope, and finishes with a
real 8 MB upload-verify-delete round trip that reports throughput.

**4. Dry run**, then a real run.

```bash
powershell -File ".\Upload-SqlBackupsToAzure.ps1" -SourcePath "E:\SQLBackups" -Recurse -Container sqlbackups -AccountName stgsqlbackups -SecretFile ".\secrets\sas.txt" -ListOnly
```

```bash
powershell -File ".\Upload-SqlBackupsToAzure.ps1" -SourcePath "E:\SQLBackups" -Recurse -Container sqlbackups -AccountName stgsqlbackups -SecretFile ".\secrets\sas.txt" -AccessTier Cool -DatePartition
```

**5. Schedule it.** Copy `config.sample.json` to `config.json`, edit, then:

```bash
powershell -File ".\Register-BackupUploadTask.ps1" -ConfigFile ".\config.json" -RepeatMinutes 30 -RunAsUser "CONTOSO\svc_sqlbackup"
```

Running every 30 minutes is deliberate. Each run picks up new backups, resumes
anything interrupted, and skips what is already in Azure — so a failed night
repairs itself instead of waiting for a human.

---

## Tuning

| Parameter | Default | Notes |
|---|---|---|
| `-BlockSizeMB` | 64 | 8–16 on a lossy or high-latency link (less to redo per failure); 100+ on a fast LAN-to-Azure path. 50,000 blocks max per blob, so 64 MB tops out at ~3.2 TB per file |
| `-Concurrency` | 4 | Parallel block uploads. 8–16 saturates a 1 Gbps link; each worker holds one block in memory, so 8 × 64 MB ≈ 512 MB RAM |
| `-MaxMBps` | 0 (off) | Throttle so the backup upload doesn't starve production traffic during business hours |
| `-AccessTier` | account default | `Cool` for weekly retention, `Archive` for long-term — but archived blobs need a rehydration of hours before restore |
| `-VerifyMd5` | off | Whole-file MD5. Costs one extra local read pass; per-block MD5 already protects the wire |
| `-MinAgeSeconds` | 60 | Raise if your backup software writes slowly with long pauses |
| `-DatePartition` | off | Blob path becomes `PREFIX/yyyy/MM/dd/name.bak` |

Memory ceiling is roughly `BlockSizeMB × Concurrency`. Watch that on a SQL host.

### Retention

Delete old blobs with an Azure **lifecycle management policy** on the storage
account, not with this script — it runs server-side and costs nothing.

For local disk, `-DeleteSourceOlderThanDays 7` removes source files older than
seven days *only after re-confirming the blob exists at the right size*.
`-MoveToPathAfterUpload` is the safer option if you'd rather not delete.

---

## When something fails

1. `Test-AzureBlobConnectivity.ps1` — it names the cause in most cases.
2. `logs\upload_yyyyMMdd.log` — every action, with the Azure error code and HTTP status.
3. Exit codes: `0` all verified, `1` at least one file failed, `2` fatal (config/auth/container). Task Scheduler shows this as the Last Run Result.

### The AzCopy error this project was built to replace

> `Access to the path '...\azcopy\azcopycheckpoint.jnl' is denied`

`azcopycheckpoint.jnl` is the **AzCopy v8** resume journal (v10 uses `.azcopy` job
plan files instead, so this error identifies a retired version). AzCopy v8 must
create and hold an exclusive lock on that journal for the whole transfer. It fails
when:

- the scheduled-task account has no write access to the journal folder — the folder was created by a human account, or `/Z:` points somewhere like `%LocalAppData%` under a service account whose profile is never loaded;
- the path is **relative** (`/Z:log\azcopy`), so it resolves against whatever working directory Task Scheduler happens to use — often `C:\Windows\System32`, where a non-admin cannot write;
- a previous run crashed and left a stale journal owned by a different account, or still locked;
- antivirus or a backup agent holds the `.jnl` open.

If you need AzCopy working today, the quickest fixes are: pass an absolute
`/Z:C:\ProgramData\azcopyjournal` that the service account owns, delete the stale
journal, and confirm no other AzCopy instance is running. Longer term, v8 is
retired — v10 or this uploader.

This uploader has no journal and no lock. Resume state lives in `state\` as one
small JSON file per blob, the path is configurable, and it is **write-probed at
startup** — if the account can't write there, the run stops immediately naming the
path, the account, and the fix, instead of failing opaquely mid-transfer.

### Other common causes, in the order they actually occur:

- **`AuthenticationFailed`** — clock skew over 15 minutes (Shared Key), or a SAS that started with a stray `?`. The diagnostic checks both.
- **`AuthorizationPermissionMismatch` / 403** — SAS missing `c` or `w`, or scoped to a blob (`sr=b`) instead of a container (`sr=c`).
- **Secret file won't decrypt** — created under a different account than the task runs as. Re-run `New-SecretFile.ps1` as the service account.
- **Certificate issuer isn't Microsoft/DigiCert** — TLS inspection. Ask the network team to bypass inspection for `*.blob.core.windows.net`.
- **Works interactively, fails as a task** — the account lacks "Log on as a batch job", or can't read the backup share, or the config uses relative paths (the task registration pins the working directory to avoid this).
- **403 from a private endpoint / firewalled account** — the storage account firewall must allow the server's outbound IP, or the private endpoint must resolve. The DNS check reports whether you're getting a private IP.

---

## Tests

The uploader is covered by an offline end-to-end suite. It starts a local HTTP
server that emulates the Blob block-blob API and drives the real script against
it — no Azure account, no network:

```bash
powershell -ExecutionPolicy Bypass -File ".\tests\Invoke-Tests.ps1"
```

23 checks across six scenarios: 40 MB chunked upload verified byte-for-byte by
SHA-256, idempotent re-run, injected 503s recovered by the retry layer, a
mid-file abort followed by a genuine resume (only the missing blocks re-sent),
an in-use file correctly skipped, and Shared Key signature structure.

Current status: **23 passed, 0 failed** on Windows PowerShell 5.1.

---

## Security notes

- The SAS never appears in the script, the config file, or the command line — `New-SecretFile.ps1` stores it DPAPI-encrypted and ACLs the file to the owning account, SYSTEM and Administrators.
- Prefer a container-scoped SAS over the account key. If the server is compromised, a SAS is revocable (rotate the signing key) and can be scoped to one container.
- SAS tokens are never written to the log; only account, container and prefix are.
- Consider a **write-only** SAS (`sp=cw`) plus a separate read credential if you want the SQL host unable to read or delete what it has already shipped. Note that `-VerifyMd5` and the post-upload size check need `r`; without it the uploader still works but cannot verify.
- Enable **immutability / legal hold** on the container to make backups ransomware-resistant. Immutable blobs cannot be overwritten, so re-running against an existing blob will fail by design.
