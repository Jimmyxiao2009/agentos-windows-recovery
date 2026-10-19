> **Archived:** this project is no longer maintained. 本项目已暂停维护并归档。

# AgentOS Windows Recovery Runtime

This repository contains the first runnable Windows transaction-recovery slice of AgentOS.
It launches a command in a kill-on-close Job Object, snapshots explicitly declared file and
registry scopes, records a durable transaction manifest, and can commit or conditionally
roll back the resulting changes.

It also exposes detached transactions for long-running desktop agents. A caller can persist
a baseline before the first mutating UI action, execute multiple steps, then seal and commit
or roll back the transaction independently of process ownership.

## Build and validate

```powershell
dotnet build .\src\AgentOS\AgentOS.csproj -c Release
dotnet run --project .\src\AgentOS\AgentOS.csproj -c Release -- self-test

# Publish a self-contained single-file win-x64 executable and validate that exact artifact.
.\scripts\publish-windows.ps1
```

The publish script writes a SHA-256-addressed validation report to
`artifacts\validation\report.json`. The current initial release is intentionally unsigned;
the report records that fact so a future code-signing stage cannot be mistaken for complete.

## Example

```powershell
$scope = Join-Path $env:TEMP 'agentos-demo'
New-Item -ItemType Directory -Force $scope | Out-Null
Set-Content (Join-Path $scope 'before.txt') 'before'

.\agentos.exe run `
  --file-scope $scope `
  --registry-scope 'HKCU\Software\AgentOS\Demo' `
  --on-success retain `
  -- pwsh -NoProfile -Command "Set-Content '$scope\before.txt' 'after'"

# Use the transaction id printed by run.
.\agentos.exe rollback <transaction-id>
.\agentos.exe verify <transaction-id>
```

Detached task integration:

```powershell
$tx = .\agentos.exe begin --file-scope C:\work --correlation task-123 | ConvertFrom-Json
# The desktop agent performs one or more UI actions here.
.\agentos.exe prepare $tx.id
.\agentos.exe commit $tx.id
# Committed recovery data remains usable until purge:
.\agentos.exe rollback $tx.id
```

Successful commands default to `Prepared`, so the caller must explicitly commit or roll
back. A non-zero root-process exit triggers automatic rollback. Rollback compares the
recorded transaction-after state to current state before changing anything; later edits
produce `Conflicted` and remain untouched unless `--force` is explicitly supplied.
`agentos scrub [--store <dir>]` is a read-only integrity walk over manifests, journals,
indexes and recovery blobs; it reports damaged evidence without mutating workspace state.

New transactions persist SHA-256 indexes for the baseline and after-state snapshot sets as
`baseline-integrity.json` / `after-integrity.json`, and anchor those index hashes in the
hash-chained journal. Commit, rollback, and verification validate the manifest, journal,
declared scopes, snapshot structure, and recovery blobs before proceeding. Rollback stages
and verifies every required before-image before its first file or registry write, so missing
or damaged recovery content fails closed as `RecoveryRequired`. Existing content-addressed
blobs are also revalidated before reuse. Transactions created before evidence indexes
(`EvidenceVersion` < 1) keep a legacy path that still validates structure and recovery
sources, but does not require index anchors.

## Initial-version boundary

This is a user-mode recovery runtime, not yet a kernel security boundary. It covers regular files, directories, available file security descriptors, NTFS alternate streams, hardlink group metadata, sparse/encrypted/compressed flags, volume/file-index identity metadata, common registry value types, explicitly named services and scheduled tasks, VSS baselines in elevated Full mode, and child-process lifetime for `run` transactions. It intentionally rejects reparse points.
It does not capture drivers, network effects, changes outside declared scopes, locked system
files, Minifilter events, or WinRE recovery. An interrupted transaction is marked
`RecoveryRequired`; `recover --assume-exclusive` is available only after the caller has
confirmed no unrelated process wrote into the declared scopes.

The integrity indexes and journal detect corruption and ordinary single-file tampering, but
they are not a full broker identity. The store root is ACL-hardened when possible, and each
transaction seals an `evidence.mac` with a CurrentUser DPAPI-protected HMAC key. This detects
same-user casual snapshot edits, but a process that can fully impersonate the user or rewrite
the DPAPI-protected key material remains inside the current threat boundary; a separate broker
identity and machine-protected key are still required.

## Plan coverage

See [`docs/PLAN_GAP_MATRIX.md`](docs/PLAN_GAP_MATRIX.md) for the full plan-vs-implementation matrix and explicitly blocked kernel/macOS items.
