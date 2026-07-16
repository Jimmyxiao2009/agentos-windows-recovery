namespace AgentOS;

internal sealed class TransactionEngine
{
    private readonly TransactionStore _store;
    private readonly VssShadowCopyProvider _vss;

    public TransactionEngine(TransactionStore store, VssShadowCopyProvider? vss = null)
    {
        _store = store;
        _vss = vss ?? new VssShadowCopyProvider();
    }

    public TransactionManifest Run(
        IReadOnlyList<string> fileScopes,
        IReadOnlyList<string> registryScopes,
        string command,
        IReadOnlyList<string> arguments,
        SuccessAction onSuccess)
        => Run(fileScopes, registryScopes, command, arguments, onSuccess, TransactionPolicy.Critical);

    public TransactionManifest Run(
        IReadOnlyList<string> fileScopes,
        IReadOnlyList<string> registryScopes,
        string command,
        IReadOnlyList<string> arguments,
        SuccessAction onSuccess,
        TransactionPolicy policy)
        => Run(fileScopes, registryScopes, [], [], command, arguments, onSuccess, policy);

    public TransactionManifest Run(
        IReadOnlyList<string> fileScopes,
        IReadOnlyList<string> registryScopes,
        IReadOnlyList<string> serviceScopes,
        IReadOnlyList<string> scheduledTaskScopes,
        string command,
        IReadOnlyList<string> arguments,
        SuccessAction onSuccess,
        TransactionPolicy policy)
    {
        using IDisposable writerLock = _store.AcquireWriterLock();
        EnsureScopes(fileScopes, registryScopes, serviceScopes, scheduledTaskScopes);
        TransactionManifest manifest = new()
        {
            Id = Guid.NewGuid().ToString("N"),
            EvidenceVersion = EvidenceIntegrity.CurrentVersion,
            State = TransactionState.Preparing,
            OwnerProcessId = Environment.ProcessId,
            FileScopes = fileScopes.ToList(),
            RegistryScopes = registryScopes.ToList(),
            Command = command,
            Arguments = arguments.ToList(),
            OnSuccess = onSuccess,
            Mode = policy.Mode,
            ExternalEffectsPermitted = policy.PermitExternalEffects,
            SandboxBox = policy.Mode == TransactionMode.Sandbox ? policy.SandboxBox : null,
            ServiceScopes = serviceScopes.ToList(),
            ScheduledTaskScopes = scheduledTaskScopes.ToList()
        };
        _store.Create(manifest);
        _store.Audit(manifest, "transaction.created", ScopeSummary(manifest, policy.Mode));

        try
        {
            SandboxieAdapter? sandboxie = policy.Mode == TransactionMode.Sandbox
                ? SandboxieAdapter.RequireInstalled()
                : null;
            CaptureBaseline(manifest, policy);
            _store.Audit(manifest, "transaction.active", "root-process-launching");

            manifest.ExitCode = sandboxie is not null
                ? sandboxie.Run(policy.SandboxBox, command, arguments, Environment.CurrentDirectory)
                : WindowsJobRunner.Run(command, arguments, Environment.CurrentDirectory);
            _store.Audit(manifest, "process.exited", $"exitCode={manifest.ExitCode}");
            CaptureAfter(manifest);
            manifest.State = TransactionState.Prepared;
            _store.Save(manifest);
            _store.Audit(manifest, "transaction.prepared", "after-state-persisted");

            if (manifest.ExitCode != 0)
            {
                manifest.Error = $"Root process exited with code {manifest.ExitCode}; automatic rollback requested.";
                return RollbackCore(manifest, force: false);
            }

            return onSuccess switch
            {
                SuccessAction.Commit => CommitCore(manifest),
                SuccessAction.Rollback => RollbackCore(manifest, force: false),
                _ => manifest
            };
        }
        catch (Exception exception)
        {
            manifest.Error = exception.ToString();
            _store.Audit(manifest, "transaction.exception", exception.GetType().Name);
            try
            {
                bool baselineExists = File.Exists(_store.BaselineFilesPath(manifest.Id)) &&
                                      File.Exists(_store.BaselineRegistryPath(manifest.Id));
                if (!baselineExists)
                {
                    foreach (VssSnapshotMetadata snapshot in manifest.VssSnapshots)
                    {
                        try { _vss.Delete(snapshot); } catch { }
                    }
                    manifest.VssSnapshots = [];
                    manifest.State = TransactionState.Failed;
                    _store.Save(manifest);
                    _store.Audit(manifest, "transaction.failed-before-execution", "no baseline was completed");
                    return manifest;
                }

                if (baselineExists)
                {
                    CaptureAfter(manifest);
                    manifest.State = TransactionState.Prepared;
                    _store.Save(manifest);
                    return RollbackCore(manifest, force: false);
                }
            }
            catch (Exception rollbackException)
            {
                manifest.Error += Environment.NewLine + "Rollback failure: " + rollbackException;
            }

            manifest.State = TransactionState.RecoveryRequired;
            _store.Save(manifest);
            _store.Audit(manifest, "transaction.recovery-required", "automatic recovery was inconclusive");
            return manifest;
        }
    }

    public TransactionManifest BeginDetached(
        IReadOnlyList<string> fileScopes,
        IReadOnlyList<string> registryScopes,
        IReadOnlyList<string> serviceScopes,
        IReadOnlyList<string> scheduledTaskScopes,
        string correlationId,
        TransactionPolicy policy)
    {
        using IDisposable writerLock = _store.AcquireWriterLock();
        if (_store.List().Any(transaction => transaction.State is TransactionState.Preparing or TransactionState.Active or TransactionState.RollingBack))
        {
            throw new InvalidOperationException("Another detached or recovering AgentOS transaction is active.");
        }

        EnsureScopes(fileScopes, registryScopes, serviceScopes, scheduledTaskScopes);
        TransactionManifest manifest = new()
        {
            Id = Guid.NewGuid().ToString("N"),
            EvidenceVersion = EvidenceIntegrity.CurrentVersion,
            State = TransactionState.Preparing,
            OwnerProcessId = Environment.ProcessId,
            FileScopes = fileScopes.ToList(),
            RegistryScopes = registryScopes.ToList(),
            ServiceScopes = serviceScopes.ToList(),
            ScheduledTaskScopes = scheduledTaskScopes.ToList(),
            Command = "detached:" + correlationId,
            Arguments = [],
            OnSuccess = SuccessAction.Retain,
            Mode = policy.Mode,
            ExternalEffectsPermitted = policy.PermitExternalEffects,
            SandboxBox = null
        };
        _store.Create(manifest);
        _store.Audit(manifest, "transaction.created", ScopeSummary(manifest, policy.Mode) + ";detached=true");
        try
        {
            CaptureBaseline(manifest, policy);
            _store.Audit(manifest, "transaction.active", "detached-caller-authorized");
            return manifest;
        }
        catch (Exception exception)
        {
            manifest.Error = exception.ToString();
            manifest.State = TransactionState.Failed;
            _store.Save(manifest);
            _store.Audit(manifest, "transaction.failed-before-execution", exception.GetType().Name);
            foreach (VssSnapshotMetadata snapshot in manifest.VssSnapshots)
            {
                try { _vss.Delete(snapshot); } catch { }
            }
            manifest.VssSnapshots = [];
            _store.Save(manifest);
            return manifest;
        }
    }

    public TransactionManifest PrepareDetached(string id, int? exitCode = null)
    {
        using IDisposable writerLock = _store.AcquireWriterLock();
        TransactionManifest manifest = _store.Load(id);
        if (manifest.State != TransactionState.Active || !manifest.Command.StartsWith("detached:", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Transaction {id} is not an active detached transaction.");
        }
        try
        {
            CaptureAfter(manifest);
        }
        catch (Exception exception)
        {
            return MarkEvidenceFailure(manifest, "prepare", exception);
        }
        manifest.ExitCode = exitCode;
        manifest.State = TransactionState.Prepared;
        _store.Save(manifest);
        _store.Audit(manifest, "transaction.prepared", "detached-after-state-persisted");
        return manifest;
    }

    public TransactionManifest Commit(string id)
    {
        using IDisposable writerLock = _store.AcquireWriterLock();
        return CommitCore(_store.Load(id));
    }

    public TransactionManifest Rollback(string id, bool force)
    {
        using IDisposable writerLock = _store.AcquireWriterLock();
        return RollbackCore(_store.Load(id), force);
    }

    public JournalVerificationResult VerifyJournal(string id)
    {
        _store.Load(id);
        return TransactionJournal.Verify(id, _store.JournalPath(id));
    }

    public PurgeResult Purge(string id)
    {
        using IDisposable writerLock = _store.AcquireWriterLock();
        TransactionManifest manifest = _store.Load(id);
        return PurgeCore(manifest);
    }

    public GarbageCollectionResult GarbageCollect(int maxTransactions, TimeSpan maxAge, long maxBytes)
    {
        if (maxTransactions < 1) throw new ArgumentOutOfRangeException(nameof(maxTransactions));
        if (maxAge <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maxAge));
        if (maxBytes < 1) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        using IDisposable writerLock = _store.AcquireWriterLock();
        long bytesBefore = _store.SizeBytes();
        List<string> purged = [];
        List<string> errors = [];
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - maxAge;
        List<TransactionManifest> terminal = _store.List()
            .Where(IsTerminal)
            .OrderByDescending(transaction => transaction.CreatedAt)
            .ToList();

        foreach (TransactionManifest manifest in terminal
                     .Where((transaction, index) => index >= maxTransactions || transaction.CreatedAt < cutoff)
                     .OrderBy(transaction => transaction.CreatedAt))
        {
            TryGarbageCollect(manifest, purged, errors);
        }

        while (_store.SizeBytes() > maxBytes)
        {
            List<TransactionManifest> remaining = _store.List()
                .Where(IsTerminal)
                .OrderBy(transaction => transaction.CreatedAt)
                .ToList();
            if (remaining.Count <= 1) break;
            if (!TryGarbageCollect(remaining[0], purged, errors)) break;
        }

        return new GarbageCollectionResult
        {
            BytesBefore = bytesBefore,
            BytesAfter = _store.SizeBytes(),
            PurgedTransactionIds = purged,
            RetainedTransactionIds = _store.List().Select(transaction => transaction.Id).ToList(),
            Errors = errors
        };
    }

    private PurgeResult PurgeCore(TransactionManifest manifest)
    {
        if (manifest.State is not (TransactionState.RolledBack or TransactionState.Committed))
        {
            throw new InvalidOperationException($"Only committed or rolled-back transactions may be purged; {manifest.Id} is {manifest.State}.");
        }

        int deletedVss = 0;
        foreach (VssSnapshotMetadata snapshot in manifest.VssSnapshots)
        {
            _vss.Delete(snapshot);
            deletedVss++;
        }
        _store.Audit(manifest, "transaction.purged", $"deletedVssSnapshots={deletedVss}");
        Directory.Delete(_store.TransactionDirectory(manifest.Id), recursive: true);
        return new PurgeResult { TransactionId = manifest.Id, Purged = true, DeletedVssSnapshots = deletedVss };
    }

    private bool TryGarbageCollect(TransactionManifest manifest, List<string> purged, List<string> errors)
    {
        try
        {
            PurgeCore(manifest);
            purged.Add(manifest.Id);
            return true;
        }
        catch (Exception exception)
        {
            errors.Add($"{manifest.Id}:{exception.Message}");
            return false;
        }
    }

    private static bool IsTerminal(TransactionManifest transaction) =>
        transaction.State is TransactionState.RolledBack or TransactionState.Committed;

    public TransactionManifest Recover(string id, bool assumeExclusive)
    {
        using IDisposable writerLock = _store.AcquireWriterLock();
        TransactionManifest manifest = _store.Load(id);
        if (manifest.State is not (TransactionState.Active or TransactionState.Preparing or TransactionState.RecoveryRequired))
        {
            throw new InvalidOperationException($"Transaction {id} is {manifest.State}, not an interrupted transaction.");
        }

        if (!assumeExclusive)
        {
            manifest.State = TransactionState.RecoveryRequired;
            manifest.Error = "The user-mode MVP cannot distinguish external writers after its owner crashed. " +
                             "Inspect the scopes, then rerun recover with --assume-exclusive if no external writer touched them.";
            _store.Save(manifest);
            _store.Audit(manifest, "transaction.recovery-required", "interrupted transaction needs exclusive recovery confirmation");
            return manifest;
        }

        try
        {
            CaptureAfter(manifest);
        }
        catch (Exception exception)
        {
            return MarkEvidenceFailure(manifest, "recovery prepare", exception);
        }
        manifest.State = TransactionState.Prepared;
        _store.Save(manifest);
        return RollbackCore(manifest, force: true);
    }

    public VerificationResult Verify(string id)
    {
        TransactionManifest manifest = _store.Load(id);
        bool expectBaseline = manifest.State == TransactionState.RolledBack;
        bool expectAfter = manifest.State is TransactionState.Prepared or TransactionState.Committed;
        if (!expectBaseline && !expectAfter)
        {
            return new VerificationResult
            {
                TransactionId = id,
                State = manifest.State,
                MatchesExpectedState = false,
                Differences = [$"State {manifest.State} has no stable verification target."]
            };
        }

        EvidenceBundle evidence = LoadEvidence(manifest, requireAfter: true);
        FileSnapshot expectedFiles = expectBaseline ? evidence.BaselineFiles : evidence.AfterFiles!;
        RegistrySnapshot expectedRegistry = expectBaseline ? evidence.BaselineRegistry : evidence.AfterRegistry!;
        ServiceSnapshot expectedServices = expectBaseline ? evidence.BaselineServices : evidence.AfterServices!;
        ScheduledTaskSnapshot expectedTasks = expectBaseline ? evidence.BaselineTasks : evidence.AfterTasks!;
        FileSnapshot actualFiles = FileSnapshotEngine.Capture(expectedFiles.Scopes, blobDirectory: null);
        RegistrySnapshot actualRegistry = RegistrySnapshotEngine.Capture(expectedRegistry.Scopes.Select(scope => scope.Scope));
        ServiceSnapshot actualServices = WindowsServiceSnapshotEngine.Capture(manifest.ServiceScopes);
        ScheduledTaskSnapshot actualTasks = ScheduledTaskSnapshotEngine.Capture(manifest.ScheduledTaskScopes);
        List<string> differences = FileSnapshotEngine.Compare(expectedFiles, actualFiles);
        differences.AddRange(RegistrySnapshotEngine.Compare(expectedRegistry, actualRegistry));
        differences.AddRange(WindowsServiceSnapshotEngine.Compare(expectedServices, actualServices));
        differences.AddRange(ScheduledTaskSnapshotEngine.Compare(expectedTasks, actualTasks));
        return new VerificationResult
        {
            TransactionId = id,
            State = manifest.State,
            MatchesExpectedState = differences.Count == 0,
            Differences = differences
        };
    }

    public StoreScrubResult ScrubStore()
    {
        List<TransactionScrubResult> transactions = [];
        foreach (TransactionManifest manifest in _store.List())
        {
            transactions.Add(ScrubTransaction(manifest));
        }

        List<string> damagedDirectories = _store.ListDamagedDirectories().ToList();
        int issueCount = transactions.Count(result => !result.Healthy) + damagedDirectories.Count;
        return new StoreScrubResult
        {
            StoreRoot = _store.Root,
            TransactionCount = transactions.Count,
            HealthyCount = transactions.Count(result => result.Healthy),
            IssueCount = issueCount,
            DamagedDirectoryCount = damagedDirectories.Count,
            Transactions = transactions,
            DamagedDirectories = damagedDirectories
        };
    }

    private TransactionScrubResult ScrubTransaction(TransactionManifest manifest)
    {
        List<string> issues = [];
        try
        {
            bool requireAfter = manifest.State is
                TransactionState.Prepared or
                TransactionState.Committed or
                TransactionState.Conflicted or
                TransactionState.RollingBack or
                TransactionState.RolledBack or
                TransactionState.RecoveryRequired;
            bool hasAfterFiles = File.Exists(_store.AfterFilesPath(manifest.Id));
            EvidenceBundle evidence = LoadEvidence(manifest, requireAfter: requireAfter && hasAfterFiles);
            // Only baseline blobs are durable recovery sources. After-state snapshots record
            // hashes for conflict detection, but do not require content-addressed blobs.
            issues.AddRange(ValidateRecoveryBlobs(manifest, evidence.BaselineFiles, "baseline"));
            if (requireAfter && !hasAfterFiles)
            {
                issues.Add("after-state evidence is missing for a prepared/terminal transaction.");
            }
        }
        catch (Exception exception)
        {
            issues.Add(exception.Message);
        }

        return new TransactionScrubResult
        {
            TransactionId = manifest.Id,
            State = manifest.State,
            Healthy = issues.Count == 0,
            Issues = issues
        };
    }

    private List<string> ValidateRecoveryBlobs(TransactionManifest manifest, FileSnapshot snapshot, string phase)
    {
        List<string> issues = [];
        string blobDirectory = _store.BlobDirectory(manifest.Id);
        foreach (FileEntry entry in snapshot.Entries.Where(entry =>
                     entry.Kind == FileEntryKind.File &&
                     !string.IsNullOrWhiteSpace(entry.Sha256)))
        {
            try
            {
                FileSnapshotEngine.ValidateBlob(blobDirectory, entry.Sha256!, entry.Length, $"{phase}:{entry.RelativePath}");
            }
            catch (Exception exception)
            {
                issues.Add(exception.Message);
            }
        }

        return issues;
    }

    private TransactionManifest CommitCore(TransactionManifest manifest)
    {
        if (manifest.State is not (TransactionState.Prepared or TransactionState.Conflicted))
        {
            throw new InvalidOperationException($"Transaction {manifest.Id} cannot be committed from {manifest.State}.");
        }

        VerificationResult verification;
        try
        {
            verification = VerifyPrepared(manifest, LoadEvidence(manifest, requireAfter: true));
        }
        catch (Exception exception)
        {
            return MarkEvidenceFailure(manifest, "commit", exception);
        }
        if (!verification.MatchesExpectedState)
        {
            manifest.State = TransactionState.Conflicted;
            manifest.Conflicts = verification.Differences;
            manifest.Error = "Current state drifted after the transaction; commit requires resolving the conflict.";
            _store.Save(manifest);
            _store.Audit(manifest, "commit.conflicted", string.Join('|', verification.Differences));
            return manifest;
        }

        manifest.State = TransactionState.Committed;
        manifest.Conflicts = [];
        _store.Save(manifest);
        _store.Audit(manifest, "transaction.committed", "commit accepted after verification");
        return manifest;
    }

    private TransactionManifest RollbackCore(TransactionManifest manifest, bool force)
    {
        if (manifest.State is not (TransactionState.Prepared or TransactionState.Committed or TransactionState.Conflicted))
        {
            throw new InvalidOperationException($"Transaction {manifest.Id} cannot be rolled back from {manifest.State}.");
        }

        EvidenceBundle evidence;
        FileSnapshotEngine.RestorePlan restorePlan;
        try
        {
            evidence = LoadEvidence(manifest, requireAfter: true);
            restorePlan = FileSnapshotEngine.PrepareRestore(
                evidence.BaselineFiles,
                evidence.AfterFiles!,
                _store.BlobDirectory(manifest.Id),
                manifest.VssSnapshots);
        }
        catch (Exception exception)
        {
            return MarkEvidenceFailure(manifest, "rollback preflight", exception);
        }

        using (restorePlan)
        {
            return ApplyRollback(manifest, force, evidence, restorePlan);
        }
    }

    private TransactionManifest ApplyRollback(
        TransactionManifest manifest,
        bool force,
        EvidenceBundle evidence,
        FileSnapshotEngine.RestorePlan restorePlan)
    {
        FileSnapshot baselineFiles = evidence.BaselineFiles;
        FileSnapshot afterFiles = evidence.AfterFiles!;
        RegistrySnapshot baselineRegistry = evidence.BaselineRegistry;
        RegistrySnapshot afterRegistry = evidence.AfterRegistry!;
        ServiceSnapshot baselineServices = evidence.BaselineServices;
        ServiceSnapshot afterServices = evidence.AfterServices!;
        ScheduledTaskSnapshot baselineTasks = evidence.BaselineTasks;
        ScheduledTaskSnapshot afterTasks = evidence.AfterTasks!;
        FileSnapshot currentFiles = FileSnapshotEngine.Capture(afterFiles.Scopes, blobDirectory: null);
        RegistrySnapshot currentRegistry = RegistrySnapshotEngine.Capture(afterRegistry.Scopes.Select(scope => scope.Scope));
        ServiceSnapshot currentServices = WindowsServiceSnapshotEngine.Capture(manifest.ServiceScopes);
        ScheduledTaskSnapshot currentTasks = ScheduledTaskSnapshotEngine.Capture(manifest.ScheduledTaskScopes);

        List<string> conflicts = FileSnapshotEngine.FindRollbackConflicts(baselineFiles, afterFiles, currentFiles);
        conflicts.AddRange(RegistrySnapshotEngine.FindRollbackConflicts(baselineRegistry, afterRegistry, currentRegistry));
        conflicts.AddRange(WindowsServiceSnapshotEngine.FindRollbackConflicts(baselineServices, afterServices, currentServices));
        conflicts.AddRange(ScheduledTaskSnapshotEngine.FindRollbackConflicts(baselineTasks, afterTasks, currentTasks));
        if (conflicts.Count > 0 && !force)
        {
            manifest.State = TransactionState.Conflicted;
            manifest.Conflicts = conflicts;
            manifest.Error = "Rollback was not started because current state contains later changes.";
            _store.Save(manifest);
            _store.Audit(manifest, "rollback.conflicted", string.Join('|', conflicts));
            return manifest;
        }

        manifest.State = TransactionState.RollingBack;
        manifest.Conflicts = conflicts;
        _store.Save(manifest);
        _store.Audit(manifest, "rollback.started", force ? "force=true" : "force=false");
        try
        {
            // Registry is restored first so file cleanup cannot remove data needed by a registry provider.
            RegistrySnapshotEngine.Restore(baselineRegistry, afterRegistry);
            restorePlan.Apply();
            ScheduledTaskSnapshotEngine.Restore(baselineTasks, afterTasks);
            WindowsServiceSnapshotEngine.Restore(baselineServices, afterServices);
            manifest.State = TransactionState.RolledBack;
            manifest.Error = force && conflicts.Count > 0
                ? $"Forced rollback completed after overriding {conflicts.Count} conflict(s)."
                : manifest.Error;
            _store.Save(manifest);
            _store.Audit(manifest, "rollback.completed", force && conflicts.Count > 0 ? "forced" : "clean");

            VerificationResult verification = Verify(manifest.Id);
            if (!verification.MatchesExpectedState)
            {
                manifest.State = TransactionState.RecoveryRequired;
                manifest.Conflicts = verification.Differences;
                manifest.Error = "Rollback ran but post-restore verification failed: " + string.Join("; ", verification.Differences);
                _store.Save(manifest);
                _store.Audit(manifest, "rollback.verification-failed", string.Join('|', verification.Differences));
            }
            return manifest;
        }
        catch (Exception exception)
        {
            manifest.State = TransactionState.RecoveryRequired;
            manifest.Error = "Rollback failed: " + exception;
            _store.Save(manifest);
            _store.Audit(manifest, "rollback.failed", exception.GetType().Name);
            return manifest;
        }
    }

    private VerificationResult VerifyPrepared(TransactionManifest manifest, EvidenceBundle evidence)
    {
        FileSnapshot expectedFiles = evidence.AfterFiles!;
        RegistrySnapshot expectedRegistry = evidence.AfterRegistry!;
        ServiceSnapshot expectedServices = evidence.AfterServices!;
        ScheduledTaskSnapshot expectedTasks = evidence.AfterTasks!;
        FileSnapshot actualFiles = FileSnapshotEngine.Capture(expectedFiles.Scopes, blobDirectory: null);
        RegistrySnapshot actualRegistry = RegistrySnapshotEngine.Capture(expectedRegistry.Scopes.Select(scope => scope.Scope));
        ServiceSnapshot actualServices = WindowsServiceSnapshotEngine.Capture(manifest.ServiceScopes);
        ScheduledTaskSnapshot actualTasks = ScheduledTaskSnapshotEngine.Capture(manifest.ScheduledTaskScopes);
        List<string> differences = FileSnapshotEngine.Compare(expectedFiles, actualFiles);
        differences.AddRange(RegistrySnapshotEngine.Compare(expectedRegistry, actualRegistry));
        differences.AddRange(WindowsServiceSnapshotEngine.Compare(expectedServices, actualServices));
        differences.AddRange(ScheduledTaskSnapshotEngine.Compare(expectedTasks, actualTasks));
        return new VerificationResult
        {
            TransactionId = manifest.Id,
            State = manifest.State,
            MatchesExpectedState = differences.Count == 0,
            Differences = differences
        };
    }

    private void CaptureAfter(TransactionManifest manifest)
    {
        EvidenceBundle baseline = LoadEvidence(manifest, requireAfter: false);
        FileSnapshot afterFiles = FileSnapshotEngine.Capture(baseline.BaselineFiles.Scopes, blobDirectory: null);
        RegistrySnapshot afterRegistry = RegistrySnapshotEngine.Capture(
            baseline.BaselineRegistry.Scopes.Select(scope => scope.Scope));
        ServiceSnapshot afterServices = WindowsServiceSnapshotEngine.Capture(manifest.ServiceScopes);
        ScheduledTaskSnapshot afterTasks = ScheduledTaskSnapshotEngine.Capture(manifest.ScheduledTaskScopes);
        ValidateSnapshotSet(manifest, afterFiles, afterRegistry, afterServices, afterTasks);
        JsonSupport.WriteAtomic(_store.AfterFilesPath(manifest.Id), afterFiles);
        JsonSupport.WriteAtomic(_store.AfterRegistryPath(manifest.Id), afterRegistry);
        JsonSupport.WriteAtomic(_store.AfterServicesPath(manifest.Id), afterServices);
        JsonSupport.WriteAtomic(_store.AfterScheduledTasksPath(manifest.Id), afterTasks);
        if (manifest.EvidenceVersion >= EvidenceIntegrity.CurrentVersion)
        {
            string indexHash = EvidenceIntegrity.WriteIndex(
                _store.AfterEvidenceIndexPath(manifest.Id),
                manifest.Id,
                "after",
                AfterEvidenceFiles(manifest.Id));
            _store.Audit(manifest, "evidence.after.persisted", indexHash);
        }
        WriteEvidenceMac(manifest);
    }

    private void CaptureBaseline(TransactionManifest manifest, TransactionPolicy policy)
    {
        if (policy.RequireVssBaseline)
        {
            manifest.VssSnapshots = _vss.CreateForScopes(manifest.FileScopes).ToList();
            _store.Save(manifest);
            _store.Audit(manifest, "vss.baseline.created", string.Join(';', manifest.VssSnapshots.Select(snapshot => snapshot.Id)));
        }
        FileSnapshot baselineFiles = FileSnapshotEngine.Capture(manifest.FileScopes, _store.BlobDirectory(manifest.Id));
        RegistrySnapshot baselineRegistry = RegistrySnapshotEngine.Capture(manifest.RegistryScopes);
        ServiceSnapshot baselineServices = WindowsServiceSnapshotEngine.Capture(manifest.ServiceScopes);
        ScheduledTaskSnapshot baselineTasks = ScheduledTaskSnapshotEngine.Capture(manifest.ScheduledTaskScopes);
        ValidateSnapshotSet(manifest, baselineFiles, baselineRegistry, baselineServices, baselineTasks);
        JsonSupport.WriteAtomic(_store.BaselineFilesPath(manifest.Id), baselineFiles);
        JsonSupport.WriteAtomic(_store.BaselineRegistryPath(manifest.Id), baselineRegistry);
        JsonSupport.WriteAtomic(_store.BaselineServicesPath(manifest.Id), baselineServices);
        JsonSupport.WriteAtomic(_store.BaselineScheduledTasksPath(manifest.Id), baselineTasks);
        if (manifest.EvidenceVersion >= EvidenceIntegrity.CurrentVersion)
        {
            string indexHash = EvidenceIntegrity.WriteIndex(
                _store.BaselineEvidenceIndexPath(manifest.Id),
                manifest.Id,
                "baseline",
                BaselineEvidenceFiles(manifest.Id));
            _store.Audit(manifest, "evidence.baseline.persisted", indexHash);
        }
        WriteEvidenceMac(manifest);
        _store.Audit(manifest, "baseline.persisted",
            $"files={baselineFiles.Entries.Count};registryScopes={baselineRegistry.Scopes.Count};services={baselineServices.Entries.Count};scheduledTasks={baselineTasks.Entries.Count}");
        manifest.State = TransactionState.Active;
        _store.Save(manifest);
    }

    private ServiceSnapshot ReadServices(TransactionManifest manifest, bool baseline)
    {
        string path = baseline ? _store.BaselineServicesPath(manifest.Id) : _store.AfterServicesPath(manifest.Id);
        return File.Exists(path) ? JsonSupport.Read<ServiceSnapshot>(path) : new ServiceSnapshot { Entries = [] };
    }

    private ScheduledTaskSnapshot ReadScheduledTasks(TransactionManifest manifest, bool baseline)
    {
        string path = baseline ? _store.BaselineScheduledTasksPath(manifest.Id) : _store.AfterScheduledTasksPath(manifest.Id);
        return File.Exists(path) ? JsonSupport.Read<ScheduledTaskSnapshot>(path) : new ScheduledTaskSnapshot { Entries = [] };
    }

    private EvidenceBundle LoadEvidence(TransactionManifest manifest, bool requireAfter)
    {
        JournalVerificationResult journal = TransactionJournal.Verify(manifest.Id, _store.JournalPath(manifest.Id));
        if (!journal.IsValid)
        {
            throw new InvalidDataException("Transaction journal integrity validation failed: " + journal.Error);
        }

        FileSnapshot baselineFiles = JsonSupport.Read<FileSnapshot>(_store.BaselineFilesPath(manifest.Id));
        RegistrySnapshot baselineRegistry = JsonSupport.Read<RegistrySnapshot>(_store.BaselineRegistryPath(manifest.Id));
        ServiceSnapshot baselineServices = ReadServices(manifest, baseline: true);
        ScheduledTaskSnapshot baselineTasks = ReadScheduledTasks(manifest, baseline: true);
        ValidateSnapshotSet(manifest, baselineFiles, baselineRegistry, baselineServices, baselineTasks);
        ValidateIndexAnchor(manifest, "baseline", _store.BaselineEvidenceIndexPath(manifest.Id), BaselineEvidenceFiles(manifest.Id));
        if (!requireAfter)
        {
            ValidateEvidenceMac(manifest);
            return new EvidenceBundle(
                baselineFiles, baselineRegistry, baselineServices, baselineTasks,
                null, null, null, null);
        }

        FileSnapshot afterFiles = JsonSupport.Read<FileSnapshot>(_store.AfterFilesPath(manifest.Id));
        RegistrySnapshot afterRegistry = JsonSupport.Read<RegistrySnapshot>(_store.AfterRegistryPath(manifest.Id));
        ServiceSnapshot afterServices = ReadServices(manifest, baseline: false);
        ScheduledTaskSnapshot afterTasks = ReadScheduledTasks(manifest, baseline: false);
        ValidateSnapshotSet(manifest, afterFiles, afterRegistry, afterServices, afterTasks);
        ValidateIndexAnchor(manifest, "after", _store.AfterEvidenceIndexPath(manifest.Id), AfterEvidenceFiles(manifest.Id));
        ValidateEvidenceMac(manifest);
        return new EvidenceBundle(
            baselineFiles, baselineRegistry, baselineServices, baselineTasks,
            afterFiles, afterRegistry, afterServices, afterTasks);
    }

    private void ValidateIndexAnchor(
        TransactionManifest manifest,
        string phase,
        string indexPath,
        IEnumerable<string> evidenceFiles)
    {
        if (manifest.EvidenceVersion < EvidenceIntegrity.CurrentVersion)
        {
            return;
        }

        string indexHash = EvidenceIntegrity.ValidateIndex(indexPath, manifest.Id, phase, evidenceFiles);
        if (!TransactionJournal.ContainsEvidenceAnchor(
                _store.JournalPath(manifest.Id),
                $"evidence.{phase}.persisted",
                indexHash))
        {
            throw new InvalidDataException($"The {phase} evidence index is not anchored in the transaction journal.");
        }
    }

    private static void ValidateSnapshotSet(
        TransactionManifest manifest,
        FileSnapshot files,
        RegistrySnapshot registry,
        ServiceSnapshot services,
        ScheduledTaskSnapshot tasks)
    {
        FileSnapshotEngine.Validate(files, manifest.FileScopes);
        RegistrySnapshotEngine.Validate(registry, manifest.RegistryScopes);
        WindowsServiceSnapshotEngine.Validate(services, manifest.ServiceScopes);
        ScheduledTaskSnapshotEngine.Validate(tasks, manifest.ScheduledTaskScopes);
    }

    private IEnumerable<string> BaselineEvidenceFiles(string id)
    {
        yield return _store.BaselineFilesPath(id);
        yield return _store.BaselineRegistryPath(id);
        yield return _store.BaselineServicesPath(id);
        yield return _store.BaselineScheduledTasksPath(id);
    }

    private IEnumerable<string> AfterEvidenceFiles(string id)
    {
        yield return _store.AfterFilesPath(id);
        yield return _store.AfterRegistryPath(id);
        yield return _store.AfterServicesPath(id);
        yield return _store.AfterScheduledTasksPath(id);
    }

    private IEnumerable<string> EvidenceMacFiles(string id)
    {
        // Manifest is intentionally excluded: state transitions rewrite it after evidence is sealed.
        foreach (string path in BaselineEvidenceFiles(id).Concat(AfterEvidenceFiles(id)))
        {
            yield return path;
        }
        yield return _store.BaselineEvidenceIndexPath(id);
        yield return _store.AfterEvidenceIndexPath(id);
    }


    private void WriteEvidenceMac(TransactionManifest manifest)
    {
        List<string> files = EvidenceMacFiles(manifest.Id).ToList();
        StoreProtection.WriteEvidenceMac(_store.TransactionDirectory(manifest.Id), files);
        // Audit after MAC write so journal appends do not invalidate the evidence MAC.
        _store.Audit(manifest, "evidence.mac.persisted", StoreProtection.MacFileName);
    }

    private void ValidateEvidenceMac(TransactionManifest manifest)
    {
        StoreProtection.ValidateEvidenceMac(_store.TransactionDirectory(manifest.Id), EvidenceMacFiles(manifest.Id));
    }

    private TransactionManifest MarkEvidenceFailure(TransactionManifest manifest, string operation, Exception exception)
    {
        manifest.State = TransactionState.RecoveryRequired;
        manifest.Error = $"{operation} was not started because persistent recovery evidence failed validation: {exception.Message}";
        _store.Save(manifest);
        try
        {
            if (TransactionJournal.Verify(manifest.Id, _store.JournalPath(manifest.Id)).IsValid)
            {
                _store.Audit(manifest, "evidence.validation-failed", operation + ":" + exception.GetType().Name);
            }
        }
        catch
        {
            // Preserve the damaged journal unchanged when even appending an audit record is unsafe.
        }
        return manifest;
    }

    private sealed record EvidenceBundle(
        FileSnapshot BaselineFiles,
        RegistrySnapshot BaselineRegistry,
        ServiceSnapshot BaselineServices,
        ScheduledTaskSnapshot BaselineTasks,
        FileSnapshot? AfterFiles,
        RegistrySnapshot? AfterRegistry,
        ServiceSnapshot? AfterServices,
        ScheduledTaskSnapshot? AfterTasks);

    private static void EnsureScopes(
        IReadOnlyCollection<string> fileScopes,
        IReadOnlyCollection<string> registryScopes,
        IReadOnlyCollection<string> serviceScopes,
        IReadOnlyCollection<string> scheduledTaskScopes)
    {
        if (fileScopes.Count + registryScopes.Count + serviceScopes.Count + scheduledTaskScopes.Count == 0)
        {
            throw new ArgumentException("At least one file, registry, service, or scheduled-task scope is required.");
        }
    }

    private static string ScopeSummary(TransactionManifest manifest, TransactionMode mode) =>
        $"mode={mode};fileScopes={manifest.FileScopes.Count};registryScopes={manifest.RegistryScopes.Count};services={manifest.ServiceScopes.Count};scheduledTasks={manifest.ScheduledTaskScopes.Count}";
}
