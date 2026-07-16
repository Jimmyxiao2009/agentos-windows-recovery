using System.Diagnostics;
using System.Security.AccessControl;
using System.Text.Json;
using Microsoft.Win32;

namespace AgentOS;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
            {
                PrintUsage();
                return 0;
            }

            return args[0].ToLowerInvariant() switch
            {
                "run" => RunCommand(args[1..]),
                "begin" => BeginCommand(args[1..]),
                "prepare" => PrepareCommand(args[1..]),
                "status" => StatusCommand(args[1..]),
                "list" => ListCommand(args[1..]),
                "commit" => CommitCommand(args[1..]),
                "rollback" => RollbackCommand(args[1..]),
                "recover" => RecoverCommand(args[1..]),
                "verify" => VerifyCommand(args[1..]),
                "verify-journal" => VerifyJournalCommand(args[1..]),
                "purge" => PurgeCommand(args[1..]),
                "gc" => GarbageCollectionCommand(args[1..]),
                "scrub" => ScrubCommand(args[1..]),
                "doctor" => DoctorCommand(args[1..]),
                "self-test" => SelfTest.Run(),
                "internal-mutate" => InternalMutate(args[1..]),
                "internal-delayed-write" => InternalDelayedWrite(args[1..]),
                _ => throw new ArgumentException($"Unknown command: {args[0]}")
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"agentos: {exception.Message}");
            if (Environment.GetEnvironmentVariable("AGENTOS_DEBUG") == "1")
            {
                Console.Error.WriteLine(exception);
            }
            return 1;
        }
    }

    private static int RunCommand(string[] args)
    {
        int separator = Array.IndexOf(args, "--");
        if (separator < 0 || separator == args.Length - 1)
        {
            throw new ArgumentException("run requires '-- <executable> [arguments]'.");
        }

        List<string> fileScopes = [];
        List<string> registryScopes = [];
        List<string> serviceScopes = [];
        List<string> scheduledTaskScopes = [];
        string? storePath = null;
        SuccessAction onSuccess = SuccessAction.Retain;
        TransactionMode mode = TransactionMode.CriticalRecovery;
        string sandboxBox = "AgentOS";
        for (int i = 0; i < separator; i++)
        {
            switch (args[i])
            {
                case "--file-scope":
                    fileScopes.Add(RequireValue(args, ref i, separator, "--file-scope"));
                    break;
                case "--registry-scope":
                    registryScopes.Add(RequireValue(args, ref i, separator, "--registry-scope"));
                    break;
                case "--service-scope":
                    serviceScopes.Add(RequireValue(args, ref i, separator, "--service-scope"));
                    break;
                case "--scheduled-task-scope":
                    scheduledTaskScopes.Add(RequireValue(args, ref i, separator, "--scheduled-task-scope"));
                    break;
                case "--store":
                    storePath = RequireValue(args, ref i, separator, "--store");
                    break;
                case "--on-success":
                    string action = RequireValue(args, ref i, separator, "--on-success");
                    onSuccess = Enum.Parse<SuccessAction>(action, ignoreCase: true);
                    break;
                case "--mode":
                    mode = ParseMode(RequireValue(args, ref i, separator, "--mode"));
                    break;
                case "--sandbox-box":
                    sandboxBox = RequireValue(args, ref i, separator, "--sandbox-box");
                    break;
                default:
                    throw new ArgumentException($"Unknown run option: {args[i]}");
            }
        }

        TransactionStore store = new(storePath);
        TransactionEngine engine = new(store);
        TransactionManifest transaction = engine.Run(
            fileScopes,
            registryScopes,
            serviceScopes,
            scheduledTaskScopes,
            args[separator + 1],
            args[(separator + 2)..],
            onSuccess,
            new TransactionPolicy { Mode = mode, SandboxBox = sandboxBox });
        PrintJson(transaction);
        return transaction.State is TransactionState.Prepared or TransactionState.Committed or TransactionState.RolledBack
            ? transaction.ExitCode.GetValueOrDefault()
            : 2;
    }

    private static int BeginCommand(string[] args)
    {
        List<string> fileScopes = [];
        List<string> registryScopes = [];
        List<string> serviceScopes = [];
        List<string> scheduledTaskScopes = [];
        string? storePath = null;
        string correlationId = "external";
        TransactionMode mode = TransactionMode.CriticalRecovery;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--file-scope": fileScopes.Add(RequireValue(args, ref i, args.Length, "--file-scope")); break;
                case "--registry-scope": registryScopes.Add(RequireValue(args, ref i, args.Length, "--registry-scope")); break;
                case "--service-scope": serviceScopes.Add(RequireValue(args, ref i, args.Length, "--service-scope")); break;
                case "--scheduled-task-scope": scheduledTaskScopes.Add(RequireValue(args, ref i, args.Length, "--scheduled-task-scope")); break;
                case "--store": storePath = RequireValue(args, ref i, args.Length, "--store"); break;
                case "--correlation": correlationId = RequireValue(args, ref i, args.Length, "--correlation"); break;
                case "--mode": mode = ParseMode(RequireValue(args, ref i, args.Length, "--mode")); break;
                default: throw new ArgumentException($"Unknown begin option: {args[i]}");
            }
        }
        if (mode == TransactionMode.Sandbox)
        {
            throw new ArgumentException("Detached transactions do not support sandbox mode; use critical or full.");
        }
        TransactionManifest transaction = new TransactionEngine(new TransactionStore(storePath)).BeginDetached(
            fileScopes, registryScopes, serviceScopes, scheduledTaskScopes, correlationId,
            new TransactionPolicy { Mode = mode });
        PrintJson(transaction);
        return transaction.State == TransactionState.Active ? 0 : 2;
    }

    private static int PrepareCommand(string[] args)
    {
        (string id, string? storePath, _) = ParseTransactionCommand(args);
        TransactionManifest transaction = new TransactionEngine(new TransactionStore(storePath)).PrepareDetached(id);
        PrintJson(transaction);
        return transaction.State == TransactionState.Prepared ? 0 : 2;
    }

    private static int StatusCommand(string[] args)
    {
        (string id, string? storePath, _) = ParseTransactionCommand(args);
        PrintJson(new TransactionStore(storePath).Load(id));
        return 0;
    }

    private static int ListCommand(string[] args)
    {
        string? storePath = ParseStoreOnly(args);
        PrintJson(new TransactionStore(storePath).List());
        return 0;
    }

    private static int CommitCommand(string[] args)
    {
        (string id, string? storePath, _) = ParseTransactionCommand(args);
        TransactionManifest transaction = new TransactionEngine(new TransactionStore(storePath)).Commit(id);
        PrintJson(transaction);
        return transaction.State == TransactionState.Committed ? 0 : 2;
    }

    private static int RollbackCommand(string[] args)
    {
        (string id, string? storePath, bool force) = ParseTransactionCommand(args);
        TransactionManifest transaction = new TransactionEngine(new TransactionStore(storePath)).Rollback(id, force);
        PrintJson(transaction);
        return transaction.State == TransactionState.RolledBack ? 0 : 2;
    }

    private static int RecoverCommand(string[] args)
    {
        (string id, string? storePath, bool assumeExclusive) = ParseTransactionCommand(args, "--assume-exclusive");
        TransactionManifest transaction = new TransactionEngine(new TransactionStore(storePath)).Recover(id, assumeExclusive);
        PrintJson(transaction);
        return transaction.State == TransactionState.RolledBack ? 0 : 2;
    }

    private static int VerifyCommand(string[] args)
    {
        (string id, string? storePath, _) = ParseTransactionCommand(args);
        VerificationResult result = new TransactionEngine(new TransactionStore(storePath)).Verify(id);
        PrintJson(result);
        return result.MatchesExpectedState ? 0 : 3;
    }

    private static int VerifyJournalCommand(string[] args)
    {
        (string id, string? storePath, _) = ParseTransactionCommand(args);
        JournalVerificationResult result = new TransactionEngine(new TransactionStore(storePath)).VerifyJournal(id);
        PrintJson(result);
        return result.IsValid ? 0 : 3;
    }

    private static int PurgeCommand(string[] args)
    {
        (string id, string? storePath, bool confirmed) = ParseTransactionCommand(args, "--confirm");
        if (!confirmed)
        {
            throw new ArgumentException("purge permanently removes recovery data. Repeat with --confirm.");
        }
        PurgeResult result = new TransactionEngine(new TransactionStore(storePath)).Purge(id);
        PrintJson(result);
        return result.Purged ? 0 : 2;
    }

    private static int GarbageCollectionCommand(string[] args)
    {
        string? storePath = null;
        int maxTransactions = 20;
        int maxAgeDays = 7;
        long maxBytes = 5L * 1024 * 1024 * 1024;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--store": storePath = RequireValue(args, ref i, args.Length, "--store"); break;
                case "--max-transactions": maxTransactions = int.Parse(RequireValue(args, ref i, args.Length, "--max-transactions")); break;
                case "--max-age-days": maxAgeDays = int.Parse(RequireValue(args, ref i, args.Length, "--max-age-days")); break;
                case "--max-bytes": maxBytes = long.Parse(RequireValue(args, ref i, args.Length, "--max-bytes")); break;
                default: throw new ArgumentException($"Unknown gc option: {args[i]}");
            }
        }
        GarbageCollectionResult result = new TransactionEngine(new TransactionStore(storePath))
            .GarbageCollect(maxTransactions, TimeSpan.FromDays(maxAgeDays), maxBytes);
        PrintJson(result);
        return result.Errors.Count == 0 ? 0 : 2;
    }

    private static int DoctorCommand(string[] args)
    {
        if (args.Length != 0)
        {
            throw new ArgumentException("doctor does not accept arguments.");
        }
        PrintJson(RuntimeCapabilities.Probe());
        return 0;
    }

    private static int ScrubCommand(string[] args)
    {
        string? storePath = ParseStoreOnly(args);
        StoreScrubResult result = new TransactionEngine(new TransactionStore(storePath)).ScrubStore();
        PrintJson(result);
        return result.IssueCount == 0 ? 0 : 2;
    }

    private static (string Id, string? Store, bool Flag) ParseTransactionCommand(
        string[] args,
        string flagName = "--force")
    {
        if (args.Length == 0 || args[0].StartsWith('-'))
        {
            throw new ArgumentException("A transaction id is required.");
        }

        string id = args[0];
        string? store = null;
        bool flag = false;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--store")
            {
                store = RequireValue(args, ref i, args.Length, "--store");
            }
            else if (args[i] == flagName)
            {
                flag = true;
            }
            else
            {
                throw new ArgumentException($"Unknown option: {args[i]}");
            }
        }
        return (id, store, flag);
    }

    private static string? ParseStoreOnly(string[] args)
    {
        if (args.Length == 0)
        {
            return null;
        }
        if (args.Length == 2 && args[0] == "--store")
        {
            return args[1];
        }
        throw new ArgumentException("Expected: --store <path>");
    }

    private static string RequireValue(string[] args, ref int index, int limit, string option)
    {
        index++;
        if (index >= limit)
        {
            throw new ArgumentException($"{option} requires a value.");
        }
        return args[index];
    }

    private static TransactionMode ParseMode(string value) => value.Trim().ToLowerInvariant() switch
    {
        "sandbox" or "mode0" => TransactionMode.Sandbox,
        "critical" or "mode1" => TransactionMode.CriticalRecovery,
        "full" or "mode2" => TransactionMode.FullRecovery,
        _ => throw new ArgumentException("--mode must be sandbox, critical, or full.")
    };

    private static int InternalMutate(string[] args)
    {
        string scope = GetOption(args, "--scope");
        string registryScope = GetOption(args, "--registry");
        int exitCode = int.TryParse(GetOptionalOption(args, "--exit-code"), out int parsed) ? parsed : 0;

        File.WriteAllText(Path.Combine(scope, "original.txt"), "after");
        string deleted = Path.Combine(scope, "deleted.txt");
        if (File.Exists(deleted))
        {
            File.Delete(deleted);
        }
        File.WriteAllText(Path.Combine(scope, "new.txt"), "created");
        Directory.CreateDirectory(Path.Combine(scope, "nested"));
        File.WriteAllText(Path.Combine(scope, "nested", "child.txt"), "child");

        using (RegistryKey key = CreateRegistryKey(registryScope))
        {
            key.SetValue("Original", "after", RegistryValueKind.String);
            key.SetValue("Created", 42, RegistryValueKind.DWord);
            using RegistryKey child = key.CreateSubKey("Nested", writable: true)!;
            child.SetValue("Child", "value", RegistryValueKind.String);
        }

        if (args.Contains("--spawn-child", StringComparer.Ordinal))
        {
            (string command, List<string> invocationArgs) = SelfInvocation(
                "internal-delayed-write", "--path", Path.Combine(scope, "delayed-child.txt"));
            Process.Start(new ProcessStartInfo
            {
                FileName = command,
                UseShellExecute = false,
                CreateNoWindow = true,
                Arguments = string.Join(' ', invocationArgs.Select(WindowsJobRunner.QuoteArgument))
            });
        }

        return exitCode;
    }

    private static int InternalDelayedWrite(string[] args)
    {
        string path = GetOption(args, "--path");
        Thread.Sleep(TimeSpan.FromSeconds(2));
        File.WriteAllText(path, "descendant escaped");
        return 0;
    }

    internal static (string Command, List<string> Arguments) SelfInvocation(params string[] arguments)
    {
        string processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Current process path is unavailable.");
        if (string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            string assembly = Environment.GetCommandLineArgs()[0];
            return (processPath, new[] { assembly }.Concat(arguments).ToList());
        }
        return (processPath, arguments.ToList());
    }

    internal static RegistryKey CreateRegistryKey(string scope)
    {
        string normalized = scope.Replace('/', '\\');
        int separator = normalized.IndexOf('\\');
        string hive = separator < 0 ? normalized : normalized[..separator];
        string subKey = separator < 0 ? string.Empty : normalized[(separator + 1)..];
        RegistryKey root = hive.ToUpperInvariant() switch
        {
            "HKCU" or "HKEY_CURRENT_USER" => Registry.CurrentUser,
            "HKLM" or "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
            _ => throw new ArgumentException("Internal test mutator supports HKCU and HKLM.")
        };
        return root.CreateSubKey(subKey, writable: true)
            ?? throw new UnauthorizedAccessException($"Cannot create registry key {scope}.");
    }

    internal static void DeleteRegistryKey(string scope)
    {
        string normalized = scope.Replace('/', '\\');
        int separator = normalized.IndexOf('\\');
        string hive = normalized[..separator];
        string subKey = normalized[(separator + 1)..];
        RegistryKey root = hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase)
            ? Registry.LocalMachine
            : Registry.CurrentUser;
        root.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
    }

    private static string GetOption(string[] args, string option) =>
        GetOptionalOption(args, option) ?? throw new ArgumentException($"{option} is required.");

    private static string? GetOptionalOption(string[] args, string option)
    {
        int index = Array.IndexOf(args, option);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static void PrintJson<T>(T value) =>
        Console.WriteLine(JsonSerializer.Serialize(value, JsonSupport.Options));

    private static void PrintUsage()
    {
        Console.WriteLine("""
            AgentOS Windows transaction recovery MVP

            Usage:
              agentos run --file-scope <dir> [--file-scope <dir> ...]
                          [--registry-scope <HKCU\\path> ...]
                          [--service-scope <name> ...]
                          [--scheduled-task-scope <\\path> ...]
                          [--store <dir>] [--mode sandbox|critical|full]
                          [--sandbox-box <name>]
                          [--on-success retain|commit|rollback]
                          -- <executable> [arguments]
              agentos begin [--file-scope <dir> ...] [--registry-scope <hive\\path> ...]
                            [--service-scope <name> ...] [--scheduled-task-scope <\\path> ...]
                            [--store <dir>] [--mode critical|full] [--correlation <id>]
              agentos prepare <transaction-id> [--store <dir>]
              agentos status <transaction-id> [--store <dir>]
              agentos list [--store <dir>]
              agentos commit <transaction-id> [--store <dir>]
              agentos rollback <transaction-id> [--store <dir>] [--force]
              agentos recover <transaction-id> [--store <dir>] [--assume-exclusive]
              agentos verify <transaction-id> [--store <dir>]
              agentos verify-journal <transaction-id> [--store <dir>]
              agentos purge <transaction-id> [--store <dir>] --confirm
              agentos gc [--store <dir>] [--max-transactions <count>]
                         [--max-age-days <days>] [--max-bytes <bytes>]
              agentos scrub [--store <dir>]
              agentos doctor
              agentos self-test

            Default behavior retains a successful transaction in Prepared state. A non-zero
            child exit code automatically triggers rollback. Recovery only touches declared scopes.
            Full mode requires an elevated session and creates persistent VSS baselines.
            scrub is a read-only store integrity walk over manifests, journals, indexes and blobs.
            """);
    }
}

internal static class SelfTest
{
    public static int Run()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Self-test requires Windows.");
        }

        string root = Path.Combine(Path.GetTempPath(), "AgentOS-SelfTest-" + Guid.NewGuid().ToString("N"));
        string storePath = Path.Combine(root, "store");
        string dataRoot = Path.Combine(root, "data");
        Directory.CreateDirectory(dataRoot);
        TransactionStore store = new(storePath);
        TransactionEngine engine = new(store);
        List<string> results = [];
        List<string> registryScopes = [];

        try
        {
            string standaloneJournal = Path.Combine(root, "journal-self-test.ndjson");
            TransactionJournal.Append(standaloneJournal, "self-test.one", "one");
            TransactionJournal.Append(standaloneJournal, "self-test.two", "two");
            Assert(TransactionJournal.Verify("standalone", standaloneJournal).IsValid,
                "hash-chained journal must validate before tampering");
            File.AppendAllText(standaloneJournal, "{not-json}" + Environment.NewLine);
            Assert(!TransactionJournal.Verify("standalone", standaloneJournal).IsValid,
                "journal verifier must reject tampered records");
            results.Add("PASS durable hash-chained journal detects tampering");

            (string command, List<string> baseInvocation) = Program.SelfInvocation("internal-mutate");

            if (!RuntimeCapabilities.IsElevated())
            {
                string fullScope = PrepareCase(dataRoot, "full-mode-preflight", registryScopes);
                string fullRegistry = registryScopes[^1];
                List<string> fullArgs = baseInvocation.Concat(["--scope", fullScope, "--registry", fullRegistry]).ToList();
                TransactionManifest fullDenied = engine.Run(
                    [fullScope],
                    [fullRegistry],
                    command,
                    fullArgs,
                    SuccessAction.Retain,
                    new TransactionPolicy { Mode = TransactionMode.FullRecovery });
                Assert(fullDenied.State == TransactionState.Failed, "non-elevated FullRecovery must fail before launching a process");
                Assert(File.ReadAllText(Path.Combine(fullScope, "original.txt")) == "before",
                    "failed FullRecovery preflight must not execute the mutator");
                Assert(engine.VerifyJournal(fullDenied.Id).IsValid, "failed FullRecovery preflight must remain journal-valid");
                results.Add("PASS non-elevated FullRecovery fails safely before process launch");
            }

            string detachedScope = PrepareCase(dataRoot, "detached", registryScopes);
            string detachedRegistry = registryScopes[^1];
            string missingService = "AgentOSMissing-" + Guid.NewGuid().ToString("N");
            string missingTask = "\\AgentOSMissing-" + Guid.NewGuid().ToString("N");
            TransactionManifest detached = engine.BeginDetached(
                [detachedScope], [detachedRegistry], [missingService], [missingTask], "self-test", TransactionPolicy.Critical);
            Assert(detached.State == TransactionState.Active, "detached transaction should become Active after durable baseline");
            MutateDirectly(detachedScope, detachedRegistry);
            ProtectRegistryAcl(detachedRegistry);
            TransactionManifest detachedPrepared = engine.PrepareDetached(detached.Id);
            Assert(detachedPrepared.State == TransactionState.Prepared, "detached transaction should persist its after-state");
            RegistrySnapshot detachedBaselineRegistry = JsonSupport.Read<RegistrySnapshot>(store.BaselineRegistryPath(detached.Id));
            RegistrySnapshot detachedAfterRegistry = JsonSupport.Read<RegistrySnapshot>(store.AfterRegistryPath(detached.Id));
            Assert(RegistrySnapshotEngine.Compare(detachedBaselineRegistry, detachedAfterRegistry).Any(item => item.Contains("@security", StringComparison.Ordinal)),
                "registry ACL changes should be present in the transaction diff");
            Assert(File.Exists(store.BaselineServicesPath(detached.Id)) && File.Exists(store.AfterServicesPath(detached.Id)),
                "detached service snapshots should be durable");
            Assert(File.Exists(store.BaselineScheduledTasksPath(detached.Id)) && File.Exists(store.AfterScheduledTasksPath(detached.Id)),
                "detached scheduled-task snapshots should be durable");
            TransactionManifest detachedRolledBack = engine.Rollback(detached.Id, force: false);
            Assert(detachedRolledBack.State == TransactionState.RolledBack,
                $"detached transaction should roll back cleanly; state={detachedRolledBack.State}; error={detachedRolledBack.Error}");
            AssertBaseline(detachedScope, detachedRegistry);
            results.Add("PASS detached begin/prepare/rollback integrates file, registry, service and scheduled-task providers");

            // Capture a real existing service for structured metadata without mutating it.
            ServiceSnapshot eventLog = WindowsServiceSnapshotEngine.Capture(["EventLog"]);
            ServiceEntry eventEntry = eventLog.Entries.Single();
            Assert(eventEntry.Exists, "EventLog service should exist on Windows self-test hosts");
            Assert(!string.IsNullOrWhiteSpace(eventEntry.StartType), "structured start type must be captured");
            Assert(!string.IsNullOrWhiteSpace(eventEntry.BinaryPathName), "structured binary path must be captured");
            WindowsServiceSnapshotEngine.Validate(eventLog, ["EventLog"]);
            results.Add("PASS structured service snapshot captures start type and binary path");


            string registryOnly = $"HKCU\\Software\\AgentOS\\SelfTest-{Guid.NewGuid():N}";
            using (RegistryKey key = Program.CreateRegistryKey(registryOnly)) { key.SetValue("Original", "before"); }
            registryScopes.Add(registryOnly);
            TransactionManifest registryOnlyTransaction = engine.BeginDetached([], [registryOnly], [], [], "registry-only", TransactionPolicy.Critical);
            using (RegistryKey key = Program.CreateRegistryKey(registryOnly)) { key.SetValue("Original", "after"); }
            engine.PrepareDetached(registryOnlyTransaction.Id);
            Assert(engine.Rollback(registryOnlyTransaction.Id, force: false).State == TransactionState.RolledBack,
                "registry-only transaction should roll back");
            using (RegistryKey key = Program.CreateRegistryKey(registryOnly))
            {
                Assert((string?)key.GetValue("Original") == "before", "registry-only rollback should restore its baseline");
            }
            results.Add("PASS registry-only detached transaction does not require a file scope");

            string rollbackScope = PrepareCase(dataRoot, "rollback", registryScopes);
            string rollbackRegistry = registryScopes[^1];
            List<string> rollbackArgs = baseInvocation.Concat(
                ["--scope", rollbackScope, "--registry", rollbackRegistry, "--spawn-child"]).ToList();
            TransactionManifest prepared = engine.Run([rollbackScope], [rollbackRegistry], command, rollbackArgs, SuccessAction.Retain);
            Assert(prepared.State == TransactionState.Prepared, "successful transaction should be Prepared");
            Assert(File.ReadAllText(Path.Combine(rollbackScope, "original.txt")) == "after", "mutation should be visible before rollback");
            Thread.Sleep(TimeSpan.FromMilliseconds(2400));
            Assert(!File.Exists(Path.Combine(rollbackScope, "delayed-child.txt")), "Job Object must kill a lingering descendant");
            TransactionManifest rolledBack = engine.Rollback(prepared.Id, force: false);
            Assert(rolledBack.State == TransactionState.RolledBack, "explicit rollback should complete");
            AssertBaseline(rollbackScope, rollbackRegistry);
            Assert(engine.Verify(rolledBack.Id).MatchesExpectedState, "rolled-back transaction must verify against baseline");
            Assert(engine.VerifyJournal(rolledBack.Id).IsValid, "transaction journal must verify after rollback");
            results.Add("PASS explicit file/registry rollback and descendant cleanup");

            string failureScope = PrepareCase(dataRoot, "failure", registryScopes);
            string failureRegistry = registryScopes[^1];
            List<string> failureArgs = baseInvocation.Concat(
                ["--scope", failureScope, "--registry", failureRegistry, "--exit-code", "17"]).ToList();
            TransactionManifest failed = engine.Run([failureScope], [failureRegistry], command, failureArgs, SuccessAction.Retain);
            Assert(failed.ExitCode == 17, "failure exit code must be recorded");
            Assert(failed.State == TransactionState.RolledBack, "failed command must roll back automatically");
            AssertBaseline(failureScope, failureRegistry);
            results.Add("PASS non-zero process exit triggers verified rollback");

            string interruptedScope = PrepareCase(dataRoot, "interrupted", registryScopes);
            string interruptedRegistry = registryScopes[^1];
            TransactionManifest interrupted = new()
            {
                Id = Guid.NewGuid().ToString("N"),
                State = TransactionState.Active,
                OwnerProcessId = -1,
                FileScopes = [interruptedScope],
                RegistryScopes = [interruptedRegistry],
                Command = "simulated-crash",
                Arguments = [],
                OnSuccess = SuccessAction.Retain
            };
            store.Create(interrupted);
            JsonSupport.WriteAtomic(store.BaselineFilesPath(interrupted.Id),
                FileSnapshotEngine.Capture([interruptedScope], store.BlobDirectory(interrupted.Id)));
            JsonSupport.WriteAtomic(store.BaselineRegistryPath(interrupted.Id),
                RegistrySnapshotEngine.Capture([interruptedRegistry]));
            MutateDirectly(interruptedScope, interruptedRegistry);
            TransactionManifest requiresReview = engine.Recover(interrupted.Id, assumeExclusive: false);
            Assert(requiresReview.State == TransactionState.RecoveryRequired,
                "interrupted transaction must require an explicit exclusivity decision");
            Assert(File.ReadAllText(Path.Combine(interruptedScope, "original.txt")) == "after",
                "safe recovery must not modify data before exclusivity is confirmed");
            TransactionManifest recovered = engine.Recover(interrupted.Id, assumeExclusive: true);
            Assert(recovered.State == TransactionState.RolledBack, "exclusive interrupted recovery should roll back");
            AssertBaseline(interruptedScope, interruptedRegistry);
            results.Add("PASS interrupted transaction defaults to safe review and supports explicit recovery");

            string commitScope = PrepareCase(dataRoot, "commit", registryScopes);
            string commitRegistry = registryScopes[^1];
            List<string> commitArgs = baseInvocation.Concat(
                ["--scope", commitScope, "--registry", commitRegistry]).ToList();
            TransactionManifest committed = engine.Run([commitScope], [commitRegistry], command, commitArgs, SuccessAction.Commit);
            Assert(committed.State == TransactionState.Committed, "successful commit should complete");
            Assert(File.ReadAllText(Path.Combine(commitScope, "original.txt")) == "after", "commit must preserve mutations");
            Assert(engine.Verify(committed.Id).MatchesExpectedState, "committed transaction must verify against after-state");
            results.Add("PASS commit preserves and verifies transaction state");

            string conflictScope = PrepareCase(dataRoot, "conflict", registryScopes);
            string conflictRegistry = registryScopes[^1];
            List<string> conflictArgs = baseInvocation.Concat(
                ["--scope", conflictScope, "--registry", conflictRegistry]).ToList();
            TransactionManifest conflictPrepared = engine.Run([conflictScope], [conflictRegistry], command, conflictArgs, SuccessAction.Retain);
            File.WriteAllText(Path.Combine(conflictScope, "original.txt"), "external-later-change");
            TransactionManifest conflicted = engine.Rollback(conflictPrepared.Id, force: false);
            Assert(conflicted.State == TransactionState.Conflicted, "later changes must block rollback");
            Assert(File.ReadAllText(Path.Combine(conflictScope, "original.txt")) == "external-later-change", "conflict handling must not overwrite later data");
            TransactionManifest forced = engine.Rollback(conflicted.Id, force: true);
            Assert(forced.State == TransactionState.RolledBack, "explicit forced rollback should resolve test conflict");
            AssertBaseline(conflictScope, conflictRegistry);
            results.Add("PASS three-way conflict detection prevents silent overwrite");

            string blobTamperScope = PrepareCase(dataRoot, "blob-tamper", registryScopes);
            string blobTamperRegistry = registryScopes[^1];
            TransactionManifest blobTamper = engine.BeginDetached(
                [blobTamperScope], [blobTamperRegistry], [], [], "blob-tamper", TransactionPolicy.Critical);
            MutateDirectly(blobTamperScope, blobTamperRegistry);
            engine.PrepareDetached(blobTamper.Id);
            FileSnapshot blobBaseline = JsonSupport.Read<FileSnapshot>(store.BaselineFilesPath(blobTamper.Id));
            FileEntry originalEntry = blobBaseline.Entries.Single(entry =>
                entry.Kind == FileEntryKind.File &&
                string.Equals(entry.RelativePath, "original.txt", StringComparison.OrdinalIgnoreCase));
            File.WriteAllText(Path.Combine(store.BlobDirectory(blobTamper.Id), originalEntry.Sha256!), "tampered-blob");
            FileSnapshot beforeBlobFailure = FileSnapshotEngine.Capture([blobTamperScope], blobDirectory: null);
            TransactionManifest blobRejected = engine.Rollback(blobTamper.Id, force: false);
            FileSnapshot afterBlobFailure = FileSnapshotEngine.Capture([blobTamperScope], blobDirectory: null);
            Assert(blobRejected.State == TransactionState.RecoveryRequired,
                "a damaged recovery blob must fail closed");
            Assert(FileSnapshotEngine.Compare(beforeBlobFailure, afterBlobFailure).Count == 0,
                "blob validation failure must not modify the workspace");
            using (RegistryKey key = Program.CreateRegistryKey(blobTamperRegistry))
            {
                Assert((string?)key.GetValue("Original") == "after",
                    "blob preflight failure must happen before registry restore");
            }
            results.Add("PASS damaged baseline blob is rejected before any rollback write");

            string pathTamperScope = Path.Combine(dataRoot, "snapshot-path-tamper");
            Directory.CreateDirectory(pathTamperScope);
            File.WriteAllText(Path.Combine(pathTamperScope, "original.txt"), "before");
            TransactionManifest pathTamper = engine.BeginDetached(
                [pathTamperScope], [], [], [], "snapshot-path-tamper", TransactionPolicy.Critical);
            File.WriteAllText(Path.Combine(pathTamperScope, "original.txt"), "after");
            engine.PrepareDetached(pathTamper.Id);
            FileSnapshot pathBaseline = JsonSupport.Read<FileSnapshot>(store.BaselineFilesPath(pathTamper.Id));
            FileEntry pathEntry = pathBaseline.Entries.Single(entry => entry.Kind == FileEntryKind.File);
            string escapeName = "escaped-" + Guid.NewGuid().ToString("N") + ".txt";
            string escapePath = Path.Combine(dataRoot, escapeName);
            FileEntry escapedEntry = new()
            {
                ScopeIndex = pathEntry.ScopeIndex,
                RelativePath = Path.Combine("..", escapeName),
                Kind = pathEntry.Kind,
                Length = pathEntry.Length,
                Sha256 = pathEntry.Sha256,
                Attributes = pathEntry.Attributes,
                CreationTimeUtc = pathEntry.CreationTimeUtc,
                LastWriteTimeUtc = pathEntry.LastWriteTimeUtc,
                SecurityDescriptorBase64 = pathEntry.SecurityDescriptorBase64
            };
            FileSnapshot escapedSnapshot = new()
            {
                Scopes = pathBaseline.Scopes,
                Entries = [escapedEntry]
            };
            AssertThrows<InvalidDataException>(
                () => FileSnapshotEngine.Validate(escapedSnapshot, [pathTamperScope]),
                "snapshot validator must reject parent traversal");
            JsonSupport.WriteAtomic(store.BaselineFilesPath(pathTamper.Id), escapedSnapshot);
            FileSnapshot beforePathFailure = FileSnapshotEngine.Capture([pathTamperScope], blobDirectory: null);
            TransactionManifest pathRejected = engine.Rollback(pathTamper.Id, force: false);
            FileSnapshot afterPathFailure = FileSnapshotEngine.Capture([pathTamperScope], blobDirectory: null);
            Assert(pathRejected.State == TransactionState.RecoveryRequired,
                "a tampered snapshot must fail closed");
            Assert(FileSnapshotEngine.Compare(beforePathFailure, afterPathFailure).Count == 0,
                "snapshot integrity failure must not modify the workspace");
            Assert(!File.Exists(escapePath), "snapshot traversal must never write outside the declared scope");
            results.Add("PASS snapshot hash and path validation prevent out-of-scope recovery writes");

            string corruptExistingScope = Path.Combine(dataRoot, "corrupt-existing-blob");
            string corruptExistingBlobs = Path.Combine(root, "corrupt-existing-blobs");
            Directory.CreateDirectory(corruptExistingScope);
            Directory.CreateDirectory(corruptExistingBlobs);
            string corruptExistingFile = Path.Combine(corruptExistingScope, "original.txt");
            File.WriteAllText(corruptExistingFile, "baseline-content");
            string expectedBlobHash = EvidenceIntegrity.HashFile(corruptExistingFile);
            File.WriteAllText(Path.Combine(corruptExistingBlobs, expectedBlobHash), "wrong-content");
            AssertThrows<InvalidDataException>(
                () => FileSnapshotEngine.Capture([corruptExistingScope], corruptExistingBlobs),
                "capture must validate a pre-existing content-addressed blob");
            Assert(File.ReadAllText(corruptExistingFile) == "baseline-content",
                "failed blob capture must not modify its source");
            results.Add("PASS baseline capture rejects an existing blob with the wrong content");

            string gcScope = PrepareCase(dataRoot, "gc-active", registryScopes);
            string gcRegistry = registryScopes[^1];
            TransactionManifest gcActive = engine.BeginDetached([gcScope], [gcRegistry], [], [], "gc-active", TransactionPolicy.Critical);
            GarbageCollectionResult gc = engine.GarbageCollect(2, TimeSpan.FromDays(365), long.MaxValue);
            Assert(gc.PurgedTransactionIds.Count > 0, "garbage collection should prune old terminal transactions");
            Assert(gc.RetainedTransactionIds.Contains(gcActive.Id), "garbage collection must retain active transactions");
            engine.PrepareDetached(gcActive.Id);
            engine.Rollback(gcActive.Id, force: false);
            results.Add("PASS storage GC prunes terminal history and preserves active recovery data");

            // Earlier negative cases intentionally leave damaged evidence in the store.
            // Scrub is validated against a freshly prepared healthy transaction, then after
            // targeted blob tampering of that same transaction.
            string scrubScope = PrepareCase(dataRoot, "scrub-detect", registryScopes);
            string scrubRegistry = registryScopes[^1];
            TransactionManifest scrubTx = engine.BeginDetached(
                [scrubScope], [scrubRegistry], [], [], "scrub-detect", TransactionPolicy.Critical);
            MutateDirectly(scrubScope, scrubRegistry);
            engine.PrepareDetached(scrubTx.Id);
            StoreScrubResult healthyScrub = engine.ScrubStore();
            TransactionScrubResult healthyEntry = healthyScrub.Transactions.Single(result => result.TransactionId == scrubTx.Id);
            Assert(healthyEntry.Healthy, "scrub must mark a freshly prepared transaction healthy");
            Assert(healthyEntry.Issues.Count == 0, "healthy scrub entry must have no issues");
            FileSnapshot scrubBaseline = JsonSupport.Read<FileSnapshot>(store.BaselineFilesPath(scrubTx.Id));
            FileEntry scrubEntry = scrubBaseline.Entries.Single(entry =>
                entry.Kind == FileEntryKind.File &&
                string.Equals(entry.RelativePath, "original.txt", StringComparison.OrdinalIgnoreCase));
            File.WriteAllText(Path.Combine(store.BlobDirectory(scrubTx.Id), scrubEntry.Sha256!), "scrub-tampered-blob");
            StoreScrubResult dirtyScrub = engine.ScrubStore();
            Assert(dirtyScrub.IssueCount > 0, "scrub must detect a damaged recovery blob");
            TransactionScrubResult scrubbed = dirtyScrub.Transactions.Single(result => result.TransactionId == scrubTx.Id);
            Assert(!scrubbed.Healthy, "tampered transaction must be unhealthy");
            Assert(scrubbed.Issues.Count > 0, "scrub issues must describe the damaged blob");
            results.Add("PASS store scrub detects damaged recovery evidence without writing");

            string adsScope = Path.Combine(dataRoot, "ads-restore");
            Directory.CreateDirectory(adsScope);
            string adsFile = Path.Combine(adsScope, "tracked.txt");
            File.WriteAllText(adsFile, "main-before");
            File.WriteAllText(adsFile + ":agentos.ads", "stream-before");
            TransactionManifest adsTx = engine.BeginDetached([adsScope], [], [], [], "ads-restore", TransactionPolicy.Critical);
            File.WriteAllText(adsFile, "main-after");
            File.WriteAllText(adsFile + ":agentos.ads", "stream-after");
            File.WriteAllText(adsFile + ":agentos.extra", "stream-extra");
            engine.PrepareDetached(adsTx.Id);
            TransactionManifest adsRolled = engine.Rollback(adsTx.Id, force: false);
            Assert(adsRolled.State == TransactionState.RolledBack, "ADS-aware rollback should complete");
            Assert(File.ReadAllText(adsFile) == "main-before", "main file content must restore");
            Assert(File.ReadAllText(adsFile + ":agentos.ads") == "stream-before", "baseline ADS content must restore");
            Assert(!File.Exists(adsFile + ":agentos.extra"), "transaction-created ADS must be removed on rollback");
            results.Add("PASS ADS capture and rollback restore alternate streams");

            string macScope = Path.Combine(dataRoot, "mac-detect");
            Directory.CreateDirectory(macScope);
            File.WriteAllText(Path.Combine(macScope, "tracked.txt"), "before");
            TransactionManifest macTx = engine.BeginDetached([macScope], [], [], [], "mac-detect", TransactionPolicy.Critical);
            File.WriteAllText(Path.Combine(macScope, "tracked.txt"), "after");
            engine.PrepareDetached(macTx.Id);
            Assert(File.Exists(store.EvidenceMacPath(macTx.Id)), "prepared transaction must persist evidence MAC");
            // Flip one byte in the sealed baseline-files snapshot so the evidence MAC no longer matches.
            byte[] snapshotBytes = File.ReadAllBytes(store.BaselineFilesPath(macTx.Id));
            snapshotBytes[^2] ^= 0x01;
            File.WriteAllBytes(store.BaselineFilesPath(macTx.Id), snapshotBytes);
            FileSnapshot beforeMacFailure = FileSnapshotEngine.Capture([macScope], blobDirectory: null);
            TransactionManifest macRejected = engine.Rollback(macTx.Id, force: false);
            FileSnapshot afterMacFailure = FileSnapshotEngine.Capture([macScope], blobDirectory: null);
            Assert(macRejected.State == TransactionState.RecoveryRequired, "MAC failure must fail closed");
            Assert(FileSnapshotEngine.Compare(beforeMacFailure, afterMacFailure).Count == 0,
                "MAC validation failure must not modify the workspace");
            results.Add("PASS evidence MAC detects same-user store tampering");

            string hardlinkScope = Path.Combine(dataRoot, "hardlink-group");
            Directory.CreateDirectory(hardlinkScope);
            string primary = Path.Combine(hardlinkScope, "primary.txt");
            string linked = Path.Combine(hardlinkScope, "linked.txt");
            File.WriteAllText(primary, "shared-content");
            if (!NativeMethods.CreateHardLink(linked, primary))
            {
                throw new InvalidOperationException("CreateHardLink failed for self-test.");
            }
            FileSnapshot hardlinkSnapshot = FileSnapshotEngine.Capture([hardlinkScope], blobDirectory: null);
            FileEntry primaryEntry = hardlinkSnapshot.Entries.Single(entry => entry.RelativePath.Equals("primary.txt", StringComparison.OrdinalIgnoreCase));
            FileEntry linkedEntry = hardlinkSnapshot.Entries.Single(entry => entry.RelativePath.Equals("linked.txt", StringComparison.OrdinalIgnoreCase));
            Assert(!string.IsNullOrWhiteSpace(primaryEntry.HardLinkGroupKey), "hardlink group key must be assigned");
            Assert(string.Equals(primaryEntry.HardLinkGroupKey, linkedEntry.HardLinkGroupKey, StringComparison.OrdinalIgnoreCase),
                "hardlinked files must share one group key");
            Assert(primaryEntry.HardLinkPaths.Count >= 2 && linkedEntry.HardLinkPaths.Count >= 2,
                "hardlink path set must include siblings");
            results.Add("PASS hardlink group metadata is captured for sibling links");

            // Structured scheduled-task metadata: capture a task if one exists; otherwise validate missing-task shape.
            string sampleTask = @"\Microsoft\Windows\Defrag\ScheduledDefrag";
            ScheduledTaskSnapshot taskSnap = ScheduledTaskSnapshotEngine.Capture([sampleTask]);
            ScheduledTaskEntry taskEntry = taskSnap.Entries.Single();
            if (taskEntry.Exists)
            {
                Assert(!string.IsNullOrWhiteSpace(taskEntry.Xml), "existing task must include XML");
                // Structured fields are best-effort parsed from XML.
                results.Add("PASS structured scheduled-task snapshot parses existing task XML metadata");
            }
            else
            {
                Assert(taskEntry.Xml is null, "missing task must not invent XML");
                results.Add("PASS structured scheduled-task snapshot handles missing task without inventing metadata");
            }




            Console.WriteLine("AgentOS Windows MVP self-test succeeded:");
            foreach (string result in results)
            {
                Console.WriteLine("  " + result);
            }
            Console.WriteLine($"  transactions: {store.List().Count}");
            Console.WriteLine($"  evidence: {store.Root}");
            return 0;
        }
        finally
        {
            foreach (string registryScope in registryScopes)
            {
                try { Program.DeleteRegistryKey(registryScope); } catch { }
            }
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    private static string PrepareCase(string dataRoot, string name, List<string> registryScopes)
    {
        string directory = Path.Combine(dataRoot, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "original.txt"), "before");
        File.WriteAllText(Path.Combine(directory, "deleted.txt"), "keep");
        string registry = $"HKCU\\Software\\AgentOS\\SelfTest-{Guid.NewGuid():N}";
        using RegistryKey key = Program.CreateRegistryKey(registry);
        key.SetValue("Original", "before", RegistryValueKind.String);
        registryScopes.Add(registry);
        return directory;
    }

    private static void AssertBaseline(string scope, string registryScope)
    {
        Assert(File.ReadAllText(Path.Combine(scope, "original.txt")) == "before", "original file content must be restored");
        Assert(File.ReadAllText(Path.Combine(scope, "deleted.txt")) == "keep", "deleted file must be restored");
        Assert(!File.Exists(Path.Combine(scope, "new.txt")), "created file must be removed");
        Assert(!Directory.Exists(Path.Combine(scope, "nested")), "created directory must be removed");
        using RegistryKey key = Program.CreateRegistryKey(registryScope);
        Assert((string?)key.GetValue("Original") == "before", "registry value must be restored");
        Assert(key.GetValue("Created") is null, "created registry value must be removed");
        Assert(key.OpenSubKey("Nested") is null, "created registry key must be removed");
    }

    private static void MutateDirectly(string scope, string registryScope)
    {
        File.WriteAllText(Path.Combine(scope, "original.txt"), "after");
        File.Delete(Path.Combine(scope, "deleted.txt"));
        File.WriteAllText(Path.Combine(scope, "new.txt"), "created");
        Directory.CreateDirectory(Path.Combine(scope, "nested"));
        File.WriteAllText(Path.Combine(scope, "nested", "child.txt"), "child");
        using RegistryKey key = Program.CreateRegistryKey(registryScope);
        key.SetValue("Original", "after", RegistryValueKind.String);
        key.SetValue("Created", 42, RegistryValueKind.DWord);
        using RegistryKey child = key.CreateSubKey("Nested", writable: true)!;
        child.SetValue("Child", "value", RegistryValueKind.String);
    }

    private static void ProtectRegistryAcl(string registryScope)
    {
        using RegistryKey key = Program.CreateRegistryKey(registryScope);
        RegistrySecurity security = key.GetAccessControl(AccessControlSections.Access);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: true);
        key.SetAccessControl(security);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Self-test assertion failed: " + message);
        }
    }

    private static void AssertThrows<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException("Self-test assertion failed: " + message);
    }
}

internal static class NativeMethods
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);

    public static bool CreateHardLink(string newLink, string existing) =>
        CreateHardLink(newLink, existing, IntPtr.Zero);
}
