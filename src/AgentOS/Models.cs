using System.Text.Json;
using System.Text.Json.Serialization;

namespace AgentOS;

internal enum TransactionState
{
    Created,
    Preparing,
    Active,
    Prepared,
    Committed,
    RollingBack,
    RolledBack,
    Conflicted,
    RecoveryRequired,
    Failed
}

internal enum SuccessAction
{
    Retain,
    Commit,
    Rollback
}

internal enum TransactionMode
{
    Sandbox,
    CriticalRecovery,
    FullRecovery
}

internal sealed class TransactionPolicy
{
    public TransactionMode Mode { get; init; } = TransactionMode.CriticalRecovery;
    public bool RequireVssBaseline => Mode == TransactionMode.FullRecovery;
    public bool PermitExternalEffects { get; init; }
    public TimeSpan LeaseTimeout { get; init; } = TimeSpan.FromMinutes(30);
    public string SandboxBox { get; init; } = "AgentOS";

    public static TransactionPolicy Critical { get; } = new();
}

internal sealed class VssSnapshotMetadata
{
    public required string Id { get; init; }
    public required string VolumeRoot { get; init; }
    public required string DeviceObject { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public string? Provider { get; init; }
}

internal sealed class TransactionManifest
{
    public required string Id { get; init; }
    public int EvidenceVersion { get; init; }
    public TransactionState State { get; set; } = TransactionState.Created;
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public int OwnerProcessId { get; set; }
    public required List<string> FileScopes { get; init; }
    public required List<string> RegistryScopes { get; init; }
    public required string Command { get; init; }
    public required List<string> Arguments { get; init; }
    public SuccessAction OnSuccess { get; init; }
    public TransactionMode Mode { get; init; } = TransactionMode.CriticalRecovery;
    public bool ExternalEffectsPermitted { get; init; }
    public string? SandboxBox { get; init; }
    public List<VssSnapshotMetadata> VssSnapshots { get; set; } = [];
    public List<string> ServiceScopes { get; init; } = [];
    public List<string> ScheduledTaskScopes { get; init; } = [];
    public int? ExitCode { get; set; }
    public string? Error { get; set; }
    public List<string> Conflicts { get; set; } = [];
    public List<string> CoverageNotes { get; init; } =
    [
        "Files: content, timestamps, DOS attributes, available security descriptors, NTFS alternate streams, sparse/encrypted/compressed flags, and volume/file-index identity metadata inside declared local scopes.",
        "Registry: keys, values and available DACLs inside declared scopes.",
        "Services and scheduled tasks: explicitly declared objects are snapshotted with structured service start type/binary/account metadata; state and created-object cleanup are conditionally restored. Include a service registry scope when full configuration rollback is required.",
        "Processes: run transactions use a kill-on-close Windows Job Object; detached transactions rely on their caller to quiesce execution before prepare or rollback.",
        "Mode FullRecovery additionally records persistent VSS baseline metadata for every declared local volume.",
        "Store: root ACL hardened to current user/Administrators/SYSTEM when possible; evidence MAC uses CurrentUser DPAPI key (not a broker identity).",
        "Not covered: writes outside declared scopes, drivers, WFP/network effects, locked system objects, reparse points and offline recovery."
    ];
}

internal sealed class FileSnapshot
{
    public required List<string> Scopes { get; init; }
    public required List<FileEntry> Entries { get; init; }
}

internal enum FileEntryKind
{
    File,
    Directory
}

internal sealed class FileEntry
{
    public int ScopeIndex { get; init; }
    public required string RelativePath { get; init; }
    public FileEntryKind Kind { get; init; }
    public long Length { get; init; }
    public string? Sha256 { get; init; }
    public FileAttributes Attributes { get; init; }
    public DateTime CreationTimeUtc { get; init; }
    public DateTime LastWriteTimeUtc { get; init; }
    public string? SecurityDescriptorBase64 { get; init; }
    public uint VolumeSerialNumber { get; init; }
    public ulong FileIndex { get; init; }
    public int HardLinkCount { get; init; }
    public bool IsSparse { get; init; }
    public bool IsEncrypted { get; init; }
    public bool IsCompressed { get; init; }
    public List<FileStreamEntry> AlternateStreams { get; init; } = [];
    public string? HardLinkGroupKey { get; init; }
    public List<string> HardLinkPaths { get; init; } = [];

    public string Key => $"{ScopeIndex}:{RelativePath}";
}

internal sealed class FileStreamEntry
{
    public required string Name { get; init; }
    public long Length { get; init; }
    public string? Sha256 { get; init; }
}

internal sealed class RegistrySnapshot
{
    public required List<RegistryScopeSnapshot> Scopes { get; init; }
}

internal sealed class RegistryScopeSnapshot
{
    public required string Scope { get; init; }
    public bool Exists { get; init; }
    public required List<RegistryKeyEntry> Keys { get; init; }
}

internal sealed class RegistryKeyEntry
{
    public required string RelativePath { get; init; }
    public required List<RegistryValueEntry> Values { get; init; }
    public string? SecurityDescriptorBase64 { get; init; }
    public string? SecurityDescriptorSddl { get; init; }
    public string? SecurityDescriptorFingerprint { get; init; }
    public bool? AccessRulesProtected { get; init; }
}

internal sealed class RegistryValueEntry
{
    public required string Name { get; init; }
    public required string Kind { get; init; }
    public required string DataBase64 { get; init; }
}

internal sealed class VerificationResult
{
    public required string TransactionId { get; init; }
    public required TransactionState State { get; init; }
    public required bool MatchesExpectedState { get; init; }
    public required List<string> Differences { get; init; }
}

internal sealed class RuntimeCapabilityReport
{
    public required bool IsWindows { get; init; }
    public required bool IsElevated { get; init; }
    public required bool VssEligible { get; init; }
    public required string VssStatus { get; init; }
    public required bool SandboxieAvailable { get; init; }
    public string? SandboxieStartExe { get; init; }
    public required bool WdkHeadersAvailable { get; init; }
    public required bool DriverSigningToolsAvailable { get; init; }
    public required List<string> Notes { get; init; }
}

internal sealed class JournalEntry
{
    public long Sequence { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public required string EventType { get; init; }
    public required string Data { get; init; }
    public required string PreviousHash { get; init; }
    public required string Hash { get; init; }
}

internal sealed class JournalVerificationResult
{
    public required string TransactionId { get; init; }
    public required bool IsValid { get; init; }
    public required int EntryCount { get; init; }
    public string? Error { get; init; }
}

internal sealed class EvidenceIndex
{
    public int Version { get; init; } = 1;
    public required string TransactionId { get; init; }
    public required string Phase { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public required SortedDictionary<string, string> Files { get; init; }
}

internal sealed class PurgeResult
{
    public required string TransactionId { get; init; }
    public required bool Purged { get; init; }
    public required int DeletedVssSnapshots { get; init; }
    public string? Error { get; init; }
}

internal sealed class GarbageCollectionResult
{
    public long BytesBefore { get; init; }
    public long BytesAfter { get; init; }
    public required List<string> PurgedTransactionIds { get; init; }
    public required List<string> RetainedTransactionIds { get; init; }
    public required List<string> Errors { get; init; }
}

internal sealed class StoreScrubResult
{
    public required string StoreRoot { get; init; }
    public required int TransactionCount { get; init; }
    public required int HealthyCount { get; init; }
    public required int IssueCount { get; init; }
    public required int DamagedDirectoryCount { get; init; }
    public required List<TransactionScrubResult> Transactions { get; init; }
    public required List<string> DamagedDirectories { get; init; }
}

internal sealed class TransactionScrubResult
{
    public required string TransactionId { get; init; }
    public required TransactionState State { get; init; }
    public required bool Healthy { get; init; }
    public required List<string> Issues { get; init; }
}

internal sealed class ServiceSnapshot
{
    public required List<ServiceEntry> Entries { get; init; }
}

internal sealed class ServiceEntry
{
    public required string Name { get; init; }
    public bool Exists { get; init; }
    public string? Configuration { get; init; }
    public int? StateCode { get; init; }
    public string? DisplayName { get; init; }
    public string? StartType { get; init; }
    public string? ServiceType { get; init; }
    public string? BinaryPathName { get; init; }
    public string? ServiceAccount { get; init; }
    public string? Dependencies { get; init; }
    public string? ErrorControl { get; init; }
}

internal sealed class ScheduledTaskSnapshot
{
    public required List<ScheduledTaskEntry> Entries { get; init; }
}

internal sealed class ScheduledTaskEntry
{
    public required string Name { get; init; }
    public bool Exists { get; init; }
    public string? Xml { get; init; }
    public string? Author { get; init; }
    public string? Description { get; init; }
    public string? PrincipalUserId { get; init; }
    public string? LogonType { get; init; }
    public string? RunLevel { get; init; }
    public bool? Enabled { get; init; }
    public string? ActionsSummary { get; init; }
    public string? TriggersSummary { get; init; }
}

internal static class JsonSupport
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public static T Read<T>(string path) where T : class
    {
        using FileStream stream = File.OpenRead(path);
        return JsonSerializer.Deserialize<T>(stream, Options)
            ?? throw new InvalidDataException($"Could not deserialize {path}.");
    }

    public static void WriteAtomic<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (FileStream stream = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       64 * 1024, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, value, Options);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}
