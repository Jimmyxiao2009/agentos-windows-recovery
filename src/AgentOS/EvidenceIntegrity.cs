using System.Security.Cryptography;

namespace AgentOS;

internal static class EvidenceIntegrity
{
    public const int CurrentVersion = 1;

    public static string WriteIndex(
        string path,
        string transactionId,
        string phase,
        IEnumerable<string> evidenceFiles)
    {
        SortedDictionary<string, string> hashes = new(StringComparer.OrdinalIgnoreCase);
        foreach (string evidenceFile in evidenceFiles)
        {
            string name = EvidenceFileName(evidenceFile);
            if (!hashes.TryAdd(name, HashFile(evidenceFile)))
            {
                throw new InvalidDataException($"Duplicate evidence file name: {name}.");
            }
        }

        JsonSupport.WriteAtomic(path, new EvidenceIndex
        {
            Version = CurrentVersion,
            TransactionId = transactionId,
            Phase = phase,
            Files = hashes
        });
        return HashFile(path);
    }

    public static string ValidateIndex(
        string path,
        string transactionId,
        string phase,
        IEnumerable<string> evidenceFiles)
    {
        EvidenceIndex index = JsonSupport.Read<EvidenceIndex>(path);
        if (index.Version != CurrentVersion ||
            !string.Equals(index.TransactionId, transactionId, StringComparison.Ordinal) ||
            !string.Equals(index.Phase, phase, StringComparison.Ordinal) ||
            index.Files is null)
        {
            throw new InvalidDataException($"The {phase} evidence index has invalid identity metadata.");
        }

        Dictionary<string, string> expected = evidenceFiles.ToDictionary(
            EvidenceFileName,
            HashFile,
            StringComparer.OrdinalIgnoreCase);
        if (index.Files.Count != expected.Count ||
            index.Files.Keys.Except(expected.Keys, StringComparer.OrdinalIgnoreCase).Any())
        {
            throw new InvalidDataException($"The {phase} evidence index does not contain the expected snapshot set.");
        }

        foreach ((string name, string expectedHash) in expected)
        {
            if (!index.Files.TryGetValue(name, out string? recordedHash) ||
                !IsSha256(recordedHash) ||
                !string.Equals(recordedHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"The {phase} evidence snapshot {name} failed SHA-256 verification.");
            }
        }
        return HashFile(path);
    }

    public static void ValidateManifest(TransactionManifest manifest, string expectedId)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (!string.Equals(manifest.Id, expectedId, StringComparison.Ordinal) ||
            manifest.EvidenceVersion is < 0 or > CurrentVersion ||
            manifest.FileScopes is null ||
            manifest.RegistryScopes is null ||
            manifest.ServiceScopes is null ||
            manifest.ScheduledTaskScopes is null ||
            manifest.Arguments is null ||
            manifest.VssSnapshots is null ||
            manifest.Conflicts is null ||
            string.IsNullOrWhiteSpace(manifest.Command) ||
            !Enum.IsDefined(manifest.State) ||
            !Enum.IsDefined(manifest.Mode) ||
            !Enum.IsDefined(manifest.OnSuccess))
        {
            throw new InvalidDataException($"Transaction manifest {expectedId} is structurally invalid.");
        }

        HashSet<string> snapshotIds = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> volumeRoots = new(StringComparer.OrdinalIgnoreCase);
        foreach (VssSnapshotMetadata snapshot in manifest.VssSnapshots)
        {
            if (snapshot is null || string.IsNullOrWhiteSpace(snapshot.Id) ||
                string.IsNullOrWhiteSpace(snapshot.VolumeRoot) ||
                string.IsNullOrWhiteSpace(snapshot.DeviceObject) ||
                !snapshotIds.Add(snapshot.Id))
            {
                throw new InvalidDataException($"Transaction manifest {expectedId} contains invalid VSS metadata.");
            }

            string root = Path.GetFullPath(snapshot.VolumeRoot);
            string rootPath = Path.GetPathRoot(root)
                ?? throw new InvalidDataException($"VSS volume root is invalid: {snapshot.VolumeRoot}.");
            if (!string.Equals(
                    Path.TrimEndingDirectorySeparator(root),
                    Path.TrimEndingDirectorySeparator(rootPath),
                    StringComparison.OrdinalIgnoreCase) ||
                !volumeRoots.Add(root))
            {
                throw new InvalidDataException($"Transaction manifest {expectedId} contains an invalid or duplicate VSS volume root.");
            }
        }
    }

    public static string HashFile(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    public static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static string EvidenceFileName(string path)
    {
        string? name = Path.GetFileName(path);
        return !string.IsNullOrWhiteSpace(name)
            ? name
            : throw new InvalidDataException($"Evidence file path is invalid: {path}.");
    }
}
