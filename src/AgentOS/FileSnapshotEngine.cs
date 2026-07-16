using System.Security.Cryptography;
using System.Security.AccessControl;

namespace AgentOS;

internal static class FileSnapshotEngine
{
    private const int Sha256HexLength = 64;

    public static FileSnapshot Capture(IEnumerable<string> requestedScopes, string? blobDirectory)
    {
        List<string> requested = requestedScopes.ToList();
        List<string> scopes = requested.Count == 0 ? [] : NormalizeScopes(requested);
        List<FileEntry> entries = [];

        for (int index = 0; index < scopes.Count; index++)
        {
            string root = scopes[index];
            if (!Directory.Exists(root))
            {
                throw new DirectoryNotFoundException($"File scope does not exist: {root}");
            }

            CaptureDirectory(root, root, index, entries, blobDirectory);
        }

        AnnotateHardLinkGroups(scopes, entries);
        return new FileSnapshot
        {
            Scopes = scopes,
            Entries = entries.OrderBy(entry => entry.ScopeIndex)
                .ThenBy(entry => entry.RelativePath, StringComparer.OrdinalIgnoreCase)
                .ToList()
        };
    }

    public static List<string> Compare(FileSnapshot expected, FileSnapshot actual)
    {
        EnsureCompatibleScopes(expected, actual);
        Dictionary<string, FileEntry> left = expected.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, FileEntry> right = actual.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);
        List<string> differences = [];

        foreach (string key in left.Keys.Union(right.Keys, StringComparer.OrdinalIgnoreCase)
                     .OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            left.TryGetValue(key, out FileEntry? expectedEntry);
            right.TryGetValue(key, out FileEntry? actualEntry);
            if (expectedEntry is null)
            {
                differences.Add($"file-added:{Display(actual, actualEntry!)}");
            }
            else if (actualEntry is null)
            {
                differences.Add($"file-missing:{Display(expected, expectedEntry)}");
            }
            else if (!Equivalent(expectedEntry, actualEntry))
            {
                differences.Add($"file-changed:{Display(expected, expectedEntry)}");
            }
        }

        return differences;
    }

    public static List<string> FindRollbackConflicts(FileSnapshot baseline, FileSnapshot after, FileSnapshot current)
    {
        EnsureCompatibleScopes(baseline, after);
        EnsureCompatibleScopes(after, current);
        Dictionary<string, FileEntry> beforeMap = baseline.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, FileEntry> afterMap = after.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, FileEntry> currentMap = current.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);
        List<string> conflicts = [];

        foreach (string key in ChangedKeys(beforeMap, afterMap))
        {
            afterMap.TryGetValue(key, out FileEntry? afterEntry);
            currentMap.TryGetValue(key, out FileEntry? currentEntry);
            if (!EquivalentNullable(afterEntry, currentEntry))
            {
                FileEntry displayEntry = afterEntry ?? beforeMap[key];
                conflicts.Add($"file-conflict:{Display(after, displayEntry)}");
            }
        }

        return conflicts;
    }

    public static void Restore(
        FileSnapshot baseline,
        FileSnapshot after,
        string blobDirectory,
        IReadOnlyList<VssSnapshotMetadata>? vssSnapshots = null)
    {
        using RestorePlan plan = PrepareRestore(baseline, after, blobDirectory, vssSnapshots);
        plan.Apply();
    }

    public static RestorePlan PrepareRestore(
        FileSnapshot baseline,
        FileSnapshot after,
        string blobDirectory,
        IReadOnlyList<VssSnapshotMetadata>? vssSnapshots = null)
    {
        EnsureCompatibleScopes(baseline, after);
        Dictionary<string, FileEntry> beforeMap = baseline.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, FileEntry> afterMap = after.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);
        HashSet<string> changed = ChangedKeys(beforeMap, afterMap).ToHashSet(StringComparer.OrdinalIgnoreCase);

        string fullBlobDirectory = Path.GetFullPath(blobDirectory);
        Directory.CreateDirectory(fullBlobDirectory);
        string stagingDirectory = Path.Combine(fullBlobDirectory, ".restore-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stagingDirectory);
        Dictionary<string, string> stagedFiles = new(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (FileEntry entry in beforeMap.Values.Where(entry => entry.Kind == FileEntryKind.File))
            {
                bool contentChanged = changed.Contains(entry.Key);
                bool streamsChanged = afterMap.TryGetValue(entry.Key, out FileEntry? afterEntry) &&
                    !StreamSetsEquivalent(entry.AlternateStreams, afterEntry.AlternateStreams);
                bool needsBaselineContent = contentChanged || !afterMap.ContainsKey(entry.Key);
                if (needsBaselineContent)
                {
                    string destination = Path.Combine(stagingDirectory, entry.Sha256!);
                    if (!stagedFiles.TryGetValue(entry.Sha256!, out string? existing))
                    {
                        string source = ResolveRecoverySource(
                            baseline,
                            entry,
                            fullBlobDirectory,
                            vssSnapshots);
                        CopyAndVerify(source, destination, entry.Sha256!, entry.Length);
                        stagedFiles.Add(entry.Sha256!, destination);
                    }
                    else
                    {
                        VerifyFile(existing, entry.Sha256!, entry.Length, "staged recovery file");
                    }
                }

                if (needsBaselineContent || streamsChanged)
                {
                    foreach (FileStreamEntry stream in entry.AlternateStreams ?? [])
                    {
                        string streamDestination = Path.Combine(stagingDirectory, stream.Sha256!);
                        if (!stagedFiles.TryGetValue(stream.Sha256!, out string? stagedStream))
                        {
                            string streamBlob = Path.Combine(fullBlobDirectory, stream.Sha256!);
                            CopyAndVerify(streamBlob, streamDestination, stream.Sha256!, stream.Length);
                            stagedFiles.Add(stream.Sha256!, streamDestination);
                        }
                        else
                        {
                            VerifyFile(stagedStream, stream.Sha256!, stream.Length, "staged alternate stream");
                        }
                    }
                }
            }

            return new RestorePlan(baseline, after, changed, stagedFiles, stagingDirectory);
        }
        catch
        {
            DeleteStagingDirectory(stagingDirectory);
            throw;
        }
    }

    public static void ValidateBlob(string blobDirectory, string sha256, long expectedLength, string description)
    {
        if (string.IsNullOrWhiteSpace(blobDirectory))
        {
            throw new ArgumentException("Blob directory is required.", nameof(blobDirectory));
        }
        if (!EvidenceIntegrity.IsSha256(sha256))
        {
            throw new InvalidDataException($"The {description} has an invalid SHA-256 name: {sha256}.");
        }

        string path = Path.Combine(Path.GetFullPath(blobDirectory), sha256);
        VerifyFile(path, sha256, expectedLength, description);
    }

    public static void Validate(FileSnapshot snapshot, IEnumerable<string> declaredScopes)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.Scopes is null || snapshot.Entries is null)
        {
            throw new InvalidDataException("File snapshot is missing scopes or entries.");
        }

        List<string> declared = declaredScopes?.ToList()
            ?? throw new InvalidDataException("Transaction manifest is missing file scopes.");
        List<string> expectedScopes = NormalizeScopesForEvidence(declared);
        if (declared.Count != expectedScopes.Count)
        {
            throw new InvalidDataException("Transaction manifest contains duplicate file scopes.");
        }
        if (!snapshot.Scopes.SequenceEqual(expectedScopes, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("File snapshot scopes do not match the transaction manifest.");
        }

        HashSet<string> keys = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, FileEntry> entriesByPath = new(StringComparer.OrdinalIgnoreCase);
        foreach (FileEntry entry in snapshot.Entries)
        {
            if (entry is null)
            {
                throw new InvalidDataException("File snapshot contains a null entry.");
            }
            if (entry.ScopeIndex < 0 || entry.ScopeIndex >= snapshot.Scopes.Count)
            {
                throw new InvalidDataException($"File snapshot entry has an invalid scope index: {entry.ScopeIndex}.");
            }
            if (!Enum.IsDefined(entry.Kind))
            {
                throw new InvalidDataException($"File snapshot entry has an invalid kind: {entry.Kind}.");
            }

            ValidateRelativePath(entry.RelativePath);
            _ = ResolveFullPath(snapshot.Scopes[entry.ScopeIndex], entry.RelativePath);
            if (!keys.Add(entry.Key))
            {
                throw new InvalidDataException($"File snapshot contains duplicate entry {entry.Key}.");
            }
            entriesByPath.Add(entry.Key, entry);

            if (entry.Kind == FileEntryKind.File)
            {
                if (entry.Length < 0 || !IsSha256(entry.Sha256))
                {
                    throw new InvalidDataException($"File snapshot entry {entry.Key} has invalid length or SHA-256 metadata.");
                }
                ValidateAlternateStreams(entry);
            }
            else if (entry.Length != 0 || entry.Sha256 is not null || (entry.AlternateStreams?.Count ?? 0) > 0)
            {
                throw new InvalidDataException($"Directory snapshot entry {entry.Key} contains file content metadata.");
            }

            if (entry.FileIndex == 0 || entry.HardLinkCount < 1)
            {
                throw new InvalidDataException($"File snapshot entry {entry.Key} is missing volume/file identity metadata.");
            }

            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException($"File snapshot entry {entry.Key} is a reparse point, which is outside the recovery contract.");
            }
            bool directoryAttribute = (entry.Attributes & FileAttributes.Directory) != 0;
            if (directoryAttribute != (entry.Kind == FileEntryKind.Directory))
            {
                throw new InvalidDataException($"File snapshot entry {entry.Key} has inconsistent kind and attributes.");
            }
            ValidateSecurityDescriptor(entry);
        }

        foreach (FileEntry entry in snapshot.Entries)
        {
            string? parent = Path.GetDirectoryName(entry.RelativePath);
            while (!string.IsNullOrEmpty(parent) && parent != ".")
            {
                string parentKey = $"{entry.ScopeIndex}:{parent}";
                if (!entriesByPath.TryGetValue(parentKey, out FileEntry? parentEntry) ||
                    parentEntry.Kind != FileEntryKind.Directory)
                {
                    throw new InvalidDataException($"File snapshot entry {entry.Key} has a missing or non-directory parent {parentKey}.");
                }
                parent = Path.GetDirectoryName(parent);
            }
        }
    }

    private static void ApplyRestore(
        FileSnapshot baseline,
        FileSnapshot after,
        HashSet<string> changed,
        IReadOnlyDictionary<string, string> stagedFiles)
    {
        foreach ((string hash, string stagedPath) in stagedFiles)
        {
            FileEntry entry = baseline.Entries.First(candidate =>
                candidate.Kind == FileEntryKind.File &&
                string.Equals(candidate.Sha256, hash, StringComparison.OrdinalIgnoreCase));
            VerifyFile(stagedPath, hash, entry.Length, "staged recovery file");
        }

        Dictionary<string, FileEntry> beforeMap = baseline.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, FileEntry> afterMap = after.Entries.ToDictionary(entry => entry.Key, StringComparer.OrdinalIgnoreCase);

        IEnumerable<FileEntry> createdFiles = afterMap
            .Where(pair => changed.Contains(pair.Key) &&
                           pair.Value.Kind == FileEntryKind.File &&
                           (!beforeMap.TryGetValue(pair.Key, out FileEntry? before) || before.Kind != FileEntryKind.File))
            .Select(pair => pair.Value);
        foreach (FileEntry entry in createdFiles)
        {
            string path = FullPath(after, entry);
            if (File.Exists(path))
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
            }
        }

        IEnumerable<FileEntry> createdDirectories = afterMap
            .Where(pair => changed.Contains(pair.Key) &&
                           pair.Value.Kind == FileEntryKind.Directory &&
                           (!beforeMap.TryGetValue(pair.Key, out FileEntry? before) || before.Kind != FileEntryKind.Directory))
            .Select(pair => pair.Value)
            .OrderByDescending(entry => entry.RelativePath.Length);
        foreach (FileEntry entry in createdDirectories)
        {
            string path = FullPath(after, entry);
            if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any())
            {
                Directory.Delete(path);
            }
        }

        IEnumerable<FileEntry> baselineDirectories = beforeMap.Values
            .Where(entry => changed.Contains(entry.Key) && entry.Kind == FileEntryKind.Directory)
            .OrderBy(entry => entry.RelativePath.Length);
        foreach (FileEntry entry in baselineDirectories)
        {
            Directory.CreateDirectory(FullPath(baseline, entry));
        }

        IEnumerable<FileEntry> baselineFiles = beforeMap.Values
            .Where(entry => changed.Contains(entry.Key) && entry.Kind == FileEntryKind.File);
        foreach (FileEntry entry in baselineFiles)
        {
            string path = FullPath(baseline, entry);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            if (File.Exists(path))
            {
                File.SetAttributes(path, FileAttributes.Normal);
            }
            File.Copy(stagedFiles[entry.Sha256!], path, overwrite: true);
        }

        foreach (FileEntry entry in beforeMap.Values.Where(entry => changed.Contains(entry.Key))
                     .OrderByDescending(entry => entry.RelativePath.Length))
        {
            string path = FullPath(baseline, entry);
            if (entry.Kind == FileEntryKind.File && File.Exists(path))
            {
                File.SetCreationTimeUtc(path, entry.CreationTimeUtc);
                File.SetLastWriteTimeUtc(path, entry.LastWriteTimeUtc);
                File.SetAttributes(path, entry.Attributes);
            }
            else if (entry.Kind == FileEntryKind.Directory && Directory.Exists(path))
            {
                Directory.SetCreationTimeUtc(path, entry.CreationTimeUtc);
                Directory.SetLastWriteTimeUtc(path, entry.LastWriteTimeUtc);
                File.SetAttributes(path, entry.Attributes);
            }
            RestoreSecurityDescriptor(path, entry);
        }
    }

    private static void CaptureDirectory(
        string root,
        string directory,
        int scopeIndex,
        List<FileEntry> entries,
        string? blobDirectory)
    {
        foreach (string path in Directory.EnumerateFileSystemEntries(directory).OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new NotSupportedException($"Reparse points are not supported in the MVP recovery scope: {path}");
            }

            string relative = Path.GetRelativePath(root, path);
            if ((attributes & FileAttributes.Directory) != 0)
            {
                DirectoryInfo info = new(path);
                NativeFileInfo.Identity identity = NativeFileInfo.GetIdentity(path, isDirectory: true);
                entries.Add(new FileEntry
                {
                    ScopeIndex = scopeIndex,
                    RelativePath = relative,
                    Kind = FileEntryKind.Directory,
                    Attributes = attributes,
                    CreationTimeUtc = info.CreationTimeUtc,
                    LastWriteTimeUtc = info.LastWriteTimeUtc,
                    SecurityDescriptorBase64 = TryGetSecurityDescriptor(path, isDirectory: true),
                    VolumeSerialNumber = identity.VolumeSerialNumber,
                    FileIndex = identity.FileIndex,
                    HardLinkCount = identity.HardLinkCount,
                    IsSparse = (attributes & FileAttributes.SparseFile) != 0,
                    IsEncrypted = (attributes & FileAttributes.Encrypted) != 0,
                    IsCompressed = (attributes & FileAttributes.Compressed) != 0
                });
                CaptureDirectory(root, path, scopeIndex, entries, blobDirectory);
            }
            else
            {
                FileInfo info = new(path);
                string hash = HashFile(path);
                if (blobDirectory is not null)
                {
                    SaveBlob(path, hash, blobDirectory);
                }

                NativeFileInfo.Identity identity = NativeFileInfo.GetIdentity(path, isDirectory: false);
                List<FileStreamEntry> alternateStreams = CaptureAlternateStreams(path, blobDirectory);
                entries.Add(new FileEntry
                {
                    ScopeIndex = scopeIndex,
                    RelativePath = relative,
                    Kind = FileEntryKind.File,
                    Length = info.Length,
                    Sha256 = hash,
                    Attributes = attributes,
                    CreationTimeUtc = info.CreationTimeUtc,
                    LastWriteTimeUtc = info.LastWriteTimeUtc,
                    SecurityDescriptorBase64 = TryGetSecurityDescriptor(path, isDirectory: false),
                    VolumeSerialNumber = identity.VolumeSerialNumber,
                    FileIndex = identity.FileIndex,
                    HardLinkCount = identity.HardLinkCount,
                    IsSparse = (attributes & FileAttributes.SparseFile) != 0,
                    IsEncrypted = (attributes & FileAttributes.Encrypted) != 0,
                    IsCompressed = (attributes & FileAttributes.Compressed) != 0,
                    AlternateStreams = alternateStreams
                });
            }
        }
    }

    private static List<string> NormalizeScopes(IEnumerable<string> requestedScopes)
    {
        List<string> scopes = NormalizeScopesForEvidence(requestedScopes);
        if (scopes.Count == 0)
        {
            throw new ArgumentException("At least one --file-scope is required for a modifying transaction.");
        }

        return scopes;
    }

    private static List<string> NormalizeScopesForEvidence(IEnumerable<string> requestedScopes)
    {
        ArgumentNullException.ThrowIfNull(requestedScopes);
        List<string> scopes = requestedScopes.Select(scope =>
            {
                if (string.IsNullOrWhiteSpace(scope))
                {
                    throw new InvalidDataException("File scope cannot be empty.");
                }
                return Path.TrimEndingDirectorySeparator(Path.GetFullPath(scope));
            })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        for (int i = 0; i < scopes.Count; i++)
        {
            for (int j = i + 1; j < scopes.Count; j++)
            {
                string prefix = scopes[i].TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (scopes[j].StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException($"File scopes cannot overlap: {scopes[i]} and {scopes[j]}");
                }
            }
        }

        return scopes;
    }

    private static HashSet<string> ChangedKeys(
        Dictionary<string, FileEntry> baseline,
        Dictionary<string, FileEntry> after)
    {
        HashSet<string> changed = new(StringComparer.OrdinalIgnoreCase);
        foreach (string key in baseline.Keys.Union(after.Keys, StringComparer.OrdinalIgnoreCase))
        {
            baseline.TryGetValue(key, out FileEntry? beforeEntry);
            after.TryGetValue(key, out FileEntry? afterEntry);
            if (!EquivalentNullable(beforeEntry, afterEntry))
            {
                changed.Add(key);
            }
        }
        return changed;
    }

    private static bool EquivalentNullable(FileEntry? left, FileEntry? right) =>
        left is null ? right is null : right is not null && Equivalent(left, right);

    private static bool Equivalent(FileEntry left, FileEntry right) =>
        left.Kind == right.Kind &&
        left.Length == right.Length &&
        string.Equals(left.Sha256, right.Sha256, StringComparison.OrdinalIgnoreCase) &&
        left.Attributes == right.Attributes &&
        left.CreationTimeUtc == right.CreationTimeUtc &&
        left.LastWriteTimeUtc == right.LastWriteTimeUtc &&
        string.Equals(left.SecurityDescriptorBase64, right.SecurityDescriptorBase64, StringComparison.Ordinal) &&
        left.IsSparse == right.IsSparse &&
        left.IsEncrypted == right.IsEncrypted &&
        left.IsCompressed == right.IsCompressed &&
        string.Equals(left.HardLinkGroupKey, right.HardLinkGroupKey, StringComparison.OrdinalIgnoreCase) &&
        PathSetsEquivalent(left.HardLinkPaths, right.HardLinkPaths) &&
        StreamSetsEquivalent(left.AlternateStreams, right.AlternateStreams);
    // VolumeSerialNumber/FileIndex/HardLinkCount are captured for attribution and future
    // hardlink-aware recovery, but user-mode restore recreates objects and cannot preserve them.


    private static void AnnotateHardLinkGroups(IReadOnlyList<string> scopes, List<FileEntry> entries)
    {
        Dictionary<string, List<int>> groups = new(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < entries.Count; i++)
        {
            FileEntry entry = entries[i];
            if (entry.Kind != FileEntryKind.File || entry.FileIndex == 0)
            {
                continue;
            }
            string key = entry.VolumeSerialNumber.ToString("X8") + ":" + entry.FileIndex.ToString("X16");
            if (!groups.TryGetValue(key, out List<int>? indexes))
            {
                indexes = [];
                groups[key] = indexes;
            }
            indexes.Add(i);
        }

        foreach ((string key, List<int> indexes) in groups)
        {
            List<FileEntry> members = indexes.Select(index => entries[index]).ToList();
            if (members.Count < 2 && members.All(member => member.HardLinkCount <= 1))
            {
                continue;
            }

            List<string> paths = members
                .Select(member => Path.GetFullPath(Path.Combine(scopes[member.ScopeIndex], member.RelativePath)))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToList();
            foreach (int index in indexes)
            {
                entries[index] = CloneWithHardLinks(entries[index], key, paths);
            }
        }
    }

    private static FileEntry CloneWithHardLinks(FileEntry entry, string groupKey, List<string> paths) => new()
    {
        ScopeIndex = entry.ScopeIndex,
        RelativePath = entry.RelativePath,
        Kind = entry.Kind,
        Length = entry.Length,
        Sha256 = entry.Sha256,
        Attributes = entry.Attributes,
        CreationTimeUtc = entry.CreationTimeUtc,
        LastWriteTimeUtc = entry.LastWriteTimeUtc,
        SecurityDescriptorBase64 = entry.SecurityDescriptorBase64,
        VolumeSerialNumber = entry.VolumeSerialNumber,
        FileIndex = entry.FileIndex,
        HardLinkCount = entry.HardLinkCount,
        IsSparse = entry.IsSparse,
        IsEncrypted = entry.IsEncrypted,
        IsCompressed = entry.IsCompressed,
        AlternateStreams = entry.AlternateStreams,
        HardLinkGroupKey = groupKey,
        HardLinkPaths = paths
    };

    private static bool PathSetsEquivalent(IReadOnlyList<string>? left, IReadOnlyList<string>? right)
    {
        left ??= [];
        right ??= [];
        if (left.Count != right.Count)
        {
            return false;
        }
        HashSet<string> leftSet = new(left, StringComparer.OrdinalIgnoreCase);
        return right.All(leftSet.Contains) && leftSet.Count == right.Count;
    }

    private static bool StreamSetsEquivalent(IReadOnlyList<FileStreamEntry>? left, IReadOnlyList<FileStreamEntry>? right)
    {
        left ??= [];
        right ??= [];
        if (left.Count != right.Count)
        {
            return false;
        }

        Dictionary<string, FileStreamEntry> leftMap = left.ToDictionary(stream => stream.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, FileStreamEntry> rightMap = right.ToDictionary(stream => stream.Name, StringComparer.OrdinalIgnoreCase);
        if (leftMap.Count != rightMap.Count)
        {
            return false;
        }

        foreach ((string name, FileStreamEntry expected) in leftMap)
        {
            if (!rightMap.TryGetValue(name, out FileStreamEntry? actual) ||
                expected.Length != actual.Length ||
                !string.Equals(expected.Sha256, actual.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static List<FileStreamEntry> CaptureAlternateStreams(string path, string? blobDirectory)
    {
        List<FileStreamEntry> streams = [];
        foreach ((string name, long length) in NativeFileInfo.ListAlternateStreams(path))
        {
            string streamPath = NativeFileInfo.StreamPath(path, name);
            if (!File.Exists(streamPath))
            {
                continue;
            }

            string hash = HashFile(streamPath);
            if (blobDirectory is not null)
            {
                SaveBlob(streamPath, hash, blobDirectory);
            }

            streams.Add(new FileStreamEntry
            {
                Name = name,
                Length = length,
                Sha256 = hash
            });
        }

        return streams;
    }

    private static void ValidateAlternateStreams(FileEntry entry)
    {
        IReadOnlyList<FileStreamEntry> streams = entry.AlternateStreams ?? [];
        HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);
        foreach (FileStreamEntry stream in streams)
        {
            if (stream is null ||
                string.IsNullOrWhiteSpace(stream.Name) ||
                stream.Length < 0 ||
                !IsSha256(stream.Sha256) ||
                !names.Add(stream.Name))
            {
                throw new InvalidDataException($"File snapshot entry {entry.Key} has invalid alternate stream metadata.");
            }
        }
    }

    private static void RestoreAlternateStreams(string path, FileEntry entry, IReadOnlyDictionary<string, string> stagedFiles)
    {
        if (entry.Kind != FileEntryKind.File)
        {
            return;
        }

        HashSet<string> expected = new(
            (entry.AlternateStreams ?? []).Select(stream => stream.Name),
            StringComparer.OrdinalIgnoreCase);

        foreach ((string name, long _) in NativeFileInfo.ListAlternateStreams(path))
        {
            if (expected.Contains(name))
            {
                continue;
            }

            string streamPath = NativeFileInfo.StreamPath(path, name);
            if (File.Exists(streamPath))
            {
                File.Delete(streamPath);
            }
        }

        foreach (FileStreamEntry stream in entry.AlternateStreams ?? [])
        {
            if (!stagedFiles.TryGetValue(stream.Sha256!, out string? stagedPath))
            {
                throw new InvalidDataException($"Staged alternate stream blob missing for {entry.RelativePath}:{stream.Name}.");
            }

            string destination = NativeFileInfo.StreamPath(path, stream.Name);
            File.Copy(stagedPath, destination, overwrite: true);
            VerifyFile(destination, stream.Sha256!, stream.Length, "restored alternate stream");
        }
    }

    private static string HashFile(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string? TryGetSecurityDescriptor(string path, bool isDirectory)
    {
        try
        {
            byte[] descriptor = isDirectory
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.All).GetSecurityDescriptorBinaryForm()
                : new FileInfo(path).GetAccessControl(AccessControlSections.All).GetSecurityDescriptorBinaryForm();
            return Convert.ToBase64String(descriptor);
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
    }

    private static void RestoreSecurityDescriptor(string path, FileEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.SecurityDescriptorBase64))
        {
            return;
        }

        byte[] descriptor = Convert.FromBase64String(entry.SecurityDescriptorBase64);
        if (entry.Kind == FileEntryKind.Directory)
        {
            DirectorySecurity security = new();
            security.SetSecurityDescriptorBinaryForm(descriptor);
            new DirectoryInfo(path).SetAccessControl(security);
        }
        else
        {
            FileSecurity security = new();
            security.SetSecurityDescriptorBinaryForm(descriptor);
            new FileInfo(path).SetAccessControl(security);
        }
    }

    private static void SaveBlob(string source, string hash, string blobDirectory)
    {
        Directory.CreateDirectory(blobDirectory);
        string destination = Path.Combine(blobDirectory, hash);
        if (File.Exists(destination))
        {
            VerifyFile(destination, hash, new FileInfo(source).Length, "existing recovery blob");
            return;
        }

        string temporary = destination + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            File.Copy(source, temporary, overwrite: false);
            using (FileStream stream = new(temporary, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            {
                stream.Flush(flushToDisk: true);
            }
            VerifyFile(temporary, hash, new FileInfo(source).Length, "new recovery blob");
            try
            {
                File.Move(temporary, destination);
            }
            catch (IOException) when (File.Exists(destination))
            {
                File.Delete(temporary);
                VerifyFile(destination, hash, new FileInfo(source).Length, "concurrently created recovery blob");
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static string ResolveRecoverySource(
        FileSnapshot baseline,
        FileEntry entry,
        string blobDirectory,
        IReadOnlyList<VssSnapshotMetadata>? vssSnapshots)
    {
        string path = FullPath(baseline, entry);
        string blob = Path.Combine(blobDirectory, entry.Sha256!);
        if (File.Exists(blob))
        {
            VerifyFile(blob, entry.Sha256!, entry.Length, "recovery blob");
            return blob;
        }

        string? volumeRoot = Path.GetPathRoot(path);
        VssSnapshotMetadata? snapshot = vssSnapshots?.FirstOrDefault(candidate =>
            !string.IsNullOrWhiteSpace(volumeRoot) &&
            string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate.VolumeRoot)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(volumeRoot)),
                StringComparison.OrdinalIgnoreCase));
        if (snapshot is null)
        {
            throw new InvalidDataException($"Recovery blob {entry.Sha256} is missing for {path}, and no VSS baseline is available.");
        }

        string baselinePath = new VssShadowCopyProvider().ResolveBaselinePath(snapshot, path);
        if (!File.Exists(baselinePath))
        {
            throw new InvalidDataException($"Recovery blob {entry.Sha256} is missing and the VSS baseline does not contain {path}.");
        }
        VerifyFile(baselinePath, entry.Sha256!, entry.Length, "VSS recovery source");
        return baselinePath;
    }

    private static void CopyAndVerify(string source, string destination, string expectedHash, long expectedLength)
    {
        File.Copy(source, destination, overwrite: false);
        using (FileStream stream = new(destination, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
        {
            stream.Flush(flushToDisk: true);
        }
        VerifyFile(destination, expectedHash, expectedLength, "staged recovery file");
    }

    private static void VerifyFile(string path, string expectedHash, long expectedLength, string description)
    {
        FileInfo info = new(path);
        if (!info.Exists)
        {
            throw new InvalidDataException($"The {description} is missing: {path}.");
        }
        if (info.Length != expectedLength)
        {
            throw new InvalidDataException($"The {description} has length {info.Length}, expected {expectedLength}: {path}.");
        }

        string actualHash = HashFile(path);
        if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"The {description} failed SHA-256 verification: {path}.");
        }
    }

    private static bool IsSha256(string? value) =>
        value is { Length: Sha256HexLength } && value.All(Uri.IsHexDigit);

    private static void ValidateRelativePath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) || Path.IsPathRooted(relativePath))
        {
            throw new InvalidDataException($"File snapshot contains an unsafe relative path: {relativePath}.");
        }

        string[] segments = relativePath.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.None);
        char[] invalid = Path.GetInvalidFileNameChars();
        foreach (string segment in segments)
        {
            if (string.IsNullOrEmpty(segment) || segment is "." or ".." ||
                segment.EndsWith(' ') || segment.EndsWith('.') || segment.IndexOfAny(invalid) >= 0)
            {
                throw new InvalidDataException($"File snapshot contains an unsafe relative path: {relativePath}.");
            }
        }
    }

    private static string ResolveFullPath(string root, string relativePath)
    {
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        string candidate = Path.GetFullPath(Path.Combine(fullRoot, relativePath));
        string prefix = Path.EndsInDirectorySeparator(fullRoot)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"File snapshot path escapes its declared scope: {relativePath}.");
        }
        return candidate;
    }

    private static void ValidateSecurityDescriptor(FileEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.SecurityDescriptorBase64))
        {
            return;
        }
        try
        {
            byte[] descriptor = Convert.FromBase64String(entry.SecurityDescriptorBase64);
            if (descriptor.Length == 0)
            {
                throw new FormatException("Security descriptor is empty.");
            }
            _ = new RawSecurityDescriptor(descriptor, 0);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new InvalidDataException($"File snapshot entry {entry.Key} has an invalid security descriptor.", exception);
        }
    }

    private static void DeleteStagingDirectory(string stagingDirectory)
    {
        try
        {
            if (Directory.Exists(stagingDirectory))
            {
                Directory.Delete(stagingDirectory, recursive: true);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static string FullPath(FileSnapshot snapshot, FileEntry entry) =>
        ResolveFullPath(snapshot.Scopes[entry.ScopeIndex], entry.RelativePath);

    private static string Display(FileSnapshot snapshot, FileEntry entry) => FullPath(snapshot, entry);

    private static void EnsureCompatibleScopes(FileSnapshot left, FileSnapshot right)
    {
        if (!left.Scopes.SequenceEqual(right.Scopes, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("File snapshot scopes do not match.");
        }
    }

    internal sealed class RestorePlan : IDisposable
    {
        private readonly FileSnapshot _baseline;
        private readonly FileSnapshot _after;
        private readonly HashSet<string> _changed;
        private readonly IReadOnlyDictionary<string, string> _stagedFiles;
        private readonly string _stagingDirectory;
        private bool _applied;

        internal RestorePlan(
            FileSnapshot baseline,
            FileSnapshot after,
            HashSet<string> changed,
            IReadOnlyDictionary<string, string> stagedFiles,
            string stagingDirectory)
        {
            _baseline = baseline;
            _after = after;
            _changed = changed;
            _stagedFiles = stagedFiles;
            _stagingDirectory = stagingDirectory;
        }

        public void Apply()
        {
            if (_applied)
            {
                throw new InvalidOperationException("The file restore plan has already been applied.");
            }
            ApplyRestore(_baseline, _after, _changed, _stagedFiles);
            foreach (FileEntry entry in _baseline.Entries.Where(entry => entry.Kind == FileEntryKind.File))
            {
                string path = FullPath(_baseline, entry);
                if (File.Exists(path))
                {
                    RestoreAlternateStreams(path, entry, _stagedFiles.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase));
                }
            }
            _applied = true;
        }

        public void Dispose() => DeleteStagingDirectory(_stagingDirectory);
    }
}
