using System.Text;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace AgentOS;

internal static class RegistrySnapshotEngine
{
    public static RegistrySnapshot Capture(IEnumerable<string> requestedScopes)
    {
        List<string> scopes = NormalizeScopes(requestedScopes);
        List<RegistryScopeSnapshot> snapshots = [];
        foreach (string scope in scopes)
        {
            RegistryLocation location = Parse(scope);
            using RegistryKey? key = location.Root.OpenSubKey(location.SubKey, writable: false);
            if (key is null)
            {
                snapshots.Add(new RegistryScopeSnapshot { Scope = scope, Exists = false, Keys = [] });
                continue;
            }

            List<RegistryKeyEntry> keys = [];
            CaptureKey(key, string.Empty, keys);
            snapshots.Add(new RegistryScopeSnapshot { Scope = scope, Exists = true, Keys = keys });
        }

        return new RegistrySnapshot { Scopes = snapshots };
    }

    public static void Validate(RegistrySnapshot snapshot, IEnumerable<string> declaredScopes)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.Scopes is null)
        {
            throw new InvalidDataException("Registry snapshot is missing scopes.");
        }

        List<string> declared = declaredScopes?.ToList()
            ?? throw new InvalidDataException("Transaction manifest is missing registry scopes.");
        List<string> expected = NormalizeScopes(declared);
        if (declared.Count != expected.Count)
        {
            throw new InvalidDataException("Transaction manifest contains duplicate registry scopes.");
        }
        if (!snapshot.Scopes.Select(scope => scope?.Scope)
            .SequenceEqual(expected, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Registry snapshot scopes do not match the transaction manifest.");
        }

        foreach (RegistryScopeSnapshot scope in snapshot.Scopes)
        {
            if (scope is null || scope.Keys is null)
            {
                throw new InvalidDataException("Registry snapshot contains a null scope or key collection.");
            }
            if (!scope.Exists && scope.Keys.Count != 0)
            {
                throw new InvalidDataException($"Missing registry scope {scope.Scope} contains key data.");
            }

            HashSet<string> keyPaths = new(StringComparer.OrdinalIgnoreCase);
            foreach (RegistryKeyEntry key in scope.Keys)
            {
                if (key is null || key.Values is null || key.RelativePath is null)
                {
                    throw new InvalidDataException($"Registry scope {scope.Scope} contains an incomplete key entry.");
                }
                ValidateRelativeKeyPath(scope.Scope, key.RelativePath);
                if (!keyPaths.Add(key.RelativePath))
                {
                    throw new InvalidDataException($"Registry scope {scope.Scope} contains duplicate key {key.RelativePath}.");
                }

                HashSet<string> valueNames = new(StringComparer.OrdinalIgnoreCase);
                foreach (RegistryValueEntry value in key.Values)
                {
                    if (value is null || value.Name is null || value.Kind is null || value.DataBase64 is null ||
                        !valueNames.Add(value.Name))
                    {
                        throw new InvalidDataException($"Registry key {scope.Scope}\\{key.RelativePath} contains an invalid or duplicate value.");
                    }
                    ValidateRegistryValue(scope.Scope, key.RelativePath, value);
                }

                if (key.AccessRulesProtected is not null &&
                    string.IsNullOrWhiteSpace(key.SecurityDescriptorSddl) &&
                    string.IsNullOrWhiteSpace(key.SecurityDescriptorBase64))
                {
                    throw new InvalidDataException($"Registry key {scope.Scope}\\{key.RelativePath} has incomplete security metadata.");
                }
                if (!string.IsNullOrWhiteSpace(key.SecurityDescriptorSddl))
                {
                    try { _ = new RawSecurityDescriptor(key.SecurityDescriptorSddl); }
                    catch (ArgumentException exception)
                    {
                        throw new InvalidDataException($"Registry key {scope.Scope}\\{key.RelativePath} has an invalid SDDL descriptor.", exception);
                    }
                }
                if (!string.IsNullOrWhiteSpace(key.SecurityDescriptorBase64))
                {
                    try
                    {
                        byte[] descriptor = Convert.FromBase64String(key.SecurityDescriptorBase64);
                        _ = new RawSecurityDescriptor(descriptor, 0);
                    }
                    catch (Exception exception) when (exception is FormatException or ArgumentException)
                    {
                        throw new InvalidDataException($"Registry key {scope.Scope}\\{key.RelativePath} has an invalid security descriptor.", exception);
                    }
                }
            }
        }
    }

    public static List<string> Compare(RegistrySnapshot expected, RegistrySnapshot actual)
    {
        EnsureCompatibleScopes(expected, actual);
        List<string> differences = [];
        for (int i = 0; i < expected.Scopes.Count; i++)
        {
            RegistryScopeSnapshot left = expected.Scopes[i];
            RegistryScopeSnapshot right = actual.Scopes[i];
            if (left.Exists != right.Exists)
            {
                differences.Add($"registry-scope-existence:{left.Scope}");
                continue;
            }

            foreach (string key in CompareScope(left, right))
            {
                differences.Add($"registry-changed:{left.Scope}\\{key}".TrimEnd('\\'));
            }
        }
        return differences;
    }

    public static List<string> FindRollbackConflicts(
        RegistrySnapshot baseline,
        RegistrySnapshot after,
        RegistrySnapshot current)
    {
        EnsureCompatibleScopes(baseline, after);
        EnsureCompatibleScopes(after, current);
        List<string> conflicts = [];

        for (int i = 0; i < baseline.Scopes.Count; i++)
        {
            RegistryScopeSnapshot beforeScope = baseline.Scopes[i];
            RegistryScopeSnapshot afterScope = after.Scopes[i];
            RegistryScopeSnapshot currentScope = current.Scopes[i];
            HashSet<string> changed = CompareScope(beforeScope, afterScope).ToHashSet(StringComparer.OrdinalIgnoreCase);
            HashSet<string> drifted = CompareScope(afterScope, currentScope).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (string key in changed.Intersect(drifted, StringComparer.OrdinalIgnoreCase))
            {
                conflicts.Add($"registry-conflict:{beforeScope.Scope}\\{key}".TrimEnd('\\'));
            }
        }

        return conflicts;
    }

    public static void Restore(RegistrySnapshot baseline, RegistrySnapshot after)
    {
        EnsureCompatibleScopes(baseline, after);
        for (int i = 0; i < baseline.Scopes.Count; i++)
        {
            RegistryScopeSnapshot beforeScope = baseline.Scopes[i];
            RegistryScopeSnapshot afterScope = after.Scopes[i];
            RegistryLocation location = Parse(beforeScope.Scope);

            if (!beforeScope.Exists)
            {
                DeleteScope(location);
                continue;
            }

            using RegistryKey baseKey = location.Root.CreateSubKey(location.SubKey, writable: true)
                ?? throw new UnauthorizedAccessException($"Cannot create registry scope {beforeScope.Scope}.");

            Dictionary<string, RegistryKeyEntry> beforeKeys = beforeScope.Keys
                .ToDictionary(entry => entry.RelativePath, StringComparer.OrdinalIgnoreCase);
            Dictionary<string, RegistryKeyEntry> afterKeys = afterScope.Keys
                .ToDictionary(entry => entry.RelativePath, StringComparer.OrdinalIgnoreCase);

            foreach (string keyPath in afterKeys.Keys.Except(beforeKeys.Keys, StringComparer.OrdinalIgnoreCase)
                         .OrderByDescending(path => path.Length))
            {
                if (!string.IsNullOrEmpty(keyPath))
                {
                    baseKey.DeleteSubKeyTree(keyPath, throwOnMissingSubKey: false);
                }
            }

            foreach (RegistryKeyEntry beforeKey in beforeScope.Keys.OrderBy(entry => entry.RelativePath.Length))
            {
                RegistryKey? createdKey = null;
                RegistryKey target = baseKey;
                try
                {
                    if (!string.IsNullOrEmpty(beforeKey.RelativePath))
                    {
                        createdKey = baseKey.CreateSubKey(beforeKey.RelativePath, writable: true)
                            ?? throw new UnauthorizedAccessException($"Cannot restore registry key {beforeScope.Scope}\\{beforeKey.RelativePath}.");
                        target = createdKey;
                    }

                    afterKeys.TryGetValue(beforeKey.RelativePath, out RegistryKeyEntry? afterKey);
                    HashSet<string> baselineNames = beforeKey.Values.Select(value => value.Name)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);
                    if (afterKey is not null)
                    {
                        foreach (string createdValue in afterKey.Values.Select(value => value.Name)
                                     .Except(baselineNames, StringComparer.OrdinalIgnoreCase))
                        {
                            target.DeleteValue(createdValue, throwOnMissingValue: false);
                        }
                    }

                    foreach (RegistryValueEntry value in beforeKey.Values)
                    {
                        target.SetValue(value.Name, Decode(value), Enum.Parse<RegistryValueKind>(value.Kind));
                    }
                }
                finally
                {
                    createdKey?.Dispose();
                }
            }

            foreach (RegistryKeyEntry beforeKey in beforeScope.Keys.OrderByDescending(entry => entry.RelativePath.Length))
            {
                RegistryKey? child = null;
                try
                {
                    RegistryKey target = baseKey;
                    if (!string.IsNullOrEmpty(beforeKey.RelativePath))
                    {
                        child = baseKey.OpenSubKey(beforeKey.RelativePath, writable: true)
                            ?? throw new UnauthorizedAccessException($"Cannot restore registry security for {beforeScope.Scope}\\{beforeKey.RelativePath}.");
                        target = child;
                    }
                    RestoreSecurityDescriptor(target, beforeKey);
                }
                finally
                {
                    child?.Dispose();
                }
            }
        }
    }

    private static HashSet<string> CompareScope(RegistryScopeSnapshot left, RegistryScopeSnapshot right)
    {
        HashSet<string> differences = new(StringComparer.OrdinalIgnoreCase);
        if (left.Exists != right.Exists)
        {
            differences.Add(string.Empty);
        }

        Dictionary<string, RegistryKeyEntry> leftKeys = left.Keys.ToDictionary(key => key.RelativePath, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, RegistryKeyEntry> rightKeys = right.Keys.ToDictionary(key => key.RelativePath, StringComparer.OrdinalIgnoreCase);
        foreach (string keyPath in leftKeys.Keys.Union(rightKeys.Keys, StringComparer.OrdinalIgnoreCase))
        {
            if (!leftKeys.TryGetValue(keyPath, out RegistryKeyEntry? leftKey) ||
                !rightKeys.TryGetValue(keyPath, out RegistryKeyEntry? rightKey))
            {
                differences.Add(keyPath);
                continue;
            }

            if (!string.Equals(leftKey.SecurityDescriptorFingerprint, rightKey.SecurityDescriptorFingerprint, StringComparison.Ordinal))
            {
                differences.Add(string.IsNullOrEmpty(keyPath) ? "@security" : keyPath + "\\@security");
            }
            if (leftKey.AccessRulesProtected != rightKey.AccessRulesProtected)
            {
                differences.Add(string.IsNullOrEmpty(keyPath) ? "@inheritance" : keyPath + "\\@inheritance");
            }

            Dictionary<string, RegistryValueEntry> leftValues = leftKey.Values.ToDictionary(value => value.Name, StringComparer.OrdinalIgnoreCase);
            Dictionary<string, RegistryValueEntry> rightValues = rightKey.Values.ToDictionary(value => value.Name, StringComparer.OrdinalIgnoreCase);
            foreach (string valueName in leftValues.Keys.Union(rightValues.Keys, StringComparer.OrdinalIgnoreCase))
            {
                leftValues.TryGetValue(valueName, out RegistryValueEntry? leftValue);
                rightValues.TryGetValue(valueName, out RegistryValueEntry? rightValue);
                if (!Equivalent(leftValue, rightValue))
                {
                    differences.Add(string.IsNullOrEmpty(valueName) ? keyPath + "\\(Default)" : keyPath + "\\" + valueName);
                }
            }
        }
        return differences;
    }

    private static void CaptureKey(RegistryKey key, string relativePath, List<RegistryKeyEntry> keys)
    {
        List<RegistryValueEntry> values = [];
        foreach (string valueName in key.GetValueNames().OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            RegistryValueKind kind = key.GetValueKind(valueName);
            object value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames)
                ?? Array.Empty<byte>();
            values.Add(new RegistryValueEntry
            {
                Name = valueName,
                Kind = kind.ToString(),
                DataBase64 = Convert.ToBase64String(Encode(kind, value))
            });
        }

        (string? descriptor, string? fingerprint, bool? protectedRules) = TryGetSecurityDescriptor(key);
        keys.Add(new RegistryKeyEntry
        {
            RelativePath = relativePath,
            Values = values,
            SecurityDescriptorSddl = descriptor,
            SecurityDescriptorFingerprint = fingerprint,
            AccessRulesProtected = protectedRules
        });
        foreach (string childName in key.GetSubKeyNames().OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            using RegistryKey? child = key.OpenSubKey(childName, writable: false);
            if (child is null)
            {
                continue;
            }

            string childPath = string.IsNullOrEmpty(relativePath) ? childName : relativePath + "\\" + childName;
            CaptureKey(child, childPath, keys);
        }
    }

    private static byte[] Encode(RegistryValueKind kind, object value) => kind switch
    {
        RegistryValueKind.String or RegistryValueKind.ExpandString => Encoding.UTF8.GetBytes((string)value),
        RegistryValueKind.MultiString => JsonSerializer.SerializeToUtf8Bytes((string[])value),
        RegistryValueKind.DWord => BitConverter.GetBytes(Convert.ToInt32(value)),
        RegistryValueKind.QWord => BitConverter.GetBytes(Convert.ToInt64(value)),
        RegistryValueKind.Binary or RegistryValueKind.None => (byte[])value,
        _ => throw new NotSupportedException($"Registry value kind {kind} is not supported.")
    };

    private static object Decode(RegistryValueEntry entry)
    {
        byte[] bytes = Convert.FromBase64String(entry.DataBase64);
        RegistryValueKind kind = Enum.Parse<RegistryValueKind>(entry.Kind);
        return kind switch
        {
            RegistryValueKind.String or RegistryValueKind.ExpandString => Encoding.UTF8.GetString(bytes),
            RegistryValueKind.MultiString => JsonSerializer.Deserialize<string[]>(bytes) ?? [],
            RegistryValueKind.DWord => BitConverter.ToInt32(bytes),
            RegistryValueKind.QWord => BitConverter.ToInt64(bytes),
            RegistryValueKind.Binary or RegistryValueKind.None => bytes,
            _ => throw new NotSupportedException($"Registry value kind {kind} is not supported.")
        };
    }

    private static bool Equivalent(RegistryValueEntry? left, RegistryValueEntry? right) =>
        left is null
            ? right is null
            : right is not null &&
              string.Equals(left.Kind, right.Kind, StringComparison.Ordinal) &&
              string.Equals(left.DataBase64, right.DataBase64, StringComparison.Ordinal);

    private static (string? Sddl, string? Fingerprint, bool? Protected) TryGetSecurityDescriptor(RegistryKey key)
    {
        try
        {
            RegistrySecurity security = key.GetAccessControl(AccessControlSections.Access);
            return (
                security.GetSecurityDescriptorSddlForm(AccessControlSections.Access),
                AccessRuleFingerprint(security),
                security.AreAccessRulesProtected);
        }
        catch (UnauthorizedAccessException) { return (null, null, null); }
        catch (System.Security.SecurityException) { return (null, null, null); }
        catch (PlatformNotSupportedException) { return (null, null, null); }
    }

    private static string AccessRuleFingerprint(RegistrySecurity security)
    {
        return string.Join('\n', security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<RegistryAccessRule>()
            .Select(rule => string.Join('|',
                ((SecurityIdentifier)rule.IdentityReference).Value,
                rule.AccessControlType,
                (int)rule.RegistryRights,
                rule.InheritanceFlags,
                rule.PropagationFlags,
                rule.IsInherited))
            .OrderBy(value => value, StringComparer.Ordinal));
    }

    private static void RestoreSecurityDescriptor(RegistryKey key, RegistryKeyEntry entry)
    {
        string? sddl = entry.SecurityDescriptorSddl;
        if (string.IsNullOrWhiteSpace(sddl) && string.IsNullOrWhiteSpace(entry.SecurityDescriptorBase64)) return;
        RegistrySecurity security = new();
        if (!string.IsNullOrWhiteSpace(sddl))
        {
            security.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
        }
        else
        {
            security.SetSecurityDescriptorBinaryForm(Convert.FromBase64String(entry.SecurityDescriptorBase64!), AccessControlSections.Access);
        }
        if (entry.AccessRulesProtected is bool protectedRules)
        {
            security.SetAccessRuleProtection(protectedRules, preserveInheritance: false);
        }
        key.SetAccessControl(security);
    }

    private static string NormalizeScope(string scope)
    {
        string value = scope.Trim().TrimEnd('\\');
        RegistryLocation location = Parse(value);
        if (string.IsNullOrWhiteSpace(location.SubKey))
        {
            throw new ArgumentException("A registry scope must identify a subkey, not an entire hive.");
        }
        return location.Canonical;
    }

    private static List<string> NormalizeScopes(IEnumerable<string> requestedScopes)
    {
        ArgumentNullException.ThrowIfNull(requestedScopes);
        return requestedScopes.Select(scope =>
            {
                if (string.IsNullOrWhiteSpace(scope))
                {
                    throw new InvalidDataException("Registry scope cannot be empty.");
                }
                return NormalizeScope(scope);
            })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void ValidateRelativeKeyPath(string scope, string relativePath)
    {
        if (relativePath.StartsWith('\\') || relativePath.EndsWith('\\') || relativePath.Contains("\\\\", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Registry scope {scope} contains an unsafe relative key path: {relativePath}.");
        }
    }

    private static void ValidateRegistryValue(string scope, string keyPath, RegistryValueEntry value)
    {
        if (!Enum.TryParse(value.Kind, ignoreCase: false, out RegistryValueKind kind) ||
            !Enum.IsDefined(kind))
        {
            throw new InvalidDataException($"Registry value {scope}\\{keyPath}\\{value.Name} has an invalid kind.");
        }

        byte[] bytes;
        try { bytes = Convert.FromBase64String(value.DataBase64); }
        catch (FormatException exception)
        {
            throw new InvalidDataException($"Registry value {scope}\\{keyPath}\\{value.Name} has invalid encoded data.", exception);
        }
        if ((kind == RegistryValueKind.DWord && bytes.Length != sizeof(int)) ||
            (kind == RegistryValueKind.QWord && bytes.Length != sizeof(long)))
        {
            throw new InvalidDataException($"Registry value {scope}\\{keyPath}\\{value.Name} has an invalid encoded length.");
        }
        if (kind == RegistryValueKind.MultiString)
        {
            try
            {
                if (JsonSerializer.Deserialize<string[]>(bytes) is null)
                {
                    throw new JsonException("Multi-string value decoded to null.");
                }
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException($"Registry value {scope}\\{keyPath}\\{value.Name} has invalid multi-string data.", exception);
            }
        }
    }

    private static RegistryLocation Parse(string scope)
    {
        string normalized = scope.Replace('/', '\\').Trim().TrimEnd('\\');
        int separator = normalized.IndexOf('\\');
        string hive = separator < 0 ? normalized : normalized[..separator];
        string subKey = separator < 0 ? string.Empty : normalized[(separator + 1)..];
        return hive.ToUpperInvariant() switch
        {
            "HKCU" or "HKEY_CURRENT_USER" => new RegistryLocation(Registry.CurrentUser, "HKCU", subKey),
            "HKLM" or "HKEY_LOCAL_MACHINE" => new RegistryLocation(Registry.LocalMachine, "HKLM", subKey),
            "HKCR" or "HKEY_CLASSES_ROOT" => new RegistryLocation(Registry.ClassesRoot, "HKCR", subKey),
            "HKU" or "HKEY_USERS" => new RegistryLocation(Registry.Users, "HKU", subKey),
            "HKCC" or "HKEY_CURRENT_CONFIG" => new RegistryLocation(Registry.CurrentConfig, "HKCC", subKey),
            _ => throw new ArgumentException($"Unsupported registry hive in scope: {scope}")
        };
    }

    private static void DeleteScope(RegistryLocation location)
    {
        int separator = location.SubKey.LastIndexOf('\\');
        string parentPath = separator < 0 ? string.Empty : location.SubKey[..separator];
        string childName = separator < 0 ? location.SubKey : location.SubKey[(separator + 1)..];
        if (string.IsNullOrEmpty(parentPath))
        {
            location.Root.DeleteSubKeyTree(childName, throwOnMissingSubKey: false);
        }
        else
        {
            using RegistryKey? parent = location.Root.OpenSubKey(parentPath, writable: true);
            parent?.DeleteSubKeyTree(childName, throwOnMissingSubKey: false);
        }
    }

    private static void EnsureCompatibleScopes(RegistrySnapshot left, RegistrySnapshot right)
    {
        if (!left.Scopes.Select(scope => scope.Scope)
            .SequenceEqual(right.Scopes.Select(scope => scope.Scope), StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Registry snapshot scopes do not match.");
        }
    }

    private readonly record struct RegistryLocation(RegistryKey Root, string Hive, string SubKey)
    {
        public string Canonical => Hive + "\\" + SubKey;
    }
}
