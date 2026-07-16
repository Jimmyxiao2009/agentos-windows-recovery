using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace AgentOS;

/// <summary>
/// Best-effort store hardening for the user-mode MVP:
/// 1) restrict the transaction root ACL to the current user + Administrators + SYSTEM;
/// 2) maintain a CurrentUser DPAPI-protected HMAC key for evidence-root authentication.
/// This raises the bar against casual same-session tampering, but is not a strong broker identity.
/// </summary>
internal static class StoreProtection
{
    public const string KeyFileName = "store-mac.key";
    public const string MacFileName = "evidence.mac";

    public static void HardenRoot(string root)
    {
        Directory.CreateDirectory(root);
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            DirectoryInfo info = new(root);
            DirectorySecurity security = info.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(NTAccount)).Cast<FileSystemAccessRule>().ToList())
            {
                security.RemoveAccessRule(rule);
            }

            security.AddAccessRule(CreateRule(WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException("Current Windows identity has no SID."),
                FileSystemRights.FullControl));
            security.AddAccessRule(CreateRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl));
            security.AddAccessRule(CreateRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl));
            info.SetAccessControl(security);
        }
        catch (Exception exception) when (exception is IdentityNotMappedException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // ACL hardening is best-effort; recovery still works without it.
        }
    }

    public static void WriteEvidenceMac(string transactionDirectory, IEnumerable<string> evidenceFiles)
    {
        Directory.CreateDirectory(transactionDirectory);
        string root = Path.GetDirectoryName(transactionDirectory)
            ?? throw new InvalidDataException("Transaction directory has no parent store root.");
        byte[] key = LoadOrCreateKey(root);
        string payload = BuildPayload(transactionDirectory, evidenceFiles);
        using HMACSHA256 hmac = new(key);
        string mac = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        File.WriteAllText(Path.Combine(transactionDirectory, MacFileName), mac + Environment.NewLine);
    }

    public static void ValidateEvidenceMac(string transactionDirectory, IEnumerable<string> evidenceFiles)
    {
        string root = Path.GetDirectoryName(transactionDirectory)
            ?? throw new InvalidDataException("Transaction directory has no parent store root.");
        string macPath = Path.Combine(transactionDirectory, MacFileName);
        if (!File.Exists(macPath))
        {
            // Legacy transactions created before MAC support remain readable.
            return;
        }

        byte[] key = LoadOrCreateKey(root);
        string expected = File.ReadAllText(macPath).Trim();
        string payload = BuildPayload(transactionDirectory, evidenceFiles);
        using HMACSHA256 hmac = new(key);
        string actual = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(actual),
                Encoding.UTF8.GetBytes(expected.ToLowerInvariant())))
        {
            throw new InvalidDataException("Evidence root MAC validation failed.");
        }
    }

    private static string BuildPayload(string transactionDirectory, IEnumerable<string> evidenceFiles)
    {
        SortedDictionary<string, string> hashes = new(StringComparer.OrdinalIgnoreCase);
        foreach (string file in evidenceFiles
                     .Select(Path.GetFullPath)
                     .Where(File.Exists)
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            string relative = Path.GetRelativePath(transactionDirectory, file).Replace('\\', '/');
            hashes[relative] = EvidenceIntegrity.HashFile(file);
        }

        StringBuilder builder = new();
        builder.Append("agentos-evidence-mac-v1\n");
        foreach ((string name, string hash) in hashes)
        {
            builder.Append(name).Append('=').Append(hash).Append('\n');
        }
        return builder.ToString();
    }

    private static byte[] LoadOrCreateKey(string root)
    {
        string path = Path.Combine(root, KeyFileName);
        if (File.Exists(path))
        {
            byte[] protectedKey = Convert.FromBase64String(File.ReadAllText(path).Trim());
            return ProtectedData.Unprotect(protectedKey, optionalEntropy: null, DataProtectionScope.CurrentUser);
        }

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] protectedBytes = ProtectedData.Protect(key, optionalEntropy: null, DataProtectionScope.CurrentUser);
        File.WriteAllText(path, Convert.ToBase64String(protectedBytes));
        try
        {
            FileInfo info = new(path);
            FileSecurity security = info.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(NTAccount)).Cast<FileSystemAccessRule>().ToList())
            {
                security.RemoveAccessRule(rule);
            }
            security.AddAccessRule(CreateFileRule(WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException("Current Windows identity has no SID."),
                FileSystemRights.FullControl));
            security.AddAccessRule(CreateFileRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl));
            security.AddAccessRule(CreateFileRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl));
            info.SetAccessControl(security);
        }
        catch
        {
            // Key usability is more important than perfect ACL application in self-test temp dirs.
        }
        return key;
    }

    private static FileSystemAccessRule CreateRule(IdentityReference identity, FileSystemRights rights) =>
        new(identity, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow);

    private static FileSystemAccessRule CreateFileRule(IdentityReference identity, FileSystemRights rights) =>
        new(identity, rights, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
}
