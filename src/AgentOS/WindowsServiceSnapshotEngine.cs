using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AgentOS;

internal static class WindowsServiceSnapshotEngine
{
    private static readonly Regex StatePattern = new(@"STATE\s*:\s*(\d+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FieldPattern = new(
        @"^\s*(TYPE|START_TYPE|ERROR_CONTROL|BINARY_PATH_NAME|LOAD_ORDER_GROUP|TAG|DISPLAY_NAME|DEPENDENCIES|SERVICE_START_NAME)\s*:\s*(.*)\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Multiline);

    public static ServiceSnapshot Capture(IEnumerable<string> requestedServices)
    {
        List<ServiceEntry> entries = Normalize(requestedServices).Select(CaptureOne).ToList();
        return new ServiceSnapshot { Entries = entries };
    }

    public static IEnumerable<string> RegistryScopes(IEnumerable<string> services) =>
        Normalize(services).Select(name => "HKLM\\SYSTEM\\CurrentControlSet\\Services\\" + name);

    public static void Validate(ServiceSnapshot snapshot, IEnumerable<string> declaredServices)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.Entries is null)
        {
            throw new InvalidDataException("Service snapshot is missing entries.");
        }

        List<string> declared = declaredServices?.ToList()
            ?? throw new InvalidDataException("Transaction manifest is missing service scopes.");
        List<string> expected = Normalize(declared);
        if (declared.Count != expected.Count)
        {
            throw new InvalidDataException("Transaction manifest contains duplicate or empty service scopes.");
        }
        if (snapshot.Entries.Any(entry => entry is null) ||
            !snapshot.Entries.Select(entry => entry.Name).SequenceEqual(expected, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Service snapshot entries do not match the transaction manifest.");
        }
        if (snapshot.Entries.GroupBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase).Any(group => group.Count() != 1))
        {
            throw new InvalidDataException("Service snapshot contains duplicate entries.");
        }
        foreach (ServiceEntry entry in snapshot.Entries)
        {
            if ((!entry.Exists && (entry.Configuration is not null || entry.StateCode is not null || entry.BinaryPathName is not null)) ||
                (entry.Exists && string.IsNullOrWhiteSpace(entry.Configuration)) ||
                entry.StateCode is < 1 or > 7)
            {
                throw new InvalidDataException($"Service snapshot entry {entry.Name} has inconsistent recovery metadata.");
            }
            if (entry.Exists && string.IsNullOrWhiteSpace(entry.StartType))
            {
                throw new InvalidDataException($"Service snapshot entry {entry.Name} is missing structured start type.");
            }
        }
    }

    public static List<string> Compare(ServiceSnapshot expected, ServiceSnapshot actual)
    {
        Dictionary<string, ServiceEntry> left = expected.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ServiceEntry> right = actual.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        return left.Keys.Union(right.Keys, StringComparer.OrdinalIgnoreCase)
            .Where(name => !Equivalent(left.GetValueOrDefault(name), right.GetValueOrDefault(name)))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Select(name => "service-changed:" + name)
            .ToList();
    }

    public static List<string> FindRollbackConflicts(ServiceSnapshot baseline, ServiceSnapshot after, ServiceSnapshot current)
    {
        Dictionary<string, ServiceEntry> before = baseline.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ServiceEntry> afterMap = after.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ServiceEntry> currentMap = current.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        return before.Keys.Union(afterMap.Keys, StringComparer.OrdinalIgnoreCase)
            .Where(name => !Equivalent(before.GetValueOrDefault(name), afterMap.GetValueOrDefault(name)))
            .Where(name => !Equivalent(afterMap.GetValueOrDefault(name), currentMap.GetValueOrDefault(name)))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Select(name => "service-conflict:" + name)
            .ToList();
    }

    public static void Restore(ServiceSnapshot baseline, ServiceSnapshot after)
    {
        Dictionary<string, ServiceEntry> before = baseline.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ServiceEntry> afterMap = after.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        foreach (string name in before.Keys.Union(afterMap.Keys, StringComparer.OrdinalIgnoreCase)
                     .Where(name => !Equivalent(before.GetValueOrDefault(name), afterMap.GetValueOrDefault(name))))
        {
            before.TryGetValue(name, out ServiceEntry? baselineEntry);
            afterMap.TryGetValue(name, out ServiceEntry? afterEntry);
            if (baselineEntry is null || !baselineEntry.Exists)
            {
                StopIgnoringNotActive(name);
                WindowsCommandResult deleted = WindowsCommand.Run("sc.exe", "delete", name);
                if (deleted.ExitCode != 0 && !ContainsNotFound(deleted))
                {
                    throw new InvalidOperationException($"Could not delete created service {name}: {deleted.StandardError} {deleted.StandardOutput}".Trim());
                }
                continue;
            }

            if (!string.IsNullOrWhiteSpace(baselineEntry.StartType) &&
                afterEntry is not null &&
                !string.Equals(baselineEntry.StartType, afterEntry.StartType, StringComparison.OrdinalIgnoreCase))
            {
                string startArg = ToScStartArg(baselineEntry.StartType);
                WindowsCommandResult configured = WindowsCommand.Run("sc.exe", "config", name, "start=", startArg);
                if (configured.ExitCode != 0)
                {
                    throw new InvalidOperationException(
                        $"Could not restore start type for service {name}: {configured.StandardError} {configured.StandardOutput}".Trim());
                }
            }

            if (baselineEntry.StateCode == 4)
            {
                WindowsCommandResult started = WindowsCommand.Run("sc.exe", "start", name);
                if (started.ExitCode != 0 && !ContainsAlreadyRunning(started))
                {
                    throw new InvalidOperationException($"Could not start service {name}: {started.StandardError} {started.StandardOutput}".Trim());
                }
            }
            else
            {
                StopIgnoringNotActive(name);
            }
        }
    }

    private static ServiceEntry CaptureOne(string name)
    {
        WindowsCommandResult configuration = WindowsCommand.Run("sc.exe", "qc", name);
        if (configuration.ExitCode != 0)
        {
            return new ServiceEntry { Name = name, Exists = false };
        }

        WindowsCommandResult status = WindowsCommand.Run("sc.exe", "query", name);
        Match state = StatePattern.Match(status.StandardOutput);
        Dictionary<string, string> fields = ParseQcFields(configuration.StandardOutput);
        RegistryServiceMetadata registry = ReadRegistryMetadata(name);

        return new ServiceEntry
        {
            Name = name,
            Exists = true,
            Configuration = configuration.StandardOutput.Trim(),
            StateCode = state.Success ? int.Parse(state.Groups[1].Value) : null,
            DisplayName = FirstNonEmpty(fields.GetValueOrDefault("DISPLAY_NAME"), registry.DisplayName),
            StartType = NormalizeStartType(fields.GetValueOrDefault("START_TYPE"), registry.Start),
            ServiceType = FirstNonEmpty(fields.GetValueOrDefault("TYPE"), registry.Type),
            BinaryPathName = FirstNonEmpty(fields.GetValueOrDefault("BINARY_PATH_NAME"), registry.ImagePath),
            ServiceAccount = FirstNonEmpty(fields.GetValueOrDefault("SERVICE_START_NAME"), registry.ObjectName),
            Dependencies = FirstNonEmpty(fields.GetValueOrDefault("DEPENDENCIES"), registry.DependOnService),
            ErrorControl = FirstNonEmpty(fields.GetValueOrDefault("ERROR_CONTROL"), registry.ErrorControl)
        };
    }

    private static Dictionary<string, string> ParseQcFields(string output)
    {
        Dictionary<string, string> fields = new(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in FieldPattern.Matches(output))
        {
            fields[match.Groups[1].Value.Trim()] = match.Groups[2].Value.Trim();
        }
        return fields;
    }

    private static RegistryServiceMetadata ReadRegistryMetadata(string serviceName)
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName);
            if (key is null)
            {
                return default;
            }

            string? depend = key.GetValue("DependOnService") switch
            {
                string[] values => string.Join('/', values),
                string value => value,
                _ => null
            };

            return new RegistryServiceMetadata(
                DisplayName: key.GetValue("DisplayName") as string,
                ImagePath: key.GetValue("ImagePath") as string,
                ObjectName: key.GetValue("ObjectName") as string,
                Start: key.GetValue("Start")?.ToString(),
                Type: key.GetValue("Type")?.ToString(),
                ErrorControl: key.GetValue("ErrorControl")?.ToString(),
                DependOnService: depend);
        }
        catch
        {
            return default;
        }
    }

    private static string? NormalizeStartType(string? scField, string? registryStart)
    {
        if (!string.IsNullOrWhiteSpace(scField))
        {
            string[] parts = scField.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length >= 2)
            {
                return parts[^1].ToUpperInvariant();
            }
            return scField.Trim().ToUpperInvariant();
        }

        return registryStart switch
        {
            "0" => "BOOT_START",
            "1" => "SYSTEM_START",
            "2" => "AUTO_START",
            "3" => "DEMAND_START",
            "4" => "DISABLED",
            _ => null
        };
    }

    private static string ToScStartArg(string startType) => startType.Trim().ToUpperInvariant() switch
    {
        "BOOT_START" or "BOOT" => "boot",
        "SYSTEM_START" or "SYSTEM" => "system",
        "AUTO_START" or "AUTO" or "AUTOMATIC" => "auto",
        "DEMAND_START" or "DEMAND" or "MANUAL" => "demand",
        "DISABLED" or "DISABLE" => "disabled",
        "DELAYED_AUTO_START" => "delayed-auto",
        _ => throw new InvalidDataException($"Unsupported service start type for restore: {startType}")
    };

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

    private static List<string> Normalize(IEnumerable<string> services) => services
        .Select(name => name.Trim())
        .Where(name => !string.IsNullOrWhiteSpace(name))
        .Select(name => name.Length <= 256 &&
                        !name.Any(character => char.IsControl(character) || character is '\\' or '/')
            ? name
            : throw new ArgumentException($"Invalid Windows service name: {name}."))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static bool Equivalent(ServiceEntry? left, ServiceEntry? right) =>
        left is null ? right is null : right is not null &&
        left.Exists == right.Exists &&
        left.StateCode == right.StateCode &&
        string.Equals(left.StartType, right.StartType, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.ServiceType, right.ServiceType, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.BinaryPathName, right.BinaryPathName, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.ServiceAccount, right.ServiceAccount, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Dependencies, right.Dependencies, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.DisplayName, right.DisplayName, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.ErrorControl, right.ErrorControl, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Configuration, right.Configuration, StringComparison.Ordinal);

    private static void StopIgnoringNotActive(string name)
    {
        WindowsCommandResult stopped = WindowsCommand.Run("sc.exe", "stop", name);
        if (stopped.ExitCode != 0 && !ContainsNotActive(stopped) && !ContainsNotFound(stopped))
        {
            throw new InvalidOperationException($"Could not stop service {name}: {stopped.StandardError} {stopped.StandardOutput}".Trim());
        }
    }

    private static bool ContainsNotActive(WindowsCommandResult result) =>
        (result.StandardError + result.StandardOutput).Contains("1062", StringComparison.Ordinal);
    private static bool ContainsAlreadyRunning(WindowsCommandResult result) =>
        (result.StandardError + result.StandardOutput).Contains("1056", StringComparison.Ordinal);
    private static bool ContainsNotFound(WindowsCommandResult result) =>
        (result.StandardError + result.StandardOutput).Contains("1060", StringComparison.Ordinal);

    private readonly record struct RegistryServiceMetadata(
        string? DisplayName,
        string? ImagePath,
        string? ObjectName,
        string? Start,
        string? Type,
        string? ErrorControl,
        string? DependOnService);
}
