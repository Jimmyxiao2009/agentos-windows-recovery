using System.Xml.Linq;

namespace AgentOS;

internal static class ScheduledTaskSnapshotEngine
{
    private static readonly XNamespace TaskNs = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static ScheduledTaskSnapshot Capture(IEnumerable<string> requestedTasks) => new()
    {
        Entries = Normalize(requestedTasks).Select(CaptureOne).ToList()
    };

    public static void Validate(ScheduledTaskSnapshot snapshot, IEnumerable<string> declaredTasks)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.Entries is null)
        {
            throw new InvalidDataException("Scheduled-task snapshot is missing entries.");
        }

        List<string> declared = declaredTasks?.ToList()
            ?? throw new InvalidDataException("Transaction manifest is missing scheduled-task scopes.");
        List<string> expected = Normalize(declared);
        if (declared.Count != expected.Count)
        {
            throw new InvalidDataException("Transaction manifest contains duplicate or empty scheduled-task scopes.");
        }
        if (snapshot.Entries.Any(entry => entry is null) ||
            !snapshot.Entries.Select(entry => entry.Name).SequenceEqual(expected, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Scheduled-task snapshot entries do not match the transaction manifest.");
        }
        if (snapshot.Entries.GroupBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase).Any(group => group.Count() != 1))
        {
            throw new InvalidDataException("Scheduled-task snapshot contains duplicate entries.");
        }
        foreach (ScheduledTaskEntry entry in snapshot.Entries)
        {
            if (entry.Exists && string.IsNullOrWhiteSpace(entry.Xml))
            {
                throw new InvalidDataException($"Scheduled task {entry.Name} exists but has no recovery XML.");
            }
            if (!entry.Exists && entry.Xml is not null)
            {
                throw new InvalidDataException($"Missing scheduled task {entry.Name} unexpectedly contains recovery XML.");
            }
            if (entry.Exists)
            {
                try { _ = XDocument.Parse(entry.Xml!, LoadOptions.None); }
                catch (System.Xml.XmlException exception)
                {
                    throw new InvalidDataException($"Scheduled task {entry.Name} contains invalid recovery XML.", exception);
                }
            }
        }
    }

    public static List<string> Compare(ScheduledTaskSnapshot expected, ScheduledTaskSnapshot actual)
    {
        Dictionary<string, ScheduledTaskEntry> left = expected.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ScheduledTaskEntry> right = actual.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        return left.Keys.Union(right.Keys, StringComparer.OrdinalIgnoreCase)
            .Where(name => !Equivalent(left.GetValueOrDefault(name), right.GetValueOrDefault(name)))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Select(name => "scheduled-task-changed:" + name)
            .ToList();
    }

    public static List<string> FindRollbackConflicts(ScheduledTaskSnapshot baseline, ScheduledTaskSnapshot after, ScheduledTaskSnapshot current)
    {
        Dictionary<string, ScheduledTaskEntry> before = baseline.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ScheduledTaskEntry> afterMap = after.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ScheduledTaskEntry> currentMap = current.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        return before.Keys.Union(afterMap.Keys, StringComparer.OrdinalIgnoreCase)
            .Where(name => !Equivalent(before.GetValueOrDefault(name), afterMap.GetValueOrDefault(name)))
            .Where(name => !Equivalent(afterMap.GetValueOrDefault(name), currentMap.GetValueOrDefault(name)))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Select(name => "scheduled-task-conflict:" + name)
            .ToList();
    }

    public static void Restore(ScheduledTaskSnapshot baseline, ScheduledTaskSnapshot after)
    {
        Dictionary<string, ScheduledTaskEntry> before = baseline.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ScheduledTaskEntry> afterMap = after.Entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        foreach (string name in before.Keys.Union(afterMap.Keys, StringComparer.OrdinalIgnoreCase)
                     .Where(name => !Equivalent(before.GetValueOrDefault(name), afterMap.GetValueOrDefault(name))))
        {
            before.TryGetValue(name, out ScheduledTaskEntry? baselineEntry);
            if (baselineEntry is null || !baselineEntry.Exists)
            {
                WindowsCommandResult deleted = WindowsCommand.Run("schtasks.exe", "/delete", "/tn", name, "/f");
                if (deleted.ExitCode != 0)
                {
                    throw new InvalidOperationException($"Could not delete scheduled task {name}: {deleted.StandardError} {deleted.StandardOutput}".Trim());
                }
                continue;
            }

            string temporaryXml = Path.Combine(Path.GetTempPath(), "AgentOS-TaskRestore-" + Guid.NewGuid().ToString("N") + ".xml");
            try
            {
                File.WriteAllText(temporaryXml, baselineEntry.Xml ?? string.Empty);
                WindowsCommand.RequireSuccess("Scheduled task restore", "schtasks.exe", "/create", "/tn", name, "/xml", temporaryXml, "/f");
            }
            finally
            {
                if (File.Exists(temporaryXml))
                {
                    File.Delete(temporaryXml);
                }
            }
        }
    }

    private static ScheduledTaskEntry CaptureOne(string name)
    {
        WindowsCommandResult result = WindowsCommand.Run("schtasks.exe", "/query", "/tn", name, "/xml");
        if (result.ExitCode != 0)
        {
            return new ScheduledTaskEntry { Name = name, Exists = false };
        }

        string xml = result.StandardOutput;
        StructuredTaskMetadata metadata = ParseStructuredMetadata(xml);
        return new ScheduledTaskEntry
        {
            Name = name,
            Exists = true,
            Xml = xml,
            Author = metadata.Author,
            Description = metadata.Description,
            PrincipalUserId = metadata.PrincipalUserId,
            LogonType = metadata.LogonType,
            RunLevel = metadata.RunLevel,
            Enabled = metadata.Enabled,
            ActionsSummary = metadata.ActionsSummary,
            TriggersSummary = metadata.TriggersSummary
        };
    }

    private static StructuredTaskMetadata ParseStructuredMetadata(string xml)
    {
        try
        {
            XDocument document = XDocument.Parse(xml, LoadOptions.None);
            XElement? root = document.Root;
            if (root is null)
            {
                return default;
            }

            XElement? registration = root.Element(TaskNs + "RegistrationInfo") ?? root.Element("RegistrationInfo");
            XElement? principals = root.Element(TaskNs + "Principals") ?? root.Element("Principals");
            XElement? principal = principals?.Elements().FirstOrDefault(element =>
                element.Name.LocalName.Equals("Principal", StringComparison.OrdinalIgnoreCase));
            XElement? settings = root.Element(TaskNs + "Settings") ?? root.Element("Settings");
            XElement? actions = root.Element(TaskNs + "Actions") ?? root.Element("Actions");
            XElement? triggers = root.Element(TaskNs + "Triggers") ?? root.Element("Triggers");

            string? enabledText = settings?.Elements().FirstOrDefault(element =>
                element.Name.LocalName.Equals("Enabled", StringComparison.OrdinalIgnoreCase))?.Value;
            bool? enabled = bool.TryParse(enabledText, out bool parsed) ? parsed : null;

            List<string> actionParts = [];
            if (actions is not null)
            {
                foreach (XElement action in actions.Elements())
                {
                    string local = action.Name.LocalName;
                    if (local.Equals("Exec", StringComparison.OrdinalIgnoreCase))
                    {
                        string command = action.Elements().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value ?? "";
                        string args = action.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value ?? "";
                        actionParts.Add(("exec:" + command + " " + args).Trim());
                    }
                    else
                    {
                        actionParts.Add(local.ToLowerInvariant());
                    }
                }
            }

            List<string> triggerParts = [];
            if (triggers is not null)
            {
                foreach (XElement trigger in triggers.Elements())
                {
                    triggerParts.Add(trigger.Name.LocalName);
                }
            }

            return new StructuredTaskMetadata(
                Author: registration?.Elements().FirstOrDefault(e => e.Name.LocalName == "Author")?.Value,
                Description: registration?.Elements().FirstOrDefault(e => e.Name.LocalName == "Description")?.Value,
                PrincipalUserId: principal?.Elements().FirstOrDefault(e => e.Name.LocalName is "UserId" or "GroupId")?.Value,
                LogonType: principal?.Elements().FirstOrDefault(e => e.Name.LocalName == "LogonType")?.Value,
                RunLevel: principal?.Elements().FirstOrDefault(e => e.Name.LocalName == "RunLevel")?.Value,
                Enabled: enabled,
                ActionsSummary: actionParts.Count == 0 ? null : string.Join(" | ", actionParts),
                TriggersSummary: triggerParts.Count == 0 ? null : string.Join(",", triggerParts));
        }
        catch
        {
            return default;
        }
    }

    private static List<string> Normalize(IEnumerable<string> tasks) => tasks
        .Select(task => task.Trim())
        .Where(task => !string.IsNullOrWhiteSpace(task))
        .Select(task => task.StartsWith('\\') ? task : "\\" + task)
        .Select(ValidateTaskName)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(task => task, StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static string ValidateTaskName(string task)
    {
        string[] segments = task.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (task.Length > 238 || task.Contains("\\\\", StringComparison.Ordinal) ||
            segments.Length == 0 || segments.Any(segment =>
                segment is "." or ".." || segment.Any(character => char.IsControl(character) || character == '/')))
        {
            throw new ArgumentException($"Invalid scheduled-task path: {task}.");
        }
        return task;
    }

    private static bool Equivalent(ScheduledTaskEntry? left, ScheduledTaskEntry? right) =>
        left is null ? right is null : right is not null && left.Exists == right.Exists &&
        string.Equals(left.Xml, right.Xml, StringComparison.Ordinal) &&
        string.Equals(left.Author, right.Author, StringComparison.Ordinal) &&
        string.Equals(left.Description, right.Description, StringComparison.Ordinal) &&
        string.Equals(left.PrincipalUserId, right.PrincipalUserId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.LogonType, right.LogonType, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.RunLevel, right.RunLevel, StringComparison.OrdinalIgnoreCase) &&
        left.Enabled == right.Enabled &&
        string.Equals(left.ActionsSummary, right.ActionsSummary, StringComparison.Ordinal) &&
        string.Equals(left.TriggersSummary, right.TriggersSummary, StringComparison.Ordinal);

    private readonly record struct StructuredTaskMetadata(
        string? Author,
        string? Description,
        string? PrincipalUserId,
        string? LogonType,
        string? RunLevel,
        bool? Enabled,
        string? ActionsSummary,
        string? TriggersSummary);
}
