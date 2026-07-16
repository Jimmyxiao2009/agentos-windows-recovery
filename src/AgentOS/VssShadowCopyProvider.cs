using System.Diagnostics;
using System.Text.Json;

namespace AgentOS;

internal sealed class VssShadowCopyProvider
{
    public static readonly string PowerShellPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "WindowsPowerShell", "v1.0", "powershell.exe");

    public IReadOnlyList<VssSnapshotMetadata> CreateForScopes(IEnumerable<string> fileScopes)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("VSS is only available on Windows.");
        }
        if (!RuntimeCapabilities.IsElevated())
        {
            throw new UnauthorizedAccessException("FullRecovery requires an elevated Administrator token to create VSS snapshots.");
        }
        if (!File.Exists(PowerShellPath))
        {
            throw new FileNotFoundException("Windows PowerShell is required for the VSS integration.", PowerShellPath);
        }

        List<string> volumes = fileScopes.Select(GetVolumeRoot)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        List<VssSnapshotMetadata> created = [];
        try
        {
            foreach (string volume in volumes)
            {
                created.Add(Create(volume));
            }
            return created;
        }
        catch
        {
            foreach (VssSnapshotMetadata snapshot in created)
            {
                try { Delete(snapshot); } catch { }
            }
            throw;
        }
    }

    public void Delete(VssSnapshotMetadata snapshot)
    {
        if (!RuntimeCapabilities.IsElevated())
        {
            throw new UnauthorizedAccessException("Deleting a VSS snapshot requires an elevated Administrator token.");
        }
        string id = snapshot.Id.Replace("'", "''", StringComparison.Ordinal);
        RunPowerShell("$ErrorActionPreference='Stop'; " +
                      "$shadow=Get-CimInstance -ClassName Win32_ShadowCopy -Filter \"ID='$id'\"; " +
                      "if ($null -eq $shadow) { throw 'VSS snapshot was not found.' }; " +
                      "Remove-CimInstance -InputObject $shadow");
    }

    public string ResolveBaselinePath(VssSnapshotMetadata snapshot, string originalPath)
    {
        string fullPath = Path.GetFullPath(originalPath);
        if (!fullPath.StartsWith(snapshot.VolumeRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"{originalPath} does not belong to VSS volume {snapshot.VolumeRoot}.");
        }
        string relative = fullPath[snapshot.VolumeRoot.Length..].TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return Path.Combine(snapshot.DeviceObject.TrimEnd('\\'), relative);
    }

    private VssSnapshotMetadata Create(string volumeRoot)
    {
        string volume = volumeRoot.Replace("'", "''", StringComparison.Ordinal);
        string script = """
            $ErrorActionPreference='Stop'
            $result=Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume='%VOLUME%';Context='ClientAccessible'}
            if ($result.ReturnValue -ne 0) { throw ('Win32_ShadowCopy.Create failed: ' + $result.ReturnValue) }
            $shadow=Get-CimInstance -ClassName Win32_ShadowCopy -Filter ("ID='" + $result.ShadowID + "'")
            if ($null -eq $shadow) { throw 'Created VSS snapshot could not be queried.' }
            [pscustomobject]@{id=$shadow.ID;deviceObject=$shadow.DeviceObject;installDate=$shadow.InstallDate;providerId=$shadow.ProviderID} | ConvertTo-Json -Compress
            """.Replace("%VOLUME%", volume, StringComparison.Ordinal);
        string output = RunPowerShell(script);
        VssPowerShellResult value = JsonSerializer.Deserialize<VssPowerShellResult>(output, JsonSupport.Options)
            ?? throw new InvalidDataException("VSS returned an empty snapshot record.");
        if (string.IsNullOrWhiteSpace(value.Id) || string.IsNullOrWhiteSpace(value.DeviceObject))
        {
            throw new InvalidDataException("VSS returned incomplete snapshot metadata.");
        }
        return new VssSnapshotMetadata
        {
            Id = value.Id,
            VolumeRoot = volumeRoot,
            DeviceObject = value.DeviceObject,
            CreatedAt = DateTimeOffset.TryParse(value.InstallDate, out DateTimeOffset timestamp) ? timestamp : DateTimeOffset.UtcNow,
            Provider = value.ProviderId
        };
    }

    private static string GetVolumeRoot(string scope)
    {
        string? root = Path.GetPathRoot(Path.GetFullPath(scope));
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            throw new ArgumentException($"Scope is not on a local volume: {scope}");
        }
        return root;
    }

    private static string RunPowerShell(string script)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = PowerShellPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);
        using Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Windows PowerShell could not be started for VSS.");
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"VSS PowerShell operation failed ({process.ExitCode}): {stderr.Trim()}");
        }
        return stdout.Trim();
    }

    private sealed class VssPowerShellResult
    {
        public string? Id { get; init; }
        public string? DeviceObject { get; init; }
        public string? InstallDate { get; init; }
        public string? ProviderId { get; init; }
    }
}
