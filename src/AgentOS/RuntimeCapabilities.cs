using System.Security.Principal;

namespace AgentOS;

internal static class RuntimeCapabilities
{
    private static readonly string[] SandboxieCandidates =
    [
        Path.Combine(Environment.GetEnvironmentVariable("SANDBOXIE_HOME") ?? string.Empty, "Start.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sandboxie-Plus", "Start.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sandboxie", "Start.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Sandboxie-Plus", "Start.exe")
    ];

    public static RuntimeCapabilityReport Probe()
    {
        bool windows = OperatingSystem.IsWindows();
        bool elevated = windows && IsElevated();
        string? sandboxie = SandboxieCandidates.FirstOrDefault(File.Exists);
        bool wdkHeaders = FindWdkHeader("fltKernel.h") is not null && FindWdkHeader("wdm.h") is not null;
        bool signingTools = FindWindowsKitTool("signtool.exe") is not null && FindWindowsKitTool("inf2cat.exe") is not null;
        List<string> notes = [];
        string vssStatus;
        if (!windows)
        {
            vssStatus = "Unavailable: VSS is Windows-only.";
        }
        else if (!elevated)
        {
            vssStatus = "Unavailable in this session: VSS baseline creation requires an elevated Administrator token.";
            notes.Add("Run FullRecovery from an elevated terminal or an installed privileged Runtime service.");
        }
        else if (!File.Exists(VssShadowCopyProvider.PowerShellPath))
        {
            vssStatus = "Unavailable: Windows PowerShell was not found.";
        }
        else
        {
            vssStatus = "Eligible: elevated VSS creation can be attempted for local NTFS volumes.";
        }

        if (sandboxie is null)
        {
            notes.Add("Sandbox mode needs Sandboxie Plus Start.exe. Install it or set SANDBOXIE_HOME.");
        }
        if (!wdkHeaders)
        {
            notes.Add("WDK kernel headers are absent; the driver project cannot be built on this host yet.");
        }
        if (!signingTools)
        {
            notes.Add("Driver catalog/signing tools are absent or incomplete.");
        }

        return new RuntimeCapabilityReport
        {
            IsWindows = windows,
            IsElevated = elevated,
            VssEligible = windows && elevated && File.Exists(VssShadowCopyProvider.PowerShellPath),
            VssStatus = vssStatus,
            SandboxieAvailable = sandboxie is not null,
            SandboxieStartExe = sandboxie,
            WdkHeadersAvailable = wdkHeaders,
            DriverSigningToolsAvailable = signingTools,
            Notes = notes
        };
    }

    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string? FindWdkHeader(string name)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Kits", "10", "Include");
        if (!Directory.Exists(root))
        {
            return null;
        }
        return Directory.EnumerateFiles(root, name, SearchOption.AllDirectories).FirstOrDefault();
    }

    private static string? FindWindowsKitTool(string name)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Kits", "10", "bin");
        if (!Directory.Exists(root))
        {
            return null;
        }
        return Directory.EnumerateFiles(root, name, SearchOption.AllDirectories).FirstOrDefault();
    }
}
