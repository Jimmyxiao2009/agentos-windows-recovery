namespace AgentOS;

/// <summary>
/// Optional Mode 0 adapter for an existing Sandboxie Plus installation. Sandboxie remains
/// responsible for namespace virtualization; AgentOS keeps the transaction journal and
/// declared-scope recovery record around the launched command.
/// </summary>
internal sealed class SandboxieAdapter
{
    private readonly string _startExe;

    private SandboxieAdapter(string startExe)
    {
        _startExe = startExe;
    }

    public static SandboxieAdapter RequireInstalled()
    {
        RuntimeCapabilityReport capabilities = RuntimeCapabilities.Probe();
        if (!capabilities.SandboxieAvailable || string.IsNullOrWhiteSpace(capabilities.SandboxieStartExe))
        {
            throw new InvalidOperationException(
                "Sandbox mode requires Sandboxie Plus Start.exe. Install Sandboxie Plus, configure a sandbox box, " +
                "or set SANDBOXIE_HOME before starting a Mode 0 transaction.");
        }
        return new SandboxieAdapter(capabilities.SandboxieStartExe);
    }

    public int Run(string sandboxBox, string command, IReadOnlyList<string> arguments, string workingDirectory)
    {
        if (string.IsNullOrWhiteSpace(sandboxBox) || sandboxBox.IndexOfAny(['/', '\\', ':', '"']) >= 0)
        {
            throw new ArgumentException("Sandboxie box names must be non-empty simple identifiers.", nameof(sandboxBox));
        }

        // /wait is Sandboxie's documented synchronous launch option. Keeping Start.exe in the
        // Job Object makes the launcher lifetime observable; Sandboxie enforces the child namespace.
        List<string> sandboxieArguments = ["/box:" + sandboxBox, "/wait", command];
        sandboxieArguments.AddRange(arguments);
        return WindowsJobRunner.Run(_startExe, sandboxieArguments, workingDirectory);
    }
}
