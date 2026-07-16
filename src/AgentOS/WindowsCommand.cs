using System.Diagnostics;

namespace AgentOS;

internal sealed class WindowsCommandResult
{
    public required int ExitCode { get; init; }
    public required string StandardOutput { get; init; }
    public required string StandardError { get; init; }
}

internal static class WindowsCommand
{
    public static WindowsCommandResult Run(string executable, params string[] arguments) => Run(executable, (IEnumerable<string>)arguments);

    public static WindowsCommandResult Run(string executable, IEnumerable<string> arguments)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start {executable}.");
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new WindowsCommandResult
        {
            ExitCode = process.ExitCode,
            StandardOutput = stdout,
            StandardError = stderr
        };
    }

    public static void RequireSuccess(string operation, string executable, params string[] arguments)
    {
        WindowsCommandResult result = Run(executable, arguments);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"{operation} failed ({result.ExitCode}): {result.StandardError.Trim()} {result.StandardOutput.Trim()}".Trim());
        }
    }
}
