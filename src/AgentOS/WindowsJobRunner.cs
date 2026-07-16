using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace AgentOS;

internal static class WindowsJobRunner
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint Infinite = 0xffffffff;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectLimitDieOnUnhandledException = 0x00000400;
    private const int JobObjectExtendedLimitInformation = 9;

    public static int Run(string command, IReadOnlyList<string> arguments, string workingDirectory)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The MVP process runner requires Windows Job Objects.");
        }

        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed.");
        }

        try
        {
            ConfigureJob(job);
            string commandLine = string.Join(' ', new[] { command }.Concat(arguments).Select(QuoteArgument));
            STARTUPINFO startupInfo = new() { cb = Marshal.SizeOf<STARTUPINFO>() };
            if (!CreateProcessW(
                    null,
                    new StringBuilder(commandLine),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateSuspended | CreateUnicodeEnvironment,
                    IntPtr.Zero,
                    workingDirectory,
                    ref startupInfo,
                    out PROCESS_INFORMATION processInfo))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not launch {command}.");
            }

            try
            {
                if (!AssignProcessToJobObject(job, processInfo.hProcess))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed.");
                }

                if (ResumeThread(processInfo.hThread) == uint.MaxValue)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed.");
                }

                uint waitResult = WaitForSingleObject(processInfo.hProcess, Infinite);
                if (waitResult != 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), $"WaitForSingleObject returned {waitResult}.");
                }

                if (!GetExitCodeProcess(processInfo.hProcess, out uint exitCode))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed.");
                }

                return unchecked((int)exitCode);
            }
            finally
            {
                CloseHandle(processInfo.hThread);
                CloseHandle(processInfo.hProcess);
            }
        }
        finally
        {
            // Closing the job terminates descendants that outlived the root process.
            CloseHandle(job);
        }
    }

    private static void ConfigureJob(IntPtr job)
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION information = new();
        information.BasicLimitInformation.LimitFlags =
            JobObjectLimitKillOnJobClose | JobObjectLimitDieOnUnhandledException;
        int size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(information, buffer, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject failed.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    internal static string QuoteArgument(string argument)
    {
        if (argument.Length > 0 && !argument.Any(character => char.IsWhiteSpace(character) || character == '"'))
        {
            return argument;
        }

        StringBuilder builder = new();
        builder.Append('"');
        int backslashes = 0;
        foreach (char character in argument)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }

            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }
        builder.Append('\\', backslashes * 2);
        builder.Append('"');
        return builder.ToString();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, IntPtr information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string? applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
