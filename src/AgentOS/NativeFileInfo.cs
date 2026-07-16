using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AgentOS;

internal static class NativeFileInfo
{
    private const uint FileShareReadWriteDelete = 0x00000007;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint GenericRead = 0x80000000;

    public readonly record struct Identity(uint VolumeSerialNumber, ulong FileIndex, int HardLinkCount);

    public static Identity GetIdentity(string path, bool isDirectory)
    {
        using SafeFileHandle handle = CreateFile(
            path,
            GenericRead,
            FileShareReadWriteDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | (isDirectory ? 0u : 0u) | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFile failed for " + path);
        }

        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation info))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle failed for " + path);
        }

        ulong index = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
        return new Identity(info.VolumeSerialNumber, index, (int)info.NumberOfLinks);
    }

    public static List<(string Name, long Length)> ListAlternateStreams(string path)
    {
        List<(string Name, long Length)> streams = [];
        IntPtr handle = FindFirstStreamW(path, 0, out Win32StreamId streamId, 0);
        if (handle == new IntPtr(-1))
        {
            int error = Marshal.GetLastWin32Error();
            // ERROR_HANDLE_EOF (38) means no streams API result; ERROR_INVALID_PARAMETER for some FS.
            if (error is 38 or 87 or 2)
            {
                return streams;
            }
            throw new Win32Exception(error, "FindFirstStreamW failed for " + path);
        }

        try
        {
            do
            {
                string name = streamId.CStreamName ?? string.Empty;
                if (string.IsNullOrWhiteSpace(name) ||
                    string.Equals(name, "::$DATA", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                streams.Add((name, streamId.StreamSize));
            }
            while (FindNextStreamW(handle, out streamId));

            int endError = Marshal.GetLastWin32Error();
            if (endError is not 0 and not 38)
            {
                throw new Win32Exception(endError, "FindNextStreamW failed for " + path);
            }
        }
        finally
        {
            _ = FindClose(handle);
        }

        return streams
            .OrderBy(stream => stream.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static string StreamPath(string path, string streamName)
    {
        // streamName is like ":zone.identifier:$DATA"
        string suffix = streamName.StartsWith(":", StringComparison.Ordinal) ? streamName : ":" + streamName;
        int data = suffix.IndexOf(":$DATA", StringComparison.OrdinalIgnoreCase);
        string shortName = data >= 0 ? suffix[..data] : suffix;
        return path + shortName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Win32StreamId
    {
        public long StreamSize;
        public long StreamAllocationSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string CStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out ByHandleFileInformation lpFileInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(string lpFileName, int InfoLevel, out Win32StreamId lpFindStreamData, int dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(IntPtr hFindStream, out Win32StreamId lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr hFindFile);
}
