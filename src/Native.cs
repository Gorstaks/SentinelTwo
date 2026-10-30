using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace SentinelTwo
{
    internal static class Native
    {
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_PRIVATE = 0x20000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_EXECUTABLE_MASK = 0xF0;

        public const int AF_INET = 2;
        public const int AF_INET6 = 23;
        public const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;
        public const uint MIB_TCP_STATE_ESTAB = 5;
        private const uint ERROR_INSUFFICIENT_BUFFER = 122;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USER_INFO_1003
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string usri1003_password;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct USER_MODALS_INFO_0
        {
            public uint min_passwd_len;
            public uint max_passwd_age;
            public uint min_passwd_age;
            public uint force_logoff;
            public uint password_hist_len;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION buffer, IntPtr length);

        [DllImport("kernel32.dll")]
        public static extern bool FreeConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, IntPtr size, out IntPtr bytesRead);

        [DllImport("user32.dll")]
        public static extern IntPtr GetClipboardOwner();

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint NetUserSetInfo(string serverName, string userName, uint level, ref USER_INFO_1003 buffer, out uint parmError);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetUserModalsGet(string serverName, uint level, out IntPtr buffer);

        [DllImport("netapi32.dll")]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WTSQuerySessionInformation(IntPtr server, int session, int infoClass, out IntPtr buffer, out int bytes);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        public static uint MinimumPasswordLength()
        {
            IntPtr buffer;
            uint result = NetUserModalsGet(null, 0, out buffer);
            if (result != 0) throw new Win32Exception((int)result);
            try
            {
                USER_MODALS_INFO_0 info = (USER_MODALS_INFO_0)Marshal.PtrToStructure(buffer, typeof(USER_MODALS_INFO_0));
                return info.min_passwd_len;
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }

        public static string SessionText(int session, int infoClass)
        {
            IntPtr buffer;
            int bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, session, infoClass, out buffer, out bytes))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                return Marshal.PtrToStringUni(buffer) ?? "";
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }

        // Returns 0 when the file is signed and trusted, either embedded or through a system catalog.
        // Catalog-signed system binaries (for example notepad.exe on Windows 10/11) have no embedded signature.
        public static uint VerifyAuthenticode(string path)
        {
            uint embedded = VerifyEmbedded(path);
            if (embedded != 0x800B0100) return embedded; // TRUST_E_NOSIGNATURE triggers the catalog lookup
            return VerifyCatalog(path);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public IntPtr pcwszCatalogFilePath;
            public IntPtr pcwszMemberTag;
            public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext(out IntPtr hCatAdmin, ref Guid subsystem, uint flags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr file, ref uint hashSize, byte[] hash, uint flags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] hash, uint hashSize, uint flags, IntPtr previous);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint flags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO catInfo, uint flags);

        private static uint VerifyCatalog(string path)
        {
            Guid driverAction = new Guid("{F750E6C3-38EE-11D1-85E5-00C04FC295EE}");
            Guid verifyAction = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
            IntPtr hCatAdmin;
            if (!CryptCATAdminAcquireContext(out hCatAdmin, ref driverAction, 0)) return (uint)Marshal.GetLastWin32Error();
            try
            {
                using (System.IO.FileStream fs = new System.IO.FileStream(path, System.IO.FileMode.Open,
                    System.IO.FileAccess.Read, System.IO.FileShare.Read))
                {
                    IntPtr handle = fs.SafeFileHandle.DangerousGetHandle();
                    uint hashSize = 0;
                    CryptCATAdminCalcHashFromFileHandle(handle, ref hashSize, null, 0);
                    if (hashSize == 0) return 0x800B0100;
                    byte[] hash = new byte[hashSize];
                    if (!CryptCATAdminCalcHashFromFileHandle(handle, ref hashSize, hash, 0)) return (uint)Marshal.GetLastWin32Error();

                    IntPtr catalog = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
                    if (catalog == IntPtr.Zero) return 0x800B0100; // no catalog contains this file

                    IntPtr catalogPath = IntPtr.Zero, memberTag = IntPtr.Zero, memberPath = IntPtr.Zero, hashPtr = IntPtr.Zero;
                    IntPtr catalogInfo = IntPtr.Zero, filePtr = IntPtr.Zero;
                    try
                    {
                        CATALOG_INFO info = new CATALOG_INFO();
                        info.cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO));
                        if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0)) return (uint)Marshal.GetLastWin32Error();

                        StringBuilder tag = new StringBuilder();
                        foreach (byte b in hash) tag.Append(b.ToString("X2"));

                        catalogPath = Marshal.StringToHGlobalUni(info.wszCatalogFile);
                        memberTag = Marshal.StringToHGlobalUni(tag.ToString());
                        memberPath = Marshal.StringToHGlobalUni(path);
                        hashPtr = Marshal.AllocHGlobal((int)hashSize);
                        Marshal.Copy(hash, 0, hashPtr, (int)hashSize);

                        WINTRUST_CATALOG_INFO cat = new WINTRUST_CATALOG_INFO();
                        cat.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO));
                        cat.pcwszCatalogFilePath = catalogPath;
                        cat.pcwszMemberTag = memberTag;
                        cat.pcwszMemberFilePath = memberPath;
                        cat.pbCalculatedFileHash = hashPtr;
                        cat.cbCalculatedFileHash = hashSize;
                        catalogInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)));
                        Marshal.StructureToPtr(cat, catalogInfo, false);

                        WINTRUST_DATA data = new WINTRUST_DATA();
                        data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                        data.dwUIChoice = 2;           // WTD_UI_NONE
                        data.fdwRevocationChecks = 0;  // WTD_REVOKE_NONE
                        data.dwUnionChoice = 2;        // WTD_CHOICE_CATALOG
                        data.pFile = catalogInfo;
                        data.dwStateAction = 1;        // WTD_STATEACTION_VERIFY
                        uint result = WinVerifyTrust(IntPtr.Zero, ref verifyAction, ref data);
                        data.dwStateAction = 2;        // WTD_STATEACTION_CLOSE
                        WinVerifyTrust(IntPtr.Zero, ref verifyAction, ref data);
                        return result;
                    }
                    finally
                    {
                        if (catalogInfo != IntPtr.Zero) Marshal.FreeHGlobal(catalogInfo);
                        if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
                        if (memberPath != IntPtr.Zero) Marshal.FreeHGlobal(memberPath);
                        if (memberTag != IntPtr.Zero) Marshal.FreeHGlobal(memberTag);
                        if (catalogPath != IntPtr.Zero) Marshal.FreeHGlobal(catalogPath);
                        CryptCATAdminReleaseCatalogContext(hCatAdmin, catalog, 0);
                    }
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }

        private static uint VerifyEmbedded(string path)
        {
            IntPtr pathPtr = Marshal.StringToHGlobalUni(path);
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO();
            fileInfo.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fileInfo.pcwszFilePath = pathPtr;
            IntPtr filePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            try
            {
                Marshal.StructureToPtr(fileInfo, filePtr, false);
                WINTRUST_DATA data = new WINTRUST_DATA();
                data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                data.dwUIChoice = 2;            // WTD_UI_NONE
                data.fdwRevocationChecks = 0;   // WTD_REVOKE_NONE
                data.dwUnionChoice = 1;         // WTD_CHOICE_FILE
                data.pFile = filePtr;
                data.dwStateAction = 1;         // WTD_STATEACTION_VERIFY
                Guid action = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
                uint result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                data.dwStateAction = 2;         // WTD_STATEACTION_CLOSE
                WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(filePtr);
                Marshal.FreeHGlobal(pathPtr);
            }
        }

        public sealed class TcpRow
        {
            public uint State;
            public string LocalAddress;
            public int LocalPort;
            public string RemoteAddress;
            public int RemotePort;
            public int Pid;
        }

        // Established and other TCP connections for IPv4 and IPv6, with owning PIDs.
        public static List<TcpRow> GetTcpRows()
        {
            List<TcpRow> rows = new List<TcpRow>();
            ParseTable(FetchTable(AF_INET), false, rows);
            ParseTable(FetchTable(AF_INET6), true, rows);
            return rows;
        }

        private static byte[] FetchTable(int family)
        {
            int size = 0;
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref size, true, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
            for (int attempt = 0; attempt < 5; attempt++)
            {
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    result = GetExtendedTcpTable(buffer, ref size, true, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
                    if (result == 0)
                    {
                        byte[] data = new byte[size];
                        Marshal.Copy(buffer, data, 0, size);
                        return data;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
                if (result != ERROR_INSUFFICIENT_BUFFER) break;
            }
            throw new Win32Exception((int)result);
        }

        // Raw layouts: MIB_TCPROW_OWNER_PID is 24 bytes, MIB_TCP6ROW_OWNER_PID is 56 bytes.
        private static void ParseTable(byte[] b, bool ipv6, List<TcpRow> rows)
        {
            int count = (int)BitConverter.ToUInt32(b, 0);
            int rowSize = ipv6 ? 56 : 24;
            for (int i = 0; i < count; i++)
            {
                int off = 4 + i * rowSize;
                if (off + rowSize > b.Length) break;
                TcpRow row = new TcpRow();
                if (ipv6)
                {
                    row.State = BitConverter.ToUInt32(b, off + 48);
                    row.LocalAddress = ReadAddress(b, off, 16);
                    row.LocalPort = ReadPort(b, off + 20);
                    row.RemoteAddress = ReadAddress(b, off + 24, 16);
                    row.RemotePort = ReadPort(b, off + 44);
                    row.Pid = (int)BitConverter.ToUInt32(b, off + 52);
                }
                else
                {
                    row.State = BitConverter.ToUInt32(b, off);
                    row.LocalAddress = ReadAddress(b, off + 4, 4);
                    row.LocalPort = ReadPort(b, off + 8);
                    row.RemoteAddress = ReadAddress(b, off + 12, 4);
                    row.RemotePort = ReadPort(b, off + 16);
                    row.Pid = (int)BitConverter.ToUInt32(b, off + 20);
                }
                rows.Add(row);
            }
        }

        private static string ReadAddress(byte[] b, int off, int length)
        {
            byte[] bytes = new byte[length];
            Array.Copy(b, off, bytes, 0, length);
            return new IPAddress(bytes).ToString();
        }

        // Ports are stored in network byte order in the low 16 bits.
        private static int ReadPort(byte[] b, int off)
        {
            return (b[off] << 8) | b[off + 1];
        }
    }
}
