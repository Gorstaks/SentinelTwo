using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SentinelTwo
{
    // Read-only inspection of executable private or unbacked memory for embedded PE images.
    // Image-backed (MEM_IMAGE) regions are skipped because loaded modules are expected there.
    // Bounded: a fixed read budget and region limit apply, so coverage is partial by design.
    internal static class MemoryInspect
    {
        private const uint MEM_IMAGE = 0x1000000;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const long ReadBudgetBytes = 256L * 1024 * 1024;
        private const int MaxRegions = 4096;
        private const int SampleBytes = 4096;

        public static int Run(string[] args)
        {
            int pid;
            if (args.Length < 3 || !int.TryParse(args[2], out pid))
            {
                Console.WriteLine("usage: memory inspect <pid>");
                return 2;
            }
            if (pid == AvState.CurrentPid || pid <= 4)
            {
                Console.WriteLine("Refusing to inspect PID " + pid + ".");
                return 2;
            }

            Process target;
            try
            {
                target = Process.GetProcessById(pid);
            }
            catch (ArgumentException)
            {
                Console.WriteLine("No process with PID " + pid);
                return 2;
            }

            IntPtr handle = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_VM_READ, false, pid);
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("Cannot open PID " + pid + " (protected or access denied): " + target.ProcessName);
                return 1;
            }

            int regionsSeen = 0, regionsSampled = 0, findings = 0;
            long bytesRead = 0;
            bool budgetHit = false;
            try
            {
                IntPtr address = IntPtr.Zero;
                int mbiSize = Marshal.SizeOf(typeof(Native.MEMORY_BASIC_INFORMATION));
                for (int i = 0; i < MaxRegions * 4; i++)
                {
                    Native.MEMORY_BASIC_INFORMATION mbi;
                    if (Native.VirtualQueryEx(handle, address, out mbi, (IntPtr)mbiSize) == IntPtr.Zero) break;

                    long size = mbi.RegionSize.ToInt64();
                    long next = address.ToInt64() + size;
                    if (next <= address.ToInt64()) break;

                    if (mbi.State == Native.MEM_COMMIT && IsExecutable(mbi.Protect) && (mbi.Type & MEM_IMAGE) == 0)
                    {
                        regionsSeen++;
                        if (regionsSampled >= MaxRegions || bytesRead + SampleBytes > ReadBudgetBytes)
                        {
                            budgetHit = true;
                        }
                        else
                        {
                            regionsSampled++;
                            byte[] sample = new byte[SampleBytes];
                            IntPtr read;
                            if (Native.ReadProcessMemory(handle, mbi.BaseAddress, sample, (IntPtr)Math.Min(SampleBytes, size), out read))
                            {
                                bytesRead += read.ToInt64();
                                if (LooksLikePe(sample, read.ToInt64()))
                                {
                                    findings++;
                                    Console.WriteLine("PE image in private executable memory: base 0x" + mbi.BaseAddress.ToInt64().ToString("X") +
                                                      " size " + size + " protect 0x" + mbi.Protect.ToString("X") + " type 0x" + mbi.Type.ToString("X"));
                                }
                            }
                        }
                    }
                    address = new IntPtr(next);
                }
            }
            finally
            {
                Native.CloseHandle(handle);
            }

            Console.WriteLine("PID " + pid + " (" + target.ProcessName + "): " + regionsSeen + " executable unbacked regions, " +
                              regionsSampled + " sampled, " + bytesRead + " bytes read, " + findings + " PE finding(s).");
            if (budgetHit) Console.WriteLine("Read budget or region limit reached; coverage is partial.");
            Console.WriteLine("Report only. Injection is not confirmed by a PE header alone.");
            return 0;
        }

        private static bool IsExecutable(uint protect)
        {
            uint p = protect & 0xFF;
            return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        // DOS "MZ" header, e_lfanew pointing inside the sample, and a "PE\0\0" signature there.
        internal static bool LooksLikePe(byte[] sample, long valid)
        {
            if (valid < 64) return false;
            if (sample[0] != 'M' || sample[1] != 'Z') return false;
            int lfanew = BitConverter.ToInt32(sample, 0x3C);
            if (lfanew < 0x40 || lfanew + 4 > valid) return false;
            return sample[lfanew] == 'P' && sample[lfanew + 1] == 'E' && sample[lfanew + 2] == 0 && sample[lfanew + 3] == 0;
        }
    }
}
