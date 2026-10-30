using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SentinelTwo
{
    internal static class Monitors
    {
        private const long FiftyMB = 50L * 1024 * 1024;
        private const long FiveHundredMB = 500L * 1024 * 1024;

        // JIT and Electron hosts legitimately hold RWX memory; their path suffixes are excluded from memory sampling.
        public static readonly string[] JitSuffixes = {
            "\\java.exe", "\\javaw.exe", "\\node.exe", "\\electron.exe",
            "\\chrome.exe", "\\msedge.exe", "\\firefox.exe", "\\brave.exe",
            "\\Code.exe", "\\kiro.exe", "\\Discord.exe", "\\Slack.exe", "\\Teams.exe",
            "\\steam.exe", "\\steamwebhelper.exe", "\\obs64.exe", "\\obs32.exe",
            "\\dotnet.exe", "\\w3wp.exe", "\\Spotify.exe", "\\Signal.exe",
            "\\Notion.exe", "\\Obsidian.exe", "\\GitKraken.exe", "\\Postman.exe",
            "\\1Password.exe", "\\Bitwarden.exe", "\\WindowsTerminal.exe"
        };

        // ---------------- Memory ----------------
        public static Detection MemoryAnalysis(int pid, string name, string path)
        {
            if (pid <= 4 || pid == AvState.CurrentPid) return null;
            IntPtr handle = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_VM_READ, false, pid);
            if (handle == IntPtr.Zero) return null;

            List<string> flags = new List<string>();
            try
            {
                IntPtr addr = IntPtr.Zero;
                int rwx = 0;
                int unbacked = 0;
                long privExec = 0;
                int size = Marshal.SizeOf(typeof(Native.MEMORY_BASIC_INFORMATION));
                for (int i = 0; i < 2000; i++)
                {
                    Native.MEMORY_BASIC_INFORMATION mbi;
                    if (Native.VirtualQueryEx(handle, addr, out mbi, (IntPtr)size) == IntPtr.Zero) break;
                    if (mbi.State == Native.MEM_COMMIT)
                    {
                        if (mbi.Protect == Native.PAGE_EXECUTE_READWRITE || mbi.Protect == Native.PAGE_EXECUTE_WRITECOPY) rwx++;
                        if (mbi.Type == Native.MEM_PRIVATE && (mbi.Protect & Native.PAGE_EXECUTABLE_MASK) != 0)
                        {
                            unbacked++;
                            privExec += mbi.RegionSize.ToInt64();
                        }
                    }
                    long next = addr.ToInt64() + mbi.RegionSize.ToInt64();
                    if (next <= addr.ToInt64()) break;
                    addr = new IntPtr(next);
                }
                if (rwx >= 5) flags.Add("RWX:" + rwx);
                if (unbacked >= 8) flags.Add("Unbacked:" + unbacked);
                if (privExec > FiftyMB) flags.Add("PrivExec:" + (privExec / (1024 * 1024)) + "MB");
            }
            finally
            {
                Native.CloseHandle(handle);
            }

            // Hollowing: the first loaded module should match the image path.
            try
            {
                Process p = Process.GetProcessById(pid);
                string imagePath = null;
                try { imagePath = p.MainModule.FileName; } catch (Exception) { }
                ProcessModuleCollection modules = p.Modules;
                if (imagePath != null && modules.Count > 0 && modules[0].FileName != null &&
                    !string.Equals(modules[0].FileName, imagePath, StringComparison.OrdinalIgnoreCase))
                {
                    flags.Add("Hollowed");
                }
                if (p.PrivateMemorySize64 > FiveHundredMB && modules.Count < 10) flags.Add("HighMemLowMod");
                if (imagePath != null && !File.Exists(imagePath) && !Directory.Exists(imagePath)) flags.Add("NoBackingFile");
            }
            catch (Exception)
            {
                // Access denied or process exited: missing telemetry, not evidence.
            }

            return NewMemoryFinding(pid, name, flags);
        }

        private static Detection NewMemoryFinding(int pid, string name, List<string> flags)
        {
            List<string> structural = new List<string>();
            int allocation = 0;
            foreach (string f in flags)
            {
                if (f == "Hollowed" || f == "NoBackingFile")
                {
                    if (!structural.Contains(f)) structural.Add(f);
                }
                if (f.StartsWith("RWX:") || f.StartsWith("Unbacked:") || f.StartsWith("PrivExec:") || f == "HighMemLowMod") allocation++;
            }
            if (structural.Count == 0 || (structural.Count < 2 && allocation == 0)) return null;
            structural.Sort(StringComparer.Ordinal);
            return new Detection
            {
                Rule = "MemoryAnomaly",
                Evidence = name + " (PID " + pid + "): " + string.Join(" | ", flags.ToArray()),
                Reasoning = "Memory allocation pattern corroborated by image/file inconsistency; injection is not confirmed",
                Confidence = 0.75,
                Tier = Correlation.Tier2,
                Category = "memory",
                Fingerprint = string.Join("|", structural.ToArray()),
                ProcessName = name,
                ProcessId = pid
            };
        }

        // ---------------- Clipboard ----------------
        private static readonly string[] LegitClipboardOwners = {
            "explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe",
            "powershell.exe", "pwsh.exe", "code.exe", "WindowsTerminal.exe"
        };

        public static void TestClipboardAnomaly()
        {
            if (!AvState.InteractiveSession) return;
            try
            {
                uint ownerPid = 0;
                IntPtr owner = Native.GetClipboardOwner();
                if (owner != IntPtr.Zero) Native.GetWindowThreadProcessId(owner, out ownerPid);
                int pid = (int)ownerPid;
                if (pid <= 0 || pid == AvState.CurrentPid) return;

                ProcessInfo info;
                if (!AvState.Ancestry.TryGetValue(pid, out info)) return;
                if (AvState.ContainsCI(LegitClipboardOwners, info.Name)) return;

                string[] staging = {
                    Environment.GetEnvironmentVariable("TEMP"), Environment.GetEnvironmentVariable("APPDATA"), "Downloads"
                };
                if (!AvState.PathContainsAny(info.Path, staging)) return;
                if (AvState.IsDup("Clipboard|" + pid, 120)) return;

                AvLog.Write("detection", "ClipboardHijack",
                    info.Name + " (PID " + pid + ") owns clipboard from staging path",
                    "Background process from temp location holding clipboard ownership",
                    0.78, Correlation.Tier2, info.Name, pid);
                AvState.AddSignal(pid, "clipboard", 0.78);
            }
            catch (Exception)
            {
                // Clipboard owner is unavailable (no desktop, locked session).
            }
        }

        // ---------------- Module integrity ----------------
        public static void InitializeModuleBaseline()
        {
            foreach (Process p in SafeProcesses())
            {
                try
                {
                    HashSet<string> mods = new HashSet<string>();
                    foreach (ProcessModule m in p.Modules) mods.Add(m.FileName.ToLowerInvariant());
                    AvState.ModuleBaseline[p.Id] = mods;
                }
                catch (Exception)
                {
                    // Protected process; no baseline.
                }
            }
        }

        public static void TestModuleInjection()
        {
            foreach (Process p in SafeProcesses())
            {
                int pid = p.Id;
                string name = p.ProcessName;
                try
                {
                    HashSet<string> current = new HashSet<string>();
                    foreach (ProcessModule m in p.Modules) current.Add(m.FileName.ToLowerInvariant());

                    HashSet<string> baseline;
                    if (AvState.ModuleBaseline.TryGetValue(pid, out baseline))
                    {
                        foreach (string mod in current)
                        {
                            if (baseline.Contains(mod)) continue;

                            if (!File.Exists(mod) && !Directory.Exists(mod))
                            {
                                if (!AvState.IsDup("Phantom|" + pid + "|" + mod, 300))
                                {
                                    AvLog.Write("detection", "PhantomModule",
                                        name + " (PID " + pid + ") has loaded DLL with deleted backing file: " + mod,
                                        "Loaded module file deleted from disk - dropper pattern",
                                        0.82, Correlation.Tier2, name, pid);
                                    AvState.AddSignal(pid, "dll_injection", 0.82);
                                }
                            }

                            string[] staging = {
                                Environment.GetEnvironmentVariable("TEMP"),
                                Environment.GetEnvironmentVariable("APPDATA"),
                                Environment.GetEnvironmentVariable("LOCALAPPDATA") + "\\Temp",
                                "downloads"
                            };
                            foreach (string sp in staging)
                            {
                                if (string.IsNullOrEmpty(sp)) continue;
                                if (mod.IndexOf(sp.ToLowerInvariant(), StringComparison.Ordinal) >= 0)
                                {
                                    if (!AvState.IsDup("TempDLL|" + pid + "|" + mod, 300))
                                    {
                                        AvLog.Write("detection", "StagedDllInjection",
                                            name + " (PID " + pid + ") loaded DLL from staging: " + mod,
                                            "New DLL from temp/staging path injected into running process",
                                            0.80, Correlation.Tier2, name, pid);
                                        AvState.AddSignal(pid, "dll_injection", 0.80);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    AvState.ModuleBaseline[pid] = current;
                }
                catch (Exception)
                {
                    // Access denied on this process; skip it.
                }
            }
        }

        // ---------------- Capability (screen/camera/mic) ----------------
        public static List<Detection> TestSurveillanceAccess()
        {
            List<Detection> results = new List<Detection>();
            foreach (Process p in SafeProcesses())
            {
                try
                {
                    List<string> categories = AvState.GetCategories(p.Id);
                    bool corroborated = false;
                    foreach (string c in categories)
                    {
                        if (c == "credential" || c == "evasion" || c == "c2" || c == "escalation" || c == "memory" || c == "clipboard")
                        {
                            corroborated = true;
                        }
                    }
                    if (!corroborated) continue;

                    List<string> mods = new List<string>();
                    foreach (ProcessModule m in p.Modules) mods.Add(m.ModuleName.ToLowerInvariant());
                    Detection finding = NewSurveillanceFinding(p.Id, p.ProcessName, p.MainWindowHandle != IntPtr.Zero, mods, categories);
                    if (finding == null) continue;
                    AvState.AddSignal(p.Id, finding.Category, finding.Confidence);
                    if (AvState.TestNewIndicatorObservation(p.Id, finding.Rule, finding.Fingerprint)) results.Add(finding);
                }
                catch (Exception)
                {
                    // Module enumeration denied; skip.
                }
            }
            return results;
        }

        private static Detection NewSurveillanceFinding(int pid, string name, bool hasWindow, List<string> modules, List<string> categories)
        {
            if (hasWindow) return null;
            string[] corrNames = { "credential", "evasion", "c2", "escalation", "memory", "clipboard" };
            List<string> corroboration = new List<string>();
            foreach (string c in categories)
            {
                if (AvState.ContainsCI(corrNames, c) && !corroboration.Contains(c)) corroboration.Add(c);
            }
            if (corroboration.Count == 0) return null;

            List<string> devices = new List<string>();
            if (HasAny(modules, "d3d11.dll", "dxgi.dll", "d3d9.dll")) devices.Add("screen");
            if (HasAny(modules, "mfplat.dll", "mf.dll", "mfreadwrite.dll", "ksuser.dll")) devices.Add("camera");
            if (HasAny(modules, "audioses.dll", "mmdevapi.dll")) devices.Add("microphone");
            if (devices.Count == 0) return null;

            corroboration.Sort(StringComparer.Ordinal);
            return new Detection
            {
                Rule = "BackgroundSurveillance",
                Evidence = name + " (PID " + pid + ") loaded " + string.Join("/", devices.ToArray()) +
                           "-related DLLs with other indicators: " + string.Join(", ", corroboration.ToArray()),
                Reasoning = "Corroborated capability indicator; actual device access or surveillance was not observed",
                Confidence = 0.70,
                Tier = Correlation.Tier2,
                Category = "surveillance",
                ProcessName = name,
                ProcessId = pid,
                Fingerprint = string.Join("|", devices.ToArray()) + ":" + string.Join("|", corroboration.ToArray())
            };
        }

        private static bool HasAny(List<string> modules, params string[] names)
        {
            foreach (string n in names)
            {
                if (modules.Contains(n)) return true;
            }
            return false;
        }

        // ---------------- WMI persistence ----------------
        public static void TestWmiPersistence()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "root\\subscription", "SELECT Name, CommandLineTemplate FROM CommandLineEventConsumer"))
                {
                    foreach (ManagementObject consumer in searcher.Get())
                    {
                        string name = Convert.ToString(consumer["Name"]);
                        string template = Convert.ToString(consumer["CommandLineTemplate"]);
                        if (AvState.IsDup("WMI|" + name, 600)) continue;
                        AvLog.Write("detection", "WmiPersistence", "WMI consumer: " + name + " -> " + template,
                            "WMI event subscription for fileless persistence", 0.88, Correlation.Tier1, "WMI", 0);
                        Ui.Write("[Tier1] WMI Persistence: " + name, ConsoleColor.Yellow);
                    }
                }
            }
            catch (Exception)
            {
                // WMI subscription namespace unavailable.
            }
        }

        // ---------------- Self integrity ----------------
        public static string CurrentExecutablePath()
        {
            return Assembly.GetEntryAssembly() != null
                ? Assembly.GetEntryAssembly().Location
                : Process.GetCurrentProcess().MainModule.FileName;
        }

        public static void InitializeSelfProtection()
        {
            try
            {
                AvState.SelfHash = Reputation.Sha256File(CurrentExecutablePath());
            }
            catch (Exception)
            {
                AvState.SelfHash = null;
            }
        }

        public static void TestSelfIntegrity()
        {
            if (string.IsNullOrEmpty(AvState.SelfHash)) return;
            try
            {
                string current = Reputation.Sha256File(CurrentExecutablePath());
                if (current == AvState.SelfHash) return;
                if (AvState.IsDup("SelfTamper", 300)) return;
                AvLog.Write("detection", "SelfProtection", "Program file modified on disk",
                    "AntivirusLite executable hash changed - possible tampering", 0.97, Correlation.Tier1, "AntivirusLite", AvState.CurrentPid);
                Ui.Write("[CRITICAL] Self-protection: executable tampered", ConsoleColor.Red);
            }
            catch (Exception)
            {
                // Executable temporarily locked during an update; try again next cycle.
            }
        }

        public static Process[] SafeProcesses()
        {
            List<Process> list = new List<Process>();
            foreach (Process p in Process.GetProcesses())
            {
                if (p.Id <= 4 || p.Id == AvState.CurrentPid) continue;
                list.Add(p);
            }
            return list.ToArray();
        }
    }
}
