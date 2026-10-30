using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;

namespace SentinelTwo
{
    // Behavioral monitor loop. Tier1 detections with confidence >= 0.85 may terminate a process;
    // Tier2 detections are logged only.
    internal static class AntivirusLite
    {
        public const string Version = AppVersion.Current;
        public const int ScanIntervalSeconds = 5;

        public static void Run()
        {
            ShowBanner();
            int cycle = 0;
            try
            {
                while (true)
                {
                    DateTime t0 = DateTime.Now;
                    cycle++;
                    try
                    {
                        Stage("Ancestry", UpdateAncestry);
                        Stage("Process", ProcessScan);
                        Stage("Network", () => Network.Analyze(Network.Snapshot()));
                        Stage("Files", FileMonitor.Analyze);

                        if (cycle % 9 == 0) Stage("Memory", MemoryScan);
                        if (cycle % 4 == 0) Stage("Clipboard", Monitors.TestClipboardAnomaly);
                        if (cycle % 6 == 0) Stage("DNS", Rules.DnsAnomaly);
                        if (cycle % 12 == 0) Stage("Modules", Monitors.TestModuleInjection);
                        if (cycle % 60 == 0) Stage("WMI", Monitors.TestWmiPersistence);
                        if (cycle % 6 == 0) Stage("Integrity", Monitors.TestSelfIntegrity);
                        if (cycle % 4 == 0) Stage("Capabilities", ReportSurveillance);
                    }
                    catch (Exception ex)
                    {
                        Ui.Write("Cycle " + cycle + " failed: " + ex.Message, ConsoleColor.Yellow);
                        AvLog.Write("system", "ScanError", ex.Message, "Cycle " + cycle + " did not complete", 1, "System", "", 0);
                    }

                    if (cycle % 20 == 0) Prune();

                    double ms = Math.Max(100, ScanIntervalSeconds * 1000 - (DateTime.Now - t0).TotalMilliseconds);
                    Thread.Sleep((int)ms);
                }
            }
            finally
            {
                Ui.Write("AntivirusLite shutting down...", ConsoleColor.Yellow);
                FileMonitor.Dispose();
                AvLog.Write("system", "Shutdown", "Stopped after " + cycle + " cycles", "Clean shutdown", 1.0, "System", "AntivirusLite", AvState.CurrentPid);
            }
        }

        private static void Stage(string name, Action action)
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                Ui.Write(name + " scan failed: " + ex.Message, ConsoleColor.Yellow);
                if (!AvState.IsDup("ScanError|" + name, 60))
                {
                    Dictionary<string, object> meta = new Dictionary<string, object>();
                    meta["stage"] = name;
                    AvLog.Write("system", "ScanError", ex.Message, name + " stage failed; other stages continue",
                        1, "System", "", 0, meta);
                }
            }
        }

        private static void Prune()
        {
            Network.PruneBeacons();

            List<int> deadPids = new List<int>();
            foreach (int pid in AvState.Correlation.Keys)
            {
                if (!AvState.Ancestry.ContainsKey(pid)) deadPids.Add(pid);
            }
            foreach (int pid in deadPids) AvState.Correlation.Remove(pid);
        }

        private static void UpdateAncestry()
        {
            Dictionary<int, ProcessInfo> fresh = new Dictionary<int, ProcessInfo>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\cimv2",
                    "SELECT ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate FROM Win32_Process"))
                {
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        int id = Convert.ToInt32(mo["ProcessId"]);
                        ProcessInfo info = new ProcessInfo();
                        info.Name = mo["Name"] as string;
                        info.ParentId = Convert.ToInt32(mo["ParentProcessId"]);
                        info.CommandLine = mo["CommandLine"] as string;
                        info.Path = mo["ExecutablePath"] as string;
                        string created = mo["CreationDate"] as string;
                        info.Created = string.IsNullOrEmpty(created) ? DateTime.MinValue : ManagementDateTimeConverter.ToDateTime(created);
                        fresh[id] = info;
                    }
                }
            }
            catch (Exception)
            {
                // Empty snapshot: matches the script, which then clears per-process state for all PIDs.
            }

            foreach (int key in new List<int>(AvState.Ancestry.Keys))
            {
                ProcessInfo old = AvState.Ancestry[key];
                ProcessInfo now;
                if (!fresh.TryGetValue(key, out now) || now.Created != old.Created)
                {
                    AvState.Correlation.Remove(key);
                    AvState.ModuleBaseline.Remove(key);
                    AvState.ReportedIndicators.Remove(key);
                }
            }
            AvState.Ancestry = fresh;
        }

        private static void ProcessScan()
        {
            foreach (int pid in new List<int>(AvState.Ancestry.Keys))
            {
                ProcessInfo i;
                if (!AvState.Ancestry.TryGetValue(pid, out i) || i == null) continue;
                if (pid <= 4 || pid == AvState.CurrentPid) continue;
                string n = i.Name;
                string cl = i.CommandLine;

                List<Detection> dets = new List<Detection>();
                dets.Add(Rules.Destructive(cl, pid, n));
                dets.Add(Rules.CredentialAccess(cl, pid, n));
                dets.Add(Rules.Evasion(cl, pid, n));
                dets.Add(Rules.Persistence(cl, pid, n));
                dets.Add(Rules.Execution(cl, pid, n));
                dets.Add(Rules.Escalation(cl, pid, n));
                dets.Add(Rules.LateralMovement(cl, pid, n));
                dets.Add(Rules.Genealogy(pid, n, i.ParentId));
                dets.Add(Rules.UnsignedStaged(pid, n, i.Path));

                foreach (Detection d in dets)
                {
                    if (d == null) continue;
                    if (d.Rule == "EncodedExec")
                    {
                        // Repeated log lines are suppressed, but the correlation signal keeps accumulating.
                        AvState.AddSignal(pid, d.Category, d.Confidence);
                        if (!AvState.TestNewIndicatorObservation(pid, d.Rule, cl)) continue;
                    }
                    else
                    {
                        if (AvState.IsDup(d.Rule + "|" + pid)) continue;
                    }

                    AvLog.Write("detection", d.Rule, d.Evidence, d.Reasoning, d.Confidence, d.Tier, n, pid);
                    if (d.Rule != "EncodedExec") AvState.AddSignal(pid, d.Category, d.Confidence);
                    Ui.Write("[" + d.Tier + "] " + d.Rule + ": " + n + " (PID " + pid + ")",
                        d.Tier == Correlation.Tier1 ? ConsoleColor.Yellow : ConsoleColor.Cyan);

                    if (d.Tier == Correlation.Tier1 && d.Confidence >= Correlation.KillThreshold)
                    {
                        Correlation.Kill(pid, n, d.Rule, d.Confidence);
                    }
                }
                Correlation.Composite(pid, n);
            }
        }

        private static void MemoryScan()
        {
            List<Process> filtered = new List<Process>();
            foreach (Process p in Monitors.SafeProcesses())
            {
                ProcessInfo info;
                string path = AvState.Ancestry.TryGetValue(p.Id, out info) && info != null ? info.Path : null;
                if (IsJit(path)) continue;
                filtered.Add(p);
            }
            if (filtered.Count == 0) return;

            // Random sample of up to 25 processes per pass.
            Random rng = new Random();
            for (int i = filtered.Count - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                Process tmp = filtered[i];
                filtered[i] = filtered[j];
                filtered[j] = tmp;
            }
            int take = Math.Min(25, filtered.Count);
            for (int k = 0; k < take; k++)
            {
                Process p = filtered[k];
                ProcessInfo info;
                string path = AvState.Ancestry.TryGetValue(p.Id, out info) && info != null ? info.Path : null;
                Detection d = Monitors.MemoryAnalysis(p.Id, p.ProcessName, path);
                if (d == null) continue;
                AvState.AddSignal(p.Id, d.Category, d.Confidence);
                if (!AvState.TestNewIndicatorObservation(p.Id, d.Rule, d.Fingerprint)) continue;
                AvLog.Write("detection", d.Rule, d.Evidence, d.Reasoning, d.Confidence, d.Tier, p.ProcessName, p.Id);
                Ui.Write("[Tier2] " + d.Rule + ": " + d.Evidence, ConsoleColor.Yellow);
                Correlation.Composite(p.Id, p.ProcessName);
            }
        }

        private static bool IsJit(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            foreach (string suffix in Monitors.JitSuffixes)
            {
                if (path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static void ReportSurveillance()
        {
            foreach (Detection s in Monitors.TestSurveillanceAccess())
            {
                AvLog.Write("detection", s.Rule, s.Evidence, s.Reasoning, s.Confidence, s.Tier, s.ProcessName, s.ProcessId);
                Ui.Write("[" + s.Tier + "] " + s.Rule + ": " + s.Evidence, ConsoleColor.Cyan);
            }
        }

        private static void ShowBanner()
        {
            Ui.Write("", ConsoleColor.Gray);
            Ui.Write(" ================================================", ConsoleColor.Green);
            Ui.Write("  SentinelTwo v" + Version + " (behavioral monitor)", ConsoleColor.Green);
            Ui.Write("  Behavioral monitor - heuristic detections", ConsoleColor.Gray);
            Ui.Write(" ================================================", ConsoleColor.Green);

            Ui.Write("  [OK] Elevated", ConsoleColor.Green);
            Ui.Write("  [OK] Log: " + AvLog.LogPath, ConsoleColor.Green);
            bool fw = false;
            try { fw = FileMonitor.Initialize(); } catch (Exception ex) { Ui.Write("File monitor initialization failed: " + ex.Message, ConsoleColor.Yellow); }
            Ui.Write(fw ? "  [OK] FileWatcher: " + FileMonitor.MonitoredRoots : "  [DEGRADED] FileWatcher", fw ? ConsoleColor.Green : ConsoleColor.Yellow);
            Ui.Write(AvState.InteractiveSession
                ? "  [INFO] Clipboard monitoring in interactive session " + AvState.SessionId
                : "  [UNAVAILABLE] Clipboard: no interactive desktop", ConsoleColor.Gray);
            Ui.Write("  [ARMED] Active Response ENABLED", ConsoleColor.Red);
            Ui.Write("  Processes will be KILLED on high-confidence behavioral match.", ConsoleColor.Red);
            Ui.Write("  Ctrl+C to stop.", ConsoleColor.Gray);

            Monitors.InitializeSelfProtection();
            UpdateAncestry();
            Monitors.InitializeModuleBaseline();
            AvLog.Write("system", "Startup", "AntivirusLite v" + Version + " Elevated=true",
                "Initialization complete", 1.0, "System", "AntivirusLite", AvState.CurrentPid);
        }
    }
}
