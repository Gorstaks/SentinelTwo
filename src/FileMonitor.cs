using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Management;

namespace SentinelTwo
{
    internal sealed class FileEvent
    {
        public string Path;
        public DateTime Time;
        public string Kind;
        public string Detail;
    }

    // Watches user profile trees and flags bulk file activity and known ransomware extensions.
    internal static class FileMonitor
    {
        private const int QueueCapacity = 10000;

        private static readonly string[] RansomExtensions = {
            ".encrypted", ".enc", ".locked", ".crypto", ".crypt", ".locky",
            ".wncry", ".ryuk", ".lockbit", ".conti", ".hive", ".blackcat", ".play", ".royal",
            ".clop", ".akira", ".blackbasta", ".rhysida", ".medusa", ".trigona"
        };

        private static readonly ConcurrentQueue<FileEvent> Events = new ConcurrentQueue<FileEvent>();
        private static readonly List<FileSystemWatcher> Watchers = new List<FileSystemWatcher>();
        private static int rateCount;
        private static DateTime rateStart = DateTime.Now;

        public static string MonitoredRoots = "";

        public static bool Initialize()
        {
            List<string> roots = new List<string>();
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                "root\\cimv2", "SELECT LocalPath, Special FROM Win32_UserProfile"))
            {
                foreach (ManagementObject profile in searcher.Get())
                {
                    object special = profile["Special"];
                    string local = profile["LocalPath"] as string;
                    if ((special is bool && (bool)special) || string.IsNullOrEmpty(local)) continue;
                    if (!Directory.Exists(local) || roots.Contains(local)) continue;
                    roots.Add(local);
                }
            }

            foreach (string root in roots)
            {
                try
                {
                    FileSystemWatcher watcher = new FileSystemWatcher(root);
                    watcher.IncludeSubdirectories = true;
                    watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
                    watcher.Filter = "*";
                    watcher.Renamed += (s, e) => Enqueue(e.FullPath, "Renamed");
                    watcher.Created += (s, e) => Enqueue(e.FullPath, "Created");
                    watcher.Changed += (s, e) => Enqueue(e.FullPath, "Changed");
                    watcher.Error += (s, e) => Enqueue("", "Error", e.GetException().Message);
                    watcher.EnableRaisingEvents = true;
                    Watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    Ui.Write("File monitor unavailable for " + root + ": " + ex.Message, ConsoleColor.Yellow);
                }
            }
            MonitoredRoots = string.Join("; ", roots.ToArray());
            return Watchers.Count > 0;
        }

        private static void Enqueue(string path, string kind)
        {
            Enqueue(path, kind, "");
        }

        private static void Enqueue(string path, string kind, string detail)
        {
            if (Events.Count < QueueCapacity)
            {
                Events.Enqueue(new FileEvent { Path = path, Time = DateTime.Now, Kind = kind, Detail = detail });
            }
            else if (Events.Count == QueueCapacity)
            {
                Events.Enqueue(new FileEvent { Path = "", Time = DateTime.Now, Kind = "Error", Detail = "Event queue capacity exceeded; some file events were dropped." });
            }
        }

        public static void Analyze()
        {
            if (Events.IsEmpty) return;

            Dictionary<string, FileEvent> byPath = new Dictionary<string, FileEvent>(StringComparer.OrdinalIgnoreCase);
            int drained = 0;
            FileEvent record;
            while (drained < QueueCapacity && Events.TryDequeue(out record))
            {
                drained++;
                if (record.Kind == "Error")
                {
                    AvLog.Write("system", "FileMonitorError", record.Detail, "File events may have been lost", 1, "System", "", 0);
                }
                else
                {
                    byPath[record.Path] = record;
                }
            }

            DateTime now = DateTime.Now;
            int ransomHits = 0;
            foreach (FileEvent e in byPath.Values)
            {
                string ext = Path.GetExtension(e.Path ?? "");
                if (AvState.ContainsCI(RansomExtensions, ext)) ransomHits++;
            }

            // Reset before counting this batch, so a quiet period cannot discard it.
            if ((now - rateStart).TotalSeconds > 30)
            {
                rateCount = 0;
                rateStart = now;
            }
            rateCount += byPath.Count;
            double elapsed = (now - rateStart).TotalSeconds;

            if (rateCount >= 50 && elapsed <= 30)
            {
                if (!AvState.IsDup("BulkFile", 60))
                {
                    double conf = Math.Min(0.95, 0.75 + rateCount * 0.002);
                    AvLog.Write("detection", "BulkFileOps",
                        rateCount + " file ops in " + Math.Round(elapsed) + "s",
                        "High file activity; may also be caused by copying, installation or synchronization",
                        conf, Correlation.Tier1, "FileSystem", 0);
                    AvState.AddSignal(0, "ransomware_rate", conf);
                    Ui.Write("[RANSOMWARE] Bulk: " + rateCount + " ops in " + Math.Round(elapsed) + "s", ConsoleColor.Red);
                }
            }

            if (ransomHits >= 5 && elapsed <= 30)
            {
                if (!AvState.IsDup("RansomExt", 60))
                {
                    AvLog.Write("detection", "RansomwareExtensions",
                        ransomHits + " files with ransomware extensions in " + Math.Round(elapsed) + "s",
                        "Mass rename to known encryption extensions",
                        0.92, Correlation.Tier1, "FileSystem", 0);
                    AvState.AddSignal(0, "ransomware_ext", 0.92);
                    Ui.Write("[RANSOMWARE] Extensions: " + ransomHits + " files", ConsoleColor.Red);
                }
            }
        }

        public static void Dispose()
        {
            foreach (FileSystemWatcher w in Watchers)
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            Watchers.Clear();
        }
    }
}
