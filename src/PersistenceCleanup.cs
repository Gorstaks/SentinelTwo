using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace SentinelTwo
{
    // Removes Run/RunOnce values that launch a file SentinelTwo already quarantined. A value is a
    // candidate only when all of these hold: its launch target equals the manifest's original path,
    // that original path no longer exists, and the quarantined copy still has the recorded SHA-256.
    // Each removal stores the original value first, reads back the deletion, and logs a receipt.
    internal static class PersistenceCleanup
    {
        private static readonly string[] RunKeys = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        private static string ReceiptLog
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "persistence", "changes.jsonl"); }
        }

        private static string SnapshotRoot
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "persistence", "snapshots"); }
        }

        public static int Run(string[] args)
        {
            if (args.Length < 2) return Usage();
            bool apply = args.Length > 2 && args[2] == "--apply";
            if (args[1] == "clean") return Clean(apply);
            if (args[1] == "clean-tasks") return PersistenceTasks.CleanTasks(apply);
            if (args[1] == "clean-services") return PersistenceTasks.CleanServices(apply);
            if (args[1] == "clean-wmi") return PersistenceWmi.Clean(apply);
            if (args[1] == "restore" && args.Length > 2 && args[2] != "--apply")
            {
                return Restore(args[2], args.Length > 3 && args[3] == "--apply");
            }
            return Usage();
        }

        private static int Usage()
        {
            Console.WriteLine("usage:");
            Console.WriteLine("  persistence clean [--apply]                 remove Run/RunOnce values that launch quarantined files");
            Console.WriteLine("  persistence clean-tasks [--apply]      remove scheduled tasks whose exec targets are quarantined files");
            Console.WriteLine("  persistence clean-services [--apply]   remove auto-start services whose image is a quarantined file");
            Console.WriteLine("  persistence clean-wmi [--apply]        remove WMI command-line subscriptions that launch quarantined files");
            Console.WriteLine("  persistence restore <snapshot-dir> [--apply] re-create values, tasks, or services removed by clean");
            return 2;
        }

        private sealed class Candidate
        {
            public RegistryKey Root;
            public string RootName;
            public string KeyPath;
            public string ValueName;
            public string ValueData;
            public string Target;
        }

        internal sealed class ManifestEntry
        {
            public string Original;
            public string Quarantined;
            public string Sha256;
        }

        private static int Clean(bool apply)
        {
            List<ManifestEntry> manifest = ReadManifest();
            if (manifest.Count == 0)
            {
                Console.WriteLine("No quarantine manifest entries; nothing to clean.");
                return 0;
            }

            List<Candidate> candidates = new List<Candidate>();
            foreach (Candidate c in FindRunValues())
            {
                ManifestEntry match = null;
                foreach (ManifestEntry m in manifest)
                {
                    if (string.Equals(m.Original, c.Target, StringComparison.OrdinalIgnoreCase)) { match = m; break; }
                }
                if (match == null) continue;
                if (File.Exists(match.Original))
                {
                    Console.WriteLine("Skipped (original path still exists): " + Describe(c));
                    continue;
                }
                if (!File.Exists(match.Quarantined) ||
                    !string.Equals(Reputation.Sha256File(match.Quarantined), match.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Skipped (quarantined copy missing or hash changed): " + Describe(c));
                    continue;
                }
                candidates.Add(c);
            }

            if (candidates.Count == 0)
            {
                Console.WriteLine("No Run/RunOnce values match quarantined payloads.");
                return 0;
            }
            foreach (Candidate c in candidates)
            {
                Console.WriteLine((apply ? "Removing " : "Would remove ") + Describe(c));
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to remove these values.");
                return 0;
            }

            string snapshot = Path.Combine(SnapshotRoot, DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));
            Directory.CreateDirectory(snapshot);
            List<Dictionary<string, object>> saved = new List<Dictionary<string, object>>();
            foreach (Candidate c in candidates)
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["root"] = c.RootName;
                d["key"] = c.KeyPath;
                d["name"] = c.ValueName;
                d["data"] = c.ValueData;
                saved.Add(d);
            }
            File.WriteAllText(Path.Combine(snapshot, "run-values.json"), new JavaScriptSerializer().Serialize(saved), Encoding.UTF8);

            int failures = 0;
            foreach (Candidate c in candidates)
            {
                using (RegistryKey key = c.Root.OpenSubKey(c.KeyPath, true))
                {
                    if (key == null) { failures++; continue; }
                    key.DeleteValue(c.ValueName, false);
                }
                if (ValueExists(c.Root, c.KeyPath, c.ValueName))
                {
                    failures++;
                    Console.WriteLine("Read-back failed, value still present: " + Describe(c));
                    continue;
                }
                Receipt("persistence-clean", Describe(c));
                Console.WriteLine("Removed and verified: " + Describe(c));
            }
            Console.WriteLine("Snapshot of removed values: " + snapshot + " (restore with: persistence restore \"" + snapshot + "\" --apply)");
            return failures == 0 ? 0 : 1;
        }

        private static int Restore(string snapshotDir, bool apply)
        {
            if (File.Exists(Path.Combine(snapshotDir, "tasks.json"))) return PersistenceTasks.RestoreTasks(snapshotDir, apply);
            if (File.Exists(Path.Combine(snapshotDir, "services.json"))) return PersistenceTasks.RestoreServices(snapshotDir, apply);
            if (File.Exists(Path.Combine(snapshotDir, "wmi.json"))) return PersistenceWmi.Restore(snapshotDir, apply);
            string file = Path.Combine(snapshotDir, "run-values.json");
            if (!File.Exists(file))
            {
                Console.WriteLine("No run-values.json, tasks.json, or services.json in " + snapshotDir);
                return 2;
            }
            List<Dictionary<string, object>> saved = new JavaScriptSerializer().Deserialize<List<Dictionary<string, object>>>(
                File.ReadAllText(file, Encoding.UTF8));
            foreach (Dictionary<string, object> d in saved)
            {
                Console.WriteLine((apply ? "Restoring " : "Would restore ") + d["root"] + "\\" + d["key"] + " :: " + d["name"] + " = " + d["data"]);
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to restore these values.");
                return 0;
            }

            int failures = 0;
            foreach (Dictionary<string, object> d in saved)
            {
                RegistryKey root = Convert.ToString(d["root"]) == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                string keyPath = Convert.ToString(d["key"]);
                string name = Convert.ToString(d["name"]);
                string data = Convert.ToString(d["data"]);
                using (RegistryKey key = root.CreateSubKey(keyPath))
                {
                    key.SetValue(name, data, RegistryValueKind.String);
                }
                object readBack = ReadValue(root, keyPath, name);
                if (!string.Equals(Convert.ToString(readBack), data, StringComparison.Ordinal))
                {
                    failures++;
                    Console.WriteLine("Read-back mismatch restoring " + name);
                    continue;
                }
                Receipt("persistence-restore", Convert.ToString(d["root"]) + "\\" + keyPath + " :: " + name);
            }
            return failures == 0 ? 0 : 1;
        }

        private static IEnumerable<Candidate> FindRunValues()
        {
            RegistryKey[] roots = { Registry.LocalMachine, Registry.CurrentUser };
            string[] names = { "HKLM", "HKCU" };
            for (int r = 0; r < roots.Length; r++)
            {
                foreach (string keyPath in RunKeys)
                {
                    using (RegistryKey key = roots[r].OpenSubKey(keyPath))
                    {
                        if (key == null) continue;
                        foreach (string valueName in key.GetValueNames())
                        {
                            string data = Convert.ToString(key.GetValue(valueName));
                            yield return new Candidate
                            {
                                Root = roots[r],
                                RootName = names[r],
                                KeyPath = keyPath,
                                ValueName = valueName,
                                ValueData = data,
                                Target = LaunchTarget(data)
                            };
                        }
                    }
                }
            }
        }

        // Extracts the executable from a Run value: quoted path, or the first token up to .exe.
        public static string LaunchTarget(string command)
        {
            if (string.IsNullOrEmpty(command)) return null;
            Match quoted = Regex.Match(command, "^\\s*\"([^\"]+)\"");
            string raw;
            if (quoted.Success) raw = quoted.Groups[1].Value;
            else
            {
                Match bare = Regex.Match(command, @"^\s*(\S+?\.exe)\b", RegexOptions.IgnoreCase);
                if (!bare.Success) return null;
                raw = bare.Groups[1].Value;
            }
            string expanded = Environment.ExpandEnvironmentVariables(raw);
            try
            {
                return Path.GetFullPath(expanded);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static bool ValueExists(RegistryKey root, string keyPath, string name)
        {
            using (RegistryKey key = root.OpenSubKey(keyPath))
            {
                return key != null && key.GetValue(name) != null;
            }
        }

        private static object ReadValue(RegistryKey root, string keyPath, string name)
        {
            using (RegistryKey key = root.OpenSubKey(keyPath))
            {
                return key == null ? null : key.GetValue(name);
            }
        }

        // Returns the quarantine manifest entry for target only when the original path is gone and the
        // quarantined copy still has its recorded hash. Otherwise returns null.
        internal static ManifestEntry FindQuarantined(string target, List<ManifestEntry> manifest)
        {
            if (string.IsNullOrEmpty(target)) return null;
            foreach (ManifestEntry m in manifest)
            {
                if (!string.Equals(m.Original, target, StringComparison.OrdinalIgnoreCase)) continue;
                if (File.Exists(m.Original)) return null;
                if (!File.Exists(m.Quarantined)) return null;
                if (!string.Equals(Reputation.Sha256File(m.Quarantined), m.Sha256, StringComparison.OrdinalIgnoreCase)) return null;
                return m;
            }
            return null;
        }

        internal static List<ManifestEntry> ReadManifest()
        {
            List<ManifestEntry> list = new List<ManifestEntry>();
            string path = Path.Combine(FileScanner.QuarantineDirectory, "manifest.jsonl");
            if (!File.Exists(path)) return list;
            foreach (string line in File.ReadAllLines(path))
            {
                if (string.IsNullOrEmpty(line.Trim())) continue;
                Dictionary<string, object> d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(line);
                list.Add(new ManifestEntry
                {
                    Original = Convert.ToString(d["original"]),
                    Quarantined = Convert.ToString(d["quarantined"]),
                    Sha256 = Convert.ToString(d["sha256"])
                });
            }
            return list;
        }

        private static string Describe(Candidate c)
        {
            return c.RootName + "\\" + c.KeyPath + " :: " + c.ValueName + " -> " + c.Target;
        }

        internal static void Receipt(string action, string detail)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ReceiptLog));
                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["time"] = DateTime.UtcNow.ToString("o");
                entry["action"] = action;
                entry["detail"] = detail;
                File.AppendAllText(ReceiptLog, new JavaScriptSerializer().Serialize(entry) + "\r\n", Encoding.UTF8);
            }
            catch (Exception)
            {
                // Receipt logging does not undo a verified change.
            }
        }
    }
}
