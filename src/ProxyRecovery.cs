using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace SentinelTwo
{
    // Current-user WinINET proxy inspection, disable, and restore. Enterprise policy settings are never
    // changed: if a policy key defines the proxy, the command refuses. Each change is snapshotted,
    // read back, and logged.
    internal static class ProxyRecovery
    {
        private const string SettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        private static readonly string[] PolicyPaths = {
            @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
            @"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
        };
        private static readonly string[] Values = { "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect" };

        private static string DataDirectory
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "proxy"); }
        }

        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr session, int option, IntPtr buffer, int length);

        public static int Run(string[] args)
        {
            if (args.Length < 2) return Usage();
            bool apply = args.Length > 2 && args[2] == "--apply";
            switch (args[1])
            {
                case "status": return Status();
                case "disable": return Disable(apply);
                case "restore":
                    if (args.Length < 3 || args[2] == "--apply") return Usage();
                    return Restore(args[2], args.Length > 3 && args[3] == "--apply");
                default: return Usage();
            }
        }

        private static int Usage()
        {
            Console.WriteLine("usage:");
            Console.WriteLine("  proxy status");
            Console.WriteLine("  proxy disable [--apply]              (snapshot first; refused when policy manages the proxy)");
            Console.WriteLine("  proxy restore <snapshot-dir> [--apply]");
            return 2;
        }

        private static Dictionary<string, object> ReadCurrent()
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(SettingsPath))
            {
                foreach (string v in Values)
                {
                    d[v] = key == null ? null : key.GetValue(v);
                }
            }
            return d;
        }

        private static bool PolicyManaged()
        {
            foreach (string path in PolicyPaths)
            {
                foreach (RegistryKey root in new RegistryKey[] { Registry.LocalMachine, Registry.CurrentUser })
                {
                    using (RegistryKey key = root.OpenSubKey(path))
                    {
                        if (key == null) continue;
                        foreach (string v in new string[] { "ProxyEnable", "ProxyServer", "AutoConfigURL" })
                        {
                            if (key.GetValue(v) != null) return true;
                        }
                    }
                }
            }
            return false;
        }

        internal static List<string> Findings(Dictionary<string, object> s)
        {
            List<string> notes = new List<string>();
            string server = Convert.ToString(s["ProxyServer"]);
            string pac = Convert.ToString(s["AutoConfigURL"]);
            if (IsEnabled(s) && !string.IsNullOrEmpty(server) && (server.StartsWith("127.0.0.1") || server.StartsWith("localhost") || server.StartsWith("[::1]")))
                notes.Add("proxy points at loopback (" + server + ")");
            if (!string.IsNullOrEmpty(pac) && pac.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                notes.Add("PAC script fetched over plain HTTP (" + pac + ")");
            return notes;
        }

        private static bool IsEnabled(Dictionary<string, object> s)
        {
            return s["ProxyEnable"] != null && Convert.ToInt32(s["ProxyEnable"]) == 1;
        }

        private static int Status()
        {
            Dictionary<string, object> s = ReadCurrent();
            Console.WriteLine("ProxyEnable=" + (s["ProxyEnable"] ?? "(not set)") +
                              "  ProxyServer=" + (s["ProxyServer"] ?? "(not set)") +
                              "  AutoConfigURL=" + (s["AutoConfigURL"] ?? "(not set)"));
            Console.WriteLine("Policy-managed: " + (PolicyManaged() ? "yes (changes refused)" : "no"));
            foreach (string note in Findings(s)) Console.WriteLine("Finding: " + note);
            Console.WriteLine("WinHTTP (machine-wide):");
            string output = NetshOutput("winhttp show proxy");
            Console.Write(output);
            return 0;
        }

        private static int Disable(bool apply)
        {
            Dictionary<string, object> s = ReadCurrent();
            if (!IsEnabled(s))
            {
                Console.WriteLine("Current-user proxy is already disabled.");
                return 0;
            }
            if (PolicyManaged())
            {
                Console.WriteLine("Refusing: a policy key manages proxy settings. Change it through policy.");
                return 2;
            }
            Console.WriteLine("Plan: set ProxyEnable=0 for the current user (ProxyServer and AutoConfigURL are kept for restore).");
            foreach (string note in Findings(s)) Console.WriteLine("Finding: " + note);
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to disable.");
                return 0;
            }

            string snapshot = Path.Combine(DataDirectory, "snapshots", DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));
            Directory.CreateDirectory(snapshot);
            File.WriteAllText(Path.Combine(snapshot, "wininet.json"), new JavaScriptSerializer().Serialize(s), Encoding.UTF8);

            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(SettingsPath))
            {
                key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            }
            Notify();

            Dictionary<string, object> after = ReadCurrent();
            if (IsEnabled(after))
            {
                Console.WriteLine("Read-back failed: ProxyEnable is still 1. Restoring snapshot.");
                Restore(snapshot, true);
                Receipt("proxy-disable-failed", snapshot);
                return 1;
            }
            Receipt("proxy-disable", snapshot);
            Console.WriteLine("Proxy disabled and verified. Rollback: proxy restore \"" + snapshot + "\" --apply");
            return 0;
        }

        private static int Restore(string snapshotDir, bool apply)
        {
            string file = Path.Combine(snapshotDir, "wininet.json");
            if (!File.Exists(file))
            {
                Console.WriteLine("No wininet.json in " + snapshotDir);
                return 2;
            }
            Dictionary<string, object> saved = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(
                File.ReadAllText(file, Encoding.UTF8));
            if (!apply)
            {
                Console.WriteLine("Dry run: would restore ProxyEnable=" + (saved["ProxyEnable"] ?? "(not set)") +
                                  " ProxyServer=" + (saved["ProxyServer"] ?? "(not set)") + ". Add --apply to restore.");
                return 0;
            }

            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(SettingsPath))
            {
                foreach (string v in Values)
                {
                    object value = saved.ContainsKey(v) ? saved[v] : null;
                    if (value == null)
                    {
                        key.DeleteValue(v, false);
                    }
                    else if (v == "ProxyEnable" || v == "AutoDetect")
                    {
                        key.SetValue(v, Convert.ToInt32(value), RegistryValueKind.DWord);
                    }
                    else
                    {
                        key.SetValue(v, Convert.ToString(value), RegistryValueKind.String);
                    }
                }
            }
            Notify();

            Dictionary<string, object> now = ReadCurrent();
            foreach (string v in Values)
            {
                string expected = saved.ContainsKey(v) && saved[v] != null ? Convert.ToString(saved[v]) : "";
                string actual = now[v] == null ? "" : Convert.ToString(now[v]);
                if (expected != actual)
                {
                    Console.WriteLine("Read-back mismatch for " + v + ".");
                    Receipt("proxy-restore-failed", snapshotDir);
                    return 1;
                }
            }
            Receipt("proxy-restore", snapshotDir);
            Console.WriteLine("Proxy settings restored and verified.");
            return 0;
        }

        // Tells WinINET that settings changed so running applications pick them up.
        private static void Notify()
        {
            const int SETTINGS_CHANGED = 39;
            const int REFRESH = 37;
            InternetSetOption(IntPtr.Zero, SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, REFRESH, IntPtr.Zero, 0);
        }

        private static string NetshOutput(string arguments)
        {
            System.Diagnostics.ProcessStartInfo info = new System.Diagnostics.ProcessStartInfo(
                Path.Combine(Environment.SystemDirectory, "netsh.exe"), arguments);
            info.UseShellExecute = false;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.CreateNoWindow = true;
            using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(info))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                return stdout + stderr;
            }
        }

        private static void Receipt(string action, string snapshot)
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["time"] = DateTime.UtcNow.ToString("o");
                entry["action"] = action;
                entry["snapshot"] = snapshot;
                File.AppendAllText(Path.Combine(DataDirectory, "changes.jsonl"), new JavaScriptSerializer().Serialize(entry) + "\r\n", Encoding.UTF8);
            }
            catch (Exception)
            {
                // Receipt failure does not change the verified result printed above.
            }
        }
    }
}
