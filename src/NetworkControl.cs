using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Text;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    // DNS and program-scoped outbound firewall control with snapshots and rollback.
    // Every mutating command is a dry run unless --apply is given. Changes are read back and recorded.
    internal static class NetworkControl
    {
        private const string RulePrefix = "SentinelTwo-block-";

        public static string DataDirectory
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "network"); }
        }

        private static string ChangeLog
        {
            get { return Path.Combine(DataDirectory, "changes.jsonl"); }
        }

        private static string RuleManifest
        {
            get { return Path.Combine(DataDirectory, "firewall-rules.json"); }
        }

        public static int Run(string[] args)
        {
            if (args.Length < 2) return Usage();
            string area = args[0];
            string verb = args[1];
            List<string> rest = new List<string>();
            bool apply = false;
            string adapter = null;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--apply") apply = true;
                else if (args[i] == "--adapter" && i + 1 < args.Length) adapter = args[++i];
                else rest.Add(args[i]);
            }

            if (area == "dns")
            {
                if (verb == "status") return DnsStatus();
                if (verb == "snapshot") { SnapshotDns(); return 0; }
                if (verb == "set") return DnsSet(rest, adapter, apply);
                if (verb == "restore") return rest.Count == 1 ? DnsRestore(rest[0], apply) : Usage();
            }
            else if (area == "firewall")
            {
                if (verb == "list") return FirewallList();
                if (verb == "block" && rest.Count == 1) return FirewallBlock(rest[0], apply);
                if (verb == "unblock" && rest.Count == 1) return FirewallUnblock(rest[0], apply);
                if (verb == "unblock-all") return FirewallUnblockAll(apply);
                if (verb == "block-port" && rest.Count == 2) return FirewallBlockPort(rest[0], rest[1], apply);
                if (verb == "unblock-port" && rest.Count == 2) return FirewallUnblockPort(rest[0], rest[1], apply);
            }
            return Usage();
        }

        private static int Usage()
        {
            Console.WriteLine("usage:");
            Console.WriteLine("  dns status");
            Console.WriteLine("  dns snapshot");
            Console.WriteLine("  dns set <ip> [ip2] --adapter <name> [--apply]");
            Console.WriteLine("  dns restore <snapshot-dir> [--apply]");
            Console.WriteLine("  firewall list");
            Console.WriteLine("  firewall block <program.exe> [--apply]");
            Console.WriteLine("  firewall unblock <program.exe> [--apply]");
            Console.WriteLine("  firewall unblock-all [--apply]");
            Console.WriteLine("  firewall block-port tcp|udp <port> [--apply]");
            Console.WriteLine("  firewall unblock-port tcp|udp <port> [--apply]");
            return 2;
        }

        // ---------------- DNS ----------------

        private sealed class AdapterDns
        {
            public string Name;
            public int Index;
            public bool DhcpEnabled;
            public List<string> Servers = new List<string>();
        }

        private static List<AdapterDns> ReadAdapters()
        {
            List<AdapterDns> list = new List<AdapterDns>();
            using (ManagementObjectSearcher s = new ManagementObjectSearcher("root\\cimv2",
                "SELECT Index, Description, DHCPEnabled, DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"))
            {
                foreach (ManagementObject cfg in s.Get())
                {
                    AdapterDns a = new AdapterDns();
                    a.Index = Convert.ToInt32(cfg["Index"]);
                    a.DhcpEnabled = cfg["DHCPEnabled"] != null && (bool)cfg["DHCPEnabled"];
                    string[] dns = cfg["DNSServerSearchOrder"] as string[];
                    if (dns != null) a.Servers.AddRange(dns);
                    a.Name = AdapterName(a.Index, Convert.ToString(cfg["Description"]));
                    list.Add(a);
                }
            }
            return list;
        }

        private static string AdapterName(int index, string fallback)
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher("root\\cimv2",
                "SELECT NetConnectionID FROM Win32_NetworkAdapter WHERE Index = " + index))
            {
                foreach (ManagementObject mo in s.Get())
                {
                    string id = mo["NetConnectionID"] as string;
                    if (!string.IsNullOrEmpty(id)) return id;
                }
            }
            return fallback;
        }

        private static int DnsStatus()
        {
            foreach (AdapterDns a in ReadAdapters())
            {
                Console.WriteLine(a.Name + "  dhcp=" + a.DhcpEnabled + "  dns=" +
                                  (a.Servers.Count == 0 ? "(none)" : string.Join(", ", a.Servers.ToArray())));
            }
            return 0;
        }

        private static string SnapshotDns()
        {
            string dir = Path.Combine(DataDirectory, "snapshots", DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));
            Directory.CreateDirectory(dir);
            List<Dictionary<string, object>> items = new List<Dictionary<string, object>>();
            foreach (AdapterDns a in ReadAdapters())
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["name"] = a.Name;
                d["index"] = a.Index;
                d["dhcp"] = a.DhcpEnabled;
                d["servers"] = a.Servers;
                items.Add(d);
            }
            File.WriteAllText(Path.Combine(dir, "dns.json"), new JavaScriptSerializer().Serialize(items), Encoding.UTF8);
            Console.WriteLine("Snapshot saved: " + dir);
            return dir;
        }

        private static int DnsSet(List<string> servers, string adapterName, bool apply)
        {
            if (servers.Count == 0 || string.IsNullOrEmpty(adapterName))
            {
                Console.WriteLine("dns set needs at least one server IP and --adapter <name>.");
                return 2;
            }
            foreach (string s in servers)
            {
                IPAddress ip;
                if (!IPAddress.TryParse(s, out ip))
                {
                    Console.WriteLine("Not an IP address: " + s);
                    return 2;
                }
            }

            AdapterDns target = null;
            foreach (AdapterDns a in ReadAdapters())
            {
                if (string.Equals(a.Name, adapterName, StringComparison.OrdinalIgnoreCase)) target = a;
            }
            if (target == null)
            {
                Console.WriteLine("No active adapter named \"" + adapterName + "\". Run: dns status");
                return 2;
            }

            Console.WriteLine("Plan: set DNS on \"" + target.Name + "\" from [" +
                              (target.Servers.Count == 0 ? "none" : string.Join(", ", target.Servers.ToArray())) +
                              "] to [" + string.Join(", ", servers.ToArray()) + "]");
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to change DNS. A snapshot is saved first.");
                return 0;
            }

            string snapshot = SnapshotDns();
            Netsh("interface ip set dns name=\"" + target.Name + "\" static " + servers[0] + " primary");
            for (int i = 1; i < servers.Count; i++)
            {
                Netsh("interface ip add dns name=\"" + target.Name + "\" addr=" + servers[i] + " index=" + (i + 1));
            }

            List<string> readBack = CurrentServers(target.Name);
            if (!SameList(readBack, servers))
            {
                Console.WriteLine("Read-back mismatch (" + string.Join(", ", readBack.ToArray()) + "). Restoring snapshot.");
                RestoreFrom(snapshot);
                Record("dns-set-failed", target.Name, servers);
                return 1;
            }
            Record("dns-set", target.Name, servers);
            Console.WriteLine("DNS on \"" + target.Name + "\" set and verified. Rollback: dns restore " + snapshot + " --apply");
            return 0;
        }

        private static int DnsRestore(string snapshotDir, bool apply)
        {
            string file = Path.Combine(snapshotDir, "dns.json");
            if (!File.Exists(file))
            {
                Console.WriteLine("No dns.json in " + snapshotDir);
                return 2;
            }
            if (!apply)
            {
                Console.WriteLine("Dry run: would restore DNS from " + snapshotDir + ". Add --apply to restore.");
                return 0;
            }
            bool ok = RestoreFrom(snapshotDir);
            Record(ok ? "dns-restore" : "dns-restore-failed", snapshotDir, new List<string>());
            return ok ? 0 : 1;
        }

        // Restores each adapter in the snapshot. DHCP adapters go back to DHCP, then are checked against
        // the snapshot. Any mismatch is replaced with the recorded static list, so the prior state is kept.
        private static bool RestoreFrom(string snapshotDir)
        {
            List<Dictionary<string, object>> items = new JavaScriptSerializer().Deserialize<List<Dictionary<string, object>>>(
                File.ReadAllText(Path.Combine(snapshotDir, "dns.json"), Encoding.UTF8));
            bool allOk = true;
            foreach (Dictionary<string, object> item in items)
            {
                string name = Convert.ToString(item["name"]);
                bool dhcp = (bool)item["dhcp"];
                List<string> servers = new List<string>();
                foreach (object s in (System.Collections.IEnumerable)item["servers"]) servers.Add(Convert.ToString(s));

                if (dhcp)
                {
                    Netsh("interface ip set dns name=\"" + name + "\" dhcp");
                    if (SameList(CurrentServers(name), servers)) continue;
                }
                if (servers.Count == 0)
                {
                    Netsh("interface ip set dns name=\"" + name + "\" dhcp");
                    continue;
                }
                Netsh("interface ip set dns name=\"" + name + "\" static " + servers[0] + " primary");
                for (int i = 1; i < servers.Count; i++)
                {
                    Netsh("interface ip add dns name=\"" + name + "\" addr=" + servers[i] + " index=" + (i + 1));
                }
                if (!SameList(CurrentServers(name), servers))
                {
                    Console.WriteLine("Could not verify restored DNS on \"" + name + "\".");
                    allOk = false;
                }
            }
            Console.WriteLine(allOk ? "DNS restored and verified." : "DNS restore finished with unverified adapters.");
            return allOk;
        }

        private static List<string> CurrentServers(string adapterName)
        {
            foreach (AdapterDns a in ReadAdapters())
            {
                if (string.Equals(a.Name, adapterName, StringComparison.OrdinalIgnoreCase)) return a.Servers;
            }
            return new List<string>();
        }

        private static bool SameList(List<string> a, List<string> b)
        {
            if (a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++)
            {
                if (!string.Equals(a[i], b[i], StringComparison.OrdinalIgnoreCase)) return false;
            }
            return true;
        }

        // ---------------- Firewall ----------------

        private static int FirewallBlock(string programArg, bool apply)
        {
            string program = Path.GetFullPath(programArg);
            if (!File.Exists(program))
            {
                Console.WriteLine("Program not found: " + program);
                return 2;
            }
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            if (!string.IsNullOrEmpty(systemRoot) && program.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Refusing to block programs under the Windows directory: " + program);
                return 2;
            }
            if (string.Equals(program, Monitors.CurrentExecutablePath(), StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Refusing to block SentinelTwo itself.");
                return 2;
            }

            string name = RuleName(program);
            Console.WriteLine("Plan: outbound block rule \"" + name + "\" for " + program);
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to create the rule.");
                return 0;
            }

            Netsh("advfirewall firewall add rule name=\"" + name + "\" dir=out action=block program=\"" + program + "\" enable=yes profile=any");
            if (!RuleExists(name))
            {
                Console.WriteLine("Read-back failed: rule not found after add.");
                return 1;
            }
            List<Dictionary<string, object>> rules = ReadRules();
            Dictionary<string, object> entry = new Dictionary<string, object>();
            entry["name"] = name;
            entry["program"] = program;
            entry["created"] = DateTime.UtcNow.ToString("o");
            rules.Add(entry);
            WriteRules(rules);
            Record("firewall-block", program, new List<string>());
            Console.WriteLine("Rule created and verified. Rollback: firewall unblock \"" + program + "\" --apply");
            return 0;
        }

        private static int FirewallUnblock(string programArg, bool apply)
        {
            string program = Path.GetFullPath(programArg);
            return RemoveRecorded(rule => string.Equals(Convert.ToString(rule["program"]), program, StringComparison.OrdinalIgnoreCase), apply);
        }

        private static int FirewallUnblockAll(bool apply)
        {
            return RemoveRecorded(rule => true, apply);
        }

        // Outbound block for one protocol and remote port across all programs. This is broad by design,
        // so the plan states the scope. DNS, DHCP, and NTP ports are refused because blocking them breaks networking.
        private static int FirewallBlockPort(string protocolArg, string portArg, bool apply)
        {
            string protocol = protocolArg.ToUpperInvariant();
            int port;
            if ((protocol != "TCP" && protocol != "UDP") || !int.TryParse(portArg, out port) || port < 1 || port > 65535)
            {
                Console.WriteLine("usage: firewall block-port tcp|udp <1-65535> [--apply]");
                return 2;
            }
            if (port == 53 || port == 67 || port == 68 || port == 123)
            {
                Console.WriteLine("Refusing port " + port + ": blocking DNS, DHCP, or NTP breaks basic networking.");
                return 2;
            }

            string key = "port:" + protocol + ":" + port;
            string name = "SentinelTwo-block-" + protocol.ToLowerInvariant() + "-" + port;
            Console.WriteLine("Plan: outbound block rule \"" + name + "\" for remote " + protocol + " port " + port + " (all programs).");
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to create the rule.");
                return 0;
            }

            Netsh("advfirewall firewall add rule name=\"" + name + "\" dir=out action=block protocol=" + protocol +
                  " remoteport=" + port + " enable=yes profile=any");
            if (!RuleExists(name))
            {
                Console.WriteLine("Read-back failed: rule not found after add.");
                return 1;
            }
            List<Dictionary<string, object>> rules = ReadRules();
            Dictionary<string, object> entry = new Dictionary<string, object>();
            entry["name"] = name;
            entry["program"] = key;
            entry["created"] = DateTime.UtcNow.ToString("o");
            rules.Add(entry);
            WriteRules(rules);
            Record("firewall-block-port", key, new List<string>());
            Console.WriteLine("Rule created and verified. Rollback: firewall unblock-port " + protocol.ToLowerInvariant() + " " + port + " --apply");
            return 0;
        }

        private static int FirewallUnblockPort(string protocolArg, string portArg, bool apply)
        {
            string key = "port:" + protocolArg.ToUpperInvariant() + ":" + portArg;
            return RemoveRecorded(rule => string.Equals(Convert.ToString(rule["program"]), key, StringComparison.OrdinalIgnoreCase), apply);
        }

        // Removes only rules recorded in the manifest. Rules created by other tools are never touched.
        private static int RemoveRecorded(Func<Dictionary<string, object>, bool> match, bool apply)
        {
            List<Dictionary<string, object>> rules = ReadRules();
            List<Dictionary<string, object>> selected = rules.FindAll(r => match(r));
            if (selected.Count == 0)
            {
                Console.WriteLine("No SentinelTwo-recorded rules match.");
                return 0;
            }
            foreach (Dictionary<string, object> r in selected)
            {
                Console.WriteLine((apply ? "Removing " : "Would remove ") + Convert.ToString(r["name"]) + " (" + Convert.ToString(r["program"]) + ")");
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to remove these rules.");
                return 0;
            }

            int failures = 0;
            foreach (Dictionary<string, object> r in selected)
            {
                string name = Convert.ToString(r["name"]);
                Netsh("advfirewall firewall delete rule name=\"" + name + "\"");
                if (RuleExists(name))
                {
                    failures++;
                    Console.WriteLine("Rule still present: " + name);
                    continue;
                }
                rules.Remove(r);
                Record("firewall-unblock", Convert.ToString(r["program"]), new List<string>());
            }
            WriteRules(rules);
            return failures == 0 ? 0 : 1;
        }

        private static int FirewallList()
        {
            List<Dictionary<string, object>> rules = ReadRules();
            if (rules.Count == 0) Console.WriteLine("No SentinelTwo firewall rules recorded.");
            foreach (Dictionary<string, object> r in rules)
            {
                string name = Convert.ToString(r["name"]);
                Console.WriteLine(name + "  " + Convert.ToString(r["program"]) + "  present=" + RuleExists(name));
            }
            return 0;
        }

        internal static string RuleName(string program)
        {
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(program.ToLowerInvariant()));
                return RulePrefix + BitConverter.ToString(hash, 0, 6).Replace("-", "").ToLowerInvariant();
            }
        }

        private static bool RuleExists(string name)
        {
            string output;
            int code = Netsh("advfirewall firewall show rule name=\"" + name + "\"", out output);
            return code == 0 && output.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static List<Dictionary<string, object>> ReadRules()
        {
            if (!File.Exists(RuleManifest)) return new List<Dictionary<string, object>>();
            List<Dictionary<string, object>> list = new JavaScriptSerializer().Deserialize<List<Dictionary<string, object>>>(
                File.ReadAllText(RuleManifest, Encoding.UTF8));
            return list ?? new List<Dictionary<string, object>>();
        }

        private static void WriteRules(List<Dictionary<string, object>> rules)
        {
            Directory.CreateDirectory(DataDirectory);
            File.WriteAllText(RuleManifest, new JavaScriptSerializer().Serialize(rules), Encoding.UTF8);
        }

        // ---------------- Shared ----------------

        private static int Netsh(string arguments)
        {
            string output;
            return Netsh(arguments, out output);
        }

        private static int Netsh(string arguments, out string output)
        {
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"), arguments);
            info.UseShellExecute = false;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.CreateNoWindow = true;
            using (Process p = Process.Start(info))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                output = stdout + stderr;
                if (p.ExitCode != 0) Console.WriteLine("netsh failed (" + p.ExitCode + "): " + output.Trim());
                return p.ExitCode;
            }
        }

        private static void Record(string action, string target, List<string> servers)
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["time"] = DateTime.UtcNow.ToString("o");
                entry["action"] = action;
                entry["target"] = target;
                entry["servers"] = servers;
                File.AppendAllText(ChangeLog, new JavaScriptSerializer().Serialize(entry) + "\r\n", Encoding.UTF8);
            }
            catch (Exception)
            {
                // Audit write failure does not undo a verified change.
            }
        }
    }
}
