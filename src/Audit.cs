using System;
using System.Collections.Generic;
using System.Management;
using Microsoft.Win32;

namespace SentinelTwo
{
    // Read-only hardening and status report. Nothing is changed. Every check reports Enabled,
    // Disabled, or Unknown with the reason, so a missing provider is never shown as a pass.
    internal static class Audit
    {
        public static void Run()
        {
            Ui.Write("SentinelTwo read-only audit", ConsoleColor.Cyan);
            Line("LSA protection (RunAsPPL)", LsaProtection());
            Line("Virtualization-based security", VbsStatus());
            Line("Hypervisor-enforced code integrity (HVCI)", HvciConfigured());
            Line("Vulnerable driver blocklist", DriverBlocklist());
            foreach (string item in DefenderStatus()) Line("Defender", item);
            foreach (string item in RunKeyEntries()) Line("Startup Run key", item);
        }

        private static void Line(string label, string value)
        {
            Console.WriteLine(label + ": " + value);
        }

        private static string LsaProtection()
        {
            object value = ReadRegistry(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
            if (value == null) return "Disabled (value not set)";
            int v = Convert.ToInt32(value);
            return v == 1 || v == 2 ? "Enabled (RunAsPPL=" + v + ")" : "Disabled (RunAsPPL=" + v + ")";
        }

        private static string VbsStatus()
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(@"root\Microsoft\Windows\DeviceGuard",
                    "SELECT VirtualizationBasedSecurityStatus, SecurityServicesRunning FROM Win32_DeviceGuard"))
                {
                    foreach (ManagementObject mo in s.Get())
                    {
                        int status = Convert.ToInt32(mo["VirtualizationBasedSecurityStatus"]);
                        string running = "";
                        object services = mo["SecurityServicesRunning"];
                        if (services is Array)
                        {
                            List<string> names = new List<string>();
                            foreach (object id in (Array)services)
                            {
                                int code = Convert.ToInt32(id);
                                names.Add(code == 1 ? "Credential Guard" : code == 2 ? "HVCI" : "service " + code);
                            }
                            running = names.Count == 0 ? "none" : string.Join(", ", names.ToArray());
                        }
                        string state = status == 2 ? "running" : status == 1 ? "enabled, not running" : "off";
                        return state + " (services: " + running + ")";
                    }
                }
                return "Unknown (no Win32_DeviceGuard instance)";
            }
            catch (Exception ex)
            {
                return "Unknown (" + ex.Message + ")";
            }
        }

        private static string HvciConfigured()
        {
            object value = ReadRegistry(Registry.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled");
            if (value == null) return "Disabled (not configured)";
            return Convert.ToInt32(value) == 1 ? "Enabled (configured)" : "Disabled (Enabled=" + value + ")";
        }

        private static string DriverBlocklist()
        {
            object value = ReadRegistry(Registry.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable");
            if (value == null) return "Unknown (value not present on this Windows build)";
            return Convert.ToInt32(value) == 1 ? "Enabled" : "Disabled";
        }

        private static List<string> DefenderStatus()
        {
            List<string> lines = new List<string>();
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender",
                    "SELECT AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected FROM MSFT_MpComputerStatus"))
                {
                    foreach (ManagementObject mo in s.Get())
                    {
                        lines.Add("antivirus enabled=" + mo["AntivirusEnabled"] +
                                  ", real-time=" + mo["RealTimeProtectionEnabled"] +
                                  ", tamper protection=" + mo["IsTamperProtected"]);
                    }
                }
            }
            catch (Exception ex)
            {
                lines.Add("Unknown (" + ex.Message + ")");
            }
            if (lines.Count == 0) lines.Add("Unknown (no Defender status instance; provider absent or disabled)");
            return lines;
        }

        private static List<string> RunKeyEntries()
        {
            List<string> entries = new List<string>();
            string[] keys = {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            };
            RegistryKey[] roots = { Registry.LocalMachine, Registry.CurrentUser };
            string[] rootNames = { "HKLM", "HKCU" };
            for (int r = 0; r < roots.Length; r++)
            {
                foreach (string key in keys)
                {
                    using (RegistryKey k = roots[r].OpenSubKey(key))
                    {
                        if (k == null) continue;
                        foreach (string name in k.GetValueNames())
                        {
                            entries.Add(rootNames[r] + "\\" + key.Substring(key.LastIndexOf('\\') + 1) + " " + name + " = " + k.GetValue(name));
                        }
                    }
                }
            }
            if (entries.Count == 0) entries.Add("none");
            return entries;
        }

        private static object ReadRegistry(RegistryKey root, string path, string name)
        {
            using (RegistryKey k = root.OpenSubKey(path))
            {
                return k == null ? null : k.GetValue(name);
            }
        }
    }
}
