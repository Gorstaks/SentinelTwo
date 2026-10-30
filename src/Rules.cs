using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace SentinelTwo
{
    // Behavioral rules over process command lines and parent/child structure.
    // Patterns are kept identical to the PowerShell originals (matched against lowercased text unless noted).
    internal static class Rules
    {
        private static readonly string[] Shells = { "cmd.exe", "powershell.exe", "pwsh.exe" };
        private static readonly string[] NormalParents = {
            "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "svchost.exe",
            "services.exe", "code.exe", "WindowsTerminal.exe", "wt.exe", "conhost.exe"
        };
        private static readonly string[] OfficeApps = { "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "MSACCESS.EXE" };

        public static Detection Destructive(string cl, int pid, string name)
        {
            if (string.IsNullOrEmpty(cl)) return null;
            string c = cl.ToLowerInvariant();
            string hit = null;
            if (Regex.IsMatch(c, @"vssadmin.*delete|shadowcopy.*delete|shadows.*\/all|resize.*shadowstorage"))
                hit = "Shadow copy destruction";
            else if (Regex.IsMatch(c, @"recoveryenabled.*no|bootstatuspolicy.*ignore"))
                hit = "Boot recovery disabled";
            else if (Regex.IsMatch(c, @"wbadmin.*delete.*(catalog|systemstate)"))
                hit = "Backup catalog destruction";
            else if (Regex.IsMatch(c, @"(net\s+stop|sc\s+(stop|config.*disabled))") &&
                     Regex.IsMatch(c, @"(sql|exchange|backup|vss|veeam)"))
                hit = "Critical service disruption";
            if (hit == null) return null;
            return new Detection
            {
                Rule = "Destructive",
                Evidence = hit + " by " + name + " (PID " + pid + ")",
                Reasoning = "Destroying recovery mechanisms - ransomware precursor",
                Confidence = 0.93,
                Tier = Correlation.Tier1,
                Category = "ransomware"
            };
        }

        public static Detection CredentialAccess(string cl, int pid, string name)
        {
            if (string.IsNullOrEmpty(cl)) return null;
            string c = cl.ToLowerInvariant();
            if (Regex.IsMatch(c, @"comsvcs.*minidump|comsvcs\.dll.*#24|comsvcs.*full"))
                return Cred("CredentialDump", "MiniDump via comsvcs.dll (PID " + pid + ")",
                    "Windows built-in DLL used for process memory dump", 0.92, Correlation.Tier1);
            if (Regex.IsMatch(c, @"lsass") && Regex.IsMatch(c, @"dump|mini|dbg|clone|fork|snap|\.dmp"))
                return Cred("CredentialDump", "LSASS memory targeting (PID " + pid + ")",
                    "Explicit LSASS memory extraction attempt", 0.90, Correlation.Tier1);
            if (Regex.IsMatch(c, @"(?:^|[\s&;|])(?:\x22?[^\x22\s]*[\\/])?reg(?:\.exe)?\x22?\s+(?:save|export)\s+\x22?(?:hklm|hkey_local_machine)\\(?:sam|security|system)(?=[\s\x22\\]|$)"))
                return Cred("CredentialDump", "Registry hive extraction (PID " + pid + ")",
                    "Extracting credential hives for offline cracking", 0.91, Correlation.Tier1);
            if (Regex.IsMatch(c, @"dpapi") && Regex.IsMatch(c, @"masterkey|credential|protect|unprotect"))
                return Cred("CredentialDump", "DPAPI credential extraction (PID " + pid + ")",
                    "Targeting DPAPI for stored credential theft", 0.85, Correlation.Tier1);
            if (Regex.IsMatch(c, @"(login\s*data|local\s*state|cookies).*chrome|key4\.db|logins\.json|cookies\.sqlite|\.tbres|tokenbroker") &&
                Regex.IsMatch(c, @"copy|type|get-content|select-string|sqlite|cryptunprotect"))
                return Cred("BrowserCredTheft", "Browser credential store access (PID " + pid + ")",
                    "Accessing browser credential files with extraction intent", 0.87, Correlation.Tier1);
            return null;
        }

        private static Detection Cred(string rule, string evidence, string reasoning, double conf, string tier)
        {
            return new Detection { Rule = rule, Evidence = evidence, Reasoning = reasoning, Confidence = conf, Tier = tier, Category = "credential" };
        }

        private static Detection Simple(string rule, string evidence, string reasoning, double conf, string category)
        {
            return new Detection { Rule = rule, Evidence = evidence, Reasoning = reasoning, Confidence = conf, Tier = Correlation.Tier1, Category = category };
        }

        public static Detection Evasion(string cl, int pid, string name)
        {
            if (string.IsNullOrEmpty(cl)) return null;
            string c = cl.ToLowerInvariant();
            if (Regex.IsMatch(c, @"amsiscanbuffer|amsiinitialized|amsicontext"))
                return Simple("Evasion", "AMSI manipulation (PID " + pid + ")", "Patching Windows AMSI interface", 0.92, "evasion");
            if (Regex.IsMatch(c, @"nttracevent|etweventwrite"))
                return Simple("Evasion", "ETW blinding (PID " + pid + ")", "Patching ETW to blind security tools", 0.93, "evasion");
            if (Regex.IsMatch(c, @"wevtutil.*(cl|clear-log)\s+(security|system|application)"))
                return Simple("Evasion", "Event log clearing (PID " + pid + ")", "Destroying forensic evidence", 0.90, "evasion");
            if (Regex.IsMatch(c, @"set-mppreference.*-disable(realtimemonitoring|ioavprotection|behaviormonitoring)"))
                return Simple("Evasion", "Defender disabled (PID " + pid + ")", "Programmatically disabling endpoint protection", 0.91, "evasion");
            if (Regex.IsMatch(c, @"add-mppreference.*-exclusion"))
                return Simple("Evasion", "Defender exclusion added (PID " + pid + ")", "Adding exclusion to hide malware", 0.85, "evasion");
            if (Regex.IsMatch(c, @"fltmc.*unload"))
                return Simple("Evasion", "Minifilter unload (PID " + pid + ")", "Unloading security filter driver", 0.90, "evasion");
            return null;
        }

        public static Detection Persistence(string cl, int pid, string name)
        {
            if (string.IsNullOrEmpty(cl)) return null;
            string c = cl.ToLowerInvariant();
            if (Regex.IsMatch(c, @"(reg\s+add|new-itemproperty|set-itemproperty).*\\(run|runonce)\b"))
                return Simple("Persistence", "Registry Run key (PID " + pid + ")", "Auto-start registry persistence", 0.82, "persistence");
            if (Regex.IsMatch(c, @"(__eventfilter|__eventconsumer|filtertoconsumerbinding)"))
                return Simple("Persistence", "WMI subscription (PID " + pid + ")", "Fileless WMI persistence", 0.88, "persistence");
            if (Regex.IsMatch(c, @"(schtasks\s*/create|register-scheduledtask)") && !c.Contains("antiviruslite"))
                return new Detection { Rule = "Persistence", Evidence = "Scheduled task (PID " + pid + ")", Reasoning = "Task-based persistence", Confidence = 0.75, Tier = Correlation.Tier2, Category = "persistence" };
            if (Regex.IsMatch(c, @"(sc\s+create|new-service)") && !c.Contains("antiviruslite"))
                return new Detection { Rule = "Persistence", Evidence = "Service creation (PID " + pid + ")", Reasoning = "Service-based persistence", Confidence = 0.78, Tier = Correlation.Tier2, Category = "persistence" };
            return null;
        }

        public static Detection Execution(string cl, int pid, string name)
        {
            if (string.IsNullOrEmpty(cl)) return null;
            if (Regex.IsMatch(cl, @"-[eE][nN][cC]\w*\s+[A-Za-z0-9+/=]{100,}"))
            {
                double kb = Math.Round(cl.Length / 1024.0, 1);
                return new Detection
                {
                    Rule = "EncodedExec",
                    Evidence = "Encoded payload (" + kb.ToString(System.Globalization.CultureInfo.InvariantCulture) + "KB) (PID " + pid + ")",
                    Reasoning = "Encoded command line; also used by legitimate automation",
                    Confidence = 0.70,
                    Tier = Correlation.Tier2,
                    Category = "execution"
                };
            }
            string c = cl.ToLowerInvariant();
            if (Regex.IsMatch(c, @"downloadstring|downloadfile|downloaddata|invoke-webrequest") &&
                Regex.IsMatch(c, @"invoke-expression|iex\s|start-process|\.invoke\("))
                return Simple("DownloadExec", "Download-and-execute (PID " + pid + ")", "Downloading and immediately executing remote content", 0.87, "execution");
            if (Regex.IsMatch(c, @"reflection\.assembly.*load|gettype.*getmethod.*invoke|\[convert\]::frombase64.*load"))
                return Simple("ReflectiveLoad", "Reflective assembly load (PID " + pid + ")", "In-memory code loading via .NET reflection", 0.88, "execution");
            if (Regex.IsMatch(c, @"net\.sockets\.tcpclient|system\.net\.sockets") &&
                Regex.IsMatch(c, @"getstream|networkstream"))
                return Simple("ReverseShell", "Socket shell (PID " + pid + ")", "Building network stream shell via .NET socket APIs", 0.92, "c2");
            if (Regex.IsMatch(c, @"-executionpolicy\s*(bypass|unrestricted)") &&
                Regex.IsMatch(c, @"-w(indowstyle)?\s*h(idden)?"))
                return new Detection { Rule = "HiddenExec", Evidence = "Hidden+bypass execution (PID " + pid + ")", Reasoning = "PowerShell running hidden with policy bypass", Confidence = 0.72, Tier = Correlation.Tier2, Category = "execution" };
            return null;
        }

        public static Detection Escalation(string cl, int pid, string name)
        {
            if (string.IsNullOrEmpty(cl)) return null;
            string c = cl.ToLowerInvariant();
            if (Regex.IsMatch(c, @"duplicatetokenex|createprocesswithtoken|impersonateloggedonuser|adjusttokenprivileges.*sedebug"))
                return Simple("Escalation", "Token manipulation (PID " + pid + ")", "Windows token API abuse for privilege escalation", 0.88, "escalation");
            if (Regex.IsMatch(c, @"impersonatenamedpipeclient|createnamedpipe.*impersonate"))
                return Simple("Escalation", "Pipe impersonation (PID " + pid + ")", "Named pipe impersonation for escalation", 0.90, "escalation");
            if (Regex.IsMatch(c, @"fodhelper|computerdefaults|sdclt.*\/kickoffelev|eventvwr.*mmc"))
                return Simple("Escalation", "UAC bypass (PID " + pid + ")", "Exploiting auto-elevation for UAC bypass", 0.89, "escalation");
            return null;
        }

        public static Detection LateralMovement(string cl, int pid, string name)
        {
            if (string.IsNullOrEmpty(cl)) return null;
            string c = cl.ToLowerInvariant();
            if (Regex.IsMatch(c, @"(sc|wmic|invoke-wmimethod|invoke-command).*\\\\") || Regex.IsMatch(c, @"/node:.*process.*call.*create"))
                return Simple("LateralMovement", "Remote execution pattern (PID " + pid + ")", "Executing commands on remote system", 0.85, "lateral");
            if (Regex.IsMatch(c, @"enter-pssession|invoke-command.*-computer|new-pssession.*-computer"))
                return new Detection { Rule = "LateralMovement", Evidence = "PSRemoting (PID " + pid + ")", Reasoning = "PowerShell remoting to other systems", Confidence = 0.70, Tier = Correlation.Tier2, Category = "lateral" };
            return null;
        }

        public static Detection Genealogy(int pid, string name, int ppid)
        {
            if (pid <= 4) return null;
            ProcessInfo parent;
            string pName = AvState.Ancestry.TryGetValue(ppid, out parent) && parent != null ? parent.Name : "DEAD";
            ProcessInfo info;
            AvState.Ancestry.TryGetValue(pid, out info);

            if (AvState.ContainsCI(Shells, name) && AvState.ContainsCI(OfficeApps, pName))
                return Simple("OfficeShellSpawn", pName + " spawned " + name + " (PID " + pid + ")",
                    "Office application spawning command shell - macro/exploit execution", 0.88, "execution");

            if (AvState.ContainsCI(Shells, name) && !AvState.ContainsCI(NormalParents, pName) && pName != "DEAD")
                return new Detection { Rule = "UnusualShellParent", Evidence = name + " spawned by " + pName + " (PID " + ppid + ")", Reasoning = "Shell from unexpected parent - possible exploitation", Confidence = 0.72, Tier = Correlation.Tier2, Category = "genealogy" };

            if (pName == "DEAD" && info != null && !string.IsNullOrEmpty(info.Path))
            {
                string[] staging = { Environment.GetEnvironmentVariable("TEMP"), Environment.GetEnvironmentVariable("APPDATA"), "Downloads" };
                if (AvState.PathContainsAny(info.Path, staging))
                    return new Detection { Rule = "OrphanStaged", Evidence = name + " (PID " + pid + ") orphaned from " + info.Path, Reasoning = "Orphan process from staging path - dropped payload", Confidence = 0.70, Tier = Correlation.Tier2, Category = "genealogy" };
            }
            return null;
        }

        public static Detection UnsignedStaged(int pid, string name, string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            if (IsTrustedLocation(path)) return null;
            if (!AvState.PathContainsAny(path, AvState.StagingTokens())) return null;
            try
            {
                if (Reputation.IsAuthenticodeValid(path)) return null;
                double conf = 0.68;
                try
                {
                    HashVerdict rep = Reputation.Lookup(Reputation.Sha256File(path));
                    if (rep.Bad) conf = 0.92;
                }
                catch (Exception)
                {
                    // Reputation is best effort; the unsigned-staged signal still stands.
                }
                return new Detection { Rule = "UnsignedStaged", Evidence = name + " (PID " + pid + ") unsigned from " + path, Reasoning = "Unsigned binary executing from staging location", Confidence = conf, Tier = Correlation.Tier2, Category = "unsigned" };
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static bool IsTrustedLocation(string path)
        {
            string[] trusted = {
                Environment.GetEnvironmentVariable("SystemRoot"),
                Environment.GetEnvironmentVariable("ProgramFiles"),
                Environment.GetEnvironmentVariable("ProgramFiles(x86)")
            };
            foreach (string t in trusted)
            {
                if (!string.IsNullOrEmpty(t) && path.StartsWith(t, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public static void DnsAnomaly()
        {
            foreach (int pid in new List<int>(AvState.Ancestry.Keys))
            {
                ProcessInfo info;
                if (!AvState.Ancestry.TryGetValue(pid, out info) || info == null || string.IsNullOrEmpty(info.CommandLine)) continue;
                string cl = info.CommandLine;

                List<string> domains = new List<string>();
                Match url = Regex.Match(cl, @"https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)");
                if (url.Success) domains.Add(url.Groups[1].Value);
                Match lookup = Regex.Match(cl, @"(nslookup|resolve-dnsname|dig)\s+(\S+)");
                if (lookup.Success) domains.Add(lookup.Groups[2].Value);

                foreach (string domain in domains)
                {
                    string[] labels = domain.Split('.');
                    if (labels.Length < 2) continue;
                    // Longest label excluding the top-level domain.
                    string mainLabel = "";
                    for (int i = 0; i < labels.Length - 1; i++)
                    {
                        if (labels[i].Length > mainLabel.Length) mainLabel = labels[i];
                    }
                    if (mainLabel.Length < 8) continue;

                    double entropy = AvState.Entropy(mainLabel);
                    if (entropy <= 3.8) continue;
                    if (AvState.IsDup("DGA|" + pid + "|" + domain, 300)) continue;
                    AvLog.Write("detection", "DgaDomain",
                        info.Name + " (PID " + pid + ") accessing high-entropy domain: " + domain +
                        " (entropy=" + Math.Round(entropy, 2).ToString(System.Globalization.CultureInfo.InvariantCulture) + ")",
                        "Domain label has high Shannon entropy suggesting DGA-generated name",
                        0.72, Correlation.Tier2, info.Name, pid);
                    AvState.AddSignal(pid, "dga", 0.72);
                }
            }
        }
    }
}
