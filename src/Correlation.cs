using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace SentinelTwo
{
    internal sealed class Detection
    {
        public string Rule;
        public string Evidence;
        public string Reasoning;
        public double Confidence;
        public string Tier;
        public string Category;
        public string ProcessName;
        public int ProcessId;
        public string Fingerprint;
    }

    internal static class Correlation
    {
        public const string Tier1 = "Tier1Behavioral";
        public const string Tier2 = "Tier2Indicator";
        public const double KillThreshold = 0.85;

        private static readonly string[] CriticalProcesses = {
            "System", "Registry", "smss", "csrss", "wininit", "winlogon", "lsass", "services"
        };

        public static void Composite(int pid, string name)
        {
            List<string> cats = AvState.GetCategories(pid);
            int cnt = AvState.GetSignalCount(pid);
            if (cnt < 2) return;

            List<KeyValuePair<string, double>> composites = new List<KeyValuePair<string, double>>();
            bool network = cats.Contains("network") || cats.Contains("beaconing");

            if (cats.Contains("memory") && network) Add(composites, "InjectedC2Beacon", 0.96);
            if (cats.Contains("credential") && network) Add(composites, "CredentialExfiltration", 0.95);
            if (cats.Contains("evasion") && (cats.Contains("execution") || cats.Contains("c2"))) Add(composites, "FilelessAttack", 0.93);
            if (cats.Contains("unsigned") && network) Add(composites, "CovertRAT", 0.90);

            int ransomware = 0;
            foreach (string c in cats) if (c.Contains("ransomware")) ransomware++;
            if (ransomware >= 2) Add(composites, "ActiveRansomware", 0.98);

            if (cats.Contains("escalation") && cats.Contains("persistence")) Add(composites, "PostExploitation", 0.91);
            if (cats.Contains("dll_injection") && network) Add(composites, "InjectedImplantC2", 0.95);
            if (cats.Contains("clipboard") && network) Add(composites, "ClipboardExfil", 0.93);
            if (cats.Contains("surveillance") && network) Add(composites, "SurveillanceExfil", 0.94);
            if (cats.Contains("dga") && cats.Contains("beaconing")) Add(composites, "DgaC2Beacon", 0.94);
            if (cats.Contains("lateral") && cats.Contains("credential")) Add(composites, "LateralCredTheft", 0.95);
            if (cats.Contains("genealogy") && network) Add(composites, "OrphanPhoneHome", 0.88);
            if (cats.Count >= 3) Add(composites, "AdvancedAttackChain", 0.96);

            foreach (KeyValuePair<string, double> comp in composites)
            {
                string dk = "Comp|" + comp.Key + "|" + pid;
                if (AvState.IsDup(dk, 120)) continue;
                string evidence = name + " (PID " + pid + "): " + string.Join("+", cats.ToArray()) +
                                  " [" + cnt + " signals in 120s]";
                AvLog.Write("detection", "Composite:" + comp.Key, evidence,
                    "Multiple behavioral signals correlated on same process",
                    comp.Value, Tier1, name, pid);
                Ui.Write("[COMPOSITE] " + comp.Key + ": " + name + " (PID " + pid + ") conf=" + comp.Value,
                    ConsoleColor.Magenta);

                bool strong = cats.Contains("credential") || cats.Contains("evasion") || cats.Contains("ransomware") ||
                               cats.Contains("escalation") || cats.Contains("c2");
                if (comp.Value >= KillThreshold && strong)
                {
                    Kill(pid, name, "Composite:" + comp.Key, comp.Value);
                }
            }
        }

        private static void Add(List<KeyValuePair<string, double>> list, string name, double conf)
        {
            list.Add(new KeyValuePair<string, double>(name, conf));
        }

        // Terminates a process only when the recorded start time still matches the ancestry snapshot,
        // which guards against killing a reused PID.
        public static void Kill(int pid, string name, string rule, double confidence)
        {
            if (pid <= 4 || pid == AvState.CurrentPid) return;
            if (confidence < KillThreshold) return;
            try
            {
                ProcessInfo expected;
                if (!AvState.Ancestry.TryGetValue(pid, out expected) || expected.Created == DateTime.MinValue) return;

                Process target = Process.GetProcessById(pid);
                double diff = Math.Abs((target.StartTime.ToUniversalTime() - expected.Created.ToUniversalTime()).TotalMilliseconds);
                if (diff > 1) return;
                if (AvState.ContainsCI(CriticalProcesses, target.ProcessName)) return;

                target.Kill();
                AvLog.Write("response", rule, "KILL: " + name + " (PID " + pid + ")",
                    "Kill authorized at conf " + confidence, confidence, "Response", name, pid);
                Ui.Write("[KILL] " + name + " (PID " + pid + ") - " + rule + " (conf=" + confidence + ")", ConsoleColor.Red);
            }
            catch (Exception ex)
            {
                Ui.Write("[KILL FAILED] " + name + " (PID " + pid + ") - " + ex.Message, ConsoleColor.DarkRed);
            }
        }
    }
}
