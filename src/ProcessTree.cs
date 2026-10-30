using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    // Operator-invoked process-tree termination. Identity is pinned by creation time: a PID whose
    // creation time changed since planning is never killed. Each termination waits for the process to
    // exit and writes a receipt. Children that appear during termination are rescanned in later rounds.
    // Protected processes (critical names, anything under the Windows directory) are never killed,
    // even as descendants. If one is still running at the end, the result is reported as incomplete.
    internal static class ProcessTree
    {
        private const int MaxRounds = 3;
        private const int ExitWaitMilliseconds = 5000;

        private static readonly string[] ProtectedNames = {
            "System", "Registry", "smss", "csrss", "wininit", "winlogon", "lsass", "services", "Idle"
        };

        private sealed class Node
        {
            public int Pid;
            public int ParentPid;
            public string Name;
            public string Path;
            public DateTime Created;
            public List<int> Children = new List<int>();
        }

        private static string ReceiptLog
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "process", "receipts.jsonl"); }
        }

        public static int Run(string[] args)
        {
            if (args.Length < 3) return Usage();
            int pid;
            if (!int.TryParse(args[2], out pid)) return Usage();
            bool apply = args.Length > 3 && args[3] == "--apply";

            if (args[1] == "tree")
            {
                Dictionary<int, Node> nodes = Snapshot();
                if (!nodes.ContainsKey(pid))
                {
                    Console.WriteLine("No process with PID " + pid);
                    return 2;
                }
                PrintTree(nodes, pid, 0);
                return 0;
            }
            if (args[1] == "terminate") return Terminate(pid, apply);
            return Usage();
        }

        private static int Usage()
        {
            Console.WriteLine("usage:");
            Console.WriteLine("  process tree <pid>");
            Console.WriteLine("  process terminate <pid> [--apply]   (kills the process and its descendants)");
            return 2;
        }

        private static Dictionary<int, Node> Snapshot()
        {
            Dictionary<int, Node> nodes = new Dictionary<int, Node>();
            using (ManagementObjectSearcher s = new ManagementObjectSearcher("root\\cimv2",
                "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate FROM Win32_Process"))
            {
                foreach (ManagementObject mo in s.Get())
                {
                    Node n = new Node();
                    n.Pid = Convert.ToInt32(mo["ProcessId"]);
                    n.ParentPid = Convert.ToInt32(mo["ParentProcessId"]);
                    n.Name = Convert.ToString(mo["Name"]);
                    n.Path = mo["ExecutablePath"] as string;
                    string created = mo["CreationDate"] as string;
                    n.Created = string.IsNullOrEmpty(created) ? DateTime.MinValue : ManagementDateTimeConverter.ToDateTime(created);
                    nodes[n.Pid] = n;
                }
            }
            foreach (Node n in nodes.Values)
            {
                Node parent;
                // A child created before its recorded parent means the parent PID was reused. Do not link it.
                if (nodes.TryGetValue(n.ParentPid, out parent) && n.Created >= parent.Created)
                {
                    parent.Children.Add(n.Pid);
                }
            }
            return nodes;
        }

        private static void PrintTree(Dictionary<int, Node> nodes, int pid, int depth)
        {
            Node n = nodes[pid];
            Console.WriteLine(new string(' ', depth * 2) + n.Pid + "  " + n.Name + "  " + (n.Path ?? "(path unavailable)"));
            foreach (int child in n.Children) PrintTree(nodes, child, depth + 1);
        }

        // Breadth-first list of the root and its descendants, deepest first, so children die before parents.
        private static List<Node> Plan(Dictionary<int, Node> nodes, int root)
        {
            List<Node> order = new List<Node>();
            Queue<int> queue = new Queue<int>();
            HashSet<int> seen = new HashSet<int>();
            queue.Enqueue(root);
            while (queue.Count > 0)
            {
                int pid = queue.Dequeue();
                if (!seen.Add(pid) || !nodes.ContainsKey(pid)) continue;
                order.Add(nodes[pid]);
                foreach (int child in nodes[pid].Children) queue.Enqueue(child);
            }
            order.Reverse();
            return order;
        }

        // Returns the reason a process must not be killed, or null when it may be terminated.
        private static string ProtectedReason(Node n)
        {
            if (n.Pid <= 4) return "system process";
            if (n.Pid == AvState.CurrentPid) return "SentinelTwo itself";
            if (AvState.ContainsCI(ProtectedNames, n.Name) || AvState.ContainsCI(ProtectedNames, n.Name.Replace(".exe", "")))
                return "protected process " + n.Name;
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            if (!string.IsNullOrEmpty(systemRoot) && !string.IsNullOrEmpty(n.Path) &&
                n.Path.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
                return "under the Windows directory";
            return null;
        }

        private static bool IsAncestorOfSelf(Dictionary<int, Node> nodes, int pid)
        {
            HashSet<int> ancestors = new HashSet<int>();
            int cursor = AvState.CurrentPid;
            while (nodes.ContainsKey(cursor) && ancestors.Add(cursor))
            {
                cursor = nodes[cursor].ParentPid;
            }
            return ancestors.Contains(pid);
        }

        private static int Terminate(int root, bool apply)
        {
            Dictionary<int, Node> nodes = Snapshot();
            if (!nodes.ContainsKey(root))
            {
                Console.WriteLine("No process with PID " + root);
                return 2;
            }
            if (IsAncestorOfSelf(nodes, root))
            {
                Console.WriteLine("Refusing to terminate an ancestor of SentinelTwo (PID " + root + ").");
                return 2;
            }
            string rootReason = ProtectedReason(nodes[root]);
            if (rootReason != null)
            {
                Console.WriteLine("Refusing PID " + root + ": " + rootReason + ".");
                return 2;
            }

            // Identities of protected descendants that stay running; they count against completion.
            Dictionary<int, DateTime> leftRunning = new Dictionary<int, DateTime>();
            Dictionary<int, DateTime> identities = new Dictionary<int, DateTime>();
            List<Node> plan = Plan(nodes, root);
            Console.WriteLine("Plan (children first):");
            foreach (Node n in plan)
            {
                string reason = ProtectedReason(n);
                Console.WriteLine("  " + n.Pid + "  " + n.Name + "  started " + n.Created.ToString("o") +
                                  (reason == null ? "" : "  [left running: " + reason + "]"));
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to terminate.");
                return 0;
            }

            HashSet<int> visited = new HashSet<int>();
            bool allVerified = true;
            for (int round = 1; round <= MaxRounds; round++)
            {
                List<Node> pending = new List<Node>();
                foreach (Node n in plan)
                {
                    if (visited.Contains(n.Pid)) continue;
                    visited.Add(n.Pid);
                    if (ProtectedReason(n) != null)
                    {
                        leftRunning[n.Pid] = n.Created;
                        continue;
                    }
                    pending.Add(n);
                }
                if (pending.Count == 0) break;

                foreach (Node n in pending)
                {
                    identities[n.Pid] = n.Created;
                    allVerified &= TerminateOne(n);
                }

                // Rescan for descendants created during termination.
                nodes = Snapshot();
                if (!nodes.ContainsKey(root)) break;
                plan = Plan(nodes, root);
            }

            Dictionary<int, Node> after = Snapshot();
            int remaining = 0;
            foreach (KeyValuePair<int, DateTime> id in identities)
            {
                if (IsSameProcess(after, id.Key, id.Value)) remaining++;
            }
            foreach (KeyValuePair<int, DateTime> id in leftRunning)
            {
                if (IsSameProcess(after, id.Key, id.Value))
                {
                    remaining++;
                    Console.WriteLine("Left running (protected): PID " + id.Key);
                }
            }

            bool complete = remaining == 0 && allVerified;
            Console.WriteLine(complete
                ? "Tree terminated; each process exit was verified (see receipts)."
                : "Termination incomplete: " + remaining + " process(es) still running or unverified. See receipts.");
            return complete ? 0 : 1;
        }

        // Same PID and same start time. A reused PID is a different process.
        private static bool IsSameProcess(Dictionary<int, Node> snapshot, int pid, DateTime started)
        {
            Node live;
            return snapshot.TryGetValue(pid, out live) && live.Created == started;
        }

        // Terminates one process only if its creation time still matches the plan. Returns true when
        // the exit is verified.
        private static bool TerminateOne(Node planned)
        {
            string outcome;
            int exitCode = -1;
            bool exited = false;
            try
            {
                Dictionary<int, Node> now = Snapshot();
                Node current;
                if (!now.TryGetValue(planned.Pid, out current))
                {
                    Receipt(planned, "already-gone", exitCode, true);
                    Console.WriteLine("Already exited: " + planned.Pid + " " + planned.Name);
                    return true;
                }
                if (current.Created != planned.Created)
                {
                    Receipt(planned, "identity-changed-skipped", exitCode, false);
                    Console.WriteLine("Skipped (PID reused): " + planned.Pid + " " + planned.Name);
                    return false;
                }

                using (Process p = Process.GetProcessById(planned.Pid))
                {
                    p.Kill();
                    exited = p.WaitForExit(ExitWaitMilliseconds);
                    if (exited) exitCode = SafeExitCode(p);
                }
                outcome = exited ? "exited" : "timeout";
            }
            catch (ArgumentException)
            {
                outcome = "already-gone";
                exited = true;
            }
            catch (Exception ex)
            {
                outcome = "failed: " + ex.Message;
            }

            Receipt(planned, outcome, exitCode, exited);
            Console.WriteLine((exited ? "Terminated " : "Not verified ") + planned.Pid + " " + planned.Name + " (" + outcome + ")");
            return exited;
        }

        private static int SafeExitCode(Process p)
        {
            try { return p.ExitCode; }
            catch (Exception) { return -1; }
        }

        private static void Receipt(Node n, string outcome, int exitCode, bool verified)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ReceiptLog));
                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["time"] = DateTime.UtcNow.ToString("o");
                entry["pid"] = n.Pid;
                entry["name"] = n.Name;
                entry["path"] = n.Path ?? "";
                entry["started"] = n.Created.ToString("o");
                entry["outcome"] = outcome;
                entry["exitCode"] = exitCode;
                entry["verified"] = verified;
                File.AppendAllText(ReceiptLog, new JavaScriptSerializer().Serialize(entry) + "\r\n", Encoding.UTF8);
            }
            catch (Exception)
            {
                // A receipt write failure must not hide the termination result printed to the console.
            }
        }
    }
}
