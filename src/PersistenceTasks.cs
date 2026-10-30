using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    // Scheduled-task and auto-start-service cleanup, narrowed like the Run-key cleanup.
    // A task is a candidate only if every exec action targets a quarantined file (see FindQuarantined).
    // A service is a candidate only if its image path targets one. Snapshots are written before any
    // removal, and removal is read back. Services with accounts that have passwords cannot be restored
    // by this tool, so their restore is refused.
    internal static class PersistenceTasks
    {
        private static string SnapshotRoot
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "persistence", "snapshots"); }
        }

        private sealed class TaskCandidate
        {
            public string Path;
            public string Xml;
            public List<string> Targets = new List<string>();
        }

        // ---------------- Scheduled tasks ----------------

        private static dynamic ConnectScheduler()
        {
            Type serviceType = Type.GetTypeFromProgID("Schedule.Service");
            dynamic service = Activator.CreateInstance(serviceType);
            service.Connect();
            return service;
        }

        private static void CollectTasks(dynamic folder, List<dynamic> tasksOut)
        {
            dynamic tasks = folder.GetTasks(1); // include hidden
            for (int i = 1; i <= tasks.Count; i++) tasksOut.Add(tasks.Item(i));
            dynamic subs = folder.GetFolders(0);
            for (int i = 1; i <= subs.Count; i++) CollectTasks(subs.Item(i), tasksOut);
        }

        private static List<TaskCandidate> FindTaskCandidates(List<PersistenceCleanup.ManifestEntry> manifest)
        {
            List<TaskCandidate> candidates = new List<TaskCandidate>();
            dynamic service = ConnectScheduler();
            List<dynamic> tasks = new List<dynamic>();
            CollectTasks(service.GetFolder("\\"), tasks);
            foreach (dynamic task in tasks)
            {
                try
                {
                    dynamic actions = task.Definition.Actions;
                    List<string> targets = new List<string>();
                    bool allMatch = true;
                    int execCount = 0;
                    for (int a = 1; a <= actions.Count; a++)
                    {
                        dynamic action = actions.Item(a);
                        if ((int)action.Type != 0) continue; // exec only
                        execCount++;
                        string target = PersistenceCleanup.LaunchTarget(Convert.ToString(action.Path));
                        if (PersistenceCleanup.FindQuarantined(target, manifest) == null) allMatch = false;
                        targets.Add(target);
                    }
                    if (execCount == 0 || !allMatch) continue;
                    TaskCandidate c = new TaskCandidate();
                    c.Path = Convert.ToString(task.Path);
                    c.Xml = Convert.ToString(task.Xml);
                    c.Targets = targets;
                    candidates.Add(c);
                }
                catch (Exception)
                {
                    // Unreadable task definition: not a candidate.
                }
            }
            return candidates;
        }

        public static int CleanTasks(bool apply)
        {
            List<PersistenceCleanup.ManifestEntry> manifest = PersistenceCleanup.ReadManifest();
            if (manifest.Count == 0)
            {
                Console.WriteLine("No quarantine manifest entries; nothing to clean.");
                return 0;
            }
            List<TaskCandidate> candidates = FindTaskCandidates(manifest);
            if (candidates.Count == 0)
            {
                Console.WriteLine("No scheduled tasks target quarantined files.");
                return 0;
            }
            foreach (TaskCandidate c in candidates)
            {
                Console.WriteLine((apply ? "Removing task " : "Would remove task ") + c.Path + " -> " + string.Join(", ", c.Targets.ToArray()));
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to remove these tasks.");
                return 0;
            }

            string snapshot = Path.Combine(SnapshotRoot, DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));
            Directory.CreateDirectory(snapshot);
            List<Dictionary<string, object>> index = new List<Dictionary<string, object>>();
            for (int i = 0; i < candidates.Count; i++)
            {
                string file = "task-" + i + ".xml";
                File.WriteAllText(Path.Combine(snapshot, file), candidates[i].Xml, Encoding.Unicode);
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["path"] = candidates[i].Path;
                d["file"] = file;
                index.Add(d);
            }
            File.WriteAllText(Path.Combine(snapshot, "tasks.json"), new JavaScriptSerializer().Serialize(index), Encoding.UTF8);

            int failures = 0;
            dynamic service = ConnectScheduler();
            foreach (TaskCandidate c in candidates)
            {
                try
                {
                    string parent = System.IO.Path.GetDirectoryName(c.Path);
                    if (string.IsNullOrEmpty(parent)) parent = "\\";
                    string name = System.IO.Path.GetFileName(c.Path);
                    service.GetFolder(parent).DeleteTask(name, 0);
                }
                catch (Exception ex)
                {
                    failures++;
                    Console.WriteLine("Delete failed for " + c.Path + ": " + ex.Message);
                    continue;
                }
                if (TaskExists(service, c.Path))
                {
                    failures++;
                    Console.WriteLine("Read-back failed, task still present: " + c.Path);
                    continue;
                }
                PersistenceCleanup.Receipt("task-clean", c.Path);
                Console.WriteLine("Removed and verified: " + c.Path);
            }
            Console.WriteLine("Snapshot: " + snapshot + " (restore with: persistence restore \"" + snapshot + "\" --apply)");
            return failures == 0 ? 0 : 1;
        }

        // GetTask is a method of the task folder, not of the scheduler service. A COM "not found"
        // error means the task is absent. Any other failure is reported to the caller.
        private static bool TaskExists(dynamic service, string path)
        {
            string parent = System.IO.Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(parent)) parent = "\\";
            string name = System.IO.Path.GetFileName(path);
            try
            {
                dynamic folder = service.GetFolder(parent);
                object task = folder.GetTask(name);
                return task != null;
            }
            catch (System.IO.FileNotFoundException)
            {
                // ERROR_FILE_NOT_FOUND from the scheduler: the folder or task no longer exists.
                return false;
            }
            catch (System.Runtime.InteropServices.COMException ex)
            {
                if (ex.ErrorCode == unchecked((int)0x80070002)) return false;
                throw;
            }
        }

        public static int RestoreTasks(string snapshotDir, bool apply)
        {
            List<Dictionary<string, object>> index = new JavaScriptSerializer().Deserialize<List<Dictionary<string, object>>>(
                File.ReadAllText(Path.Combine(snapshotDir, "tasks.json"), Encoding.UTF8));
            foreach (Dictionary<string, object> d in index)
            {
                Console.WriteLine((apply ? "Restoring task " : "Would restore task ") + d["path"]);
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to restore.");
                return 0;
            }

            dynamic service = ConnectScheduler();
            int failures = 0;
            foreach (Dictionary<string, object> d in index)
            {
                string path = Convert.ToString(d["path"]);
                string xml = File.ReadAllText(Path.Combine(snapshotDir, Convert.ToString(d["file"])), Encoding.Unicode);
                string parent = System.IO.Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(parent)) parent = "\\";
                string name = System.IO.Path.GetFileName(path);
                // TASK_CREATE_OR_UPDATE (6). Logon type follows the principal recorded in the XML.
                int logonType = xml.IndexOf("<LogonType>ServiceAccount</LogonType>", StringComparison.Ordinal) >= 0 ? 5
                              : xml.IndexOf("<LogonType>InteractiveToken</LogonType>", StringComparison.Ordinal) >= 0 ? 3 : 0;
                try
                {
                    service.GetFolder(parent).RegisterTask(name, xml, 6, Type.Missing, Type.Missing, logonType, Type.Missing);
                }
                catch (Exception ex)
                {
                    failures++;
                    Console.WriteLine("Register failed for " + path + ": " + ex.Message);
                    continue;
                }
                if (!TaskExists(service, path))
                {
                    failures++;
                    Console.WriteLine("Read-back failed for " + path);
                    continue;
                }
                PersistenceCleanup.Receipt("task-restore", path);
                Console.WriteLine("Restored and verified: " + path);
            }
            return failures == 0 ? 0 : 1;
        }

        // ---------------- Auto-start services ----------------

        private sealed class ServiceCandidate
        {
            public string Name;
            public string DisplayName;
            public string PathName;
            public string StartName;
            public string Target;
        }

        private static List<ServiceCandidate> FindServiceCandidates(List<PersistenceCleanup.ManifestEntry> manifest)
        {
            List<ServiceCandidate> list = new List<ServiceCandidate>();
            using (ManagementObjectSearcher s = new ManagementObjectSearcher("root\\cimv2",
                "SELECT Name, DisplayName, PathName, StartName FROM Win32_Service WHERE StartMode = 'Auto'"))
            {
                foreach (ManagementObject svc in s.Get())
                {
                    string pathName = Convert.ToString(svc["PathName"]);
                    string target = PersistenceCleanup.LaunchTarget(pathName);
                    if (PersistenceCleanup.FindQuarantined(target, manifest) == null) continue;
                    ServiceCandidate c = new ServiceCandidate();
                    c.Name = Convert.ToString(svc["Name"]);
                    c.DisplayName = Convert.ToString(svc["DisplayName"]);
                    c.PathName = pathName;
                    c.StartName = Convert.ToString(svc["StartName"]);
                    c.Target = target;
                    list.Add(c);
                }
            }
            return list;
        }

        public static int CleanServices(bool apply)
        {
            List<PersistenceCleanup.ManifestEntry> manifest = PersistenceCleanup.ReadManifest();
            if (manifest.Count == 0)
            {
                Console.WriteLine("No quarantine manifest entries; nothing to clean.");
                return 0;
            }
            List<ServiceCandidate> candidates = FindServiceCandidates(manifest);
            if (candidates.Count == 0)
            {
                Console.WriteLine("No auto-start services use quarantined files.");
                return 0;
            }
            foreach (ServiceCandidate c in candidates)
            {
                Console.WriteLine((apply ? "Removing service " : "Would remove service ") + c.Name + " (" + c.StartName + ") -> " + c.PathName);
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to remove these services (administrator rights required).");
                return 0;
            }

            string snapshot = Path.Combine(SnapshotRoot, DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));
            Directory.CreateDirectory(snapshot);
            List<Dictionary<string, object>> saved = new List<Dictionary<string, object>>();
            foreach (ServiceCandidate c in candidates)
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["name"] = c.Name;
                d["displayName"] = c.DisplayName;
                d["pathName"] = c.PathName;
                d["startName"] = c.StartName ?? "";
                saved.Add(d);
            }
            File.WriteAllText(Path.Combine(snapshot, "services.json"), new JavaScriptSerializer().Serialize(saved), Encoding.UTF8);

            int failures = 0;
            foreach (ServiceCandidate c in candidates)
            {
                // Stop may fail when the service is already stopped; deletion is verified separately.
                Sc("stop \"" + c.Name + "\"");
                int code = Sc("delete \"" + c.Name + "\"");
                if (code != 0)
                {
                    failures++;
                    Console.WriteLine("sc delete failed for " + c.Name + " (exit " + code + ")");
                    continue;
                }
                // ERROR_SERVICE_DOES_NOT_EXIST (1060) means the service is gone. Any other result, including
                // "marked for deletion" while a handle stays open, is reported as not verified.
                int query = Sc("query \"" + c.Name + "\"");
                if (query != 1060)
                {
                    failures++;
                    Console.WriteLine("Read-back: service " + c.Name + " is still listed (may be pending deletion until handles close).");
                    continue;
                }
                PersistenceCleanup.Receipt("service-clean", c.Name + " -> " + c.PathName);
                Console.WriteLine("Removed and verified: " + c.Name);
            }
            Console.WriteLine("Snapshot: " + snapshot + " (restore with: persistence restore \"" + snapshot + "\" --apply)");
            return failures == 0 ? 0 : 1;
        }

        public static int RestoreServices(string snapshotDir, bool apply)
        {
            List<Dictionary<string, object>> saved = new JavaScriptSerializer().Deserialize<List<Dictionary<string, object>>>(
                File.ReadAllText(Path.Combine(snapshotDir, "services.json"), Encoding.UTF8));
            int refused = 0;
            foreach (Dictionary<string, object> d in saved)
            {
                string start = Convert.ToString(d["startName"]);
                if (!IsBuiltInAccount(start))
                {
                    refused++;
                    Console.WriteLine("Refused: " + d["name"] + " ran as '" + start + "'. Its password is not stored; re-create it manually.");
                    continue;
                }
                Console.WriteLine((apply ? "Restoring service " : "Would restore service ") + d["name"] + " -> " + d["pathName"]);
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to restore (administrator rights required).");
                return refused == 0 ? 0 : 1;
            }

            int failures = refused;
            foreach (Dictionary<string, object> d in saved)
            {
                string start = Convert.ToString(d["startName"]);
                if (!IsBuiltInAccount(start)) continue;
                string name = Convert.ToString(d["name"]);
                string binPath = Convert.ToString(d["pathName"]).Replace("\"", "\\\"");
                string args = "create \"" + name + "\" binPath= \"" + binPath + "\" start= auto DisplayName= \"" +
                              Convert.ToString(d["displayName"]).Replace("\"", "") + "\" obj= \"" + start + "\"";
                if (Sc(args) != 0)
                {
                    failures++;
                    Console.WriteLine("sc create failed for " + name);
                    continue;
                }
                if (Sc("query \"" + name + "\"") != 0)
                {
                    failures++;
                    Console.WriteLine("Read-back failed for " + name);
                    continue;
                }
                PersistenceCleanup.Receipt("service-restore", name);
                Console.WriteLine("Restored and verified: " + name);
            }
            return failures == 0 ? 0 : 1;
        }

        internal static bool IsBuiltInAccount(string account)
        {
            if (string.IsNullOrEmpty(account)) return false;
            string a = account.ToUpperInvariant();
            return a == "LOCALSYSTEM" || a == "NT AUTHORITY\\LOCALSYSTEM" || a == "LOCALSERVICE" ||
                   a == "NT AUTHORITY\\LOCALSERVICE" || a == "NETWORKSERVICE" || a == "NT AUTHORITY\\NETWORKSERVICE";
        }

        private static int Sc(string arguments)
        {
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), arguments);
            info.UseShellExecute = false;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.CreateNoWindow = true;
            using (Process p = Process.Start(info))
            {
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode;
            }
        }
    }
}
