using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using Microsoft.Win32;

namespace SentinelTwo
{
    // Report-only persistence observation. Nothing is modified or removed. Each entry is an
    // observation of an autostart location and its target, not a verdict that it is malicious.
    internal static class Persistence
    {
        public static void Run()
        {
            List<string> entries = new List<string>();
            RunKeys(entries);
            StartupFolders(entries);
            AutoStartServices(entries);
            ScheduledTasks(entries);
            WmiSubscriptions(entries);

            Ui.Write("SentinelTwo persistence observation (report only, no changes)", ConsoleColor.Cyan);
            if (entries.Count == 0)
            {
                Console.WriteLine("No entries observed.");
                return;
            }
            foreach (string e in entries) Console.WriteLine(e);
            Console.WriteLine(entries.Count + " observed. Entries outside Windows and Program Files are listed with their target path for review.");
        }

        private static readonly string[] RunPaths = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        };

        private static void RunKeys(List<string> entries)
        {
            RegistryKey[] roots = { Registry.LocalMachine, Registry.CurrentUser };
            string[] rootNames = { "HKLM", "HKCU" };
            for (int r = 0; r < roots.Length; r++)
            {
                foreach (string path in RunPaths)
                {
                    using (RegistryKey key = roots[r].OpenSubKey(path))
                    {
                        if (key == null) continue;
                        foreach (string name in key.GetValueNames())
                        {
                            string target = Convert.ToString(key.GetValue(name));
                            entries.Add(Line("run-key", rootNames[r] + "\\" + path + " :: " + name, target));
                        }
                    }
                }
            }
        }

        private static void StartupFolders(List<string> entries)
        {
            string[] folders = {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };
            foreach (string folder in folders)
            {
                if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
                foreach (string file in Directory.GetFiles(folder))
                {
                    if (string.Equals(Path.GetFileName(file), "desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    entries.Add(Line("startup-folder", folder, file));
                }
            }
        }

        private static void AutoStartServices(List<string> entries)
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("root\\cimv2",
                    "SELECT Name, PathName, StartName FROM Win32_Service WHERE StartMode = 'Auto'"))
                {
                    foreach (ManagementObject svc in s.Get())
                    {
                        string path = Convert.ToString(svc["PathName"]);
                        if (IsWindowsOrProgramFiles(path)) continue;
                        entries.Add(Line("service", Convert.ToString(svc["Name"]) + " (" + Convert.ToString(svc["StartName"]) + ")", path));
                    }
                }
            }
            catch (Exception ex)
            {
                entries.Add(Line("service", "unavailable", ex.Message));
            }
        }

        // Scheduled tasks through the Task Scheduler COM service. Only enabled tasks with exec
        // actions are reported, and only when the action target is outside Windows and Program Files.
        private static void ScheduledTasks(List<string> entries)
        {
            try
            {
                Type serviceType = Type.GetTypeFromProgID("Schedule.Service");
                dynamic service = Activator.CreateInstance(serviceType);
                service.Connect();
                WalkFolder(service.GetFolder("\\"), entries);
            }
            catch (Exception ex)
            {
                entries.Add(Line("scheduled-task", "unavailable", ex.Message));
            }
        }

        private static void WalkFolder(dynamic folder, List<string> entries)
        {
            // Include hidden tasks (flag 1).
            dynamic tasks = folder.GetTasks(1);
            for (int i = 1; i <= tasks.Count; i++)
            {
                try
                {
                    dynamic task = tasks.Item(i);
                    if (!(bool)task.Enabled) continue;
                    dynamic actions = task.Definition.Actions;
                    for (int a = 1; a <= actions.Count; a++)
                    {
                        dynamic action = actions.Item(a);
                        if ((int)action.Type != 0) continue; // TASK_ACTION_EXEC
                        string target = Convert.ToString(action.Path);
                        if (IsWindowsOrProgramFiles(target)) continue;
                        entries.Add(Line("scheduled-task", Convert.ToString(task.Path), target));
                    }
                }
                catch (Exception)
                {
                    // Task unreadable (access denied or corrupt definition); skip it.
                }
            }

            dynamic subfolders = folder.GetFolders(0);
            for (int i = 1; i <= subfolders.Count; i++)
            {
                WalkFolder(subfolders.Item(i), entries);
            }
        }

        private static void WmiSubscriptions(List<string> entries)
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("root\\subscription",
                    "SELECT Name, CommandLineTemplate FROM CommandLineEventConsumer"))
                {
                    foreach (ManagementObject c in s.Get())
                    {
                        entries.Add(Line("wmi-consumer", Convert.ToString(c["Name"]), Convert.ToString(c["CommandLineTemplate"])));
                    }
                }
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("root\\subscription",
                    "SELECT Name, Query FROM __EventFilter"))
                {
                    foreach (ManagementObject f in s.Get())
                    {
                        entries.Add(Line("wmi-filter", Convert.ToString(f["Name"]), Convert.ToString(f["Query"])));
                    }
                }
            }
            catch (Exception ex)
            {
                entries.Add(Line("wmi", "unavailable", ex.Message));
            }
        }

        private static bool IsWindowsOrProgramFiles(string command)
        {
            if (string.IsNullOrEmpty(command)) return false;
            string expanded = Environment.ExpandEnvironmentVariables(command.Trim().Trim('"'));
            string[] trusted = {
                Environment.GetEnvironmentVariable("SystemRoot"),
                Environment.GetEnvironmentVariable("ProgramFiles"),
                Environment.GetEnvironmentVariable("ProgramFiles(x86)")
            };
            foreach (string t in trusted)
            {
                if (!string.IsNullOrEmpty(t) && expanded.StartsWith(t, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static string Line(string kind, string location, string target)
        {
            return "[" + kind + "] " + location + " -> " + target;
        }
    }
}
