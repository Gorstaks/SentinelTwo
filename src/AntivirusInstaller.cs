using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SentinelTwo
{
    // Installs the monitor under ProgramData with an administrator-only ACL and a hidden
    // interactive logon task that runs elevated for the installing user.
    internal static class AntivirusInstaller
    {
        public const string TaskName = "SentinelTwo Monitor";

        public static string InstallDirectory
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "monitor"); }
        }

        public static string InstalledExecutable
        {
            get { return Path.Combine(InstallDirectory, "SentinelTwo.exe"); }
        }

        public static void Install(string currentExe)
        {
            if (!AvState.InteractiveSession)
                throw new InvalidOperationException("Install from the logged-in administrator desktop, not a session-0 service.");
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity.IsSystem)
                throw new InvalidOperationException("Install as the logged-in administrator, not SYSTEM.");

            EnsureSecureDirectory(InstallDirectory);
            if (File.Exists(InstalledExecutable) && IsReparsePoint(InstalledExecutable))
                throw new InvalidOperationException("The installed script must not be a reparse point.");

            if (Tasks.Exists(TaskName)) Tasks.End(TaskName);

            if (!string.Equals(Path.GetFullPath(currentExe), Path.GetFullPath(InstalledExecutable), StringComparison.OrdinalIgnoreCase))
            {
                string staged = Path.Combine(InstallDirectory, Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    File.Copy(currentExe, staged, true);
                    if (File.Exists(InstalledExecutable)) File.Delete(InstalledExecutable);
                    File.Move(staged, InstalledExecutable);
                }
                finally
                {
                    if (File.Exists(staged)) File.Delete(staged);
                }
            }
            SecureFile(InstalledExecutable);

            string sid = identity.User.Value;
            TaskDefinition task = new TaskDefinition
            {
                Description = "SentinelTwo interactive background monitor",
                BootTrigger = false,
                TriggerSid = sid,
                PrincipalSid = sid,
                LogonType = "InteractiveToken",
                Command = InstalledExecutable,
                Arguments = "monitor",
                ExecutionTimeLimit = "PT0S",
                RestartCount = 3
            };
            Tasks.Register(TaskName, task);
            Tasks.Run(TaskName);
            Ui.Write("SentinelTwo monitor installed in ProgramData\\SentinelTwo\\monitor; hidden interactive logon task launched. Log: events.jsonl in that folder.", ConsoleColor.Green);
        }

        public static void Uninstall()
        {
            if (Tasks.Exists(TaskName))
            {
                Tasks.End(TaskName);
                Tasks.Delete(TaskName);
            }

            // Stop only instances running the installed executable, never this process.
            string installed = InstalledExecutable;
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\cimv2",
                "SELECT ProcessId, ExecutablePath FROM Win32_Process WHERE Name = 'SentinelTwo.exe' OR Name = 'AntivirusLite.exe'"))
            {
                foreach (ManagementObject mo in searcher.Get())
                {
                    int pid = Convert.ToInt32(mo["ProcessId"]);
                    string path = mo["ExecutablePath"] as string;
                    if (pid == AvState.CurrentPid) continue;
                    if (!string.Equals(path, installed, StringComparison.OrdinalIgnoreCase)) continue;
                    Process.GetProcessById(pid).Kill();
                }
            }
            Ui.Write("SentinelTwo monitor task removed. Installed program and logs remain in ProgramData\\SentinelTwo\\monitor.", ConsoleColor.Green);
        }

        public static bool IsReparsePoint(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }

        // Protected ACL granting only SYSTEM and Administrators full control.
        public static void EnsureSecureDirectory(string directory)
        {
            if (Directory.Exists(directory))
            {
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("The install directory must not be a reparse point.");
            }
            else
            {
                Directory.CreateDirectory(directory);
            }

            DirectorySecurity acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            foreach (string sid in new string[] { "S-1-5-18", "S-1-5-32-544" })
            {
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),
                    FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }
            new DirectoryInfo(directory).SetAccessControl(acl);
        }

        private static void SecureFile(string path)
        {
            FileSecurity acl = new FileSecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            foreach (string sid in new string[] { "S-1-5-18", "S-1-5-32-544" })
            {
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, AccessControlType.Allow));
            }
            new FileInfo(path).SetAccessControl(acl);
        }
    }
}
