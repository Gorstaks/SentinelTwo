using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Principal;
using System.Threading;

namespace SentinelTwo
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
                if (IntPtr.Size != 8) throw new InvalidOperationException("Use 64-bit Windows.");

                string command = args.Length > 0 ? args[0].ToLowerInvariant() : "";
                Process current = Process.GetCurrentProcess();
                AvState.SessionId = current.SessionId;
                AvState.InteractiveSession = current.SessionId != 0;
                AvLog.LogPath = Path.Combine(AntivirusInstaller.InstallDirectory, "events.jsonl");

                // Scheduled rotator tasks run as SYSTEM at boot; their administrator check is skipped.
                if (command == "version" || command == "--version")
                {
                    Console.WriteLine("SentinelTwo " + AppVersion.Current);
                    return 0;
                }

                bool needsAdmin = command != "rotator-boot" && command != "rotator-logon";
                if (needsAdmin && !IsAdministrator())
                {
                    Console.Error.WriteLine("Run as administrator.");
                    return 1;
                }

                switch (command)
                {
                    case "":
                        RunAntivirus(false);
                        return 0;
                    case "monitor":
                        RunAntivirus(true);
                        return 0;
                    case "run":
                        RunInPlace();
                        return 0;
                    case "uninstall":
                        AntivirusInstaller.Uninstall();
                        return 0;
                    case "audit":
                        Audit.Run();
                        return 0;
                    case "persistence":
                        if (args.Length > 1) return PersistenceCleanup.Run(args);
                        Persistence.Run();
                        return 0;
                    case "scan":
                        return FileScanner.Run(args);
                    case "dns":
                    case "firewall":
                        return NetworkControl.Run(args);
                    case "process":
                        return ProcessTree.Run(args);
                    case "proxy":
                        return ProxyRecovery.Run(args);
                    case "cert":
                        return CertPolicy.Run(args);
                    case "memory":
                        return MemoryInspect.Run(args);
                    case "patch":
                    case "events":
                        return Telemetry.Run(args);
                    case "rotator-install":
                        PasswordRotator.Install();
                        return 0;
                    case "rotator-uninstall":
                        PasswordRotator.Uninstall();
                        return 0;
                    case "rotator-boot":
                        PasswordRotator.BootReset(RequireSid(args));
                        return 0;
                    case "rotator-logon":
                        PasswordRotator.LogonLoop(RequireSid(args));
                        return 0;
                    default:
                        PrintUsage();
                        return 2;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
                return 1;
            }
        }

        // Without arguments, or with "monitor" from the scheduled task, the program either installs itself
        // (when not yet installed) or runs the monitor under a single-instance mutex.
        private static void RunAntivirus(bool fromTask)
        {
            if (!AvState.InteractiveSession)
                throw new InvalidOperationException("AntivirusLite needs an interactive desktop. Reinstall by running this program as the logged-in administrator.");

            string current = Monitors.CurrentExecutablePath();
            bool fromInstalled = string.Equals(Path.GetFullPath(current), Path.GetFullPath(AntivirusInstaller.InstalledExecutable), StringComparison.OrdinalIgnoreCase);
            if (!fromInstalled || !Tasks.Exists(AntivirusInstaller.TaskName))
            {
                AntivirusInstaller.Install(current);
                return;
            }

            // Scheduled runs have no window to show; the JSONL log is the output channel.
            if (fromTask) Native.FreeConsole();

            Mutex mutex = new Mutex(false, "Local\\SentinelTwo.Monitor." + AvState.SessionId);
            bool owned = false;
            try
            {
                try
                {
                    owned = mutex.WaitOne(0);
                }
                catch (AbandonedMutexException)
                {
                    owned = true;
                }
                if (!owned) return;

                Monitors.InitializeSelfProtection();
                AntivirusLite.Run();
            }
            finally
            {
                if (owned) mutex.ReleaseMutex();
                mutex.Dispose();
            }
        }

        // Runs the monitor in this process without installing, with its output visible in the console.
        private static void RunInPlace()
        {
            if (!AvState.InteractiveSession)
                throw new InvalidOperationException("The monitor needs an interactive desktop.");
            AntivirusInstaller.EnsureSecureDirectory(AntivirusInstaller.InstallDirectory);
            Mutex mutex = new Mutex(false, "Local\\SentinelTwo.Monitor." + AvState.SessionId);
            bool owned = false;
            try
            {
                try { owned = mutex.WaitOne(0); }
                catch (AbandonedMutexException) { owned = true; }
                if (!owned)
                {
                    Console.WriteLine("A monitor is already running in this session.");
                    return;
                }
                Monitors.InitializeSelfProtection();
                AntivirusLite.Run();
            }
            finally
            {
                if (owned) mutex.ReleaseMutex();
                mutex.Dispose();
            }
        }

        private static string RequireSid(string[] args)
        {
            if (args.Length < 2) throw new ArgumentException("A user SID argument is required.");
            return new SecurityIdentifier(args[1]).Value;
        }

        private static bool IsAdministrator()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void PrintUsage()
        {
            Console.WriteLine("SentinelTwo (AntivirusLite + PasswordRotator)");
            Console.WriteLine("  (none) | monitor         Install if needed, otherwise run the behavioral monitor");
            Console.WriteLine("  run                      Run the monitor in this console without installing");
            Console.WriteLine("  uninstall                Remove the monitor task and stop its instances");
            Console.WriteLine("  audit                    Read-only hardening and Defender status report");
            Console.WriteLine("  persistence              Report-only autostart observation (Run keys, startup folders, services, tasks, WMI)");
            Console.WriteLine("  persistence clean|restore ...   Remove Run values that launch quarantined files (dry run by default)");
            Console.WriteLine("  scan <path>... [--offline] [--quarantine]   Scan files; quarantine only Malicious verdicts");
            Console.WriteLine("  dns status | snapshot | set <ip>... --adapter <name> [--apply] | restore <dir> [--apply]");
            Console.WriteLine("  firewall list | block <exe> [--apply] | unblock <exe> [--apply] | unblock-all [--apply]");
            Console.WriteLine("  process tree <pid> | terminate <pid> [--apply]   (tree kill with per-process exit receipts)");
            Console.WriteLine("  proxy status | disable [--apply] | restore <dir> [--apply]");
            Console.WriteLine("  cert list | find <text> | distrust <thumbprint> [--apply] | undistrust <thumbprint> [--apply]");
            Console.WriteLine("  memory inspect <pid>   (read-only scan of executable unbacked memory for embedded PE headers)");
            Console.WriteLine("  patch scan | events process-start [minutes]   (read-only Windows Update and process-creation telemetry)");
            Console.WriteLine("  rotator-install          Install the password rotator for the current administrator");
            Console.WriteLine("  rotator-uninstall        Restore blank password and remove rotator tasks");
            Console.WriteLine("  rotator-boot <SID>       Internal: boot-time reset task entry point");
            Console.WriteLine("  rotator-logon <SID>      Internal: logon rotation task entry point");
        }
    }
}
