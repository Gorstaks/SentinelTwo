using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    public sealed class RotatorState
    {
        public bool Installed { get; set; }
        public bool RotationEnabled { get; set; }
        public string BootStamp { get; set; }
        public bool ResetSucceeded { get; set; }
        public string ResetUtc { get; set; }
    }

    // Clears the target local administrator password at boot, then replaces it with an unretained
    // random password every ten minutes while that account is signed in. Uninstall restores blank.
    internal static class PasswordRotator
    {
        private const int RotationIntervalSeconds = 600;
        private const int BootWaitLimitSeconds = 180;

        private enum Step { Stop, WaitingForReset, ResetTimer, Waiting, Rotated }

        private sealed class LocalAccount
        {
            public string Name;
            public bool Enabled;
            public string PrincipalSource;
        }

        private static string targetSid;

        private static string StateDirectory
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "LocalPasswordRotator-" + targetSid); }
        }

        private static string StateExecutable
        {
            get { return Path.Combine(StateDirectory, "SentinelTwo.exe"); }
        }

        private static string BootTask { get { return "LocalPasswordRotator-" + targetSid + "-Boot"; } }
        private static string LogonTask { get { return "LocalPasswordRotator-" + targetSid + "-Logon"; } }

        // ---------------- Entry points ----------------

        public static void Install()
        {
            string sid = WindowsIdentity.GetCurrent().User.Value;
            string desktopSid = SessionSid(Process.GetCurrentProcess().SessionId);
            if (sid != desktopSid)
                throw new InvalidOperationException("Elevation used a different account. Sign in to the intended local administrator account and run the script there.");

            targetSid = sid;
            LocalAccount account = LookupLocalAccount();

            if (Tasks.Exists(BootTask) || Tasks.Exists(LogonTask))
                throw new InvalidOperationException("An existing PasswordRotator installation was found. Run rotator-uninstall first to restore blank safely, then run it again.");
            if (Native.MinimumPasswordLength() > 0)
                throw new InvalidOperationException("Effective local password policy requires a nonempty password. No policy was changed.");

            PrepareDirectory();
            File.Copy(Monitors.CurrentExecutablePath(), StateExecutable, true);

            try
            {
                WithLock(delegate
                {
                    WriteState(new RotatorState { Installed = true, RotationEnabled = false, BootStamp = "", ResetSucceeded = false, ResetUtc = "" });
                    // Real reset: this also verifies password filters a policy query cannot predict.
                    BootResetCore();

                    Tasks.Register(BootTask, new TaskDefinition
                    {
                        Description = "PasswordRotator boot reset",
                        BootTrigger = true,
                        PrincipalSid = "S-1-5-18",
                        LogonType = "ServiceAccount",
                        Command = StateExecutable,
                        Arguments = "rotator-boot " + targetSid,
                        ExecutionTimeLimit = "PT2M",
                        RestartCount = 3
                    });
                    Tasks.Register(LogonTask, new TaskDefinition
                    {
                        Description = "PasswordRotator session rotation",
                        BootTrigger = false,
                        TriggerSid = targetSid,
                        PrincipalSid = targetSid,
                        LogonType = "InteractiveToken",
                        Command = StateExecutable,
                        Arguments = "rotator-logon " + targetSid,
                        ExecutionTimeLimit = "PT0S",
                        RestartCount = 0
                    });

                    RotatorState state = ReadState();
                    state.RotationEnabled = true;
                    WriteState(state);
                });
                Tasks.Run(LogonTask);
            }
            catch (Exception)
            {
                foreach (string name in new string[] { LogonTask, BootTask })
                {
                    if (!Tasks.Exists(name)) continue;
                    Tasks.StopAndWait(name);
                    Tasks.Delete(name);
                }
                WithLock(delegate
                {
                    RotatorState state = ReadState();
                    if (state != null)
                    {
                        state.Installed = false;
                        state.RotationEnabled = false;
                        WriteState(state);
                    }
                });
                throw;
            }

            Ui.Write("Installed for " + account.Name + ". Password is blank now; rotation begins in ten minutes while signed in. " +
                     "Boot reset is enabled. Inspect " + StateDirectory + "\\events.log for failures.", ConsoleColor.Green);
        }

        public static void Uninstall()
        {
            string sid = WindowsIdentity.GetCurrent().User.Value;
            targetSid = sid;
            if (!Tasks.Exists(BootTask) && !Tasks.Exists(LogonTask))
            {
                Ui.Write("No PasswordRotator tasks are installed for this account.", ConsoleColor.Gray);
                return;
            }
            PrepareDirectory();

            try
            {
                Tasks.SetEnabled(BootTask, false);
                Tasks.StopAndWait(LogonTask);
                Tasks.StopAndWait(BootTask);
                WithLock(delegate
                {
                    RotatorState state = ReadState();
                    if (state != null)
                    {
                        state.RotationEnabled = false;
                        WriteState(state);
                    }
                    // Validate the real reset before deleting the boot recovery mechanism.
                    LocalAccount account = LookupLocalAccount();
                    SetPassword(account.Name, "");
                    if (state != null)
                    {
                        state.Installed = false;
                        WriteState(state);
                    }
                    Log("Uninstall restored blank password; rotation disabled.");
                });
            }
            catch (Exception ex)
            {
                if (Tasks.Exists(BootTask)) Tasks.SetEnabled(BootTask, true);
                throw new InvalidOperationException("Uninstall could not restore a blank password. Tasks were retained; rotation remains disabled and the Boot task was retained for recovery. " + ex.Message, ex);
            }

            foreach (string name in new string[] { LogonTask, BootTask })
            {
                if (Tasks.Exists(name)) Tasks.Delete(name);
            }
            Ui.Write("Uninstalled. The target account password is blank. Non-secret state and logs remain in ProgramData.", ConsoleColor.Green);
        }

        // Scheduled SYSTEM task at boot.
        public static void BootReset(string sid)
        {
            targetSid = sid;
            PrepareDirectory();
            WithLock((Action)BootResetCore);
        }

        // Scheduled interactive task at logon.
        public static void LogonLoop(string sid)
        {
            targetSid = sid;
            PrepareDirectory();
            if (!IsTargetSession()) throw new InvalidOperationException("Rotation requires the target user interactive session.");

            string boot = BootStamp();
            Stopwatch timer = Stopwatch.StartNew();
            Stopwatch waiting = Stopwatch.StartNew();
            string resetToken = "";

            while (true)
            {
                double elapsed = timer.Elapsed.TotalSeconds;
                string token = resetToken;
                Step result = WithLock(() => RotationStep(boot, token, elapsed));
                switch (result)
                {
                    case Step.Stop:
                        return;
                    case Step.WaitingForReset:
                        if (waiting.Elapsed.TotalSeconds > BootWaitLimitSeconds)
                            throw new InvalidOperationException("Boot reset has not succeeded; rotation was not started. Inspect events.log and the Boot task.");
                        break;
                    case Step.ResetTimer:
                        RotatorState state = WithLock<RotatorState>(ReadState);
                        resetToken = state.ResetUtc;
                        timer.Restart();
                        waiting.Restart();
                        Log("Session rotation timer started; first rotation in ten minutes.");
                        break;
                    case Step.Rotated:
                        timer.Restart();
                        break;
                }
                Thread.Sleep(5000);
            }
        }

        // ---------------- Rotation logic ----------------

        private static Step RotationStep(string bootStamp, string resetToken, double elapsedSeconds)
        {
            RotatorState state = ReadState();
            if (state == null || !state.Installed || !state.RotationEnabled) return Step.Stop;
            if (!IsTargetSession()) return Step.Stop;
            if (!state.ResetSucceeded || state.BootStamp != bootStamp) return Step.WaitingForReset;
            if (resetToken != state.ResetUtc) return Step.ResetTimer;
            if (elapsedSeconds < RotationIntervalSeconds) return Step.Waiting;
            if (!IsTargetSession()) return Step.Stop;

            SetRandomPassword();
            Log("Password rotated; password not retained.");
            return Step.Rotated;
        }

        private static void BootResetCore()
        {
            RotatorState state = ReadState();
            if (state == null || !state.Installed) return;
            string boot = BootStamp();
            if (state.ResetSucceeded && state.BootStamp == boot) return;

            state.ResetSucceeded = false;
            state.BootStamp = boot;
            WriteState(state);
            try
            {
                LocalAccount account = LookupLocalAccount();
                SetPassword(account.Name, "");
                state.ResetSucceeded = true;
                state.ResetUtc = DateTime.UtcNow.ToString("o");
                WriteState(state);
                Log("Boot password reset succeeded.");
            }
            catch (Exception ex)
            {
                Log("Boot password reset failed; rotation blocked. " + ex.Message);
                throw;
            }
        }

        private static void SetRandomPassword()
        {
            LocalAccount account = LookupLocalAccount();
            byte[] bytes = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            string password = "Aa1!" + Convert.ToBase64String(bytes);
            Array.Clear(bytes, 0, bytes.Length);
            SetPassword(account.Name, password);
        }

        private static void SetPassword(string accountName, string password)
        {
            Native.USER_INFO_1003 info = new Native.USER_INFO_1003();
            info.usri1003_password = password;
            uint parameterError;
            uint result = Native.NetUserSetInfo(null, accountName, 1003, ref info, out parameterError);
            if (result != 0)
                throw new Win32Exception((int)result, "Windows rejected the password (error " + result + "). Password policy was not changed.");
        }

        // ---------------- Account and session checks ----------------

        private static LocalAccount LookupLocalAccount()
        {
            // Get-LocalUser distinguishes Local from Microsoft/Entra accounts. The SID is validated
            // by the SecurityIdentifier constructor before it reaches the command text.
            string sid = new SecurityIdentifier(targetSid).Value;
            string script = "$u = Get-LocalUser -SID '" + sid + "' -ErrorAction Stop; " +
                            "Write-Output ($u.Name + '|' + $u.Enabled + '|' + $u.PrincipalSource)";
            ProcessStartInfo info = new ProcessStartInfo(
                Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + script + "\"");
            info.UseShellExecute = false;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.CreateNoWindow = true;
            string output;
            using (Process p = Process.Start(info))
            {
                output = p.StandardOutput.ReadToEnd().Trim();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                if (p.ExitCode != 0) throw new InvalidOperationException("Could not read the local account: " + output);
            }

            string[] parts = output.Split('|');
            if (parts.Length != 3) throw new InvalidOperationException("Unexpected account lookup output.");
            LocalAccount account = new LocalAccount
            {
                Name = parts[0],
                Enabled = string.Equals(parts[1], "True", StringComparison.OrdinalIgnoreCase),
                PrincipalSource = parts[2]
            };
            if (account.PrincipalSource != "Local")
                throw new InvalidOperationException("Only a standalone local Windows account is supported; Microsoft, domain, and Entra accounts are refused.");
            if (!account.Enabled) throw new InvalidOperationException("The local account is disabled.");
            return account;
        }

        private static bool IsTargetSession()
        {
            try
            {
                return SessionSid(Process.GetCurrentProcess().SessionId) == targetSid;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string SessionSid(int session)
        {
            string user = Native.SessionText(session, 5);
            if (string.IsNullOrEmpty(user)) return "";
            string domain = Native.SessionText(session, 7);
            return new NTAccount(domain, user).Translate(typeof(SecurityIdentifier)).Value;
        }

        private static string BootStamp()
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\cimv2",
                "SELECT LastBootUpTime FROM Win32_OperatingSystem"))
            {
                foreach (ManagementObject os in searcher.Get())
                {
                    string raw = os["LastBootUpTime"] as string;
                    return ManagementDateTimeConverter.ToDateTime(raw).ToUniversalTime().Ticks.ToString();
                }
            }
            throw new InvalidOperationException("Boot time unavailable.");
        }

        // ---------------- State, log, lock, directory ----------------

        private static RotatorState ReadState()
        {
            string path = Path.Combine(StateDirectory, "state.json");
            if (!File.Exists(path)) return null;
            return new JavaScriptSerializer().Deserialize<RotatorState>(File.ReadAllText(path, Encoding.UTF8));
        }

        private static void WriteState(RotatorState state)
        {
            string path = Path.Combine(StateDirectory, "state.json");
            string temp = Path.Combine(StateDirectory, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                File.WriteAllText(temp, new JavaScriptSerializer().Serialize(state), Encoding.UTF8);
                if (File.Exists(path)) File.Replace(temp, path, null);
                else File.Move(temp, path);
            }
            finally
            {
                if (File.Exists(temp)) File.Delete(temp);
            }
        }

        private static void Log(string message)
        {
            try
            {
                File.AppendAllText(Path.Combine(StateDirectory, "events.log"),
                    DateTime.UtcNow.ToString("o") + " " + message + "\r\n", Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Ui.Write("PasswordRotator could not write its log: " + ex.Message, ConsoleColor.Yellow);
            }
        }

        // Both SYSTEM and the elevated target administrator open the same named mutex.
        private static T WithLock<T>(Func<T> action)
        {
            MutexSecurity security = new MutexSecurity();
            foreach (string sid in new string[] { "S-1-5-18", "S-1-5-32-544" })
            {
                security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid), MutexRights.FullControl, AccessControlType.Allow));
            }
            bool created;
            Mutex mutex = new Mutex(false, "Global\\PasswordRotator." + targetSid, out created, security);
            bool owned = false;
            try
            {
                try
                {
                    owned = mutex.WaitOne(TimeSpan.FromSeconds(60));
                }
                catch (AbandonedMutexException)
                {
                    owned = true;
                }
                if (!owned) throw new TimeoutException("Timed out waiting for the password reset/rotation lock.");
                return action();
            }
            finally
            {
                if (owned) mutex.ReleaseMutex();
                mutex.Dispose();
            }
        }

        private static void WithLock(Action action)
        {
            WithLock<bool>(delegate { action(); return true; });
        }

        // Creates the state directory with an administrator-only ACL and stores the program copy there.
        private static void PrepareDirectory()
        {
            string dir = StateDirectory;
            if (Directory.Exists(dir))
            {
                if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("PasswordRotator state directory must not be a reparse point.");
            }
            else
            {
                Directory.CreateDirectory(dir);
            }
            AntivirusInstaller.EnsureSecureDirectory(dir);
        }
    }
}
