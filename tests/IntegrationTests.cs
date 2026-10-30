using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace SentinelTwo.Tests
{
    // These tests touch the live machine. They run only with --integration. Each one skips itself when
    // %ProgramData%\SentinelTwo already exists, so data created by real use is never deleted. Registry and
    // process changes are reverted in finally blocks.
    internal static class ProgramDataGuard
    {
        public static bool CanUse()
        {
            return !Directory.Exists(Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo"));
        }

        public static void Cleanup()
        {
            TestFiles.Remove(Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo"));
        }
    }

    internal static class ScanFixtureIntegrationTests
    {
        public static void TestOfflineScanOfFixtureFolderWritesLog()
        {
            if (!ProgramDataGuard.CanUse()) return;
            string dir = TestFiles.NewDirectory();
            try
            {
                File.WriteAllText(Path.Combine(dir, "a.txt"), "x");
                Assert.Equal(0, FileScanner.Run(new string[] { "scan", dir, "--offline" }), "offline scan of fixture");
                Assert.True(File.Exists(Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "logs", "scan.jsonl")),
                            "scan log written");
            }
            finally
            {
                TestFiles.Remove(dir);
                ProgramDataGuard.Cleanup();
            }
        }
    }

    internal static class RunKeyIntegrationTests
    {
        private const string TestValue = "SentinelTwoTestRunValue";

        public static void TestRunKeyCleanRemovesAndRestoreReturnsValue()
        {
            if (!ProgramDataGuard.CanUse()) return;
            string dir = TestFiles.NewDirectory();
            try
            {
                string original = Path.Combine(dir, "gone", "evil.exe");
                string payload = Path.Combine(dir, "payload.quarantine");
                File.WriteAllText(payload, "quarantined body");

                string quarantineDir = Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "quarantine");
                Directory.CreateDirectory(quarantineDir);
                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["original"] = original;
                entry["quarantined"] = payload;
                entry["sha256"] = Reputation.Sha256File(payload);
                File.WriteAllText(Path.Combine(quarantineDir, "manifest.jsonl"),
                    new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(entry) + "\r\n");

                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    key.SetValue(TestValue, "\"" + original + "\" -x", RegistryValueKind.String);
                }

                Assert.Equal(0, PersistenceCleanup.Run(new string[] { "persistence", "clean", "--apply" }), "clean applied");
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    Assert.True(key == null || key.GetValue(TestValue) == null, "value removed");
                }

                string snapshot = Directory.GetDirectories(Path.Combine(Environment.GetEnvironmentVariable("ProgramData"),
                    "SentinelTwo", "persistence", "snapshots"))[0];
                Assert.Equal(0, PersistenceCleanup.Run(new string[] { "persistence", "restore", snapshot, "--apply" }), "restore applied");
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    Assert.True(key != null && key.GetValue(TestValue) != null, "value restored");
                }
            }
            finally
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (key != null) key.DeleteValue(TestValue, false);
                }
                TestFiles.Remove(dir);
                ProgramDataGuard.Cleanup();
            }
        }
    }

    internal static class ProcessTreeIntegrationTests
    {
        public static void TestTerminateKillsSpawnedChildOfCopiedBinary()
        {
            if (!ProgramDataGuard.CanUse()) return;
            string dir = TestFiles.NewDirectory();
            Process root = null;
            try
            {
                // Copies sit outside the Windows directory, so they are not protected.
                string shell = Path.Combine(dir, "tt_root.exe");
                string ping = Path.Combine(dir, "tt_child.exe");
                File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), shell);
                File.Copy(Path.Combine(Environment.SystemDirectory, "PING.EXE"), ping);

                ProcessStartInfo info = new ProcessStartInfo(shell, "/c \"" + ping + "\" -n 120 127.0.0.1");
                info.UseShellExecute = false;
                info.CreateNoWindow = true;
                root = Process.Start(info);
                System.Threading.Thread.Sleep(1500);

                int child = -1;
                foreach (Process p in Process.GetProcessesByName("tt_child"))
                {
                    child = p.Id;
                    p.Dispose();
                }
                Assert.True(child > 0, "child process started");

                int rc = ProcessTree.Run(new string[] { "process", "terminate", root.Id.ToString(), "--apply" });
                Assert.True(rc == 0 || rc == 1, "terminate completed with a verified or incomplete result");
                System.Threading.Thread.Sleep(500);
                Assert.True(Process.GetProcessesByName("tt_child").Length == 0, "child exited");
            }
            finally
            {
                foreach (Process p in Process.GetProcessesByName("tt_child")) { try { p.Kill(); } catch (Exception) { } }
                foreach (Process p in Process.GetProcessesByName("tt_root")) { try { p.Kill(); } catch (Exception) { } }
                if (root != null) root.Dispose();
                TestFiles.Remove(dir);
                ProgramDataGuard.Cleanup();
            }
        }
    }

    internal static class PatchIntegrationTests
    {
        public static void TestPatchScanCompletes()
        {
            // Network-dependent and can take up to the scan timeout. Exit 0 means a finished scan.
            Assert.Equal(0, Telemetry.Run(new string[] { "patch", "scan" }), "scan completed");
        }
    }
}
