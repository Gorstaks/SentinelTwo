using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SentinelTwo.Tests
{
    // Command entry points. Every case here either refuses before any write or runs without --apply.
    internal static class TestProcesses
    {
        public static Process StartSleeper()
        {
            // ping.exe is a Windows binary, so it is also a refusal case for process termination.
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "ping.exe"), "-n 60 127.0.0.1");
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            return Process.Start(info);
        }

        public static void Stop(Process p)
        {
            try { if (!p.HasExited) p.Kill(); } catch (Exception) { }
            p.Dispose();
        }
    }

    internal static class NetworkCommandTests
    {
        public static void TestBlockPortRefusesDnsPort()
        {
            Assert.Equal(2, NetworkControl.Run(new string[] { "firewall", "block-port", "tcp", "53" }), "DNS port refused");
        }

        public static void TestBlockPortDryRunChangesNothing()
        {
            Assert.Equal(0, NetworkControl.Run(new string[] { "firewall", "block-port", "tcp", "443" }), "dry run");
        }

        public static void TestBlockProgramRefusesWindowsBinary()
        {
            string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            Assert.Equal(2, NetworkControl.Run(new string[] { "firewall", "block", notepad }), "Windows binary refused");
        }

        public static void TestBlockProgramRefusesMissingFile()
        {
            Assert.Equal(2, NetworkControl.Run(new string[] { "firewall", "block", @"C:\no\such\program.exe" }), "missing program");
        }

        public static void TestFirewallListIsReadOnly()
        {
            Assert.Equal(0, NetworkControl.Run(new string[] { "firewall", "list" }), "list");
        }

        public static void TestUnblockPortWithoutRecordIsDryRun()
        {
            Assert.Equal(0, NetworkControl.Run(new string[] { "firewall", "unblock-port", "tcp", "443" }), "no record, dry run");
        }

        public static void TestDnsSetRejectsInvalidAddress()
        {
            Assert.Equal(2, NetworkControl.Run(new string[] { "dns", "set", "notanip", "--adapter", "Ethernet" }), "invalid IP");
        }

        public static void TestDnsSetRejectsUnknownAdapter()
        {
            Assert.Equal(2, NetworkControl.Run(new string[] { "dns", "set", "1.1.1.1", "--adapter", "NoSuchAdapter-zz" }), "unknown adapter");
        }

        public static void TestDnsRestoreRefusesMissingSnapshot()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                Assert.Equal(2, NetworkControl.Run(new string[] { "dns", "restore", dir, "--apply" }), "snapshot without dns.json");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }

        public static void TestDnsStatusIsReadOnly()
        {
            Assert.Equal(0, NetworkControl.Run(new string[] { "dns", "status" }), "status");
        }
    }

    internal static class ProcessCommandTests
    {
        public static void TestTerminateRefusesSystemProcess()
        {
            Assert.Equal(2, ProcessTree.Run(new string[] { "process", "terminate", "4" }), "PID 4");
        }

        public static void TestTerminateRefusesOwnAncestor()
        {
            Assert.Equal(2, ProcessTree.Run(new string[] { "process", "terminate", AvState.CurrentPid.ToString() }), "self");
        }

        public static void TestTreeOfSystemProcessPrints()
        {
            Assert.Equal(0, ProcessTree.Run(new string[] { "process", "tree", "4" }), "PID 4 tree");
        }

        public static void TestTreeOfMissingProcessFails()
        {
            Assert.Equal(2, ProcessTree.Run(new string[] { "process", "tree", "2147483646" }), "no such PID");
        }

        public static void TestTerminateRefusesWindowsBinaryEvenWhenNotApplied()
        {
            Process sleeper = TestProcesses.StartSleeper();
            try
            {
                // A Windows binary is protected, so the plan is refused even as a dry run.
                Assert.Equal(2, ProcessTree.Run(new string[] { "process", "terminate", sleeper.Id.ToString() }), "Windows binary");
                Assert.False(sleeper.HasExited, "process untouched by a refused plan");
            }
            finally
            {
                TestProcesses.Stop(sleeper);
            }
        }

        public static void TestMemoryInspectRefusesSelfSystemAndBadPid()
        {
            Assert.Equal(2, MemoryInspect.Run(new string[] { "memory", "inspect", AvState.CurrentPid.ToString() }), "self");
            Assert.Equal(2, MemoryInspect.Run(new string[] { "memory", "inspect", "4" }), "system");
            Assert.Equal(2, MemoryInspect.Run(new string[] { "memory", "inspect", "notapid" }), "not a number");
        }

        public static void TestMemoryInspectRunsAgainstChildProcess()
        {
            Process sleeper = TestProcesses.StartSleeper();
            try
            {
                int rc = MemoryInspect.Run(new string[] { "memory", "inspect", sleeper.Id.ToString() });
                Assert.True(rc == 0 || rc == 1, "reads or reports access denied, never crashes");
            }
            finally
            {
                TestProcesses.Stop(sleeper);
            }
        }
    }

    internal static class ProxyCertCommandTests
    {
        public static void TestProxyStatusIsReadOnly()
        {
            Assert.Equal(0, ProxyRecovery.Run(new string[] { "proxy", "status" }), "status");
        }

        public static void TestProxyDisableWithoutApplyDoesNotChange()
        {
            // 0 when a dry run or already disabled, 2 when policy manages the proxy. Never a write.
            int rc = ProxyRecovery.Run(new string[] { "proxy", "disable" });
            Assert.True(rc == 0 || rc == 2, "dry run or refusal");
        }

        public static void TestProxyRestoreNeedsSnapshot()
        {
            Assert.Equal(2, ProxyRecovery.Run(new string[] { "proxy", "restore" }), "no snapshot given");
        }

        public static void TestCertFindIsReadOnly()
        {
            Assert.Equal(0, CertPolicy.Run(new string[] { "cert", "find", "zz-no-such-certificate-zz" }), "no match");
        }

        public static void TestCertListIsReadOnly()
        {
            Assert.Equal(0, CertPolicy.Run(new string[] { "cert", "list" }), "list");
        }

        public static void TestCertDistrustRefusesUnknownThumbprint()
        {
            Assert.Equal(2, CertPolicy.Run(new string[] { "cert", "distrust", "0000000000000000000000000000000000000000" }), "not in trusted stores");
        }

        public static void TestCertDistrustRefusesMicrosoftRootEvenAsDryRun()
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            string thumbprint = null;
            try
            {
                foreach (X509Certificate2 c in store.Certificates)
                {
                    if (c.Subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        thumbprint = c.Thumbprint;
                        break;
                    }
                }
            }
            finally
            {
                store.Close();
            }
            if (thumbprint == null) return;
            Assert.Equal(2, CertPolicy.Run(new string[] { "cert", "distrust", thumbprint }), "Microsoft root refused");
        }

        public static void TestCertUndistrustRefusesUnrecordedThumbprint()
        {
            Assert.Equal(2, CertPolicy.Run(new string[] { "cert", "undistrust", "ABCDEF0123456789ABCDEF0123456789ABCDEF01", "--apply" }), "not recorded by SentinelTwo");
        }
    }

    internal static class PersistenceCommandTests
    {
        public static void TestPersistenceReportRuns()
        {
            Persistence.Run();
        }

        public static void TestAuditReportRuns()
        {
            Audit.Run();
        }

        public static void TestCleanDryRunChangesNothing()
        {
            Assert.Equal(0, PersistenceCleanup.Run(new string[] { "persistence", "clean" }), "run-key dry run");
            Assert.Equal(0, PersistenceTasks.CleanTasks(false), "task dry run");
            Assert.Equal(0, PersistenceTasks.CleanServices(false), "service dry run");
            int wmi = PersistenceWmi.Clean(false);
            Assert.True(wmi == 0 || wmi == 1, "WMI dry run (1 only if WMI query fails)");
        }

        public static void TestRestoreNeedsSnapshotDirectory()
        {
            Assert.Equal(2, PersistenceCleanup.Run(new string[] { "persistence", "restore" }), "no snapshot");
        }

        public static void TestRestoreRefusesEmptySnapshotDirectory()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                Assert.Equal(2, PersistenceCleanup.Run(new string[] { "persistence", "restore", dir, "--apply" }), "no snapshot files");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }
    }

    internal static class ScanCommandTests
    {
        public static void TestScanNeedsPath()
        {
            Assert.Equal(2, FileScanner.Run(new string[] { "scan" }), "no path");
        }

        public static void TestScanMissingPathReportsAndSucceeds()
        {
            Assert.Equal(0, FileScanner.Run(new string[] { "scan", @"C:\no\such\folder-zz", "--offline" }), "missing path");
        }

        public static void TestEventsCommandDeniedOrReturnsCleanly()
        {
            int rc = Telemetry.Run(new string[] { "events", "process-start", "1" });
            Assert.True(rc == 0 || rc == 1, "reads or reports access denied");
        }
    }
}
