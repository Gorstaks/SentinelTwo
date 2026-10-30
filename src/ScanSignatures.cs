using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace SentinelTwo
{
    // Local SHA-256 blocklist. One hash per line; lines starting with '#' are comments.
    // Freshness is the file's last write time. Stale or missing data is reported, not hidden.
    internal static class ScanSignatures
    {
        public const int StaleAfterDays = 7;
        private static HashSet<string> hashes;

        public static string BlocklistPath
        {
            get
            {
                return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"),
                    "SentinelTwo", "signatures", "sha256-blocklist.txt");
            }
        }

        // Returns a short status line describing the blocklist used for this scan.
        public static string Load()
        {
            hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string path = BlocklistPath;
            if (!File.Exists(path)) return "Local blocklist: not present (" + path + ")";

            foreach (string raw in File.ReadAllLines(path))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                if (Regex.IsMatch(line, "^[0-9a-fA-F]{64}$")) hashes.Add(line.ToLowerInvariant());
            }

            DateTime written = File.GetLastWriteTime(path);
            string age = (DateTime.Now - written).TotalDays > StaleAfterDays
                ? "STALE (older than " + StaleAfterDays + " days; treat hits as current only after an update)"
                : "fresh";
            return "Local blocklist: " + hashes.Count + " hashes, last updated " + written.ToString("yyyy-MM-dd") + ", " + age;
        }

        public static bool Contains(string sha256)
        {
            return hashes != null && hashes.Contains(sha256);
        }
    }

    // Static heuristics. Each hit adds a reason and a weight. Heuristics never yield Malicious alone.
    internal static class StaticHeuristics
    {
        private const long MaxSectionSample = 16L * 1024 * 1024;
        private const long MaxScriptSize = 5L * 1024 * 1024;

        private static readonly string[] PackerSections = {
            "UPX0", "UPX1", ".aspack", ".themida", ".vmp0", ".vmp1", ".petite"
        };

        private static readonly Regex DoubleExtension = new Regex(
            @"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|com|bat|cmd|js|vbs|ps1|hta|lnk)$",
            RegexOptions.IgnoreCase);

        private static readonly Regex EncodedPayload = new Regex(@"-[eE][nN][cC]\w*\s+[A-Za-z0-9+/=]{200,}");

        public sealed class Finding
        {
            public string Text;
            public int Weight;
        }

        public static List<Finding> Analyze(string path, string[] stagingTokens, bool signed)
        {
            List<Finding> findings = new List<Finding>();
            string name = Path.GetFileName(path);
            string ext = Path.GetExtension(path);

            if (DoubleExtension.IsMatch(name))
                findings.Add(new Finding { Text = "double extension (" + name + ")", Weight = 2 });

            bool isPe = IsPortableExecutable(ext, path);
            if (isPe)
            {
                AnalyzePe(path, findings);
                if (!signed) findings.Add(new Finding { Text = "unsigned executable", Weight = 1 });
            }

            bool isScript = Array.IndexOf(new string[] { ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta" }, ext.ToLowerInvariant()) >= 0;
            if (isScript) AnalyzeScript(path, findings);

            if ((isPe || isScript) && AvState.PathContainsAny(path, stagingTokens) && !signed)
                findings.Add(new Finding { Text = "unsigned executable or script in a staging location", Weight = 1 });

            return findings;
        }

        // Shannon entropy in bits per byte, range 0..8.
        public static double ByteEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;
            long[] counts = new long[256];
            foreach (byte b in data) counts[b]++;
            double e = 0;
            foreach (long c in counts)
            {
                if (c == 0) continue;
                double p = (double)c / data.Length;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }

        private static bool IsPortableExecutable(string ext, string path)
        {
            string e = ext.ToLowerInvariant();
            if (e == ".exe" || e == ".dll" || e == ".scr" || e == ".sys") return true;
            return false;
        }

        // Reads section headers, then samples each section for packing-style high entropy.
        private static void AnalyzePe(string path, List<Finding> findings)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BinaryReader br = new BinaryReader(fs))
                {
                    if (fs.Length < 1024) return;
                    if (br.ReadUInt16() != 0x5A4D) return; // MZ
                    fs.Seek(0x3C, SeekOrigin.Begin);
                    int peOffset = br.ReadInt32();
                    if (peOffset <= 0 || peOffset + 24 > fs.Length) return;
                    fs.Seek(peOffset, SeekOrigin.Begin);
                    if (br.ReadUInt32() != 0x00004550) return; // PE\0\0

                    br.ReadUInt16(); // Machine
                    int sections = br.ReadUInt16();
                    br.ReadBytes(12); // TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
                    int optionalSize = br.ReadUInt16();
                    br.ReadUInt16(); // Characteristics
                    fs.Seek(optionalSize, SeekOrigin.Current);

                    for (int i = 0; i < sections && i < 96; i++)
                    {
                        byte[] nameBytes = br.ReadBytes(8);
                        string sectionName = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                        br.ReadUInt32(); // VirtualSize
                        br.ReadUInt32(); // VirtualAddress
                        uint rawSize = br.ReadUInt32();
                        uint rawPointer = br.ReadUInt32();
                        br.ReadBytes(16); // relocation and line numbers, characteristics

                        foreach (string packer in PackerSections)
                        {
                            if (string.Equals(sectionName, packer, StringComparison.OrdinalIgnoreCase))
                                findings.Add(new Finding { Text = "packer section name " + sectionName, Weight = 1 });
                        }

                        if (rawSize < 4096 || rawPointer == 0) continue;
                        long resume = fs.Position;
                        long length = Math.Min((long)rawSize, MaxSectionSample);
                        if (rawPointer + length > fs.Length) { fs.Position = resume; continue; }
                        fs.Seek(rawPointer, SeekOrigin.Begin);
                        byte[] data = br.ReadBytes((int)length);
                        fs.Position = resume;
                        double entropy = ByteEntropy(data);
                        if (entropy > 7.0)
                            findings.Add(new Finding { Text = "high-entropy section " + sectionName + " (" + Math.Round(entropy, 2).ToString(System.Globalization.CultureInfo.InvariantCulture) + ")", Weight = 1 });
                    }
                }
            }
            catch (Exception)
            {
                // Unreadable or truncated header: no structural evidence either way.
            }
        }

        private static void AnalyzeScript(string path, List<Finding> findings)
        {
            try
            {
                FileInfo info = new FileInfo(path);
                if (info.Length > MaxScriptSize) return;
                string text = File.ReadAllText(path);
                if (EncodedPayload.IsMatch(text))
                    findings.Add(new Finding { Text = "long encoded command payload", Weight = 1 });
                string lower = text.ToLowerInvariant();
                if ((lower.Contains("downloadstring") || lower.Contains("downloadfile")) &&
                    (lower.Contains("invoke-expression") || lower.Contains("iex")))
                    findings.Add(new Finding { Text = "download and execute", Weight = 2 });
            }
            catch (Exception)
            {
                // Unreadable script; no static evidence.
            }
        }
    }
}
