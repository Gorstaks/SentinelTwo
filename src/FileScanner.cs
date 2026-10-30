using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    internal sealed class ScanResult
    {
        public string Path;
        public string Sha256;
        public long Size;
        public string Verdict;       // Malicious, Suspicious, Unknown, Clean
        public List<string> Reasons = new List<string>();
        public string Source;        // which evidence produced the verdict
    }

    // On-demand file scanner: local blocklist, online reputation, and static heuristics.
    // Verdicts: Malicious only on blocklist or reputation hit. Suspicious on combined heuristics.
    // Clean only on a known-good reputation hit. Everything else is Unknown.
    internal static class FileScanner
    {
        private const long MaxFileBytes = 200L * 1024 * 1024;
        private static readonly string[] Extensions = { ".exe", ".dll", ".scr", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta" };

        public static string QuarantineDirectory
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "quarantine"); }
        }

        private static string LogPath
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "logs", "scan.jsonl"); }
        }

        public static int Run(string[] args)
        {
            List<string> roots = new List<string>();
            bool offline = false;
            bool quarantine = false;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--offline") offline = true;
                else if (args[i] == "--quarantine") quarantine = true;
                else roots.Add(args[i]);
            }
            if (roots.Count == 0)
            {
                Console.WriteLine("usage: SentinelTwo scan <path> [more paths] [--offline] [--quarantine]");
                return 2;
            }

            Console.WriteLine(ScanSignatures.Load());
            Console.WriteLine(offline ? "Online reputation: disabled (--offline)" : "Online reputation: CIRCL and MalwareBazaar (MalwareBazaar needs SENTINEL_ABUSECH_AUTH_KEY)");

            List<string> files = new List<string>();
            long skipped = 0;
            foreach (string root in roots)
            {
                if (File.Exists(root)) files.Add(root);
                else if (Directory.Exists(root)) Collect(root, files, ref skipped);
                else Console.WriteLine("Not found: " + root);
            }

            Dictionary<string, int> counts = new Dictionary<string, int>();
            int quarantined = 0;
            foreach (string file in files)
            {
                ScanResult r = ScanFile(file, offline);
                if (r == null) continue;
                Increment(counts, r.Verdict);
                Console.WriteLine(r.Verdict.PadRight(11) + " " + r.Path + (r.Reasons.Count > 0 ? "  [" + string.Join("; ", r.Reasons.ToArray()) + "]" : ""));
                Append(r);

                if (quarantine && r.Verdict == "Malicious")
                {
                    if (Quarantine(r)) quarantined++;
                }
            }

            Console.WriteLine("Scanned " + files.Count + " files; skipped " + skipped + " over " + (MaxFileBytes / (1024 * 1024)) + " MB.");
            foreach (KeyValuePair<string, int> kv in counts) Console.WriteLine("  " + kv.Key + ": " + kv.Value);
            if (quarantine) Console.WriteLine("Quarantined: " + quarantined + " (manifest: " + Path.Combine(QuarantineDirectory, "manifest.jsonl") + ")");
            if (files.Count > 0) Console.WriteLine("Results appended to " + LogPath);
            return 0;
        }

        public static ScanResult ScanFile(string path, bool offline)
        {
            ScanResult result = new ScanResult { Path = path };
            try
            {
                FileInfo info = new FileInfo(path);
                result.Size = info.Length;
                result.Sha256 = Reputation.Sha256File(path);

                string ext = Path.GetExtension(path).ToLowerInvariant();
                bool isPe = ext == ".exe" || ext == ".dll" || ext == ".scr" || ext == ".sys";
                bool signed = isPe && Reputation.IsAuthenticodeValid(path);

                if (ScanSignatures.Contains(result.Sha256))
                {
                    result.Verdict = "Malicious";
                    result.Source = "local blocklist";
                    result.Reasons.Add("hash is on the local blocklist");
                    return result;
                }

                if (!offline && Array.IndexOf(Extensions, ext) >= 0)
                {
                    HashVerdict rep = Reputation.Lookup(result.Sha256);
                    if (rep.Bad)
                    {
                        result.Verdict = "Malicious";
                        result.Source = rep.Source;
                        result.Reasons.Add(rep.Detail);
                        return result;
                    }
                    if (rep.Source == "CIRCL")
                    {
                        result.Verdict = "Clean";
                        result.Source = "CIRCL known-good";
                        result.Reasons.Add(rep.Detail);
                        return result;
                    }
                }

                int score = 0;
                foreach (StaticHeuristics.Finding f in StaticHeuristics.Analyze(path, AvState.StagingTokens(), signed))
                {
                    score += f.Weight;
                    result.Reasons.Add(f.Text);
                }

                if (score >= 2)
                {
                    result.Verdict = "Suspicious";
                    result.Source = "static heuristics";
                }
                else
                {
                    result.Verdict = "Unknown";
                    result.Source = "no decisive evidence";
                    if (isPe && signed) result.Reasons.Add("valid Authenticode signature (not proof of safety)");
                    if (result.Reasons.Count == 0) result.Reasons.Add("no reputation or heuristic evidence");
                }
                return result;
            }
            catch (Exception ex)
            {
                result.Verdict = "Unknown";
                result.Source = "read error";
                result.Reasons.Add(ex.Message);
                return result;
            }
        }

        // Moves a malicious file into the quarantine directory. Nothing is deleted, and the manifest
        // records the original path so the move can be reversed.
        public static bool Quarantine(ScanResult r)
        {
            try
            {
                AntivirusInstaller.EnsureSecureDirectory(QuarantineDirectory);
                string dest = Path.Combine(QuarantineDirectory, r.Sha256 + ".quarantine");
                int n = 1;
                while (File.Exists(dest))
                {
                    dest = Path.Combine(QuarantineDirectory, r.Sha256 + "." + n + ".quarantine");
                    n++;
                }
                File.Move(r.Path, dest);

                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["original"] = r.Path;
                entry["quarantined"] = dest;
                entry["sha256"] = r.Sha256;
                entry["source"] = r.Source;
                entry["time"] = DateTime.UtcNow.ToString("o");
                File.AppendAllText(Path.Combine(QuarantineDirectory, "manifest.jsonl"),
                    new JavaScriptSerializer().Serialize(entry) + "\r\n", Encoding.UTF8);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Quarantine failed for " + r.Path + ": " + ex.Message);
                return false;
            }
        }

        private static void Collect(string dirPath, List<string> files, ref long skipped)
        {
            try
            {
                DirectoryInfo dir = new DirectoryInfo(dirPath);
                if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) return;
                if (string.Equals(dir.FullName.TrimEnd('\\'), QuarantineDirectory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return;

                foreach (FileInfo f in dir.GetFiles())
                {
                    if (f.Length > MaxFileBytes) skipped++;
                    else files.Add(f.FullName);
                }
                foreach (DirectoryInfo sub in dir.GetDirectories())
                {
                    Collect(sub.FullName, files, ref skipped);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Access denied directory; skip it.
            }
            catch (IOException)
            {
                // Directory changed while enumerating; skip it.
            }
        }

        private static void Increment(Dictionary<string, int> counts, string key)
        {
            int n;
            counts.TryGetValue(key, out n);
            counts[key] = n + 1;
        }

        private static void Append(ScanResult r)
        {
            try
            {
                string dir = Path.GetDirectoryName(LogPath);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                Dictionary<string, object> entry = new Dictionary<string, object>();
                entry["time"] = DateTime.UtcNow.ToString("o");
                entry["path"] = r.Path;
                entry["sha256"] = r.Sha256 ?? "";
                entry["size"] = r.Size;
                entry["verdict"] = r.Verdict;
                entry["source"] = r.Source;
                entry["reasons"] = r.Reasons;
                File.AppendAllText(LogPath, new JavaScriptSerializer().Serialize(entry) + "\r\n", Encoding.UTF8);
            }
            catch (Exception)
            {
                // Logging failure must not stop the scan; the console line is still printed.
            }
        }
    }
}
