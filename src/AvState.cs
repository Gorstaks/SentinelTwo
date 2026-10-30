using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace SentinelTwo
{
    internal sealed class ProcessInfo
    {
        public string Name;
        public int ParentId;
        public string CommandLine;
        public string Path;
        public DateTime Created; // DateTime.MinValue when unknown
    }

    internal sealed class Signal
    {
        public string Category;
        public double Confidence;
        public DateTime Time;
    }

    internal sealed class IndicatorState
    {
        public string Generation;
        public string Fingerprint;
    }

    internal static class Ui
    {
        public static void Write(string text, ConsoleColor color)
        {
            try
            {
                ConsoleColor previous = Console.ForegroundColor;
                Console.ForegroundColor = color;
                Console.WriteLine(text);
                Console.ForegroundColor = previous;
            }
            catch (Exception)
            {
                // No console (hidden scheduled-task instance). The JSONL log is the record.
            }
        }
    }

    // Shared monitor state. Single-threaded scan loop; the file watcher uses its own queue.
    internal static class AvState
    {
        public const int CorrelationTtlSeconds = 120;

        public static int SessionId;
        public static bool InteractiveSession;
        public static string SelfHash;
        public static readonly int CurrentPid = Process.GetCurrentProcess().Id;

        public static Dictionary<string, DateTime> Dedup = new Dictionary<string, DateTime>();
        public static Dictionary<int, ProcessInfo> Ancestry = new Dictionary<int, ProcessInfo>();
        public static Dictionary<int, List<Signal>> Correlation = new Dictionary<int, List<Signal>>();
        public static Dictionary<int, Dictionary<string, IndicatorState>> ReportedIndicators = new Dictionary<int, Dictionary<string, IndicatorState>>();
        public static Dictionary<int, HashSet<string>> ModuleBaseline = new Dictionary<int, HashSet<string>>();

        public static bool IsDup(string key)
        {
            return IsDup(key, 60);
        }

        // Expires entries older than ttlSeconds, then reports whether key was seen inside the window.
        public static bool IsDup(string key, int ttlSeconds)
        {
            DateTime now = DateTime.Now;
            List<string> expired = new List<string>();
            foreach (KeyValuePair<string, DateTime> entry in Dedup)
            {
                if ((now - entry.Value).TotalSeconds > ttlSeconds) expired.Add(entry.Key);
            }
            foreach (string old in expired) Dedup.Remove(old);
            if (Dedup.ContainsKey(key)) return true;
            Dedup[key] = now;
            return false;
        }

        public static void AddSignal(int pid, string category, double confidence)
        {
            DateTime now = DateTime.Now;
            List<Signal> list;
            if (!Correlation.TryGetValue(pid, out list))
            {
                list = new List<Signal>();
                Correlation[pid] = list;
            }
            list.RemoveAll(s => (now - s.Time).TotalSeconds > CorrelationTtlSeconds);
            list.Add(new Signal { Category = category, Confidence = confidence, Time = now });
        }

        public static List<string> GetCategories(int pid)
        {
            List<string> result = new List<string>();
            List<Signal> list;
            if (!Correlation.TryGetValue(pid, out list)) return result;
            DateTime now = DateTime.Now;
            foreach (Signal s in list)
            {
                if ((now - s.Time).TotalSeconds > CorrelationTtlSeconds) continue;
                if (!result.Contains(s.Category)) result.Add(s.Category);
            }
            return result;
        }

        public static int GetSignalCount(int pid)
        {
            List<Signal> list;
            if (!Correlation.TryGetValue(pid, out list)) return 0;
            DateTime now = DateTime.Now;
            int count = 0;
            foreach (Signal s in list)
            {
                if ((now - s.Time).TotalSeconds <= CorrelationTtlSeconds) count++;
            }
            return count;
        }

        // Creation time scopes an observation to one process lifetime, not a reusable PID.
        public static bool TestNewIndicatorObservation(int pid, string rule, string fingerprint)
        {
            Dictionary<string, IndicatorState> rules;
            if (!ReportedIndicators.TryGetValue(pid, out rules))
            {
                rules = new Dictionary<string, IndicatorState>();
                ReportedIndicators[pid] = rules;
            }
            string generation = "";
            ProcessInfo info;
            if (Ancestry.TryGetValue(pid, out info) && info.Created != DateTime.MinValue)
            {
                generation = info.Created.ToUniversalTime().Ticks.ToString();
            }
            IndicatorState previous;
            if (rules.TryGetValue(rule, out previous) &&
                previous.Generation == generation && previous.Fingerprint == fingerprint)
            {
                return false;
            }
            rules[rule] = new IndicatorState { Generation = generation, Fingerprint = fingerprint };
            return true;
        }

        public static double Entropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            Dictionary<char, int> freq = new Dictionary<char, int>();
            foreach (char c in s)
            {
                int n;
                freq.TryGetValue(c, out n);
                freq[c] = n + 1;
            }
            double e = 0.0;
            double len = s.Length;
            foreach (int v in freq.Values)
            {
                double p = v / len;
                if (p > 0) e -= p * Math.Log(p, 2);
            }
            return e;
        }

        public static bool ContainsCI(string[] values, string value)
        {
            if (value == null) return false;
            foreach (string v in values)
            {
                if (string.Equals(v, value, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        // Equivalent of PowerShell -like "*token*". Empty tokens are ignored so they cannot match everything.
        public static bool PathContainsAny(string path, string[] tokens)
        {
            if (string.IsNullOrEmpty(path)) return false;
            foreach (string t in tokens)
            {
                if (string.IsNullOrEmpty(t)) continue;
                if (path.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        public static string[] StagingTokens()
        {
            return new string[] {
                Environment.GetEnvironmentVariable("TEMP"),
                Environment.GetEnvironmentVariable("APPDATA"),
                Environment.GetEnvironmentVariable("LOCALAPPDATA") + "\\Temp",
                "Downloads", "Desktop", "Public"
            };
        }
    }
}
