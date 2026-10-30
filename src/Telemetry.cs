using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;

namespace SentinelTwo
{
    // Read-only telemetry helpers.
    //   patch scan            lists pending Windows Update software items (no download or install)
    //   events process-start  reads recent Security 4688 process-creation events (log-based, not real-time ETW)
    internal static class Telemetry
    {
        private const int ScanTimeoutMilliseconds = 180000;

        public static int Run(string[] args)
        {
            if (args.Length < 2) return Usage();
            if (args[0] == "patch" && args[1] == "scan") return PatchScan();
            if (args[0] == "events" && args[1] == "process-start")
            {
                int minutes = 15;
                if (args.Length > 2 && !int.TryParse(args[2], out minutes)) return Usage();
                return ProcessStart(minutes);
            }
            return Usage();
        }

        private static int Usage()
        {
            Console.WriteLine("usage:");
            Console.WriteLine("  patch scan                        (pending security software updates; scan only)");
            Console.WriteLine("  events process-start [minutes]    (Security 4688 process creations; needs process-creation auditing and admin)");
            return 2;
        }

        // ---------------- Windows Update scan ----------------

        private static int PatchScan()
        {
            List<string> lines = new List<string>();
            Exception failure = null;
            Thread worker = new Thread(delegate ()
            {
                try
                {
                    lines.AddRange(SearchPending());
                }
                catch (Exception ex)
                {
                    failure = ex;
                }
            });
            worker.IsBackground = true;
            worker.Start();
            if (!worker.Join(ScanTimeoutMilliseconds))
            {
                Console.WriteLine("Windows Update search did not finish within " + (ScanTimeoutMilliseconds / 1000) + " seconds. Result unknown.");
                return 1;
            }
            if (failure != null)
            {
                Console.WriteLine("Windows Update search failed: " + failure.Message);
                return 1;
            }

            Console.WriteLine("Pending software updates (scan only; nothing was downloaded or installed):");
            if (lines.Count == 0) Console.WriteLine("  none");
            foreach (string line in lines) Console.WriteLine("  " + line);
            return 0;
        }

        private static List<string> SearchPending()
        {
            List<string> results = new List<string>();
            Type sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
            if (sessionType == null) throw new InvalidOperationException("Windows Update Agent is not available.");
            dynamic session = Activator.CreateInstance(sessionType);
            dynamic searcher = session.CreateUpdateSearcher();
            dynamic search = searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0");
            dynamic updates = search.Updates;
            for (int i = 0; i < updates.Count; i++)
            {
                dynamic u = updates.Item(i);
                string severity = Convert.ToString(Safe(() => u.MsrcSeverity));
                string title = Convert.ToString(u.Title);
                string kb = Join(u.KBArticleIDs);
                string cves = Join(Safe(() => u.CveIDs));
                results.Add((string.IsNullOrEmpty(severity) ? "unrated" : severity) + "  " + title +
                            (kb.Length > 0 ? "  KB" + kb : "") + (cves.Length > 0 ? "  CVE " + cves : ""));
            }
            results.Sort(StringComparer.OrdinalIgnoreCase);
            return results;
        }

        // Some properties exist only on newer Windows versions. A failed read yields null.
        private static object Safe(Func<object> read)
        {
            try { return read(); }
            catch (Exception) { return null; }
        }

        private static string Join(object collection)
        {
            if (collection == null) return "";
            List<string> items = new List<string>();
            dynamic c = collection;
            for (int i = 0; i < c.Count; i++) items.Add(Convert.ToString(c.Item(i)));
            return string.Join(",", items.ToArray());
        }

        // ---------------- Process-creation events ----------------

        private static int ProcessStart(int minutes)
        {
            if (minutes < 1 || minutes > 1440)
            {
                Console.WriteLine("minutes must be between 1 and 1440.");
                return 2;
            }

            string query = "*[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) <= " + (minutes * 60000) + "]]]";
            EventLogQuery log = new EventLogQuery("Security", PathType.LogName, query);
            log.ReverseDirection = true;
            int count = 0;
            try
            {
                using (EventLogReader reader = new EventLogReader(log))
                {
                    EventRecord record;
                    while ((record = reader.ReadEvent()) != null && count < 500)
                    {
                        count++;
                        Console.WriteLine(record.TimeCreated.Value.ToString("o") + "  " +
                                          Prop(record, 5) + "  parent=" + Prop(record, 13) + "  cmd=" + Prop(record, 8));
                        record.Dispose();
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Access to the Security log was denied. Run as administrator with process-creation auditing enabled.");
                return 1;
            }
            catch (EventLogException ex)
            {
                Console.WriteLine("Security log query failed: " + ex.Message);
                return 1;
            }

            Console.WriteLine(count + " process-creation event(s) in the last " + minutes + " minute(s).");
            if (count == 0) Console.WriteLine("If you expected events, check that process-creation auditing is enabled (Audit Process Creation).");
            Console.WriteLine("Log-based telemetry only. Processes that start and exit without a logged event are not seen.");
            return 0;
        }

        // Security 4688 stores fields positionally: 5 = NewProcessName, 8 = CommandLine, 13 = ParentProcessName.
        private static string Prop(EventRecord record, int index)
        {
            if (record.Properties == null || record.Properties.Count <= index) return "";
            return Convert.ToString(record.Properties[index].Value);
        }
    }
}
