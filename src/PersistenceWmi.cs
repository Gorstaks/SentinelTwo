using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Text;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    // WMI event-subscription cleanup for command-line consumers that launch quarantined files.
    // The consumer, its bindings, and its filter (only when no other binding uses it) are removed together.
    // The full definition is snapshotted first. Removal is read back. Restore re-creates the same objects.
    internal static class PersistenceWmi
    {
        private const string Namespace = "root\\subscription";

        private sealed class Consumer
        {
            public string Name;
            public string CommandLine;
            public string ExecutablePath;
            public string WorkingDirectory;
            public string Target;
        }

        private sealed class Filter
        {
            public string Name;
            public string Query;
            public string QueryLanguage;
            public string EventNamespace;
        }

        private sealed class Binding
        {
            public string FilterName;
            public string ConsumerName;
        }

        private static string SnapshotRoot
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "persistence", "snapshots"); }
        }

        // Extracts the Name value from a WMI object path such as __EventFilter.Name="X".
        internal static string KeyName(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            int start = path.IndexOf("Name=\"", StringComparison.Ordinal);
            if (start < 0) return null;
            start += 6;
            int end = path.IndexOf('"', start);
            return end < 0 ? null : path.Substring(start, end - start);
        }

        // WQL string literal with single quotes doubled.
        private static string Literal(string value)
        {
            return "'" + (value ?? "").Replace("'", "''") + "'";
        }

        private static List<Consumer> ReadConsumers()
        {
            List<Consumer> list = new List<Consumer>();
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(Namespace, "SELECT * FROM CommandLineEventConsumer"))
            {
                foreach (ManagementObject c in s.Get())
                {
                    Consumer item = new Consumer();
                    item.Name = Convert.ToString(c["Name"]);
                    item.CommandLine = c["CommandLineTemplate"] as string;
                    item.ExecutablePath = c["ExecutablePath"] as string;
                    item.WorkingDirectory = c["WorkingDirectory"] as string;
                    item.Target = PersistenceCleanup.LaunchTarget(item.ExecutablePath ?? item.CommandLine);
                    list.Add(item);
                }
            }
            return list;
        }

        private static List<Filter> ReadFilters()
        {
            List<Filter> list = new List<Filter>();
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(Namespace, "SELECT * FROM __EventFilter"))
            {
                foreach (ManagementObject f in s.Get())
                {
                    Filter item = new Filter();
                    item.Name = Convert.ToString(f["Name"]);
                    item.Query = f["Query"] as string;
                    item.QueryLanguage = f["QueryLanguage"] as string;
                    item.EventNamespace = f["EventNamespace"] as string;
                    list.Add(item);
                }
            }
            return list;
        }

        private static List<Binding> ReadBindings()
        {
            List<Binding> list = new List<Binding>();
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(Namespace, "SELECT * FROM __FilterToConsumerBinding"))
            {
                foreach (ManagementObject b in s.Get())
                {
                    Binding item = new Binding();
                    item.FilterName = KeyName(Convert.ToString(b["Filter"]));
                    item.ConsumerName = KeyName(Convert.ToString(b["Consumer"]));
                    list.Add(item);
                }
            }
            return list;
        }

        public static int Clean(bool apply)
        {
            List<PersistenceCleanup.ManifestEntry> manifest = PersistenceCleanup.ReadManifest();
            if (manifest.Count == 0)
            {
                Console.WriteLine("No quarantine manifest entries; nothing to clean.");
                return 0;
            }

            List<Consumer> consumers;
            List<Filter> filters;
            List<Binding> bindings;
            try
            {
                consumers = ReadConsumers();
                filters = ReadFilters();
                bindings = ReadBindings();
            }
            catch (Exception ex)
            {
                Console.WriteLine("WMI subscription query failed: " + ex.Message);
                return 1;
            }

            List<Consumer> selected = new List<Consumer>();
            foreach (Consumer c in consumers)
            {
                if (PersistenceCleanup.FindQuarantined(c.Target, manifest) != null) selected.Add(c);
            }
            if (selected.Count == 0)
            {
                Console.WriteLine("No WMI command-line consumers launch quarantined files.");
                return 0;
            }

            List<string> selectedNames = new List<string>();
            foreach (Consumer c in selected) selectedNames.Add(c.Name);

            // A filter is removed only when every binding that uses it belongs to a selected consumer.
            List<Filter> removeFilters = new List<Filter>();
            foreach (Filter f in filters)
            {
                bool usedBySelected = false;
                bool usedByOther = false;
                foreach (Binding b in bindings)
                {
                    if (b.FilterName != f.Name) continue;
                    if (selectedNames.Contains(b.ConsumerName)) usedBySelected = true;
                    else usedByOther = true;
                }
                if (usedBySelected && !usedByOther) removeFilters.Add(f);
            }
            List<Binding> removeBindings = new List<Binding>();
            foreach (Binding b in bindings)
            {
                if (selectedNames.Contains(b.ConsumerName)) removeBindings.Add(b);
            }

            foreach (Consumer c in selected)
            {
                Console.WriteLine((apply ? "Removing " : "Would remove ") + "WMI consumer " + c.Name + " -> " + c.Target);
            }
            foreach (Filter f in removeFilters)
            {
                Console.WriteLine((apply ? "Removing " : "Would remove ") + "WMI filter " + f.Name + " (" + f.Query + ")");
            }
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to remove these subscriptions (administrator rights required).");
                return 0;
            }

            // Snapshot the full definitions before any deletion.
            string snapshot = Path.Combine(SnapshotRoot, DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));
            Directory.CreateDirectory(snapshot);
            Dictionary<string, object> saved = new Dictionary<string, object>();
            List<Dictionary<string, object>> consumerList = new List<Dictionary<string, object>>();
            foreach (Consumer c in selected)
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["name"] = c.Name;
                d["commandLine"] = c.CommandLine ?? "";
                d["executablePath"] = c.ExecutablePath ?? "";
                d["workingDirectory"] = c.WorkingDirectory ?? "";
                consumerList.Add(d);
            }
            List<Dictionary<string, object>> bindingList = new List<Dictionary<string, object>>();
            foreach (Binding b in removeBindings)
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["filter"] = b.FilterName ?? "";
                d["consumer"] = b.ConsumerName ?? "";
                bindingList.Add(d);
            }
            List<Dictionary<string, object>> filterList = new List<Dictionary<string, object>>();
            foreach (Filter f in removeFilters)
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["name"] = f.Name;
                d["query"] = f.Query ?? "";
                d["queryLanguage"] = f.QueryLanguage ?? "WQL";
                d["eventNamespace"] = f.EventNamespace ?? "root\\cimv2";
                filterList.Add(d);
            }
            saved["consumers"] = consumerList;
            saved["bindings"] = bindingList;
            saved["filters"] = filterList;
            File.WriteAllText(Path.Combine(snapshot, "wmi.json"), new JavaScriptSerializer().Serialize(saved), Encoding.UTF8);

            try
            {
                // Bindings first, then consumers, then filters, so no binding points at a deleted object.
                foreach (Binding b in removeBindings) DeleteBinding(b.FilterName, b.ConsumerName);
                foreach (Consumer c in selected) DeleteByQuery("CommandLineEventConsumer", "Name = " + Literal(c.Name));
                foreach (Filter f in removeFilters) DeleteByQuery("__EventFilter", "Name = " + Literal(f.Name));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Delete failed: " + ex.Message + ". Restore from " + snapshot + " if partially applied.");
                return 1;
            }

            int failures = 0;
            foreach (Consumer c in selected)
            {
                if (Exists("CommandLineEventConsumer", "Name = " + Literal(c.Name)))
                {
                    failures++;
                    Console.WriteLine("Read-back failed, consumer still present: " + c.Name);
                    continue;
                }
                PersistenceCleanup.Receipt("wmi-clean", c.Name + " -> " + c.Target);
                Console.WriteLine("Removed and verified: " + c.Name);
            }
            Console.WriteLine("Snapshot: " + snapshot + " (restore with: persistence restore \"" + snapshot + "\" --apply)");
            return failures == 0 ? 0 : 1;
        }

        public static int Restore(string snapshotDir, bool apply)
        {
            Dictionary<string, object> saved = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(
                File.ReadAllText(Path.Combine(snapshotDir, "wmi.json"), Encoding.UTF8));
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to re-create the WMI subscription from " + snapshotDir + " (administrator rights required).");
                return 0;
            }

            int failures = 0;
            foreach (Dictionary<string, object> f in Items(saved, "filters"))
            {
                try
                {
                    ManagementObject filter = CreateInstance("__EventFilter");
                    filter["Name"] = Convert.ToString(f["name"]);
                    filter["Query"] = Convert.ToString(f["query"]);
                    filter["QueryLanguage"] = Convert.ToString(f["queryLanguage"]);
                    filter["EventNamespace"] = Convert.ToString(f["eventNamespace"]);
                    filter.Put();
                }
                catch (Exception ex)
                {
                    failures++;
                    Console.WriteLine("Filter restore failed: " + ex.Message);
                }
            }
            foreach (Dictionary<string, object> c in Items(saved, "consumers"))
            {
                try
                {
                    ManagementObject consumer = CreateInstance("CommandLineEventConsumer");
                    consumer["Name"] = Convert.ToString(c["name"]);
                    consumer["CommandLineTemplate"] = Convert.ToString(c["commandLine"]);
                    consumer["ExecutablePath"] = Convert.ToString(c["executablePath"]);
                    consumer["WorkingDirectory"] = Convert.ToString(c["workingDirectory"]);
                    consumer.Put();
                }
                catch (Exception ex)
                {
                    failures++;
                    Console.WriteLine("Consumer restore failed: " + ex.Message);
                }
            }
            foreach (Dictionary<string, object> b in Items(saved, "bindings"))
            {
                try
                {
                    ManagementObject binding = CreateInstance("__FilterToConsumerBinding");
                    binding["Filter"] = "__EventFilter.Name=\"" + Convert.ToString(b["filter"]) + "\"";
                    binding["Consumer"] = "CommandLineEventConsumer.Name=\"" + Convert.ToString(b["consumer"]) + "\"";
                    binding.Put();
                }
                catch (Exception ex)
                {
                    failures++;
                    Console.WriteLine("Binding restore failed: " + ex.Message);
                }
            }

            foreach (Dictionary<string, object> c in Items(saved, "consumers"))
            {
                string name = Convert.ToString(c["name"]);
                if (!Exists("CommandLineEventConsumer", "Name = " + Literal(name)))
                {
                    failures++;
                    Console.WriteLine("Read-back failed for consumer " + name);
                    continue;
                }
                PersistenceCleanup.Receipt("wmi-restore", name);
                Console.WriteLine("Restored and verified: " + name);
            }
            return failures == 0 ? 0 : 1;
        }

        private static IEnumerable<Dictionary<string, object>> Items(Dictionary<string, object> saved, string key)
        {
            object raw;
            if (!saved.TryGetValue(key, out raw) || raw == null) yield break;
            foreach (object o in (System.Collections.IEnumerable)raw)
            {
                yield return (Dictionary<string, object>)o;
            }
        }

        private static ManagementObject CreateInstance(string className)
        {
            ManagementClass cls = new ManagementClass(new ManagementPath(Namespace + ":" + className));
            return cls.CreateInstance();
        }

        private static bool Exists(string className, string whereClause)
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(Namespace,
                "SELECT * FROM " + className + " WHERE " + whereClause))
            {
                foreach (ManagementObject mo in s.Get()) return true;
                return false;
            }
        }

        private static void DeleteByQuery(string className, string whereClause)
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(Namespace,
                "SELECT * FROM " + className + " WHERE " + whereClause))
            {
                foreach (ManagementObject mo in s.Get()) mo.Delete();
            }
        }

        private static void DeleteBinding(string filterName, string consumerName)
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(Namespace, "SELECT * FROM __FilterToConsumerBinding"))
            {
                foreach (ManagementObject b in s.Get())
                {
                    if (KeyName(Convert.ToString(b["Filter"])) == filterName &&
                        KeyName(Convert.ToString(b["Consumer"])) == consumerName)
                    {
                        b.Delete();
                    }
                }
            }
        }
    }
}
