using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    // Explicit certificate distrust. A certificate is distrusted by adding a copy to the machine's
    // Disallowed store, which Windows checks before trusting a chain. Only thumbprints named by the
    // operator are changed. Entries added here are recorded, and undistrust removes only those entries.
    // Certificates are never removed from the Root or CA stores.
    internal static class CertPolicy
    {
        private static string ManifestPath
        {
            get { return Path.Combine(Environment.GetEnvironmentVariable("ProgramData"), "SentinelTwo", "certs", "distrusted.json"); }
        }

        public static int Run(string[] args)
        {
            if (args.Length < 2) return Usage();
            string verb = args[1];
            bool apply = args[args.Length - 1] == "--apply";
            if (verb == "list") return ListEntries();
            if (verb == "find" && args.Length >= 3) return Find(args[2]);
            if (verb == "distrust" && args.Length >= 3) return Distrust(Normalize(args[2]), apply);
            if (verb == "undistrust" && args.Length >= 3) return Undistrust(Normalize(args[2]), apply);
            return Usage();
        }

        private static int Usage()
        {
            Console.WriteLine("usage:");
            Console.WriteLine("  cert list                              (distrust entries recorded by SentinelTwo)");
            Console.WriteLine("  cert find <text>                       (search LocalMachine Root and CA stores by subject or thumbprint)");
            Console.WriteLine("  cert distrust <thumbprint> [--apply]   (add to LocalMachine Disallowed; dry run by default)");
            Console.WriteLine("  cert undistrust <thumbprint> [--apply] (remove an entry SentinelTwo added)");
            return 2;
        }

        internal static string Normalize(string thumbprint)
        {
            return thumbprint.Replace(" ", "").Replace(":", "").ToUpperInvariant();
        }

        private static X509Certificate2 FindTrusted(string thumbprint)
        {
            foreach (StoreName name in new StoreName[] { StoreName.Root, StoreName.CertificateAuthority })
            {
                X509Store store = new X509Store(name, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                try
                {
                    foreach (X509Certificate2 c in store.Certificates)
                    {
                        if (string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase)) return c;
                    }
                }
                finally
                {
                    store.Close();
                }
            }
            return null;
        }

        private static bool InDisallowed(string thumbprint)
        {
            X509Store store = new X509Store(StoreName.Disallowed, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                foreach (X509Certificate2 c in store.Certificates)
                {
                    if (string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase)) return true;
                }
                return false;
            }
            finally
            {
                store.Close();
            }
        }

        private static int Find(string text)
        {
            int hits = 0;
            foreach (StoreName name in new StoreName[] { StoreName.Root, StoreName.CertificateAuthority })
            {
                X509Store store = new X509Store(name, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                try
                {
                    foreach (X509Certificate2 c in store.Certificates)
                    {
                        if (c.Subject.IndexOf(text, StringComparison.OrdinalIgnoreCase) < 0 &&
                            c.Thumbprint.IndexOf(Normalize(text), StringComparison.OrdinalIgnoreCase) < 0) continue;
                        hits++;
                        Console.WriteLine(name + "  " + c.Thumbprint + "  " + c.Subject + "  expires " + c.NotAfter.ToString("yyyy-MM-dd"));
                    }
                }
                finally
                {
                    store.Close();
                }
            }
            if (hits == 0) Console.WriteLine("No matching certificates in LocalMachine Root or CA stores.");
            return 0;
        }

        private static List<Dictionary<string, object>> ReadManifest()
        {
            if (!File.Exists(ManifestPath)) return new List<Dictionary<string, object>>();
            return new JavaScriptSerializer().Deserialize<List<Dictionary<string, object>>>(File.ReadAllText(ManifestPath, Encoding.UTF8))
                   ?? new List<Dictionary<string, object>>();
        }

        private static void WriteManifest(List<Dictionary<string, object>> entries)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ManifestPath));
            File.WriteAllText(ManifestPath, new JavaScriptSerializer().Serialize(entries), Encoding.UTF8);
        }

        private static int ListEntries()
        {
            List<Dictionary<string, object>> entries = ReadManifest();
            if (entries.Count == 0) Console.WriteLine("No certificates distrusted by SentinelTwo.");
            foreach (Dictionary<string, object> e in entries)
            {
                string thumb = Convert.ToString(e["thumbprint"]);
                Console.WriteLine(thumb + "  " + e["subject"] + "  added " + e["added"] + "  present=" + InDisallowed(thumb));
            }
            return 0;
        }

        private static int Distrust(string thumbprint, bool apply)
        {
            X509Certificate2 cert = FindTrusted(thumbprint);
            if (cert == null)
            {
                Console.WriteLine("Certificate " + thumbprint + " is not in LocalMachine Root or CA stores; refusing.");
                return 2;
            }
            if (InDisallowed(thumbprint))
            {
                Console.WriteLine("Already in the Disallowed store: " + cert.Subject);
                return 0;
            }
            // Microsoft roots and CAs underpin Windows Update and OS trust. Changing them is out of scope here.
            if (cert.Subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Console.WriteLine("Refusing: Microsoft roots and CAs are not distrusted by this command (" + cert.Subject + ").");
                return 2;
            }
            Console.WriteLine("Plan: add to LocalMachine Disallowed: " + cert.Thumbprint + "  " + cert.Subject);
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to distrust. Undo with: cert undistrust " + thumbprint + " --apply");
                return 0;
            }

            try
            {
                X509Store store = new X509Store(StoreName.Disallowed, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                try
                {
                    store.Add(cert);
                }
                finally
                {
                    store.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not write the Disallowed store (administrator rights required): " + ex.Message);
                return 1;
            }

            if (!InDisallowed(thumbprint))
            {
                Console.WriteLine("Read-back failed: certificate is not in the Disallowed store.");
                return 1;
            }
            List<Dictionary<string, object>> entries = ReadManifest();
            Dictionary<string, object> entry = new Dictionary<string, object>();
            entry["thumbprint"] = thumbprint;
            entry["subject"] = cert.Subject;
            entry["added"] = DateTime.UtcNow.ToString("o");
            entries.Add(entry);
            WriteManifest(entries);
            Console.WriteLine("Distrusted and verified: " + thumbprint);
            return 0;
        }

        private static int Undistrust(string thumbprint, bool apply)
        {
            List<Dictionary<string, object>> entries = ReadManifest();
            Dictionary<string, object> mine = null;
            foreach (Dictionary<string, object> e in entries)
            {
                if (string.Equals(Convert.ToString(e["thumbprint"]), thumbprint, StringComparison.OrdinalIgnoreCase)) mine = e;
            }
            if (mine == null)
            {
                Console.WriteLine("SentinelTwo did not add " + thumbprint + "; it will not be removed.");
                return 2;
            }
            Console.WriteLine("Plan: remove from LocalMachine Disallowed: " + thumbprint + "  " + mine["subject"]);
            if (!apply)
            {
                Console.WriteLine("Dry run. Add --apply to remove.");
                return 0;
            }

            X509Store store;
            try
            {
                store = new X509Store(StoreName.Disallowed, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not open the Disallowed store (administrator rights required): " + ex.Message);
                return 1;
            }
            try
            {
                X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                foreach (X509Certificate2 c in found)
                {
                    store.Remove(c);
                }
            }
            finally
            {
                store.Close();
            }

            if (InDisallowed(thumbprint))
            {
                Console.WriteLine("Read-back failed: certificate is still in the Disallowed store.");
                return 1;
            }
            entries.Remove(mine);
            WriteManifest(entries);
            Console.WriteLine("Removed and verified: " + thumbprint);
            return 0;
        }
    }
}
