using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    internal sealed class HashVerdict
    {
        public bool Bad;
        public string Source;
        public string Detail;
    }

    // Best-effort hash lookups. Results are cached per hash for the life of the process.
    internal static class Reputation
    {
        private static readonly Dictionary<string, HashVerdict> Cache = new Dictionary<string, HashVerdict>(StringComparer.OrdinalIgnoreCase);

        public static HashVerdict Lookup(string hash)
        {
            HashVerdict cached;
            if (Cache.TryGetValue(hash, out cached)) return cached;

            HashVerdict verdict = QueryCircl(hash);
            if (verdict == null) verdict = QueryMalwareBazaar(hash);
            if (verdict == null)
            {
                verdict = new HashVerdict { Bad = false, Source = "Unknown", Detail = "No verdict; unknown hash or lookup unavailable" };
            }
            Cache[hash] = verdict;
            return verdict;
        }

        // Known-good check: CIRCL hashlookup trust score above 50.
        private static HashVerdict QueryCircl(string hash)
        {
            try
            {
                string body = Http("https://hashlookup.circl.lu/lookup/sha256/" + hash, "GET", null, null, 6);
                Dictionary<string, object> r = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(body);
                object trust;
                if (r != null && r.TryGetValue("hashlookup:trust", out trust) && trust != null)
                {
                    int score = Convert.ToInt32(trust);
                    if (score > 50)
                    {
                        return new HashVerdict { Bad = false, Source = "CIRCL", Detail = "Trust=" + score };
                    }
                }
            }
            catch (Exception)
            {
                // Unknown hash (404) or offline; fall through to the next source.
            }
            return null;
        }

        // Known-bad check: requires SENTINEL_ABUSECH_AUTH_KEY. Without it the lookup is skipped.
        private static HashVerdict QueryMalwareBazaar(string hash)
        {
            string key = Environment.GetEnvironmentVariable("SENTINEL_ABUSECH_AUTH_KEY");
            if (string.IsNullOrEmpty(key)) return null;
            try
            {
                string body = Http("https://mb-api.abuse.ch/api/v1/", "POST",
                    "query=get_info&hash=" + Uri.EscapeDataString(hash), key, 8);
                Dictionary<string, object> r = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(body);
                object status;
                if (r != null && r.TryGetValue("query_status", out status) && status != null)
                {
                    string s = status.ToString();
                    if (s == "ok" || s == "hash_found")
                    {
                        return new HashVerdict { Bad = true, Source = "MalwareBazaar", Detail = "Known malware" };
                    }
                }
            }
            catch (Exception)
            {
                // Lookup unavailable; treated as no verdict.
            }
            return null;
        }

        private static string Http(string url, string method, string body, string authKey, int timeoutSeconds)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;
            request.Timeout = timeoutSeconds * 1000;
            request.ReadWriteTimeout = timeoutSeconds * 1000;
            request.UserAgent = "SentinelTwo-AntivirusLite";
            if (!string.IsNullOrEmpty(authKey)) request.Headers["Auth-Key"] = authKey;
            if (body != null)
            {
                byte[] data = Encoding.UTF8.GetBytes(body);
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = data.Length;
                using (Stream s = request.GetRequestStream())
                {
                    s.Write(data, 0, data.Length);
                }
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        public static string Sha256File(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
            }
        }

        public static bool IsAuthenticodeValid(string path)
        {
            return Native.VerifyAuthenticode(path) == 0;
        }
    }
}
