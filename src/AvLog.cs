using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace SentinelTwo
{
    // JSONL event log with size rotation and a per-second burst limit.
    internal static class AvLog
    {
        private const long MaxBytes = 50L * 1024 * 1024;
        private const int MaxFiles = 5;
        private const int Burst = 200;

        private static readonly object Gate = new object();
        private static int count;
        private static DateTime window = DateTime.MinValue;

        public static string LogPath;

        public static void Write(string type, string rule, string evidence, string reasoning,
            double confidence, string tier, string processName, int processId)
        {
            Write(type, rule, evidence, reasoning, confidence, tier, processName, processId, null);
        }

        public static void Write(string type, string rule, string evidence, string reasoning,
            double confidence, string tier, string processName, int processId, Dictionary<string, object> metadata)
        {
            DateTime now = DateTime.Now;
            lock (Gate)
            {
                if ((now - window).TotalSeconds >= 1)
                {
                    count = 0;
                    window = now;
                }
                if (count >= Burst) return;
                count++;
            }

            Dictionary<string, object> data = new Dictionary<string, object>();
            data["ruleName"] = rule;
            data["evidence"] = evidence;
            data["reasoning"] = reasoning;
            data["confidence"] = confidence;
            data["tier"] = tier;
            data["processName"] = processName ?? "";
            data["processId"] = processId;
            data["metadata"] = metadata ?? new Dictionary<string, object>();

            Dictionary<string, object> root = new Dictionary<string, object>();
            root["type"] = type;
            root["timestamp"] = now.ToString("o");
            root["data"] = data;

            string json = new JavaScriptSerializer().Serialize(root);
            try
            {
                Rotate();
                File.AppendAllText(LogPath, json + "\r\n", Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Ui.Write("Unable to write AntivirusLite log: " + ex.Message, ConsoleColor.Yellow);
            }
        }

        private static void Rotate()
        {
            if (!File.Exists(LogPath)) return;
            if (new FileInfo(LogPath).Length < MaxBytes) return;
            for (int i = MaxFiles; i >= 1; i--)
            {
                string old = LogPath + "." + i;
                if (i == MaxFiles && File.Exists(old)) File.Delete(old);
                if (File.Exists(old)) File.Move(old, LogPath + "." + (i + 1));
            }
            File.Move(LogPath, LogPath + ".1");
        }
    }
}
