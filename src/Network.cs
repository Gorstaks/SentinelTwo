using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;

namespace SentinelTwo
{
    internal sealed class Connection
    {
        public IPAddress Remote;
        public int RemotePort;
        public int Pid;
        public string Key;
        public bool New;
    }

    internal sealed class BeaconState
    {
        public List<DateTime> Times = new List<DateTime>();
        public string Name;
    }

    // Established TCP sampling (not packet capture). Connection creation time is not exposed by
    // GetExtendedTcpTable, so the first snapshot that shows a connection is its observation time.
    internal static class Network
    {
        private static HashSet<string> previousSnapshot;
        private static readonly Dictionary<string, BeaconState> Beacons = new Dictionary<string, BeaconState>();

        public static List<Connection> Snapshot()
        {
            List<Connection> result = new List<Connection>();
            foreach (Native.TcpRow row in Native.GetTcpRows())
            {
                if (row.State != Native.MIB_TCP_STATE_ESTAB) continue;
                if (row.Pid <= 4) continue;
                IPAddress remote;
                if (!IPAddress.TryParse(row.RemoteAddress, out remote)) continue;
                string key = row.Pid + "|" + row.LocalAddress + "|" + row.LocalPort + "|" + row.RemoteAddress + "|" + row.RemotePort;
                result.Add(new Connection { Remote = remote, RemotePort = row.RemotePort, Pid = row.Pid, Key = key });
            }
            return result;
        }

        public static bool IsPrivate(IPAddress address)
        {
            if (address == null) return true;
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            if (IPAddress.IsLoopback(address)) return true;
            byte[] bytes = address.GetAddressBytes();
            if (bytes.Length == 4)
            {
                return bytes[0] == 0 || bytes[0] == 10 ||
                       (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                       (bytes[0] == 192 && bytes[1] == 168) ||
                       (bytes[0] == 169 && bytes[1] == 254) || bytes[0] >= 224;
            }
            return address.IsIPv6LinkLocal || address.IsIPv6Multicast ||
                   ((bytes[0] & 0xFE) == 0xFC) || address.Equals(IPAddress.IPv6Any);
        }

        public static void Analyze(List<Connection> connections)
        {
            Dictionary<int, List<Connection>> byPid = new Dictionary<int, List<Connection>>();
            HashSet<string> current = new HashSet<string>();
            foreach (Connection c in connections)
            {
                current.Add(c.Key);
                c.New = previousSnapshot != null && !previousSnapshot.Contains(c.Key);
                List<Connection> list;
                if (!byPid.TryGetValue(c.Pid, out list))
                {
                    list = new List<Connection>();
                    byPid[c.Pid] = list;
                }
                list.Add(c);
            }
            previousSnapshot = current;

            foreach (KeyValuePair<int, List<Connection>> entry in byPid)
            {
                int pid = entry.Key;
                if (pid <= 4 || pid == AvState.CurrentPid) continue;
                ProcessInfo info;
                if (!AvState.Ancestry.TryGetValue(pid, out info)) continue;
                string path = info.Path;
                string name = info.Name;

                if (!string.IsNullOrEmpty(path) && IsInstalledSoftware(path)) continue;

                List<Connection> pub = new List<Connection>();
                foreach (Connection c in entry.Value)
                {
                    if (!IsPrivate(c.Remote)) pub.Add(c);
                }
                if (pub.Count == 0) continue;

                string[] staging = AvState.StagingTokens();
                if (AvState.PathContainsAny(path, staging))
                {
                    if (!AvState.IsDup("NetStage|" + pid, 300))
                    {
                        AvLog.Write("detection", "StagedPayloadNetwork",
                            name + " from staging path -> " + pub.Count + " public connections",
                            "Binary in temp/download location making outbound connections",
                            0.82, Correlation.Tier1, name, pid);
                        AvState.AddSignal(pid, "network", 0.82);
                        Ui.Write("[Tier1] StagedPayload: " + name + " (PID " + pid + ") from " + path, ConsoleColor.Yellow);
                    }
                }

                DateTime now = DateTime.Now;
                foreach (Connection c in pub)
                {
                    if (c.New) TrackBeacon(pid, c.Remote.ToString(), c.RemotePort, name, now);
                }
            }
        }

        private static bool IsInstalledSoftware(string path)
        {
            string pf = Environment.GetEnvironmentVariable("ProgramFiles");
            string pf86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)");
            string root = Environment.GetEnvironmentVariable("SystemRoot");
            return (!string.IsNullOrEmpty(pf) && path.StartsWith(pf, StringComparison.OrdinalIgnoreCase)) ||
                   (!string.IsNullOrEmpty(pf86) && path.StartsWith(pf86, StringComparison.OrdinalIgnoreCase)) ||
                   (!string.IsNullOrEmpty(root) && path.StartsWith(root, StringComparison.OrdinalIgnoreCase));
        }

        // Drops beacon tracks with no recent connection (older than 15 minutes).
        public static void PruneBeacons()
        {
            DateTime now = DateTime.Now;
            List<string> stale = new List<string>();
            foreach (KeyValuePair<string, BeaconState> entry in Beacons)
            {
                List<DateTime> times = entry.Value.Times;
                if (times.Count == 0 || (now - times[times.Count - 1]).TotalMinutes > 15) stale.Add(entry.Key);
            }
            foreach (string k in stale) Beacons.Remove(k);
        }

        private static void TrackBeacon(int pid, string addr, int port, string name, DateTime observedAt)
        {
            string k = pid + "|" + addr + "|" + port;
            DateTime now = DateTime.Now;
            BeaconState state;
            if (!Beacons.TryGetValue(k, out state))
            {
                state = new BeaconState { Name = name };
                state.Times.Add(observedAt);
                Beacons[k] = state;
                return;
            }
            if (state.Times.Contains(observedAt)) return;
            state.Times.Add(observedAt);
            List<DateTime> recent = new List<DateTime>();
            foreach (DateTime t in state.Times)
            {
                if ((now - t).TotalMinutes <= 10) recent.Add(t);
            }
            recent.Sort();
            if (recent.Count > 20) recent = recent.GetRange(recent.Count - 20, 20);
            state.Times = recent;
            if (recent.Count < 5) return;

            List<double> intervals = new List<double>();
            for (int i = 1; i < recent.Count; i++)
            {
                intervals.Add((recent[i] - recent[i - 1]).TotalSeconds);
            }
            double mean = 0;
            foreach (double v in intervals) mean += v;
            mean /= intervals.Count;
            if (!(mean > 0 && mean < 300)) return;

            double variance = 0;
            foreach (double v in intervals) variance += Math.Pow(v - mean, 2);
            variance /= intervals.Count;
            double cv = Math.Sqrt(variance) / mean;
            if (cv >= 0.40) return;

            if (AvState.IsDup("Beacon|" + k, 300)) return;
            double conf = Math.Min(0.95, 0.70 + (0.40 - cv) * 0.6);
            AvLog.Write("detection", "Beaconing",
                name + " -> " + addr + ":" + port + " CV=" + Math.Round(cv, 3) +
                " int=" + Math.Round(mean, 1) + "s obs=" + recent.Count,
                "Repeated new TCP connections with regular intervals; heuristic only",
                conf, Correlation.Tier2, name, pid);
            AvState.AddSignal(pid, "beaconing", conf);
            Ui.Write("[Tier2] Beaconing: " + name + " (PID " + pid + ") CV=" + Math.Round(cv, 3), ConsoleColor.Yellow);
        }
    }
}
