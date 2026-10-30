# Capability gap: Sentinel 3.4.5 matrix vs SentinelTwo

Status key: **Have** (implemented here), **Partial** (some of the row), **Missing** (not started), **Out of scope** (matrix says a userland agent cannot do it).

| Matrix area | SentinelTwo status | Notes |
| --- | --- | --- |
| Antivirus / EPP | Partial | `scan` command: local SHA-256 blocklist (with freshness), CIRCL and MalwareBazaar lookups, Authenticode with catalog fallback, PE section entropy and packer names, double extensions, script download-exec and encoded payloads. Malicious only on blocklist or reputation hit; Clean only on CIRCL known-good; otherwise Unknown. `--quarantine` moves Malicious files with a manifest. No maintained signature engine, archive unpacking, or before-execution blocking. |
| NanoAV integrated coverage | Missing | Sentinel.Core NanoAV code is not ported. |
| Behavioral execution / scripts | Partial | Command-line rules, encoded exec, download-exec, reflective load, socket shell, genealogy. `events process-start` reads Security 4688 process-creation events (log-based, needs auditing and admin; not real-time ETW). No ETW provider consumption; polling only. |
| Injection / fileless payloads | Partial | Memory RWX/unbacked sampling, hollowing checks, module-load tracking. `memory inspect <pid>` reads executable private or unbacked regions (bounded at 256 MB and 4096 regions) and reports embedded PE headers. Report only. No PE-free shellcode detection, no protected-process access. |
| Credentials / session theft | Partial | Command-line credential-dump rules. No kernel-file credential-store read attribution. |
| Process response | Partial | Monitor kill (Tier1, start-time checked). `process terminate <pid> [--apply]`: children-first tree kill, creation-time identity check before each kill, descendant rescans, protected processes (critical names, Windows directory, SentinelTwo and its ancestors) never killed, per-process exit receipts in `%ProgramData%\SentinelTwo\process\receipts.jsonl`. Orphans reparented away from the root before the rescan are not found. |
| Network / C2 | Partial | TCP polling, beaconing, DGA heuristic. `dns` command: snapshot, set with read-back and automatic restore on mismatch, restore. `firewall` command: program-scoped outbound block rules recorded in a manifest, with unblock. All changes are dry runs unless `--apply`. `firewall block-port` adds recorded outbound blocks for one remote TCP or UDP port (DNS, DHCP, and NTP refused). No DNS telemetry. |
| Browser / proxy recovery | Partial | `proxy status` reports the current-user WinINET proxy (loopback proxy, plain-HTTP PAC) and WinHTTP. `proxy disable --apply` sets ProxyEnable=0 after saving a snapshot, refuses when policy keys manage proxy settings, and reads back. `proxy restore <dir> --apply` reverses it. No browser profile, extension, or machine-wide WinHTTP changes. |
| Persistence | Partial | `persistence` lists Run/RunOnce, startup folders, auto-start services, scheduled tasks and WMI consumers (report only). `persistence clean` removes HKLM/HKCU Run and RunOnce values that launch a quarantined file. `clean-tasks` removes scheduled tasks whose exec actions all target quarantined files (XML snapshot, read-back, restore). `clean-services` removes auto-start services whose image is a quarantined file; restore is refused for accounts with passwords. Quarantine match requires the original path to be gone and the quarantined hash to match. `clean-wmi` removes CommandLineEventConsumer subscriptions (with their bindings, and filters used only by them) that launch quarantined files, after snapshotting them. No HKCU-alternate-view cleanup. |
| Ransomware | Partial | Rate and extension heuristics; kill via correlation. No pre-write protection. |
| Credential/driver hardening | Have (read-only) | `audit` command reports LSA protection, VBS/Credential Guard/HVCI states, vulnerable-driver blocklist setting. Configuration is never changed. |
| Defender integration | Have (read-only) | `audit` reports Defender enabled/real-time/tamper state when the provider is present. ASR is not managed. |
| Exploit / patch management | Partial | `patch scan` lists pending Windows Update software items with severity, KB, and CVE IDs where the update exposes them. Scan only: nothing is downloaded or installed. No CVE-to-exploit data (ExploitShield feed not ported), no installation. |
| DNS / certificate recovery | Partial | `dns` command (snapshot, set, verified restore). `cert` command: `find` and `list` (read-only), `distrust <thumbprint> --apply` adds a LocalMachine Root or CA certificate to the Disallowed store and records it, `undistrust` removes only entries SentinelTwo recorded. Refuses subjects containing "Microsoft". No Root-store removal, no proxy/browser CA cleanup. |
| Tamper resistance / evidence | Partial | Self-hash integrity check and JSONL log. No protected IPC or incident evidence store. |
| Identity / social engineering | Out of scope | Matrix states domain/cloud enforcement needs external infrastructure. |

## Not yet done (ordered by value and risk)
1. Persistence observation (Run keys, services, tasks), report-only.
2. NanoAV-style file scanning, with explicit Unknown handling and freshness reporting.
3. ETW process/network telemetry. Needs a TraceEvent-class library; C# 5 plus no NuGet makes this a dependency decision.
4. Firewall, DNS, and certificate changes. These modify system state and need an approval and rollback design first.
5. ExploitShield / WUA patching. Modifies system state; needs approval.
