# SentinelTwo port notes

## Status
- Phase 1 (port of AntivirusLite.ps1 + PasswordRotator.ps1 to C# 5 / .NET 4.8): source complete, builds with build.bat (csc v4.0.30319, /langversion:5, /platform:x64).
- Output: bin\SentinelTwo.exe (requireAdministrator manifest).
- Verified: compiles; non-elevated run exits 1 with "Run as administrator." (tested with a manifest-less temp build).
- NOT verified: install, monitor loop, kill gate, rotator install/rotate/uninstall. These change live system state and need an elevated test on an approved machine.
- Phase 2 (add missing features from E:\Gorstak\Sentinel): not started; scope still to be agreed.

## Live-machine warning
- A PowerShell AntivirusLite install is already active on this machine: task "AntivirusLite" runs C:\ProgramData\AntivirusLite\AntivirusLite.ps1, and events.jsonl is updating.
- SentinelTwo's install uses the same task name and would overwrite it (schtasks /Create /F) and stop the running task.
- rotator-install blanks the target account password immediately and never stores the rotating password. Do not run it on this machine without explicit approval.

## Files
- src/Native.cs            P/Invoke: TCP tables, VirtualQueryEx, netapi, wtsapi, WinVerifyTrust
- src/AvState.cs           shared state, dedup, signals, entropy, console helper
- src/AvLog.cs             JSONL log (JavaScriptSerializer), rotation, burst limit
- src/Correlation.cs       Detection type, composite rules, kill gate
- src/Rules.cs             command-line rules, genealogy, unsigned staged, DNS
- src/Reputation.cs        CIRCL / MalwareBazaar lookups, SHA256, Authenticode
- src/Network.cs           TCP snapshot, IsPrivate, network analysis, beaconing
- src/Monitors.cs          memory, clipboard, modules, surveillance, WMI, self-integrity
- src/FileMonitor.cs       FileSystemWatcher queue, ransomware heuristics
- src/Tasks.cs             schtasks wrapper, task XML, COM running-state check
- src/AntivirusLite.cs     ancestry, scan loop, banner, prune
- src/AntivirusInstaller.cs install/uninstall, ACLs
- src/PasswordRotator.cs   boot reset, rotation loop, install, uninstall
- src/Program.cs          dispatch, admin gate, monitor mutex, FreeConsole for scheduled runs
- app.manifest, build.bat

## Commands
- (none) | monitor     install if needed, else run the monitor
- uninstall            remove monitor task, stop its instances
- rotator-install / rotator-uninstall
- rotator-boot <SID> / rotator-logon <SID>   internal task entry points

## Known behavior differences
- GetExtendedTcpTable has no connection creation time. Beacon intervals use the snapshot time the connection was first seen (5 s sampling).
- Local-account check (Local vs Microsoft/Entra) still calls Get-LocalUser through powershell.exe, fail-closed.
- Uninstall of the rotator writes a blank password; the script does the same.
- Uses dynamic (Microsoft.CSharp.dll) only for the Task Scheduler COM running-state query.

## Tranche 2 (capability matrix, option 4)
- docs/CAPABILITY_GAP.md maps each Sentinel matrix row to Have / Partial / Missing / Out of scope.
- src/Audit.cs adds `audit`: read-only report of LSA protection, VBS/Credential Guard/HVCI, vulnerable-driver blocklist, Defender status, and HKLM/HKCU Run/RunOnce entries. Missing providers report Unknown.
- Built successfully. The audit output has not been run: the exe requires elevation, and I did not elevate it.

## Tranche 3: persistence observation (C# 5, report only)
- src/Persistence.cs adds `persistence`: Run/RunOnce (HKLM, HKCU, Wow6432Node), startup folders, auto-start services, enabled scheduled tasks (COM Schedule.Service), and WMI CommandLine consumers and event filters.
- Entries are reported when the target is outside %SystemRoot% and Program Files. Nothing is changed.
- Limitation: bare executable names such as BthUdTask.exe are reported because their resolved location is not checked against System32.
- Verified with a temporary harness that read the live machine (3 observations). The harness was deleted.

## Tranche 4: file scanning (C# 5)
- `scan <path>... [--offline] [--quarantine]` (src/FileScanner.cs, src/ScanSignatures.cs).
- Verdicts: Malicious (local blocklist or MalwareBazaar hit), Suspicious (static heuristics score >= 2), Clean (CIRCL known-good only), Unknown (everything else, including signed files).
- Local blocklist: %ProgramData%\SentinelTwo\signatures\sha256-blocklist.txt, one SHA-256 per line. Freshness is reported; stale lists are marked.
- Results: %ProgramData%\SentinelTwo\logs\scan.jsonl. Quarantine: %ProgramData%\SentinelTwo\quarantine with manifest.jsonl recording the original path. Files are moved, never deleted.
- Authenticode: embedded check, then catalog fallback (CryptCATAdmin APIs). Verified: notepad.exe and cmd.exe return 0; an unsigned file returns a trust error.
- Verified with a harness on a fixture set: blocklist hit (Malicious), double extension and download-exec (Suspicious), signed system binary (Unknown), plain text (Unknown).
- NOT verified: quarantine. Setting the owner on the quarantine directory requires an elevated process, and the test ran non-elevated. The shipped binary requires elevation, so the path should work there, but it has not been run.
- No online lookups were tested. The scan ran with --offline.
- Test fixtures and test blocklist/log/quarantine data were removed from the machine after the test.

## Tranche 5: DNS and firewall control (C# 5)
- src/NetworkControl.cs: `dns status|snapshot|set|restore`, `firewall list|block|unblock|unblock-all`.
- Every mutating command is a dry run unless `--apply`.
- DNS set: saves a snapshot first, applies, reads back via WMI, and restores the snapshot on mismatch. Restore sends DHCP adapters back to DHCP, verifies, and falls back to the recorded static list if the DNS values differ.
- Firewall block: refuses files under %SystemRoot% and SentinelTwo itself. Rule names are SentinelTwo-block-<hash>. Only rules recorded in %ProgramData%\SentinelTwo\network\firewall-rules.json can be removed.
- Audit log: %ProgramData%\SentinelTwo\network\changes.jsonl.
- Verified: status, dry runs, input validation, snapshot JSON format, and refusal of a missing restore snapshot. Ran non-elevated, so no change was applied.
- NOT verified: any --apply path. It needs elevation and would change this machine's network. Test on a disposable VM before using on real hosts.
- Test folders under %ProgramData%\SentinelTwo were removed after testing.

## Tranche 6: narrow persistence cleanup (C# 5)
- src/PersistenceCleanup.cs: `persistence clean [--apply]` and `persistence restore <snapshot-dir> [--apply]`.
- Candidate rule: a Run or RunOnce value (HKLM or HKCU) whose launch target equals a quarantine manifest entry's original path, where that original path no longer exists and the quarantined copy's SHA-256 still matches. Dry run by default.
- Removals save the value to %ProgramData%\SentinelTwo\persistence\snapshots\<time>\run-values.json, read back the deletion, and log to changes.jsonl.
- Bug fixed during testing: the SHA-256 comparison was case-sensitive, but Sha256File returns uppercase hex. Now case-insensitive.
- Verified end to end on HKCU with a test quarantine entry: dry run, clean --apply (value removed and read back), restore --apply (value re-created and read back). Test data was removed afterward.
- HKLM apply path has the same code but was not run (requires elevation).

## Tranche 7: process-tree termination with exit receipts (C# 5)
- src/ProcessTree.cs: `process tree <pid>` (read-only) and `process terminate <pid> [--apply]`.
- Plan: root plus descendants, children first. Dry run by default.
- Identity: each process is killed only if its creation time still matches the plan. A PID reuse is skipped and receipted.
- Protected, never killed (also as descendants): PIDs 0 and 4, critical names (System, smss, csrss, wininit, winlogon, lsass, services, Idle), anything under %SystemRoot%, SentinelTwo itself, and its ancestors. Protected processes that remain running make the result incomplete.
- Receipts: %ProgramData%\SentinelTwo\process\receipts.jsonl with outcome, exit code, and verified flag.
- Limitation: children reparented to another parent before the rescan are not found.
- Verified with a disposable tree (copies of cmd.exe and ping.exe in TEMP): dry run, guards (self, PID 4), tree kill with exit verification, protected conhost.exe left alone and exited on its own. Test processes and data were removed.

## Tranche 8: proxy recovery (C# 5)
- src/ProxyRecovery.cs: `proxy status`, `proxy disable [--apply]`, `proxy restore <dir> [--apply]`.
- Current-user WinINET only. Disable sets ProxyEnable=0 and keeps the other values. Snapshots are in %ProgramData%\SentinelTwo\proxy\snapshots.
- Refused when HKLM or HKCU policy keys define ProxyEnable, ProxyServer, or AutoConfigURL.
- Findings: loopback proxy server, PAC URL over plain HTTP.
- Verified on HKCU with a temporary loopback proxy: status, disable --apply (read back ProxyEnable=0), restore --apply (read back the test state). The original HKCU values were then restored and test data removed.
- WinHTTP is reported only.

## Tranche 9: certificate distrust (C# 5)
- src/CertPolicy.cs: `cert list`, `cert find <text>`, `cert distrust <thumbprint> [--apply]`, `cert undistrust <thumbprint> [--apply]`.
- Distrust copies a LocalMachine Root or CA certificate into LocalMachine Disallowed. Entries are recorded in %ProgramData%\SentinelTwo\certs\distrusted.json. Undistrust removes only recorded entries. Root and CA stores are never changed.
- Refuses any subject containing "Microsoft" (conservative: also refuses non-Microsoft certificates with that word in the subject).
- Verified: find, list, dry run, guard refusal for a Microsoft root, and a non-elevated apply that failed cleanly with rc=1 and no store change.
- NOT verified: the elevated apply, read-back, and undistrust. Test on a disposable VM first.

## Tranche 10: memory PE inspection (C# 5, read-only)
- src/MemoryInspect.cs: `memory inspect <pid>`. Walks committed executable regions that are not MEM_IMAGE, reads up to 4 KB of each, and reports regions with MZ plus a PE\0\0 header at e_lfanew.
- Budget: 256 MB total and 4096 regions. Output states when coverage is partial.
- Refuses PIDs 0, 4, and SentinelTwo itself. Cannot open protected processes.
- Verified: ran against a live PowerShell process (29 regions sampled, 0 PE findings, no changes). Notepad relaunched under a new PID during the test, so the test target changed.
- NOT verified: positive detection. No test process with an embedded PE in private memory was created.
- The monitor's MemoryAnalysis is unchanged; this is operator-invoked only.

## Tranche 11: scheduled-task and service cleanup (C# 5)
- src/PersistenceTasks.cs: `persistence clean-tasks [--apply]`, `clean-services [--apply]`. `persistence restore <dir> [--apply]` dispatches on tasks.json or services.json.
- Task candidates: every exec action targets a quarantined file (manifest match, original gone, hash matches). Snapshot stores each task's XML. Restore re-registers from XML.
- Service candidates: Win32_Service StartMode=Auto with image path matching a quarantined entry. Removal uses sc stop/delete and verifies with sc query (1060 = gone). Restore re-creates built-in-account services only (LocalSystem, LocalService, NetworkService); others are refused because their passwords are not stored.
- Bug found and fixed during testing: GetTask is a folder method, not a scheduler-service method, so the first read-back always reported "absent" and would have reported false success. Also GetFolder can raise FileNotFoundException after the last task is removed; that is now treated as absent. Other errors propagate.
- Verified non-elevated on a user-owned daily test task: dry run, clean --apply (removal read back), restore --apply (re-registration read back), and removal of the test folder.
- Verified: service clean dry run (no candidates), restore refusal for a domain account, and built-in restore dry run.
- NOT verified: service removal and service re-creation (need administrator rights). Task restore for elevated or service-account principals was not tested.

## Tranche 12: WMI subscription cleanup and port-level firewall blocks (C# 5)
- src/PersistenceWmi.cs: `persistence clean-wmi [--apply]` and restore (wmi.json). Candidates are CommandLineEventConsumer objects whose command targets a quarantined file. Filters are removed only when every binding that uses them belongs to a selected consumer. Snapshot before deletion. Restore re-creates filter, consumer, then bindings.
- NetworkControl: `firewall block-port tcp|udp <port> [--apply]` and `unblock-port`. Rules are named SentinelTwo-block-<proto>-<port> and recorded in firewall-rules.json. Ports 53, 67, 68, and 123 are refused.
- Verified non-elevated: clean-wmi dry run (read path works, no candidates), restore dry run, block-port dry run, refusals (DNS port, bad protocol), and unblock-port with no record.
- NOT verified: WMI consumer removal and restore (need administrator rights), and any port-rule apply.

## Tranche 13: read-only patch scan and process-creation events (C# 5)
- src/Telemetry.cs: `patch scan` (Microsoft.Update.Session search for IsInstalled=0, Type=Software, IsHidden=0; 180 s timeout; no download or install) and `events process-start [minutes]` (Security 4688 via EventLogReader; positional fields 5, 8, 13).
- Verified: patch scan returned 0 pending items, matching a direct COM query. events process-start denied cleanly when not elevated, and rejects out-of-range minutes.
- NOT verified: events output with real 4688 records (needs elevation and process-creation auditing). Field positions 5, 8, and 13 follow the Windows 10/11 4688 layout and need checking on the target OS.
- Not done: real-time ETW (needs a third-party library), ExploitShield CVE mapping (needs an offline feed), patch installation, credential-store read attribution (needs file-access auditing).

## Tests (tests\)
- Build: tests\build_tests.bat (csc v4.0.30319, C# 5, no test packages). Output: tests\bin\SentinelTwo.Tests.exe. No administrator manifest, so unit tests run unelevated.
- Run unit tests: `tests\bin\SentinelTwo.Tests.exe` (exit 0 = all passed).
- Run integration tests: `tests\bin\SentinelTwo.Tests.exe --integration`. These make temporary changes: an HKCU Run value (removed afterward), two copied binaries that are killed, a scan log, and a Windows Update search. Each skips itself if %ProgramData%\SentinelTwo already exists, so real data is never deleted.
- Framework: Runner.cs. Methods named Test* in classes ending in Tests are run; classes ending in IntegrationTests run only with --integration.
- Unit tests (CoreTests.cs, CommandTests.cs): entropy, shared state, rule patterns, network privacy, PE heuristics on synthetic PE images, offline scanner verdicts, Authenticode (catalog and unsigned), SHA-256 vector, persistence path matching, composite correlation, and command refusals or dry runs. No system state changes.
- Last run: unit 85 passed, 0 failed. Integration 89 passed, 0 failed (includes the 4 integration classes), with cleanup verified.
- Not covered by automated tests: any elevated path (service removal and re-creation, WMI subscription removal and restore, firewall rule add and delete, DNS apply, cert distrust apply, proxy apply on machine scope, quarantine ACL), real 4688 event parsing, and real-time ETW (not built).
- Bugs found by tests and fixed: a fixture folder was not created before a write in a test; the scanner printed "Results appended" when nothing was scanned.

## Monitor rename and run-in-place
- Installed monitor is now ProgramData\SentinelTwo\monitor\SentinelTwo.exe, scheduled task "SentinelTwo Monitor". Previously ProgramData\AntivirusLite\AntivirusLite.exe and task "AntivirusLite".
- New command `run`: runs the monitor in the current console without installing (uses the same single-instance mutex as the installed monitor).
- Migration from the old install (needs an elevated shell): run the old build's uninstall first, then the new build. The old uninstall kills only the old executable's process, so it must run before the rename.
- Not verified on this machine: the elevated uninstall and install steps (the shell here is not elevated).

## Versioning and releases
- version.txt is the single source of truth (MAJOR.MINOR.PATCH). tools\write-version.ps1 writes src\AppVersion.cs from it; build.bat and tests\build_tests.bat both run it.
- `SentinelTwo.exe version` prints the version. The monitor banner shows it.
- build.bat copies bin\SentinelTwo.exe to releases\<version>\SentinelTwo.exe. If that file exists and differs, the build does not overwrite it and exits with code 3. To rebuild the same version, delete the old release file first. For a new build, bump version.txt by one patch.
- Current state: version 0.0.1. releases\0.0.1\SentinelTwo.exe was copied by hand at 7:10 and differs from the current build, so it was left as is.
- .gitignore ignores everything except source (src, tests, tools .cs and .ps1), docs (.md, docs\), version.txt, build scripts, app.manifest, and .gitignore. bin, tests\bin, releases, logs, and data files are excluded. Verified with a temporary git repo; the project is not a git repository yet.
