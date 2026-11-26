# SentinelTwo

A single-file Windows endpoint monitor and response tool, written in C# 5 for .NET Framework 4.8. It has no NuGet dependencies and builds with the `csc.exe` that ships with Windows.

SentinelTwo began as a port of two PowerShell tools, AntivirusLite (a behavioral monitor) and PasswordRotator. It has since gained file scanning, persistence reporting, and several recovery commands. It is a userland agent. It does not block execution before it happens and has no kernel component.

> **Status:** early (version 0.0.1). Many state-changing paths have not been tested on a live elevated machine. See [Verification status](#verification-status) before running it on a machine you care about.

## Features

- **Behavioral monitor.** Polls processes, network connections, memory and files, and raises detections for:
  - command-line rules (encoded execution, download-and-execute, reflective loading, credential-dump tools)
  - process genealogy and unsigned staged binaries
  - TCP beaconing and DGA-like DNS names
  - RWX or unbacked executable memory, process hollowing and module loads
  - clipboard and surveillance behavior, WMI activity, self-integrity changes
  - ransomware-style file activity (rate and extension heuristics)
- **Correlation and kill gate.** Individual signals are combined by composite rules. A process is killed only when the gate is satisfied, and the process start time is checked first.
- **File scanner.** Local SHA-256 blocklist, CIRCL known-good lookups, MalwareBazaar lookups, Authenticode checks with catalog fallback, PE section entropy, packer names, double extensions, and script heuristics.
- **Recovery and hardening commands.** DNS, firewall, proxy, certificate, persistence, and process-tree actions. Each one records what it changed so it can be reversed.
- **Read-only reporting.** Hardening audit, persistence listing, memory inspection, pending Windows updates, and process-creation events.
- **Password rotator.** Optional scheduled tasks that rotate the current administrator's password. Read the warning below first.

## Requirements

- Windows 10 or later, x64
- .NET Framework 4.8 (the build uses `%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`)
- Administrator rights to run. The executable carries a `requireAdministrator` manifest.

## Build

```bat
build.bat
```

This writes `bin\SentinelTwo.exe` and copies it to `releases\<version>\`. The version comes from `version.txt`. If a release file for that version already exists with different content, the build refuses to overwrite it and exits with code 3. Bump the patch version in `version.txt` to publish a new build.

Tests:

```bat
tests\build_tests.bat
tests\bin\SentinelTwo.Tests.exe                 :: unit tests, no elevation needed
tests\bin\SentinelTwo.Tests.exe --integration   :: also touches the live machine
```

The GitHub Actions workflow builds on every push and pull request. On `main`, it publishes a release tagged `v<version>` if none exists for that version.

## Usage

```text
SentinelTwo.exe [command] [options]
```

Every command that changes system state is a **dry run unless you pass `--apply`**.

### Monitor

| Command | Description |
| --- | --- |
| *(none)* or `monitor` | Install the scheduled task if needed, otherwise run the monitor |
| `run` | Run the monitor in the current console without installing |
| `uninstall` | Remove the monitor task and stop its instances |
| `version` | Print the version |

### Scanning and reporting

| Command | Description |
| --- | --- |
| `scan <path>... [--offline] [--quarantine]` | Scan files. `--quarantine` moves only Malicious files. `--offline` skips online lookups |
| `audit` | Report LSA protection, VBS, Credential Guard, HVCI, the vulnerable-driver blocklist, Defender state and Run keys. Changes nothing |
| `persistence` | List Run/RunOnce keys, startup folders, auto-start services, scheduled tasks and WMI consumers |
| `memory inspect <pid>` | Look for embedded PE headers in executable private or unbacked memory (limit 256 MB, 4096 regions) |
| `patch scan` | List pending Windows Update items with severity, KB and CVE IDs. Installs nothing |
| `events process-start [minutes]` | Read process-creation events (Security 4688). Needs process-creation auditing enabled |

Scan verdicts:

| Verdict | Meaning |
| --- | --- |
| Malicious | Local blocklist or MalwareBazaar hit |
| Suspicious | Static heuristic score of 2 or more |
| Clean | CIRCL known-good only |
| Unknown | Everything else, including signed files |

Put your own SHA-256 hashes, one per line, in `%ProgramData%\SentinelTwo\signatures\sha256-blocklist.txt`. The scan output reports how old the list is.

### Response and recovery

| Command | Description |
| --- | --- |
| `process tree <pid>` | Show the process and its descendants |
| `process terminate <pid> [--apply]` | Kill the tree, children first. Checks each process's creation time before killing it and writes an exit receipt |
| `dns status \| snapshot \| set <ip>... --adapter <name> [--apply] \| restore <dir> [--apply]` | Manage DNS servers. `set` reads the result back and restores the snapshot on mismatch |
| `firewall list \| block <exe> [--apply] \| unblock <exe> [--apply] \| unblock-all [--apply]` | Program-scoped outbound block rules, recorded in a manifest |
| `firewall block-port ...` | Outbound block for one remote TCP or UDP port. DNS, DHCP and NTP ports are refused |
| `proxy status \| disable [--apply] \| restore <dir> [--apply]` | Report or disable the current-user WinINET proxy. Refuses when policy manages proxy settings |
| `cert list \| find <text> \| distrust <thumbprint> [--apply] \| undistrust <thumbprint> [--apply]` | Move a LocalMachine Root or CA certificate to the Disallowed store. Refuses subjects containing "Microsoft" |
| `persistence clean [--apply]` | Remove Run/RunOnce values that launch a quarantined file |
| `persistence clean-tasks`, `clean-services`, `clean-wmi` | Same idea for scheduled tasks, auto-start services and WMI consumers |
| `persistence restore <snapshot-dir> [--apply]` | Reverse a cleanup from its snapshot |

Safeguards that apply to these commands:

- Processes are never killed if they are critical system processes (System, smss, csrss, wininit, winlogon, lsass, services), live under the Windows directory, or are SentinelTwo or one of its ancestors.
- Firewall rules cannot target files under the Windows directory or SentinelTwo itself. Only rules recorded in the manifest can be removed.
- Persistence cleanup only removes entries whose target matches a quarantine manifest entry: the original path is gone and the quarantined file's SHA-256 still matches.

### Password rotator

| Command | Description |
| --- | --- |
| `rotator-install` | Install the rotator for the current administrator |
| `rotator-uninstall` | Restore a blank password and remove the rotator tasks |
| `rotator-boot <SID>`, `rotator-logon <SID>` | Internal task entry points. Do not run by hand |

> **Warning:** `rotator-install` blanks the target account's password immediately and never stores the rotating password. `rotator-uninstall` also leaves the account with a blank password. Do not use it unless you understand and accept that.

## Data locations

Everything is stored under `%ProgramData%\SentinelTwo`:

| Path | Contents |
| --- | --- |
| `logs\` | Monitor JSONL log (with rotation) and `scan.jsonl` |
| `signatures\sha256-blocklist.txt` | Your local hash blocklist |
| `quarantine\` | Quarantined files and `manifest.jsonl` with original paths. Files are moved, never deleted |
| `network\` | `firewall-rules.json`, DNS snapshots, `changes.jsonl` audit log |
| `persistence\snapshots\` | Snapshots taken before each cleanup |
| `process\receipts.jsonl` | Per-process exit receipts |

## Verification status

- Verified (per NOTES.md): the build, read-only commands, dry runs, input validation, and the HKCU persistence clean and restore cycle.
- **Not verified on an elevated live machine:** monitor install and loop, the kill gate, quarantine, every `--apply` path for DNS and firewall changes, HKLM persistence cleanup, and the password rotator.
- Test `--apply` commands and the rotator on a disposable VM first.
- The installer uses the scheduled task name `AntivirusLite`. If the original PowerShell AntivirusLite is installed, SentinelTwo will overwrite its task.

## Limitations

- Polling only. There is no ETW consumption and no DNS telemetry.
- No maintained signature engine, archive unpacking, or blocking before execution.
- No kernel-level credential-store attribution, and no protected IPC or evidence store.
- Beacon intervals use the time a connection was first seen in a 5 second sample, because the TCP table has no creation time.
- Identity and cloud enforcement are out of scope for a userland agent.

[docs/CAPABILITY_GAP.md](docs/CAPABILITY_GAP.md) maps each capability area to Have, Partial, Missing or Out of scope. [NOTES.md](NOTES.md) holds the porting notes and per-feature test details.

## Project layout

```text
src/        C# 5 sources, compiled together into one executable
tests/      Unit and integration test runner
tools/      write-version.ps1, used by the build
docs/       Capability gap matrix
releases/   Built executables, one folder per version
```

## License

No license file is present. Add one before accepting outside contributions or redistributing.
