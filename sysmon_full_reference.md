# Sysmon Full Reference

This reference normalizes Sysmon to the current public Windows event set and schema. Microsoft currently documents Event IDs **1-29** and **255**. The tables below focus on **Sysmon EventData fields** rather than generic Windows Event Log system metadata such as Provider, Channel, Computer, EventRecordID, Execution, and Security/UserID.

Normalization highlights used in this reference:
- **Event ID 1** includes `ParentUser`
- **Event ID 5** does **not** expose `ExitStatus` in the current public schema
- **Event ID 12** covers **registry key and value create/delete** operations
- **Event ID 14** covers **key and value rename** operations
- **Event ID 15** uses `Hash` (singular) and also includes `Contents`
- **Event IDs 27-29** are part of the current official event list and should be included in modern Sysmon references

`RuleName` appears on most filterable events and reflects the matching Sysmon rule name or tag. In the current public schema, **Event IDs 4, 16, and 255** do not carry `RuleName`.

---

## Event ID 1 - Process Create

Records extended information about a newly created process, including command line, file metadata, integrity, logon context, hashes, and the parent process. It is the foundational Sysmon event for execution-chain analysis.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. | Often `-` or empty if no named rule matched. |
| UtcTime | UTC timestamp when the event was generated. | EventData timestamp, separate from `System/TimeCreated`. |
| ProcessGuid | Stable unique GUID for the created process. | Preferred over PID for correlation across events. |
| ProcessId | OS process identifier (PID) of the created process. | Reused by Windows over time. |
| Image | Full path of the executable image that started. | Child process path. |
| FileVersion | File version metadata from the PE image. | May be empty for some binaries/scripts. |
| Description | File description metadata from the PE image. | PE metadata field. |
| Product | Product name metadata from the PE image. | PE metadata field. |
| Company | Company metadata from the PE image. | PE metadata field. |
| OriginalFileName | Original file name from the PE header. | Useful when attackers rename binaries. |
| CommandLine | Full command line used to create the process. | High-value field for hunting. |
| CurrentDirectory | Working directory of the created process. | Can help explain relative paths. |
| User | Security context of the created process. | Usually `DOMAIN\User` or service account. |
| LogonGuid | GUID for the associated logon session. | Useful for correlating with auth events. |
| LogonId | Hex logon session ID. | Often easier to join with Windows Security logs. |
| TerminalSessionId | Terminal Services / RDP session ID. | Useful in multi-user systems. |
| IntegrityLevel | Process integrity label. | Common values include Low, Medium, High, System. |
| Hashes | File hashes of the executable image. | Content depends on configured hash algorithms. |
| ParentProcessGuid | Stable GUID of the parent process. | Best parent correlation field. |
| ParentProcessId | PID of the parent process. | Point-in-time only. |
| ParentImage | Full path of the parent executable. | High-value for parent-child analysis. |
| ParentCommandLine | Full command line of the parent process. | Often critical for context. |
| ParentUser | Security context of the parent process. | Frequently missing from older cheat sheets. |

**Common Use Cases:** Process tree reconstruction, LOLBin hunting, encoded PowerShell detection, parent-child anomaly detection, and session-based attribution.

**Detection Tips:** Prioritize suspicious parent-child pairs, high-risk interpreters (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`), unexpected `OriginalFileName` mismatches, and command lines with encoded, hidden, or download behavior.

---

## Event ID 2 - File Creation Time Changed

Records when a process explicitly changes a file creation timestamp. This is classically useful for detecting **timestomping**, though legitimate software can also do it.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. | May be empty. |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process that changed the timestamp. |  |
| ProcessId | PID of the process that changed the timestamp. |  |
| Image | Full path of the process image. |  |
| TargetFilename | Full path of the file whose creation time changed. |  |
| CreationUtcTime | New creation time after modification. | UTC. |
| PreviousCreationUtcTime | Previous creation time before modification. | UTC. |
| User | Security context of the process. |  |

**Common Use Cases:** Timestomp detection, file timeline integrity checks, and post-compromise artifact review.

**Detection Tips:** Investigate files whose creation time becomes much older than nearby activity, especially in temp, startup, service, or tool-staging directories.

---

## Event ID 3 - Network Connection

Records TCP and UDP network connections made by a process. This event is disabled by default because of volume, but it is central for C2, staging, and lateral-movement analysis.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process responsible for the connection. |  |
| ProcessId | PID of the process. |  |
| Image | Full path of the process image. |  |
| User | Security context of the process. |  |
| Protocol | Network protocol string. | Commonly `tcp` or `udp`. |
| Initiated | Whether the process initiated the connection. | Boolean-like value. |
| SourceIsIpv6 | Whether the source address is IPv6. | Boolean-like value. |
| SourceIp | Source IP address. | Usually local host IP. |
| SourceHostname | Resolved source hostname. | Depends on configuration / lookup success. |
| SourcePort | Source port number. |  |
| SourcePortName | Service name mapped from the source port. | May be empty. |
| DestinationIsIpv6 | Whether the destination address is IPv6. | Boolean-like value. |
| DestinationIp | Destination IP address. |  |
| DestinationHostname | Resolved destination hostname. | Depends on reverse lookup / DNS settings. |
| DestinationPort | Destination port number. |  |
| DestinationPortName | Service name mapped from the destination port. | Example: `https`. |

**Common Use Cases:** C2 tracing, egress review, lateral movement analysis, and mapping process-to-network behavior.

**Detection Tips:** Focus on script hosts and office apps initiating outbound connections, rare remote IPs/domains, odd ports, and repeated low-volume beacons.

---

## Event ID 4 - Sysmon Service State Changed

Records Sysmon service start/stop state. Unexpected stops or repeated restarts can indicate tampering or operational problems.

| Field Name | Description | Notes |
|------------|------------|-------|
| UtcTime | UTC timestamp when the event was generated. |  |
| State | Reported Sysmon service state. | Commonly `Started` or `Stopped`. |
| Version | Sysmon binary version. |  |
| SchemaVersion | Active Sysmon configuration schema version. |  |

**Common Use Cases:** Telemetry health monitoring, tamper detection, and change tracking after upgrades.

**Detection Tips:** Treat unexpected `Stopped` events on monitored endpoints as potentially suspicious until explained.

---

## Event ID 5 - Process Terminated

Records that a process exited and provides the core identifiers needed to close out a process timeline. In the current public schema, it does **not** include `ExitStatus`.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the process terminated. |  |
| ProcessGuid | GUID of the terminated process. | Best join key to Event ID 1. |
| ProcessId | PID of the terminated process. |  |
| Image | Full path of the terminated executable image. |  |
| User | Security context of the terminated process. |  |

**Common Use Cases:** Process lifetime measurement, short-lived malware analysis, and cleanup sequencing.

**Detection Tips:** Short-lived interpreter or LOLBin processes that appear and disappear rapidly are often worth reviewing alongside their parent process and follow-on file/network events.

---

## Event ID 6 - Driver Loaded

Records when a kernel driver is loaded, including hashes and signing information. Because driver loading is relatively rare and high-impact, it is valuable for rootkit and kernel-threat detection.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the driver load was recorded. |  |
| ImageLoaded | Full path of the loaded driver file. | Usually `.sys`. |
| Hashes | File hashes of the driver. | Based on configured algorithms. |
| Signed | Whether Sysmon considers the file signed. | Schema type is string; commonly `true`/`false`. |
| Signature | Signer name for the driver. | May be empty. |
| SignatureStatus | Signature validation status. | Validation is asynchronous. |

**Common Use Cases:** Unsigned driver hunting, EDR/AV bypass investigations, and kernel persistence analysis.

**Detection Tips:** Prioritize unsigned or unexpectedly signed third-party drivers, especially from user-writable or temporary paths.

---

## Event ID 7 - Image Loaded

Records when a module is loaded into a process. This event is disabled by default because it is noisy, but it is extremely useful for DLL injection, side-loading, and unusual module path analysis.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the image load was recorded. |  |
| ProcessGuid | GUID of the process loading the module. |  |
| ProcessId | PID of the process loading the module. |  |
| Image | Full path of the process image. | Host process. |
| ImageLoaded | Full path of the loaded module. | Often a DLL. |
| FileVersion | File version metadata of the loaded module. |  |
| Description | File description metadata. |  |
| Product | Product metadata. |  |
| Company | Company metadata. |  |
| OriginalFileName | Original file name from the PE header. | Useful when modules are renamed. |
| Hashes | File hashes of the loaded module. |  |
| Signed | Whether the module is signed. | Schema type is string. |
| Signature | Signer name for the module. |  |
| SignatureStatus | Signature validation status. | Validation is asynchronous. |
| User | Security context of the host process. |  |

**Common Use Cases:** DLL side-loading detection, unsigned DLL hunting, memory-resident implant investigations, and application trust review.

**Detection Tips:** Look for unsigned modules, modules from user-writable directories, and mismatched `OriginalFileName` values inside high-trust processes.

---

## Event ID 8 - CreateRemoteThread

Records when one process creates a thread in another process, a classic code-injection technique. `StartModule` and `StartFunction` are inferred and may be empty.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| SourceProcessGuid | GUID of the source process creating the remote thread. |  |
| SourceProcessId | PID of the source process. |  |
| SourceImage | Full path of the source process image. |  |
| TargetProcessGuid | GUID of the target process receiving the thread. |  |
| TargetProcessId | PID of the target process. |  |
| TargetImage | Full path of the target process image. |  |
| NewThreadId | Thread ID created in the target process. |  |
| StartAddress | Start address for the new thread. | Often a raw address string. |
| StartModule | Module inferred from the start address. | Can be empty or approximate. |
| StartFunction | Exported function name inferred from the start address. | Can be empty. |
| SourceUser | Security context of the source process. |  |
| TargetUser | Security context of the target process. |  |

**Common Use Cases:** Injection detection, process-hollowing workflow correlation, and post-exploitation triage.

**Detection Tips:** Rare source-target combinations are high value, especially office apps, script hosts, or browser helpers creating threads in system or security-sensitive processes.

---

## Event ID 9 - RawAccessRead

Records raw read operations against a device using `\\.\` style access. This is commonly relevant to disk imaging, locked-file access, credential theft tooling, and low-level exfiltration paths.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process performing the raw read. |  |
| ProcessId | PID of the process performing the raw read. |  |
| Image | Full path of the process image. |  |
| Device | Target device path being read. | Example: `\Device\HarddiskVolume1`. |
| User | Security context of the process. |  |

**Common Use Cases:** Disk forensics tool review, suspicious low-level access detection, and destructive or stealthy attacker tradecraft analysis.

**Detection Tips:** Non-backup, non-AV tools doing raw disk reads deserve immediate context review.

---

## Event ID 10 - ProcessAccess

Records when one process opens another process, often as a precursor to reading memory, writing memory, or querying handles. This event is especially important for LSASS access, credential theft, debugging, and injection workflows.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| SourceProcessGUID | GUID of the process opening the target process. | Field name uses uppercase `GUID` in current schema. |
| SourceProcessId | PID of the source process. |  |
| SourceThreadId | Thread ID in the source process making the call. |  |
| SourceImage | Full path of the source process image. |  |
| TargetProcessGUID | GUID of the process being opened. | Field name uses uppercase `GUID` in current schema. |
| TargetProcessId | PID of the target process. |  |
| TargetImage | Full path of the target process image. |  |
| GrantedAccess | Access mask granted/requested on the target process. | Common hunting field for LSASS access. |
| CallTrace | Stack trace / module trace associated with the open-process call. | High-value but often verbose. |
| SourceUser | Security context of the source process. |  |
| TargetUser | Security context of the target process. |  |

**Common Use Cases:** LSASS access hunting, credential theft detection, memory tampering investigations, and precision process-injection analytics.

**Detection Tips:** Review access to `lsass.exe`, `winlogon.exe`, security products, or browser processes. High-risk `GrantedAccess` values plus suspicious `CallTrace` paths are strong signals.

---

## Event ID 11 - FileCreate

Records when a file is created or overwritten. This is one of the most useful staging and persistence events in Sysmon.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process creating the file. |  |
| ProcessId | PID of the process creating the file. |  |
| Image | Full path of the process image. |  |
| TargetFilename | Full path of the created or overwritten file. |  |
| CreationUtcTime | File creation time. | UTC. |
| User | Security context of the creating process. |  |

**Common Use Cases:** Payload drop detection, webshell discovery, startup-folder monitoring, and temp-folder staging analysis.

**Detection Tips:** Focus on user-writable paths, startup locations, service paths, and executables created shortly after suspicious process or network activity.

---

## Event ID 12 - RegistryEvent (Object Create and Delete)

Records registry **key and value** create/delete activity. This event covers registry key and value create/delete operations, even though many older references simplify it to keys only. Sysmon also normalizes root key names such as `HKLM`, `HKU`, and `HKCR`.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| EventType | Specific registry action recorded under Event ID 12. | Commonly `CreateKey`, `DeleteKey`, `CreateValue`, or `DeleteValue`. |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process performing the registry action. |  |
| ProcessId | PID of the process performing the registry action. |  |
| Image | Full path of the process image. |  |
| TargetObject | Full path of the key or value that was affected. | Uses Sysmon root-key abbreviations. |
| User | Security context of the process. |  |

**Common Use Cases:** Persistence hunting in Run keys, IFEO, service configuration, COM hijack surfaces, and security-control tampering.

**Detection Tips:** Treat changes in autorun keys, IFEO, AppInit, Winlogon, Services, and Defender-related paths as higher priority than general software noise.

---

## Event ID 13 - RegistryEvent (Value Set)

Records registry value modification. The schema exposes a generic `Details` field, while official descriptions specifically call out recording written values for `DWORD` and `QWORD`. Treat `Details` as type-dependent content rather than assume perfect parity across all registry data types.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| EventType | Registry action type. | Typically `SetValue`. |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process modifying the value. |  |
| ProcessId | PID of the process modifying the value. |  |
| Image | Full path of the process image. |  |
| TargetObject | Full path of the registry value that was modified. |  |
| Details | Value data recorded for the write operation. | Content varies by registry data type. |
| User | Security context of the process. |  |

**Common Use Cases:** Security-control disablement, persistence setup, configuration tampering, and malware runtime configuration tracking.

**Detection Tips:** High-signal paths include `Run`, `RunOnce`, `Services`, `Image File Execution Options`, `Winlogon`, `LSA`, `WDigest`, and Defender policy paths.

---

## Event ID 14 - RegistryEvent (Key and Value Rename)

Records rename operations for registry keys **and values**. Older material often reduces this to `RenameKey`, but the event class covers both key and value rename operations.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| EventType | Registry rename action type. | Often seen as `RenameKey`; the event class covers key and value rename operations. |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process performing the rename. |  |
| ProcessId | PID of the process performing the rename. |  |
| Image | Full path of the process image. |  |
| TargetObject | Original full path of the key or value before rename. |  |
| NewName | New key/value name or new full path, depending on renderer/parser. | Parser output can vary slightly. |
| User | Security context of the process. |  |

**Common Use Cases:** Stealthy persistence renaming, evasion, cleanup, and registry object relocation analysis.

**Detection Tips:** Registry renames are relatively uncommon. Any rename in persistence or security-sensitive paths is worth immediate review.

---

## Event ID 15 - FileCreateStreamHash

Records creation of a named file stream and hashes associated with stream creation. It is especially useful for alternate data streams and browser-attached `Zone.Identifier` Mark-of-the-Web behavior. In current schema, this event includes `Contents`, a field older cheat sheets often omit.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process creating the stream. |  |
| ProcessId | PID of the process creating the stream. |  |
| Image | Full path of the process image. |  |
| TargetFilename | Full path of the file associated with the stream. | Often the host file for the ADS. |
| CreationUtcTime | File creation timestamp associated with the event. | UTC. |
| Hash | Hash data recorded for the stream event. | Field name is singular `Hash`, not `Hashes`. |
| Contents | Captured text-stream contents when available. | Often useful for MOTW-related text streams; version-specific in older releases. |
| User | Security context of the process. |  |

**Common Use Cases:** MOTW visibility, browser-download provenance, ADS abuse detection, and suspicious alternate stream triage.

**Detection Tips:** Prioritize stream activity on executables, scripts, archives, or files that later execute, especially when the stream implies internet origin.

---

## Event ID 16 - ServiceConfigurationChange

Records changes to the Sysmon configuration. In the current public schema, this event contains only three fields and no `RuleName`.

| Field Name | Description | Notes |
|------------|------------|-------|
| UtcTime | UTC timestamp when the configuration change was recorded. |  |
| Configuration | The configuration content or update payload recorded by Sysmon. | Exact rendering depends on change method and parser. |
| ConfigurationFileHash | Hash of the configuration file applied. | Often rendered as a single hash string. |

**Common Use Cases:** Telemetry governance, configuration drift tracking, and tamper investigation.

**Detection Tips:** Investigate unexpected config changes, especially those followed by drops in event volume or disabled high-value event types.

---

## Event ID 17 - PipeEvent (Pipe Created)

Records creation of a named pipe. Named pipes are common in legitimate IPC but also heavily used by malware and offensive tooling.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| EventType | Pipe action type. | Typically `CreatePipe`. |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process creating the pipe. |  |
| ProcessId | PID of the process creating the pipe. |  |
| PipeName | Name/path of the named pipe. | High-value hunting field. |
| Image | Full path of the process image. |  |
| User | Security context of the process. |  |

**Common Use Cases:** C2 framework IPC detection, service abuse review, and malware component coordination analysis.

**Detection Tips:** Investigate random-looking, short-lived, or tooling-associated pipe names created by unusual processes.

---

## Event ID 18 - PipeEvent (Pipe Connected)

Records connection to a named pipe between a client and server. This complements Event ID 17 and is often more valuable when correlated as a pair.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| EventType | Pipe action type. | Typically `ConnectPipe`. |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process making the pipe connection. |  |
| ProcessId | PID of the process making the pipe connection. |  |
| PipeName | Name/path of the named pipe connected to. |  |
| Image | Full path of the process image. |  |
| User | Security context of the process. |  |

**Common Use Cases:** IPC flow analysis, multi-process malware tracing, and suspicious client-server coordination detection.

**Detection Tips:** Correlate pipe create/connect events by `PipeName` and time proximity, then pivot to the associated processes.

---

## Event ID 19 - WmiEvent (WmiEventFilter activity detected)

Records creation or modification activity related to WMI event filters, a common building block of permanent WMI event subscription persistence.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| EventType | WMI action class for this event. | Commonly `WmiFilterEvent`. |
| UtcTime | UTC timestamp when the event was generated. |  |
| Operation | Operation performed on the WMI filter. | Exact values vary by activity. |
| User | Security context responsible for the operation. |  |
| EventNamespace | WMI namespace in which the filter exists. | Example: `root\subscription`. |
| Name | Name of the WMI event filter. |  |
| Query | WQL query tied to the filter. | High-value analytic field. |

**Common Use Cases:** Permanent WMI subscription hunting, fileless persistence investigations, and suspicious WQL filter review.

**Detection Tips:** Filters in `root\subscription` that watch startup, logon, or timed conditions deserve careful review.

---

## Event ID 20 - WmiEvent (WmiEventConsumer activity detected)

Records activity related to WMI consumers, the execution side of permanent WMI event subscription abuse.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| EventType | WMI action class for this event. | Commonly `WmiConsumerEvent`. |
| UtcTime | UTC timestamp when the event was generated. |  |
| Operation | Operation performed on the WMI consumer. | Exact values vary by activity. |
| User | Security context responsible for the operation. |  |
| Name | Consumer name. |  |
| Type | Consumer type. | Example: command, script, log, or similar consumer type. |
| Destination | Execution or output target associated with the consumer. | Semantics depend on consumer type. |

**Common Use Cases:** Fileless persistence, hidden execution chains, and malicious automation review.

**Detection Tips:** Command/script consumers are especially high-value when they launch interpreters or reference network/temporary paths.

---

## Event ID 21 - WmiEvent (WmiEventConsumerToFilter activity detected)

Records the binding of a WMI consumer to a WMI filter. This completes the permanent WMI subscription chain.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| EventType | WMI action class for this event. | Commonly `WmiBindingEvent`. |
| UtcTime | UTC timestamp when the event was generated. |  |
| Operation | Operation performed on the binding. | Exact values vary by activity. |
| User | Security context responsible for the operation. |  |
| Consumer | Consumer path/name being bound. |  |
| Filter | Filter path/name being bound. |  |

**Common Use Cases:** Complete WMI persistence reconstruction and detection of stealthy, fileless execution chains.

**Detection Tips:** Event IDs 19-21 should almost always be reviewed together rather than in isolation.

---

## Event ID 22 - DNSEvent (DNS Query)

Records DNS queries issued by a process, whether successful or not. This telemetry is available for Windows 8.1 and later, not Windows 7 and earlier.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the querying process. |  |
| ProcessId | PID of the querying process. |  |
| QueryName | DNS name queried. | High-value field for infra hunting. |
| QueryStatus | DNS status/result code. | Success/failure code string. |
| QueryResults | Returned result data. | Can contain multiple results. |
| Image | Full path of the querying process image. |  |
| User | Security context of the querying process. |  |

**Common Use Cases:** Infrastructure discovery, DGA hunting, beacon detection, and enrichment of encrypted-network investigations.

**Detection Tips:** Look for rare domains, high-entropy subdomains, frequent TXT lookups, or DNS activity from processes that should not resolve external names.

---

## Event ID 23 - FileDelete (File Delete archived)

Records file deletion and also archives the deleted file. This is the archived counterpart to Event ID 26.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process deleting the file. |  |
| ProcessId | PID of the process deleting the file. |  |
| User | Security context of the deleting process. |  |
| Image | Full path of the deleting process image. |  |
| TargetFilename | Full path of the deleted file. |  |
| Hashes | File hashes of the deleted file. | Based on configured algorithms. |
| IsExecutable | Whether Sysmon identified the file as executable/PE-like. | Boolean-like value. |
| Archived | Archive status for the deleted file. | Schema type is string, not strict boolean. |

**Common Use Cases:** Ransomware triage, attacker cleanup reconstruction, and preservation of deleted malware artifacts.

**Detection Tips:** Mass deletions, security-tool deletions, or deletes immediately following suspicious execution or network activity deserve fast review.

---

## Event ID 24 - ClipboardChange (New Content in the Clipboard)

Records clipboard content changes. This capability captures text clipboard data that can be archived and referenced by hash.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process that wrote to the clipboard. |  |
| ProcessId | PID of the process that wrote to the clipboard. |  |
| Image | Full path of the process image. |  |
| Session | Terminal/session ID associated with the clipboard action. |  |
| ClientInfo | Client username/hostname context if capturable. | Often useful for RDP scenarios. |
| Hashes | Hash of the captured clipboard data artifact. | Often maps to archived content. |
| Archived | Archive status for captured clipboard content. | Schema type is string. |
| User | Security context of the process. |  |

**Common Use Cases:** Data theft monitoring, credential-copy detection, RDP investigation, and sensitive text exfiltration review.

**Detection Tips:** Clipboard activity from `powershell.exe`, offensive tooling, or suspicious remote-session contexts can be high signal. Deploy carefully because clipboard monitoring has privacy implications.

---

## Event ID 25 - ProcessTampering (Process Image Change)

Records detection of advanced process image manipulation techniques such as **process hollowing** and **herpaderping**.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the tampered process. |  |
| ProcessId | PID of the tampered process. |  |
| Image | Full path of the process image as reported by Sysmon. |  |
| Type | Tampering category detected by Sysmon. | Public docs do not publish a complete stable enumeration of values. |
| User | Security context of the affected process. |  |

**Common Use Cases:** Advanced malware detection, injection workflow analysis, and stealth execution investigations.

**Detection Tips:** This event is rare enough that most occurrences merit immediate investigation, especially when paired with Event IDs 1, 8, and 10.

---

## Event ID 26 - FileDeleteDetected (File Delete Logged)

Records file deletion without archiving the deleted content. This is the lighter-weight counterpart to Event ID 23.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the event was generated. |  |
| ProcessGuid | GUID of the process deleting the file. |  |
| ProcessId | PID of the process deleting the file. |  |
| User | Security context of the deleting process. |  |
| Image | Full path of the deleting process image. |  |
| TargetFilename | Full path of the deleted file. |  |
| Hashes | File hashes of the deleted file. | Based on configured algorithms. |
| IsExecutable | Whether the deleted file was considered executable/PE-like. | Boolean-like value. |

**Common Use Cases:** Ransomware cleanup detection, large-scale deletion analytics, and deletion telemetry when full archiving is too expensive.

**Detection Tips:** Watch for sudden spikes from a single process or user context, especially in documents, temp folders, admin shares, or security-tool directories.

---

## Event ID 27 - FileBlockExecutable

Records when Sysmon **detects and blocks** creation of a new executable (PE-format) file. This is a preventive capability, not merely observational.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the block event was generated. |  |
| ProcessGuid | GUID of the process attempting to create the executable. |  |
| ProcessId | PID of the process attempting to create the executable. |  |
| User | Security context of the process. |  |
| Image | Full path of the process image. |  |
| TargetFilename | Full path of the executable file whose creation was blocked. |  |
| Hashes | Hashes of the blocked executable content. |  |

**Common Use Cases:** Blocking PE drops into downloads, temp, email-attachment, or browser-staging locations.

**Detection Tips:** Use sparingly and intentionally. Blocking PE creation in user-writable directories can be powerful, but allow-listing for software updates and installers is essential.

---

## Event ID 28 - FileBlockShredding

Records when Sysmon detects and blocks file shredding activity such as secure-delete style overwrites. This is another preventive capability rather than a passive log.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the block event was generated. |  |
| ProcessGuid | GUID of the process attempting to shred the file. |  |
| ProcessId | PID of the process attempting to shred the file. |  |
| User | Security context of the process. |  |
| Image | Full path of the process image. |  |
| TargetFilename | Full path of the file targeted for shredding. |  |
| Hashes | Hashes of the targeted file content as recorded by Sysmon. |  |
| IsExecutable | Whether the targeted file was considered executable/PE-like. | Boolean-like value. |

**Common Use Cases:** Anti-cleanup enforcement, ransomware or destructive tooling prevention, and secure-delete abuse detection.

**Detection Tips:** Any shredding attempt by administrative tools, scripts, or utilities on endpoints that do not legitimately use secure deletion is suspicious.

---

## Event ID 29 - FileExecutableDetected

Records creation of a new executable (PE-format) file **without blocking it**. This is the non-blocking counterpart to Event ID 27.

| Field Name | Description | Notes |
|------------|------------|-------|
| RuleName | Matching Sysmon rule name/tag. |  |
| UtcTime | UTC timestamp when the detection event was generated. |  |
| ProcessGuid | GUID of the process that created the executable. |  |
| ProcessId | PID of the process that created the executable. |  |
| User | Security context of the process. |  |
| Image | Full path of the process image. |  |
| TargetFilename | Full path of the created executable file. |  |
| Hashes | Hashes of the created executable content. |  |

**Common Use Cases:** PE drop visibility without prevention, executable-staging hunts, and controlled environments where blocking is too disruptive.

**Detection Tips:** New executables in user profiles, temp folders, removable media, archive-extract directories, or browser download locations are high-value pivots.

---

## Event ID 255 - Error

Records an internal Sysmon error. These events matter operationally because they can signal lost visibility, resource exhaustion, or outright bugs.

| Field Name | Description | Notes |
|------------|------------|-------|
| UtcTime | UTC timestamp when the error was recorded. |  |
| ID | Error code or identifier. | Treat as opaque unless mapped to known issue context. |
| Description | Error description text. | Primary field for triage. |

**Common Use Cases:** Telemetry quality monitoring, troubleshooting dropped events, and validating Sysmon health after upgrades or config changes.

**Detection Tips:** Repeated Event ID 255 activity should be escalated to telemetry engineering because it can silently reduce detection coverage.

---

# Cross-Event Detection Notes

Sysmon is most powerful when events are correlated into behavior chains rather than treated as isolated alerts.

A practical high-value chain often looks like:
- **Event 1** (execution)
- **Event 22** (DNS)
- **Event 3** (network)
- **Event 11 / 15 / 29** (file staging)
- **Event 12-14** (persistence)
- **Event 8 / 10 / 25** (injection or tampering)

For SOC and threat hunting use, the events that usually provide the best return on effort are **1, 3, 10, 11, 12-15, 22, 23/26, 24, 25, and 29**, with **6, 8, 17-21, 27, and 28** being highly valuable in more targeted or mature deployments.
