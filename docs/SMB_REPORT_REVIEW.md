# Reading an SMB inspection report

Choose **Export SMB report (JSON)** under **Settings** in **SMB inspection**. When two scans return different share totals, first compare TCP reachability for the same IPs, then check whether each server finished listing shares for the same account. A server can give Guest a different view. For hosts with complete listings in both scans, compare share names by IP.

The top-level `Completed` field describes the scan as a whole. Each host has an `EnumerationStatus` describing its share list.

| Enumeration status | Meaning |
| --- | --- |
| `Complete` | The server returned the last page of shares visible to the session. |
| `Partial` | Listing stopped after one or more names had been returned. The report retains those names. |
| `Failed` | Enumeration failed before any share names were recovered. The error records the reason. |
| `Not attempted` | The scan did not reach share enumeration, or the user selected a port-only check. |

## Share type and root permissions

`ShareType` preserves the type reported by the server. TKNet checks file access for disk shares, including a `print$` driver share reported as a disk. Printer queues, devices and IPC resources have no file access checks. TKNet filters the special `IPC$` name from the list. [Microsoft SHARE_INFO_1](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_1)

`ReadCheck` and `WriteCheck` describe separate operations. If the server denies mounting the share, both checks are marked denied. If the mount succeeds but the account cannot list the root, the share stays in the report and the write check remains untested.

After a successful root listing, the write check attempts to create a new temporary file, then close and remove it. A successful creation establishes write access at the root. If cleanup fails, the report includes a warning with the file name. Permissions can differ in subdirectories.

## Connections and incomplete results

The inspection connects directly to TCP port 445. Before authentication starts, transient connection errors allow up to three connection attempts. After that pass, addresses still eligible for recovery receive one final attempt using up to eight workers, bounded by the selected thread count. The configured TCP timeout applies to each attempt. A successful connection is used for the SMB session.

Each IP contributes one final record. `ConnectionAttempts` and `ConnectionErrors` cover both passes. `ConnectionRecoveryAttempted` indicates that the address received a final attempt. These fields help explain why recovery may add time when many connections time out.

The scanner attempts the configured account at most once per target for SMB authentication. A separate Guest session, if used, appears in the report. An access denial on a share does not resubmit the account.

When the server reports that the `srvsvc` pipe is temporarily unavailable or busy, TKNet retries opening the pipe in the same authenticated session and IPC tree. The three eligible statuses are `STATUS_INSTANCE_NOT_AVAILABLE`, `STATUS_PIPE_NOT_AVAILABLE`, and `STATUS_PIPE_BUSY`. There are up to four opens, with cancellable waits of 250, 500, and 1,000 milliseconds. Once enumeration begins, an error on a later page preserves the earlier results. [Microsoft named-pipe status codes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/8f11e0f3-d545-46cc-97e6-f00569e3e1bc)

## Host information and exports

Under **Settings**, SMB inspection can resolve a hostname after the SMB session closes. Optional SNMP queries can add device information, and Windows clients can query WMI for operating system details. A missing name or metadata warning leaves the share list available.

Reports contain server addresses, share names, and access results. The exported settings omit account credentials and the SNMP community. [Release verification](RELEASE_READINESS.md)
