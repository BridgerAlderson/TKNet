# Opening SMB shares in Dolphin

On Linux, enter the account under **Settings** in **SMB authentication**. Double-click a disk share in the **SMB shares** tab or choose **Open in file manager** from the share's context menu. Opening a host takes you to the server root. Opening a share takes you to its directory.

| Credentials at the time of opening | File manager behavior |
| --- | --- |
| Username and password | TKNet sends the current account, optional domain, and password to Dolphin through the desktop session bus. |
| Username with NTLM hash mode enabled | TKNet supplies the username and optional domain. Dolphin can use a saved session or prompt for a password. The hash stays with the scanner. |
| No username | TKNet opens the location using the desktop file manager's session. |
| Windows | Explorer uses the current Windows session. |

Authenticated opening requires a system installation of Dolphin, KIO SMB support, and a running desktop session bus. If the handoff fails, TKNet displays the error.

## How the handoff works

TKNet encodes the server, share, and account into a location Dolphin can open. It reuses a responsive Dolphin window or starts one in a local directory. Before delivering the SMB location, it checks the identity of the executable behind the D-Bus connection against the installed Dolphin executable. It sends one `openDirectories` request to the verified window. The startup wait has a timeout and ends when the application closes. [Dolphin window interface](https://github.com/KDE/dolphin/blob/master/src/dolphinmainwindow.h)

Only the network path appears in TKNet's log, status text, and clipboard links. When TKNet starts Dolphin, its command line contains a local directory. The credential-bearing location travels in memory on the desktop bus. Dolphin and KIO manage their own session history and credential storage.

## Interpreting access errors

A successful D-Bus reply means Dolphin received the location. Dolphin and KIO then contact the server and display the result. A share can appear in the inventory even when the account cannot open its root.

The scanner sends its credentials to the engine over standard input. Within an authenticated SMB session, denial of a share permission does not trigger a new login with the configured account. Opening a location in Dolphin is a separate user action. The server or domain controls account lockout policy. [Reading SMB scan results](SMB_REPORT_REVIEW.md)
