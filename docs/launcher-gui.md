# Launcher GUI (Alpha)

The launcher is a native Windows Forms operator console for the repository's
existing local and profile runners. It is intentionally labeled **alpha / partial
validation**. The PowerShell policy and worker layers have local automated
coverage, but the actual form has not been exercised on a Windows host in the
current validation environment.

## Prerequisites

- Windows 10/11 or Windows Server with Desktop Experience
- Windows PowerShell 5.1 with .NET Framework 4.8
- An elevated process for Remediate mode
- Script-specific Windows features and permissions

PowerShell 7 is an intended launcher runtime and remains part of the Windows
release gate.

Start from the repository root:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\tools\Launcher-GUI.ps1
```

## Operator workflow

The environment row validates the kit root and discovers numbered operational
scripts on a background task so the form remains responsive. `00-*`
orchestration entry points are not shown as selectable tasks.

Use **Run script** to filter by number, filename, task, or synopsis. Select a
script, review its supported modes, and enter only script-specific advanced
arguments. The launcher rejects mode, root, target, output, confirmation, and
integrity overrides. It accepts quoted values and literal `$true`/`$false`
boolean syntax; executable PowerShell syntax is rejected.

Use **Run profile** to select and validate profile JSON before execution. The
launcher displays profile name, version, default mode, integrity summary, steps,
and dependencies. The selected GUI mode remains authoritative; profile settings
may strengthen strict/signature policy but cannot silently select remediation.

Audit is the default. Remediate is disabled when the launcher is not elevated.
Before remediation starts, a native confirmation dialog shows the target,
computer, effective arguments, and integrity policy. Declining starts nothing.

## Results, stop, and recovery

Each run starts a child of the current PowerShell executable through an internal
schema-versioned JSON manifest. User-controlled runner values are not interpolated
into a command string. Normal, information, warning, and error streams are
captured, and the process exit maps to one result:

- exit `0`: Completed
- exit `2`: Completed with warnings
- exit `1` or another exit: Failed
- explicitly terminated worker: Stopped

`Stop run` terminates the worker; it does not undo changes. After stopping
remediation, rerun Audit to establish final endpoint state. Closing during an
active run defaults to keeping the window open and requires an explicit stop
request before close.

The live view retains the latest 10,000 lines and drains a bounded 5,000-line
pending queue. A user-scoped temporary full log is capped at 25 MiB. `Clear view`
does not delete it; `Save captured output` copies the capped log to a chosen
path. The saved file may therefore contain a truncation marker rather than every
line from runs exceeding 25 MiB. Exported logs may contain sensitive endpoint
evidence and should be reviewed before sharing.

## Validation status

Local checks cover parsing, argument and manifest policy, worker stream capture,
exit mapping, runner compatibility, fuzz tests, and secret scanning. This is not
equivalent to a Windows UI release gate.

Before production readiness can be claimed, validate Windows PowerShell 5.1 and
PowerShell 7 happy paths, remediation without unsupported host prompts,
keyboard-only navigation, Accessibility Insights FastPass, Inspect/UIA,
Narrator, visible focus, High Contrast, 100%, 150%, and 200% scaling, long paths,
minimum window size, every terminal state, close protection, and high-volume
output responsiveness. Publish a screenshot only after a real Windows capture
passes that checklist.
