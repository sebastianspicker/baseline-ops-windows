# Windows Forms launcher

`tools/Launcher-GUI.ps1` provides an optional Windows Forms interface for
operators who want to run one numbered script or one orchestration profile. It
sends each run through `tools/Launcher-Worker.ps1` and uses the policy and
process helpers in `tools/Launcher.Core.psm1`.

The command-line runners remain the full interface. The launcher does not offer
batch execution or `-WhatIf`.

## Requirements

- Windows with Windows Forms
- Windows PowerShell 5.1 and .NET Framework 4.8, or PowerShell 7.6.3
- Endpoint features and permissions required by the selected script
- Elevation to select Remediate mode

Automated tests cover launcher policy, worker manifests, argument parsing,
stream bounds, output capture, exit mapping, and process-tree termination. They
do not verify the interactive form. Before deployment, manually test keyboard
navigation, UI Automation, screen readers, High Contrast, scaling, minimum
size, long paths, and live endpoint remediation.

## Start the launcher

Before elevating the launcher, install authenticated release files in a
protected directory. A user-owned Git checkout or Downloads extraction is not a
safe root for elevated execution.

From the protected directory, start the Windows PowerShell 5.1 version with:

```powershell
$ProgramFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$KitRoot = Join-Path $ProgramFiles 'BaselineOpsForWindows-v2.3.0-alpha.1'
Set-Location -LiteralPath $KitRoot
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Launcher-GUI.ps1
```

For PowerShell 7.6.3, use:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -Command `
  "if (`$PSVersionTable.PSVersion.ToString() -cne '7.6.3') { throw 'PowerShell 7.6.3 is required.' }; & .\tools\Launcher-GUI.ps1"
```

An elevated launcher enables `Require valid signature` by default. Repository
source files are unsigned and will be rejected with this setting. Sign the
deployment scripts according to the applicable trust policy. Clear the setting
only in an isolated lab after reviewing the source. Clearing it does not bypass
the protected-path checks.

## Run a script

1. Confirm the toolkit root.
2. Select `Run script`.
3. Filter by script number, filename, task, or synopsis.
4. Select a numbered script and review its supported modes.
5. Enter only script-specific advanced arguments.
6. Review mode, target, arguments, and integrity policy.
7. Start the run.

The selection list contains numbered capabilities only; it excludes all `00-*`
control scripts. Advanced arguments cannot override the mode, toolkit root,
target, output, confirmation, signature, or hash policy. Quoted values and the
literals `$true` and `$false` are accepted. Executable PowerShell syntax is
rejected.

Audit is the default mode. An audit can still write evidence when the selected
script collects or exports data.

## Run a profile

1. Select `Run profile`.
2. Choose a profile JSON file.
3. Review its name, version, default mode, signature policy, steps, and dependencies.
4. Select the effective GUI mode.
5. Confirm remediation if Remediate mode is selected.

The launcher validates the profile before execution. Profile settings may
enable strict handling or require signatures, but only the operator's GUI
selection can enable remediation.

The launcher has no preview control. To check profile control flow without
running child scripts, close the launcher and use the command-line profile
runner:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 `
  -ProfilePath .\examples\profiles\hardening-remediate.json `
  -RootPath $KitRoot -Mode Remediate -Strict -OutputFormat None `
  -WhatIf -Confirm:$false
```

## Output and process control

Each run starts a child process from the current PowerShell executable. A
schema-versioned JSON manifest passes runner values as data; values are never
interpolated into a command string.

The launcher maps process results as follows:

| Process result | Launcher state |
| --- | --- |
| Exit `0` | Completed |
| Exit `2` | Completed with warnings |
| Exit `1` or another code | Failed |
| Worker terminated by `Stop run` | Stopped |

`Stop run` terminates the entire worker process tree. Any endpoint changes that
finished before termination remain in place. After stopping remediation, run
the matching audit to determine the endpoint's current state.

The live view keeps the latest 10,000 lines and has a bounded 5,000-line pending
queue. The temporary full log is limited to 25 MiB. Buffered output is flushed
every 250 ms or after 64 KiB. It is also flushed when output is saved, the run
finishes, or the collector closes. `Clear view` clears only the display; it does
not delete the temporary log. `Save captured output` copies that log to a path
selected by the operator. If the log was truncated, the saved file includes a
truncation marker.

Temporary logs are stored under `%TEMP%\baselineops-windows-launcher`. Before a
new run, the launcher removes the previous temporary log. It also attempts to
clean up when the form closes normally, but files can remain after a crash.
Saved output remains until the operator removes it.

## Manual validation checklist

Before deployment, test the actual form under every PowerShell host used in the
target environment:

- Audit and remediation on a disposable Windows endpoint
- Keyboard-only operation and visible focus
- Inspect or another UI Automation client
- Narrator or the deployed screen reader
- High Contrast
- 100%, 150%, and 200% display scaling
- Minimum window size and long paths
- Completed, warning, failed, stopped, and close-protection states
- High-volume output and UI responsiveness
- Cleanup and review of temporary and saved logs

Automated worker tests do not show that any of these interactive checks passed.
