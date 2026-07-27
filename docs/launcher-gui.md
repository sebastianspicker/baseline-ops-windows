# Windows Forms launcher

`tools/Launcher-GUI.ps1` is an optional Windows Forms interface for running one numbered script or one orchestration profile. It launches work through `tools/Launcher-Worker.ps1` and uses policy and process helpers from `tools/Launcher.Core.psm1`.

The launcher does not replace the command-line runners. It does not expose batch execution or `-WhatIf`.

## Requirements

- Windows with Windows Forms
- Windows PowerShell 5.1 and .NET Framework 4.8, or PowerShell 7.6.3
- Endpoint features and permissions required by the selected script
- Elevation to select Remediate mode

Automated tests cover launcher policy, worker manifests, argument parsing, stream bounds, output capture, exit mapping, and process-tree termination. The interactive form still requires manual testing for keyboard navigation, UI Automation, screen readers, High Contrast, scaling, minimum size, long paths, and live endpoint remediation.

## Start the launcher

Do not start an elevated launcher from a user-owned Git checkout or Downloads extraction. Install authenticated release files in a protected directory first.

Start the Windows PowerShell 5.1 path from that directory:

```powershell
$ProgramFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$KitRoot = Join-Path $ProgramFiles 'BaselineOpsForWindows-v2.3.0-alpha.1'
Set-Location -LiteralPath $KitRoot
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Launcher-GUI.ps1
```

Start the PowerShell 7.6.3 path:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -Command `
  "if (`$PSVersionTable.PSVersion.ToString() -cne '7.6.3') { throw 'PowerShell 7.6.3 is required.' }; & .\tools\Launcher-GUI.ps1"
```

When elevated, the launcher enables `Require valid signature` by default. The repository source files are unsigned, so the default rejects them. Sign deployment scripts under the applicable trust policy. Clearing the requirement is suitable only for an isolated lab after source review and does not bypass protected-path checks.

## Run a script

1. Confirm the toolkit root.
2. Select `Run script`.
3. Filter by script number, filename, task, or synopsis.
4. Select a numbered script and review its supported modes.
5. Enter only script-specific advanced arguments.
6. Review mode, target, arguments, and integrity policy.
7. Start the run.

The launcher excludes `00-*` control scripts from the selectable list. It rejects advanced arguments that try to override mode, toolkit root, target, output, confirmation, signature, or hash policy. It accepts quoted argument values and literal `$true` or `$false` values, but rejects executable PowerShell syntax.

Audit is the default. Audit can still write evidence when the selected script collects or exports data.

## Run a profile

1. Select `Run profile`.
2. Choose a profile JSON file.
3. Review its name, version, default mode, signature policy, steps, and dependencies.
4. Select the effective GUI mode.
5. Confirm remediation if Remediate mode is selected.

The profile is validated before execution. Its settings may enable strict handling or signature requirements, but cannot select remediation without the operator's GUI selection.

For a no-child-execution preview, close the launcher and use the command-line profile runner:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 `
  -ProfilePath .\examples\profiles\hardening-remediate.json `
  -RootPath $KitRoot -Mode Remediate -Strict -OutputFormat None `
  -WhatIf -Confirm:$false
```

## Output and process control

Each run starts a child of the current PowerShell executable using a schema-versioned JSON manifest. Runner values are passed as data, not interpolated into a command string.

The launcher maps process results as follows:

| Process result | Launcher state |
| --- | --- |
| Exit `0` | Completed |
| Exit `2` | Completed with warnings |
| Exit `1` or another code | Failed |
| Worker terminated by `Stop run` | Stopped |

`Stop run` terminates the worker process tree. It does not roll back changes already completed by an endpoint script. Run the corresponding audit after stopping remediation to determine current state.

The live view retains the latest 10,000 lines and uses a bounded 5,000-line pending queue. The temporary full log is limited to 25 MiB. `Clear view` clears the display but does not remove that log. `Save captured output` copies the temporary log to a selected path, and a truncated log contains a truncation marker.

Temporary logs are stored under `%TEMP%\baselineops-windows-launcher`. The launcher removes the previous temporary log before a run and attempts cleanup on normal close. Files can remain after a crash. Saved output remains until the operator removes it.

## Manual validation checklist

Before approving the launcher for an environment, test the actual form under each deployed PowerShell host:

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

Do not treat the automated worker tests as evidence that these interactive checks passed.
