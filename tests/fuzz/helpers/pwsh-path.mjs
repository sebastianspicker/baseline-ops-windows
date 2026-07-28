// Resolves an installed PowerShell executable for fuzz tests without launching
// through a relative PATH lookup. Explicit overrides must be absolute.
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { posix, win32 } from 'node:path';
import process from 'node:process';

function getPlatformCandidates(platform, environment) {
  switch (platform) {
    case 'darwin':
      return ['/opt/homebrew/bin/pwsh', '/usr/local/bin/pwsh'];
    case 'linux':
      return ['/usr/bin/pwsh', '/opt/microsoft/powershell/7/pwsh'];
    case 'win32': {
      const programFiles = environment.ProgramFiles || 'C:\\Program Files';
      const localAppData = environment.LOCALAPPDATA;
      const candidates = [win32.join(programFiles, 'PowerShell', '7', 'pwsh.exe')];
      if (localAppData) {
        candidates.push(win32.join(localAppData, 'Microsoft', 'WindowsApps', 'pwsh.exe'));
      }
      return candidates;
    }
    default:
      throw new Error(`Unsupported platform for PowerShell: ${platform}`);
  }
}

function getTrustedWindowsRoots(environment) {
  const programFiles = environment.ProgramFiles || 'C:\\Program Files';
  return ['PowerShell', 'WindowsApps'].map(
    (directory) => `${win32.resolve(programFiles, directory).toLowerCase()}\\`
  );
}

function findWindowsWhereExecutable(environment, executableExists) {
  try {
    const windowsRoot = environment.SystemRoot || 'C:\\Windows';
    const whereExecutable = win32.join(windowsRoot, 'System32', 'where.exe');
    const trustedRoots = getTrustedWindowsRoots(environment);
    return execFileSync(whereExecutable, ['pwsh'], { encoding: 'utf8', windowsHide: true })
      .split(/\r?\n/)
      .filter(Boolean)
      .filter((candidate) => win32.isAbsolute(candidate) && executableExists(candidate))
      .find((candidate) => {
        const normalized = win32.resolve(candidate).toLowerCase();
        return trustedRoots.some((root) => normalized.startsWith(root));
      });
  } catch {
    return undefined;
  }
}

export function resolvePwshBinary({
  platform = process.platform,
  override = process.env.PWSH_BIN,
  environment = process.env,
  executableExists = existsSync
} = {}) {
  if (override) {
    const path = platform === 'win32' ? win32 : posix;
    if (!path.isAbsolute(override)) {
      throw new Error('PWSH_BIN must be an absolute executable path');
    }
    return override;
  }

  let executable = getPlatformCandidates(platform, environment)
    .find((candidate) => executableExists(candidate));
  if (!executable && platform === 'win32') {
    executable = findWindowsWhereExecutable(environment, executableExists);
  }
  if (!executable) {
    throw new Error(
      `PowerShell was not found in the supported ${platform} installation locations; set PWSH_BIN to an absolute path`
    );
  }
  return executable;
}
