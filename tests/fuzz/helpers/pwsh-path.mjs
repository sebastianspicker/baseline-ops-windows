import { posix, win32 } from 'node:path';
import process from 'node:process';

export function resolvePwshBinary({
  platform = process.platform,
  override = process.env.PWSH_BIN
} = {}) {
  if (override) {
    const path = platform === 'win32' ? win32 : posix;
    if (!path.isAbsolute(override)) {
      throw new Error('PWSH_BIN must be an absolute executable path');
    }
    return override;
  }

  switch (platform) {
    case 'darwin':
      return '/usr/local/bin/pwsh';
    case 'linux':
      return '/usr/bin/pwsh';
    case 'win32':
      return 'C:\\Program Files\\PowerShell\\7\\pwsh.exe';
    default:
      throw new Error(`Unsupported platform for PowerShell: ${platform}`);
  }
}
