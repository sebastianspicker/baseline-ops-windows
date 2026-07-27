// Verifies supported installation discovery and prevents ambiguous relative
// PATH-based PowerShell resolution.
import assert from 'node:assert/strict';
import test from 'node:test';

import { resolvePwshBinary } from './helpers/pwsh-path.mjs';

test('PowerShell resolver chooses an existing absolute installation path', () => {
  const only = (expected) => (candidate) => candidate === expected;
  assert.equal(
    resolvePwshBinary({
      platform: 'darwin',
      override: '',
      executableExists: only('/usr/local/bin/pwsh')
    }),
    '/usr/local/bin/pwsh'
  );
  assert.equal(
    resolvePwshBinary({
      platform: 'linux',
      override: '',
      executableExists: only('/opt/microsoft/powershell/7/pwsh')
    }),
    '/opt/microsoft/powershell/7/pwsh'
  );
  assert.equal(
    resolvePwshBinary({
      platform: 'win32',
      override: '',
      environment: { ProgramFiles: 'D:\\Programs', LOCALAPPDATA: 'C:\\Users\\tester\\AppData\\Local' },
      executableExists: only('C:\\Users\\tester\\AppData\\Local\\Microsoft\\WindowsApps\\pwsh.exe')
    }),
    'C:\\Users\\tester\\AppData\\Local\\Microsoft\\WindowsApps\\pwsh.exe'
  );
});

test('PowerShell resolver accepts only absolute overrides', () => {
  assert.equal(
    resolvePwshBinary({ platform: 'linux', override: '/opt/powershell/pwsh' }),
    '/opt/powershell/pwsh'
  );
  assert.equal(
    resolvePwshBinary({ platform: 'win32', override: 'D:\\PowerShell\\pwsh.exe' }),
    'D:\\PowerShell\\pwsh.exe'
  );
  assert.throws(
    () => resolvePwshBinary({ platform: 'linux', override: 'pwsh' }),
    /PWSH_BIN must be an absolute executable path/
  );
});

test('PowerShell resolver fails clearly on an unsupported platform', () => {
  assert.throws(
    () => resolvePwshBinary({ platform: 'aix', override: '' }),
    /Unsupported platform for PowerShell: aix/
  );
});

test('PowerShell resolver fails clearly when no supported installation exists', () => {
  assert.throws(
    () => resolvePwshBinary({ platform: 'linux', override: '', executableExists: () => false }),
    /PowerShell was not found.*set PWSH_BIN/
  );
});
