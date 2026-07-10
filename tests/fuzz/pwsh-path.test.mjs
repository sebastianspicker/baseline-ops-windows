import assert from 'node:assert/strict';
import test from 'node:test';

import { resolvePwshBinary } from './helpers/pwsh-path.mjs';

test('PowerShell resolver uses fixed absolute platform defaults', () => {
  assert.equal(resolvePwshBinary({ platform: 'darwin', override: '' }), '/usr/local/bin/pwsh');
  assert.equal(resolvePwshBinary({ platform: 'linux', override: '' }), '/usr/bin/pwsh');
  assert.equal(
    resolvePwshBinary({ platform: 'win32', override: '' }),
    'C:\\Program Files\\PowerShell\\7\\pwsh.exe'
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
