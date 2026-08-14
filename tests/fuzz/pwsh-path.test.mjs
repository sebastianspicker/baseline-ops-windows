// Verifies supported installation discovery and prevents ambiguous relative
// PATH-based PowerShell resolution.
import assert from 'node:assert/strict';
import test from 'node:test';

import { resolvePwshBinary } from './helpers/pwsh-path.mjs';

test('PowerShell resolver chooses an existing absolute installation path', () => {
  const installationCases = [
    {
      options: { platform: 'darwin', override: '' },
      expected: '/usr/local/bin/pwsh'
    },
    {
      options: { platform: 'linux', override: '' },
      expected: '/opt/microsoft/powershell/7/pwsh'
    },
    {
      options: {
        platform: 'win32',
        override: '',
        environment: { ProgramFiles: 'D:\\Programs', LOCALAPPDATA: 'C:\\Users\\tester\\AppData\\Local' }
      },
      expected: 'C:\\Users\\tester\\AppData\\Local\\Microsoft\\WindowsApps\\pwsh.exe'
    }
  ];

  for (const { options, expected } of installationCases) {
    assert.equal(
      resolvePwshBinary({
        ...options,
        executableExists: (candidate) => candidate === expected
      }),
      expected
    );
  }
});

test('Windows PowerShell resolver accepts only trusted where.exe results', () => {
  const trusted = 'D:\\Programs\\PowerShell\\Preview\\pwsh.exe';
  const untrusted = 'D:\\Downloads\\pwsh.exe';
  const calls = [];

  const resolved = resolvePwshBinary({
    platform: 'win32',
    override: '',
    environment: { ProgramFiles: 'D:\\Programs', SystemRoot: 'E:\\Windows' },
    executableExists: (candidate) => candidate === trusted || candidate === untrusted,
    executeWhere: (...args) => {
      calls.push(args);
      return `pwsh.exe\r\n${untrusted}\r\n${trusted}\r\n`;
    }
  });

  assert.equal(resolved, trusted);
  assert.deepEqual(calls, [
    [
      'E:\\Windows\\System32\\where.exe',
      ['pwsh'],
      { encoding: 'utf8', windowsHide: true }
    ]
  ]);
});

test('Windows PowerShell resolver treats where.exe failures as no installation', () => {
  assert.throws(
    () =>
      resolvePwshBinary({
        platform: 'win32',
        override: '',
        executableExists: () => false,
        executeWhere: () => {
          throw new Error('where.exe failed');
        }
      }),
    /PowerShell was not found.*set PWSH_BIN/
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
