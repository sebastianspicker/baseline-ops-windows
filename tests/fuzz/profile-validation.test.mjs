// Property-tests the profile validator with bounded generated documents,
// exercising rejection paths that are easy to miss with hand-written fixtures.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import fc from 'fast-check';

import { resolvePwshBinary } from './helpers/pwsh-path.mjs';

const testDirectory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testDirectory, '../..');
const validator = join(repoRoot, 'scripts', '00-Validate-Profile.ps1');

function runValidator(profile, executable) {
  const previousCwd = process.cwd();
  const workDir = mkdtempSync(join(tmpdir(), 'profile-fuzz-'));

  try {
    process.chdir(workDir);
    writeFileSync('profile.json', JSON.stringify(profile), 'utf8');

    const result = spawnSync(
      executable,
      [
        '-NoProfile',
        '-File',
        validator,
        '-ProfilePath',
        'profile.json',
        '-RootPath',
        repoRoot,
        '-OutputFormat',
        'Json',
        '-OutputPath',
        'result.json',
        '-Mode',
        'Audit'
      ],
      { encoding: 'utf8' }
    );

    if (result.error) {
      throw new Error(`Failed to start PowerShell at "${executable}": ${result.error.message}`, {
        cause: result.error
      });
    }

    let parsed = null;
    try {
      parsed = JSON.parse(readFileSync('result.json', 'utf8'));
    } catch {
      parsed = null;
    }

    return {
      status: result.status,
      stderr: result.stderr,
      stdout: result.stdout,
      result: parsed
    };
  } finally {
    process.chdir(previousCwd);
    rmSync(workDir, { recursive: true, force: true });
  }
}

const validProfileArbitrary = fc.record({
  ProfileName: fc.string({ minLength: 1, maxLength: 32 }).filter((value) => !/^\s*$/.test(value)),
  Version: fc.constantFrom('1.0', '2.0'),
  Defaults: fc.record({
    Mode: fc.constantFrom('Audit', 'Remediate'),
    OutputFormat: fc.constantFrom('Console', 'Json', 'Csv', 'None')
  }),
  Steps: fc.uniqueArray(
    // Profiles may only schedule workload scripts. The 00-* scripts are
    // control-plane entry points and the validator must reject them.
    fc.constantFrom('01-ASR-Defender-Allowlist.ps1', '19-Software-Audit.ps1'),
    { minLength: 1, maxLength: 2 }
  ).chain((scripts) =>
    fc.tuple(
      ...scripts.map((script) =>
        fc.record({
          Script: fc.constant(script),
          // Profile JSON is untrusted orchestration input. The runner-owned
          // authority contract permits the schema field but requires it empty.
          Args: fc.constant([]),
          DependsOn: fc.constant([])
        })
      )
    )
  ),
  Integrity: fc.record({
    ExpectedHashes: fc.constant({})
  })
});

const invalidProfileArbitrary = fc.oneof(
  validProfileArbitrary.map((profile) => ({
    ...profile,
    Defaults: { ...profile.Defaults, Mode: 'Apply' }
  })),
  validProfileArbitrary.map((profile) => ({
    ...profile,
    Steps: [{ Script: '../escape.ps1', Args: [], DependsOn: [] }]
  })),
  validProfileArbitrary.map((profile) => ({
    ...profile,
    Integrity: { ExpectedHashes: { '../escape.ps1': 'SHA256:abc' } }
  })),
  validProfileArbitrary.map((profile) => ({
    ...profile,
    Steps: profile.Steps.map((step, index) =>
      index === 0 ? { ...step, Args: ['untrusted-profile-argument'] } : step
    )
  }))
);

test('validator reports spawn errors and restores the original working directory', () => {
  const originalCwd = process.cwd();

  assert.throws(
    () => runValidator({}, '/definitely-missing/pwsh'),
    /Failed to start PowerShell at "\/definitely-missing\/pwsh"/
  );
  assert.equal(process.cwd(), originalCwd);
});

test('generated valid profile JSON is accepted by the profile validator', () => {
  const pwshBinary = resolvePwshBinary();

  fc.assert(
    fc.property(validProfileArbitrary, (profile) => {
      const run = runValidator(profile, pwshBinary);

      assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
      assert.equal(run.result?.Result, 'OK');
      assert.equal(run.result?.Summary?.Issues, 0);
    }),
    { numRuns: 12 }
  );
});

test('generated unsafe profile/config JSON is rejected as a validation failure', () => {
  const pwshBinary = resolvePwshBinary();

  fc.assert(
    fc.property(invalidProfileArbitrary, (profile) => {
      const run = runValidator(profile, pwshBinary);

      assert.notEqual(run.status, 0, 'unsafe profile unexpectedly passed');
      assert.equal(run.result?.Result, 'FAIL');
      assert.ok(run.result?.Summary?.HighIssues > 0);
    }),
    { numRuns: 12 }
  );
});
