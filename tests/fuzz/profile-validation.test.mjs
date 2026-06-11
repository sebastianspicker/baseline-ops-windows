import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import fc from 'fast-check';

const repoRoot = resolve(new URL('../..', import.meta.url).pathname);
const validator = join(repoRoot, 'scripts', '00-Validate-Profile.ps1');

function runValidator(profile) {
  const workDir = mkdtempSync(join(tmpdir(), 'profile-fuzz-'));
  const profilePath = join(workDir, 'profile.json');
  const outputPath = join(workDir, 'result.json');

  try {
    writeFileSync(profilePath, JSON.stringify(profile), 'utf8');
    const result = spawnSync(
      'pwsh',
      [
        '-NoProfile',
        '-File',
        validator,
        '-ProfilePath',
        profilePath,
        '-RootPath',
        repoRoot,
        '-OutputFormat',
        'Json',
        '-OutputPath',
        outputPath,
        '-Mode',
        'Audit'
      ],
      { cwd: repoRoot, encoding: 'utf8' }
    );

    let parsed = null;
    try {
      parsed = JSON.parse(readFileSync(outputPath, 'utf8'));
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
    fc.constantFrom('00-Report-Aggregate.ps1', '00-Validate-Profile.ps1'),
    { minLength: 1, maxLength: 2 }
  ).chain((scripts) =>
    fc.tuple(
      ...scripts.map((script) =>
        fc.record({
          Script: fc.constant(script),
          Args: fc.array(fc.string({ maxLength: 16 }).filter((value) => !/^\s*$/.test(value)), { maxLength: 3 }),
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
  }))
);

test('generated valid profile JSON is accepted by the profile validator', () => {
  fc.assert(
    fc.property(validProfileArbitrary, (profile) => {
      const run = runValidator(profile);

      assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
      assert.equal(run.result?.Result, 'OK');
      assert.equal(run.result?.Summary?.Issues, 0);
    }),
    { numRuns: 12 }
  );
});

test('generated unsafe profile/config JSON is rejected as a validation failure', () => {
  fc.assert(
    fc.property(invalidProfileArbitrary, (profile) => {
      const run = runValidator(profile);

      assert.notEqual(run.status, 0, 'unsafe profile unexpectedly passed');
      assert.equal(run.result?.Result, 'FAIL');
      assert.ok(run.result?.Summary?.HighIssues > 0);
    }),
    { numRuns: 12 }
  );
});
