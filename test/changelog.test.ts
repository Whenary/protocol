import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { validateChangelog } from '../../../scripts/check-protocol-changelog.mjs';

const content = readFileSync(join(__dirname, '..', 'CHANGELOG.md'), 'utf8');

describe('@whenary/protocol CHANGELOG format', () => {
  it('has no format violations', () => {
    const errors = validateChangelog(content);
    expect(errors).toEqual([]);
  });

  it('has at least one released version entry', () => {
    expect(content).toMatch(/^## \[\d+\.\d+\.\d+\] \(\d{4}-\d{2}-\d{2}\)/m);
  });

  it('has no [Unreleased] section', () => {
    expect(content).not.toContain('## [Unreleased]');
  });
});
