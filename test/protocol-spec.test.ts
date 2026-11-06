import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as primitives from '../src/primitives.js';
import * as protocol from '../src/protocol.js';

const spec = readFileSync(join(__dirname, '../PROTOCOL.md'), 'utf8');
const readme = readFileSync(join(__dirname, '../README.md'), 'utf8');

function runtimeExports(module: object): string[] {
  return Object.keys(module).filter((name) => name !== 'default');
}

describe('protocol specification', () => {
  it('names every runtime export and every key-purpose string', () => {
    const missing = [
      ...runtimeExports(protocol),
      ...runtimeExports(primitives),
      ...Object.values(protocol.CRYPTO_KEY_PURPOSES),
    ].filter((name) => !spec.includes(name));
    expect(missing).toEqual([]);
  });

  it('writes the control-character check as hex escapes', () => {
    const source = readFileSync(join(__dirname, '../src/protocol.ts'), 'utf8');
    const line = source.split('\n').find((row) => row.includes('.test(value)'));
    expect(line).toContain(String.raw`/[\x00-\x1F\x7F]/`);
    expect([...(line ?? '')].some((ch) => ch.charCodeAt(0) < 32 || ch.charCodeAt(0) === 127)).toBe(
      false,
    );
  });

  it('points the package readme at the specification and does not claim a Python check', () => {
    expect(readme).toContain('PROTOCOL.md');
    expect(readme).not.toContain('Python');
  });
});
