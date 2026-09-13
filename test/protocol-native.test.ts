import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CRYPTO_PROTOCOL_VECTORS, notificationAad } from '../src/protocol.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('native notification AAD adapters', () => {
  const kotlin = readFileSync(
    join(ROOT, 'apps/native-shell/android/app/src/main/java/com/whenary/app/WhenaryNotificationCrypto.kt'),
    'utf8',
  );
  const swift = readFileSync(
    join(
      ROOT,
      'apps/native-shell/ios/App/NotificationServiceExtension/NotificationService.swift',
    ),
    'utf8',
  );
  const vector = CRYPTO_PROTOCOL_VECTORS.notificationContext;

  it('embeds the shared known-answer vector', () => {
    expect(notificationAad(vector.input)).toBe(vector.aad);
    expect(kotlin).toContain(vector.aad);
    expect(swift).toContain(vector.aad);
  });

  it('encodes the same notification context parts as the shared protocol', () => {
    expect(kotlin).toContain('fun notificationAad(');
    expect(swift).toContain('static func notificationAad(');
    expect(kotlin).toContain('whenary.e2ee.notification.v1');
    expect(swift).toContain('whenary.e2ee.notification.v1');
    expect(kotlin).toContain('notificationAad(calendarId, eventId, keyVersion)');
    expect(swift).toContain('NotificationService.notificationAad(');
  });
});
