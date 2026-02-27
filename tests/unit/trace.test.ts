/**
 * Tests for OpenTelemetry trace plugin
 */

import { describe, test, expect } from 'bun:test';
import { flashAuthTrace } from '../../src/plugins/trace.js';

describe('flashAuthTrace', () => {
  test('should create a plugin with default config', () => {
    const plugin = flashAuthTrace();
    expect(plugin).toBeDefined();
  });

  test('should accept custom span prefix', () => {
    const plugin = flashAuthTrace({ spanPrefix: 'myapp.auth' });
    expect(plugin).toBeDefined();
  });

  test('should accept all config options', () => {
    const plugin = flashAuthTrace({
      spanPrefix: 'custom',
      recordSubject: false,
      recordRoles: false,
      recordTokenType: false,
    });
    expect(plugin).toBeDefined();
  });

  test('should export FlashAuthTraceConfig type', async () => {
    // Verify the type is importable
    const mod = await import('../../src/plugins/trace.js');
    expect(mod.flashAuthTrace).toBeFunction();
  });
});
