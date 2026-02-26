/**
 * FlashAuth OpenTelemetry trace plugin for Elysia
 *
 * Adds OpenTelemetry tracing to FlashAuth authentication operations.
 * Requires @elysiajs/opentelemetry to be installed and configured on the Elysia app.
 *
 * @example
 * ```typescript
 * import { Elysia } from 'elysia';
 * import { opentelemetry } from '@elysiajs/opentelemetry';
 * import { flashAuth } from 'flashauth';
 * import { flashAuthTrace } from 'flashauth/trace';
 *
 * const app = new Elysia()
 *   .use(opentelemetry())
 *   .use(flashAuth(auth))
 *   .use(flashAuthTrace())
 *   .listen(3000);
 * ```
 */

import { Elysia } from 'elysia';

/**
 * Configuration for the FlashAuth trace plugin
 */
export interface FlashAuthTraceConfig {
  /** Span name prefix (default: 'flashauth') */
  spanPrefix?: string;
  /** Whether to record the token subject (user ID) as a span attribute (default: true) */
  recordSubject?: boolean;
  /** Whether to record role names as span attributes (default: true) */
  recordRoles?: boolean;
  /** Whether to record token type as a span attribute (default: true) */
  recordTokenType?: boolean;
}

/**
 * Create FlashAuth OpenTelemetry trace plugin
 *
 * This plugin hooks into the Elysia request lifecycle to add tracing
 * spans for FlashAuth operations (token validation, role checks, etc.)
 *
 * Requires `@elysiajs/opentelemetry` to be installed and `.use(opentelemetry())`
 * applied to the Elysia app before this plugin.
 */
export function flashAuthTrace(config: FlashAuthTraceConfig = {}) {
  const {
    spanPrefix = 'flashauth',
    recordSubject = true,
    recordRoles = true,
    recordTokenType = true,
  } = config;

  return new Elysia({ name: 'flashauth-trace' })
    .onAfterHandle(({ flashAuth, path, request }: any) => {
      // Only add trace attributes if flashAuth context is available
      if (!flashAuth) return;

      try {
        // Try to get the current span from OpenTelemetry context
        // This works when @elysiajs/opentelemetry is installed
        const otel = tryGetOpenTelemetry();
        if (!otel) return;

        const span = otel.trace.getActiveSpan();
        if (!span) return;

        // Set span attributes for FlashAuth
        span.setAttribute(`${spanPrefix}.authenticated`, !!flashAuth.claims);
        span.setAttribute(`${spanPrefix}.path`, path || request?.url || '');

        if (flashAuth.claims) {
          if (recordSubject && flashAuth.claims.sub) {
            span.setAttribute(`${spanPrefix}.user.id`, flashAuth.claims.sub);
          }
          if (recordRoles && flashAuth.claims.roles?.length) {
            span.setAttribute(`${spanPrefix}.user.roles`, flashAuth.claims.roles.join(','));
          }
          if (recordTokenType && flashAuth.claims.token_type) {
            span.setAttribute(`${spanPrefix}.token.type`, flashAuth.claims.token_type);
          }
          if (flashAuth.claims.jti) {
            span.setAttribute(`${spanPrefix}.token.id`, flashAuth.claims.jti);
          }
        }
      } catch {
        // Silently ignore if OpenTelemetry is not available
      }
    })
    .onError(({ error, path, request }: any) => {
      try {
        const otel = tryGetOpenTelemetry();
        if (!otel) return;

        const span = otel.trace.getActiveSpan();
        if (!span) return;

        span.setAttribute(`${spanPrefix}.error`, true);
        span.setAttribute(`${spanPrefix}.error.type`, error?.constructor?.name || 'Error');
        span.setAttribute(`${spanPrefix}.error.message`, error?.message || 'Unknown error');
        span.setAttribute(`${spanPrefix}.path`, path || request?.url || '');
      } catch {
        // Silently ignore
      }
    });
}

/**
 * Try to dynamically import the OpenTelemetry API
 * Returns null if not available
 */
let _otelApi: any = null;
let _otelChecked = false;

function tryGetOpenTelemetry(): any {
  if (_otelChecked) return _otelApi;
  _otelChecked = true;
  try {
    // Try to require the OpenTelemetry API (it's a transitive dep of @elysiajs/opentelemetry)
    _otelApi = require('@opentelemetry/api');
  } catch {
    _otelApi = null;
  }
  return _otelApi;
}
