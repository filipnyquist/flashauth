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
 * import { flashAuth, flashAuthTrace } from 'flashauth';
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
 * Eagerly attempt to load the OpenTelemetry API module.
 * Resolves to the module or null if not available.
 */
let _otelApi: any = null;
const _otelReady: Promise<void> = import('@opentelemetry/api')
  .then((mod) => { _otelApi = mod; })
  .catch(() => { _otelApi = null; });

function getOtelApi(): any {
  return _otelApi;
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
    .onStart(async () => {
      // Wait for the OTel import to settle before handling any requests
      await _otelReady;
    })
    .onAfterHandle(({ flashAuth, path, request }: any) => {
      // Only add trace attributes if flashAuth context is available
      if (!flashAuth) return;

      try {
        const otel = getOtelApi();
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
        const otel = getOtelApi();
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
