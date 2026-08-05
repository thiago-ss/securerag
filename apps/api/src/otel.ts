/**
 * OTel bootstrap (S10, ADR-0011): @opentelemetry/sdk-node +
 * @fastify/otel + @opentelemetry/instrumentation-pino.
 *
 * Attribute policy (binding): span and log-record attributes carry
 * identifiers and status ONLY — never prompts, retrieved text, answer text,
 * or document content. Enforced by apps/api/test/otel-safety.test.ts.
 *
 * Env:
 *  - OTEL_ENABLED=1|true       (default: disabled)
 *  - OTEL_SERVICE_NAME         (default 'securerag-api')
 *  - OTEL_EXPORTER=console|otlp (default console; production sends OTLP)
 *  - OTEL_OTLP_ENDPOINT        (e.g. http://collector:4318/v1/traces)
 */
import { NodeSDK } from '@opentelemetry/sdk-node';
import { ConsoleSpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { PinoInstrumentation } from '@opentelemetry/instrumentation-pino';
import fastifyOtel from '@fastify/otel';

const { FastifyOtelInstrumentation } = fastifyOtel;

export interface OtelResult {
  sdk: NodeSDK;
  /** Registered with the SDK and ready to be registered on the Fastify app. */
  instrumentation: InstanceType<typeof FastifyOtelInstrumentation>;
}

export function setupOtel(env: Record<string, string | undefined>): OtelResult | null {
  const enabled = env['OTEL_ENABLED'] === 'true' || env['OTEL_ENABLED'] === '1';
  if (!enabled) return null;

  const serviceName = env['OTEL_SERVICE_NAME'] ?? 'securerag-api';
  const instrumentation = new FastifyOtelInstrumentation();
  const traceExporter =
    env['OTEL_EXPORTER'] === 'otlp' && env['OTEL_OTLP_ENDPOINT'] !== undefined
      ? new OTLPTraceExporter({ url: env['OTEL_OTLP_ENDPOINT'] })
      : new ConsoleSpanExporter();

  const sdk = new NodeSDK({
    serviceName,
    instrumentations: [instrumentation, new PinoInstrumentation()],
    spanProcessor: new SimpleSpanProcessor(traceExporter),
  });
  sdk.start();

  return { sdk, instrumentation };
}
