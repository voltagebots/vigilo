import 'dotenv/config';
import cron from 'node-cron';
import { VigiloMCPClient, VigiloEvent, parseTransports } from './collectors/mcp';
import { analyzeEvents, signalDedupHash, Signal } from './agents/analyst';
import { SlackAlerter } from './slack/alerter';
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
});

function requireEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`Missing required env var: ${key}`);
  return v;
}

// In-process dedup: hash → expiry timestamp
const dedupCache = new Map<string, number>();
const DEDUP_TTL_MS = parseInt(process.env.SIGNAL_COOLDOWN_MS ?? String(60 * 60 * 1000)); // 1h default

function isDuplicate(signal: Signal): boolean {
  const hash = signalDedupHash(signal.category, signal.title, signal.server);
  const expiry = dedupCache.get(hash);
  if (expiry && Date.now() < expiry) return true;
  dedupCache.set(hash, Date.now() + DEDUP_TTL_MS);
  return false;
}

async function main() {
  const slackToken   = requireEnv('SLACK_BOT_TOKEN');
  const alertChannel = requireEnv('VIGILO_ALERT_CHANNEL');
  const scanSchedule = process.env.SCAN_CRON ?? '*/5 * * * *';
  const lookbackMins = parseInt(process.env.LOOKBACK_MINUTES ?? '6');

  const transports = parseTransports();
  logger.info({ servers: transports.map(t => t.label) }, 'connecting to vigilo daemons');

  // Connect all clients in parallel
  const clients = await Promise.all(
    transports.map(async ({ label, transport }) => {
      const c = new VigiloMCPClient(label);
      await c.connect(transport);
      logger.info({ server: label, transport: transport.type }, 'connected');
      return c;
    }),
  );

  const alerter = new SlackAlerter(slackToken, alertChannel);

  const runScan = async () => {
    const since = new Date(Date.now() - lookbackMins * 60 * 1000);
    logger.info({ since, servers: clients.map(c => c.serverLabel) }, 'scan started');

    // Fetch events from all daemons in parallel
    const perServerEvents = await Promise.allSettled(
      clients.map(c => c.getAllEvents(since, 'medium')),
    );

    const allEvents: VigiloEvent[] = [];
    for (let i = 0; i < clients.length; i++) {
      const result = perServerEvents[i];
      if (result.status === 'fulfilled') {
        allEvents.push(...result.value);
      } else {
        logger.error({ server: clients[i].serverLabel, err: result.reason }, 'failed to fetch events');
      }
    }

    logger.info({ eventCount: allEvents.length }, 'events aggregated');

    if (allEvents.length === 0) {
      await alerter.postScanSummary(0, 0, clients.map(c => c.serverLabel));
      return;
    }

    try {
      const signals = await analyzeEvents(allEvents, clients.map(c => c.serverLabel));

      let posted = 0;
      for (const signal of signals) {
        if (isDuplicate(signal)) {
          logger.info({ category: signal.category, title: signal.title }, 'signal suppressed (dedup)');
          continue;
        }
        const evidence = (signal.evidenceIndices ?? [])
          .map(i => allEvents[i])
          .filter(Boolean)
          .map(e => ({ resource: e.resource, action: e.action, process: e.process, server: e.server }));

        await alerter.postSignal(signal, evidence);
        logger.info({ signalId: signal.id, severity: signal.severity, title: signal.title }, 'signal posted');
        posted++;
      }

      await alerter.postScanSummary(allEvents.length, posted, clients.map(c => c.serverLabel));
    } catch (err) {
      logger.error({ err }, 'analysis failed');
    }
  };

  await runScan();
  cron.schedule(scanSchedule, () => { runScan(); });
  logger.info({ schedule: scanSchedule }, 'vigilo agent running');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
