import 'dotenv/config';
import cron from 'node-cron';
import { SentinelMCPClient, MCPTransport } from './collectors/mcp';
import { analyzeEvents } from './agents/analyst';
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

async function main() {
  const slackToken    = requireEnv('SLACK_BOT_TOKEN');
  const alertChannel  = requireEnv('VIGILO_ALERT_CHANNEL');
  const scanSchedule  = process.env.SCAN_CRON ?? '*/5 * * * *'; // every 5 min default
  const lookbackMins  = parseInt(process.env.LOOKBACK_MINUTES ?? '6');

  // MCP transport: stdio (local daemon) or http (remote)
  const transport: MCPTransport = process.env.VIGILO_MCP_URL
    ? { type: 'http', url: process.env.VIGILO_MCP_URL }
    : {
        type: 'stdio',
        command: process.env.VIGILO_DAEMON_BIN ?? 'vigilo',
        args: ['-config', process.env.VIGILO_CONFIG ?? '/etc/vigilo/config.yaml'],
      };

  const mcpClient = new SentinelMCPClient();
  const alerter   = new SlackAlerter(slackToken, alertChannel);

  logger.info({ transport: transport.type }, 'connecting to vigilo daemon via MCP');
  await mcpClient.connect(transport);

  const runScan = async () => {
    const since = new Date(Date.now() - lookbackMins * 60 * 1000);
    logger.info({ since }, 'scan started');

    try {
      const events = await mcpClient.getAllEvents(since, 'medium');
      logger.info({ eventCount: events.length }, 'events fetched from daemon');

      const signals = await analyzeEvents(events);

      for (const signal of signals) {
        const evidence = (signal.evidenceIndices ?? [])
          .map(i => events[i])
          .filter(Boolean)
          .map(e => ({ resource: e.resource, action: e.action, process: e.process }));

        await alerter.postSignal(signal, evidence);
        logger.info({ signalId: signal.id, severity: signal.severity, title: signal.title }, 'signal posted');
      }

      if (signals.length === 0) {
        logger.info({ eventsAnalyzed: events.length }, 'no threats detected');
      }

      await alerter.postScanSummary(events.length, signals.length);
    } catch (err) {
      logger.error({ err }, 'scan failed');
    }
  };

  // Run immediately on startup, then on schedule
  await runScan();
  cron.schedule(scanSchedule, () => { runScan(); });
  logger.info({ schedule: scanSchedule }, 'vigilo agent running');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
