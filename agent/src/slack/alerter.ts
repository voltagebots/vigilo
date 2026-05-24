import { WebClient } from '@slack/web-api';
import { Signal, Severity } from '../agents/analyst';

const EMOJI: Record<Severity, string> = {
  low: ':information_source:',
  medium: ':warning:',
  high: ':rotating_light:',
  critical: ':skull_and_crossbones:',
};

export class SlackAlerter {
  private client: WebClient;
  constructor(token: string, private channel: string) {
    this.client = new WebClient(token);
  }

  async postSignal(signal: Signal, events: { resource: string; action: string; process?: string }[]): Promise<string> {
    const emoji = EMOJI[signal.severity];
    const evidence = events
      .slice(0, 3)
      .map(e => `• \`${e.action}\` → \`${e.resource}\`${e.process ? ` (${e.process})` : ''}`)
      .join('\n');

    const res = await this.client.chat.postMessage({
      channel: this.channel,
      text: `${emoji} ${signal.title}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: `${emoji} ${signal.title}`, emoji: true },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Severity*\n${signal.severity.toUpperCase()}` },
            { type: 'mrkdwn', text: `*Category*\n${signal.category.replace(/_/g, ' ')}` },
            { type: 'mrkdwn', text: `*Detected*\n<!date^${Math.floor(signal.detectedAt.getTime() / 1000)}^{time_secs}|${signal.detectedAt.toISOString()}>` },
            { type: 'mrkdwn', text: `*Signal ID*\n\`${signal.id}\`` },
          ],
        },
        { type: 'section', text: { type: 'mrkdwn', text: `*What happened*\n${signal.description}` } },
        ...(evidence ? [{ type: 'section', text: { type: 'mrkdwn', text: `*Evidence*\n${evidence}` } }] : []),
        { type: 'section', text: { type: 'mrkdwn', text: `*Action needed*\n${signal.suggestedAction}` } },
      ],
    });

    return res.ts as string;
  }

  async postScanSummary(eventsAnalyzed: number, signalCount: number): Promise<void> {
    if (signalCount > 0) return; // individual alerts already posted
    await this.client.chat.postMessage({
      channel: this.channel,
      text: `:white_check_mark: Sentinel scan — ${eventsAnalyzed} events, no threats detected`,
    });
  }
}
