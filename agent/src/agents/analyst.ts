import Anthropic from '@anthropic-ai/sdk';
import { createHash } from 'crypto';
import { SentinelEvent } from '../collectors/mcp';

const client = new Anthropic();

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Signal {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  suggestedAction: string;
  evidenceIndices: number[];
  detectedAt: Date;
}

const SYSTEM = `You are a principal security analyst specializing in crypto infrastructure threat detection.

Analyze OS-level events from a server running crypto infrastructure (hot wallets, signing services, bridge validators, exchange integrations).

Look for attack patterns including:
- Private key / keystore file read by unexpected process → exfiltration likely
- Shell (bash/sh) spawned from app process (node, python) → RCE / code injection
- Outbound connection to suspicious port or new IP after file access → active exfiltration
- Environment variable dump followed by outbound connection → secret theft
- New process reading .env or credential files → credential harvesting
- Unexpected package install (npm/pip) → supply chain / persistence
- Privilege escalation (sudo by app process) → attacker expanding access
- Crypto-specific: access to keystore/, wallet.json, mnemonic files, .pem keys

For each sequence of events that indicates a threat, output a signal.
Correlate events across sources — a file read alone may be info, but file read + network connection = high.

Respond ONLY with a valid JSON array of signals:
[{
  "severity": "low|medium|high|critical",
  "category": "key_exfiltration|rce|credential_theft|supply_chain|privilege_escalation|lateral_movement|reconnaissance",
  "title": "one-line summary",
  "description": "2-3 sentences explaining the threat and why it is suspicious",
  "suggestedAction": "immediate mitigation step",
  "evidenceIndices": [0, 3, 7]
}]

If no threats detected, respond with [].`;

export async function analyzeEvents(events: SentinelEvent[]): Promise<Signal[]> {
  if (events.length === 0) return [];

  const summary = events.map((e, i) => ({ index: i, ...e }));

  const msg = await client.messages.create({
    model: 'claude-opus-4-7',
    max_tokens: 4096,
    system: SYSTEM,
    messages: [{
      role: 'user',
      content: `Analyze these ${events.length} OS-level events for attack patterns:\n\n${JSON.stringify(summary, null, 2)}`,
    }],
  });

  const raw = msg.content[0].type === 'text' ? msg.content[0].text : '[]';

  let parsed: Omit<Signal, 'id' | 'detectedAt'>[] = [];
  try {
    const match = raw.match(/\[[\s\S]*\]/);
    parsed = match ? JSON.parse(match[0]) : [];
  } catch {
    return [];
  }

  return parsed.map(s => ({
    ...s,
    id: createHash('sha256')
      .update(`${s.category}:${s.title}:${Date.now()}`)
      .digest('hex')
      .slice(0, 16),
    detectedAt: new Date(),
  }));
}
