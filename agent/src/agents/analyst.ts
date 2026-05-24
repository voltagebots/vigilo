import Anthropic from '@anthropic-ai/sdk';
import { createHash } from 'crypto';
import { VigiloEvent } from '../collectors/mcp';

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
  server?: string;
}

const SYSTEM = `You are a principal security analyst specializing in crypto infrastructure threat detection.

Analyze OS-level events from servers running crypto infrastructure (hot wallets, signing services, bridge validators, exchange integrations).

Events may come from multiple servers — each has a "server" field. Cross-server patterns (e.g. lateral movement, coordinated exfiltration) are especially significant.

Look for attack patterns including:
- Private key / keystore file read by unexpected process → exfiltration likely
- Shell (bash/sh) spawned from app process (node, python) → RCE / code injection
- Outbound connection to suspicious port or new IP after file access → active exfiltration
- Environment variable dump followed by outbound connection → secret theft
- New process reading .env or credential files → credential harvesting
- Unexpected package install (npm/pip) → supply chain / persistence
- Privilege escalation (sudo by app process) → attacker expanding access
- Crypto-specific: access to keystore/, wallet.json, mnemonic files, .pem keys
- Cross-server: same attack pattern on multiple servers → coordinated campaign

For each threat sequence, output one signal. Correlate across sources and servers.

Respond ONLY with a valid JSON array of signals. No markdown, no explanation outside the JSON:
[{
  "severity": "low|medium|high|critical",
  "category": "key_exfiltration|rce|credential_theft|supply_chain|privilege_escalation|lateral_movement|reconnaissance",
  "title": "one-line summary",
  "description": "2-3 sentences explaining the threat and why it is suspicious",
  "suggestedAction": "immediate mitigation step",
  "evidenceIndices": [0, 3, 7],
  "server": "server label or null if cross-server"
}]

If no threats detected, respond with [].`;

/**
 * Stable dedup hash for a signal — based on category + title fingerprint.
 * Does not include time so the same attack re-hashes identically across scans.
 */
export function signalDedupHash(category: string, title: string, server?: string): string {
  return createHash('sha256')
    .update([category, title.toLowerCase().replace(/\s+/g, ' '), server ?? ''].join('|'))
    .digest('hex')
    .slice(0, 32);
}

// ── Goose pattern: Context compaction ────────────────────────────────────────
// Keep all critical/high events; sample medium/info to stay within ~150 events.
// Returns the compacted list and a note to inject into the prompt.
const MAX_EVENTS = 150;
const SAMPLE_LOW_PRIORITY_EVERY = 3;

function compactEvents(events: VigiloEvent[]): { compacted: VigiloEvent[]; note: string } {
  if (events.length <= MAX_EVENTS) {
    return { compacted: events, note: '' };
  }

  const high = events.filter(e => e.severity === 'critical' || e.severity === 'high');
  const low  = events.filter(e => e.severity === 'medium'   || e.severity === 'info');
  const sampled = low.filter((_, i) => i % SAMPLE_LOW_PRIORITY_EVERY === 0);
  const compacted = [...high, ...sampled].slice(0, MAX_EVENTS);

  const note = `[Context compacted: ${events.length} total events → ${compacted.length} shown. ` +
    `All ${high.length} critical/high events included; medium/info sampled 1-in-${SAMPLE_LOW_PRIORITY_EVERY}.]`;

  return { compacted, note };
}

// ── Goose pattern: MOIM preamble ─────────────────────────────────────────────
// Inject situational awareness before the event list so Claude knows the scope.
function buildMoim(events: VigiloEvent[], servers: string[]): string {
  const serverList = servers.length > 0 ? servers.join(', ') : 'local';
  const bySeverity = {
    critical: events.filter(e => e.severity === 'critical').length,
    high:     events.filter(e => e.severity === 'high').length,
    medium:   events.filter(e => e.severity === 'medium').length,
    info:     events.filter(e => e.severity === 'info').length,
  };
  return [
    `[Monitoring scope: ${servers.length || 1} server(s): ${serverList}]`,
    `[Event breakdown: ${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.info} info]`,
    `[Scan time: ${new Date().toISOString()}]`,
  ].join('  ');
}

// ── Goose pattern: Inspector — response validation + single retry ─────────────
function parseSignals(raw: string): Omit<Signal, 'id' | 'detectedAt'>[] | null {
  try {
    const match = raw.match(/\[[\s\S]*\]/);
    if (!match) return null;
    const parsed = JSON.parse(match[0]);
    if (!Array.isArray(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function callClaude(userContent: string, retrying = false): Promise<string> {
  const msg = await client.messages.create({
    model: 'claude-opus-4-7',
    max_tokens: 4096,
    system: SYSTEM,
    messages: [
      { role: 'user', content: userContent },
      ...(retrying ? [] : []),
    ],
  });
  return msg.content[0].type === 'text' ? msg.content[0].text : '[]';
}

export async function analyzeEvents(
  events: VigiloEvent[],
  servers: string[] = [],
): Promise<Signal[]> {
  if (events.length === 0) return [];

  const { compacted, note } = compactEvents(events);
  const moim = buildMoim(compacted, servers);
  const indexed = compacted.map((e, i) => ({ index: i, ...e }));

  const userContent = [
    moim,
    note,
    `\nAnalyze these ${compacted.length} OS-level events for attack patterns:\n\n${JSON.stringify(indexed, null, 2)}`,
  ].filter(Boolean).join('\n');

  // First attempt
  let raw = await callClaude(userContent);
  let parsed = parseSignals(raw);

  // Inspector: retry once on malformed JSON
  if (parsed === null) {
    raw = await callClaude(
      userContent +
      '\n\n[Previous response was not valid JSON. Respond ONLY with the JSON array, no prose.]',
      true,
    );
    parsed = parseSignals(raw);
  }

  if (!parsed) return [];

  return parsed.map(s => ({
    ...s,
    id: createHash('sha256')
      .update(`${s.category}:${s.title}:${Date.now()}`)
      .digest('hex')
      .slice(0, 16),
    detectedAt: new Date(),
  }));
}
