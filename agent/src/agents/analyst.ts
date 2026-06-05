import Anthropic, { APIError } from '@anthropic-ai/sdk';
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

BEFORE the JSON, you MUST emit a <dup_check> block. In it, list each signal you plan to emit and confirm it is semantically distinct from the others. Same root cause expressed differently (e.g. two processes reading the same key file) counts as ONE signal — collapse them. Remove duplicates before the JSON.

<dup_check>
1. [title] — distinct from others because: [reason]
2. [title] — distinct from others because: [reason]
</dup_check>

Then respond with a valid JSON array of signals. No markdown, no explanation outside the dup_check block and the JSON:
[{
  "severity": "low|medium|high|critical",
  "category": "key_exfiltration|rce|credential_theft|supply_chain|privilege_escalation|lateral_movement|reconnaissance",
  "title": "one-line summary",
  "description": "2-3 sentences explaining the threat and why it is suspicious",
  "suggestedAction": "immediate mitigation step",
  "evidenceIndices": [0, 3, 7],
  "server": "server label or null if cross-server"
}]

If no threats detected, emit <dup_check>none</dup_check> then [].`;

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
const MAX_EVENTS = 150;
const SAMPLE_LOW_PRIORITY_EVERY = 3;

function compactEvents(events: VigiloEvent[]): { compacted: VigiloEvent[]; note: string } {
  if (events.length <= MAX_EVENTS) {
    return { compacted: events, note: '' };
  }

  const high    = events.filter(e => e.severity === 'critical' || e.severity === 'high');
  const low     = events.filter(e => e.severity === 'medium'   || e.severity === 'info');
  const sampled = low.filter((_, i) => i % SAMPLE_LOW_PRIORITY_EVERY === 0);
  const compacted = [...high, ...sampled].slice(0, MAX_EVENTS);

  const note =
    `[Context compacted: ${events.length} total events → ${compacted.length} shown. ` +
    `All ${high.length} critical/high events included; medium/info sampled 1-in-${SAMPLE_LOW_PRIORITY_EVERY}.]`;

  return { compacted, note };
}

// ── Goose pattern: MOIM preamble ─────────────────────────────────────────────
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

// ── Backward scan helpers (from Anthropic defending-code reference harness) ───
//
// Agents often emit structured content mid-response with trailing prose.
// Naive last-message or greedy-regex extraction returns the prose or a
// malformed superset. Scanning from the end finds the last complete block.

// Finds the last complete [...] array in text.
// Greedy /\[[\s\S]*\]/ matches first '[' to last ']' — breaks when Claude
// emits prose after the array. Backward scan is precise.
function findLastJsonArray(text: string): string | null {
  let depth = 0, end = -1;
  for (let i = text.length - 1; i >= 0; i--) {
    const ch = text[i];
    if      (ch === ']') { if (end === -1) end = i; depth++; }
    else if (ch === '[') { if (--depth === 0) return text.slice(i, end + 1); }
  }
  return null;
}

// Finds the last <tag>…</tag> block via backward scan.
function findTaggedContent(text: string, tag: string): string | null {
  const close = `</${tag}>`, open = `<${tag}>`;
  const ci = text.lastIndexOf(close);
  if (ci === -1) return null;
  const oi = text.lastIndexOf(open, ci);
  if (oi === -1) return null;
  return text.slice(oi + open.length, ci);
}

function parseSignals(raw: string): Omit<Signal, 'id' | 'detectedAt'>[] | null {
  try {
    const arr = findLastJsonArray(raw);
    if (!arr) return null;
    const parsed = JSON.parse(arr);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

// ── Exponential backoff on transient API errors ───────────────────────────────
//
// The reference harness resumes Claude Code CLI sessions on 429/5xx.
// For the Messages API, session state lives in the messages[] array —
// we rebuild it on each retry, which is equivalent.

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 529]);
const MAX_ATTEMPTS = 6;
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

async function callClaude(messages: Anthropic.MessageParam[]): Promise<string> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (attempt > 0) await sleep(Math.min(2 ** attempt * 1_000, 30_000));
    try {
      const msg = await client.messages.create({
        model: 'claude-opus-4-7',
        max_tokens: 4096,
        system: SYSTEM,
        messages,
      });
      return msg.content[0].type === 'text' ? msg.content[0].text : '[]';
    } catch (err) {
      const status = (err as APIError)?.status;
      if (status != null && RETRYABLE_STATUS.has(status)) { lastErr = err; continue; }
      throw err;
    }
  }
  throw lastErr;
}

// ── Main export ───────────────────────────────────────────────────────────────

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

  const baseMessages: Anthropic.MessageParam[] = [
    { role: 'user', content: userContent },
  ];

  let raw = await callClaude(baseMessages);

  // ── Forced dedup reasoning gate ───────────────────────────────────────────
  // If <dup_check> is absent, Claude skipped its dedup reasoning pass.
  // Correct with a single follow-up turn (conversation context preserved).
  if (!findTaggedContent(raw, 'dup_check')) {
    raw = await callClaude([
      ...baseMessages,
      { role: 'assistant', content: raw },
      {
        role: 'user',
        content: 'You must emit a <dup_check>…</dup_check> block before the JSON array. ' +
          'Re-emit your full response with the dedup reasoning included.',
      },
    ]);
  }

  let parsed = parseSignals(raw);

  // ── Inspector: single retry on malformed JSON ─────────────────────────────
  if (parsed === null) {
    raw = await callClaude([
      ...baseMessages,
      { role: 'assistant', content: raw },
      {
        role: 'user',
        content: '[Previous response did not contain a valid JSON array. ' +
          'Respond with <dup_check>…</dup_check> then ONLY the JSON array — no other prose.]',
      },
    ]);
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
