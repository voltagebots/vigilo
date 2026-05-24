import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

export interface SentinelEvent {
  id: number;
  source: 'file_access' | 'process' | 'network' | 'auth';
  timestamp: string;
  pid?: number;
  ppid?: number;
  process?: string;
  cmd_line?: string;
  user_id?: string;
  action: string;
  resource: string;
  detail?: string;
  severity: 'info' | 'medium' | 'high' | 'critical';
}

export type MCPTransport =
  | { type: 'stdio'; command: string; args?: string[] }
  | { type: 'http'; url: string };

export class SentinelMCPClient {
  private client: Client;

  constructor() {
    this.client = new Client({ name: 'vigilo-agent', version: '0.1.0' });
  }

  async connect(transport: MCPTransport): Promise<void> {
    const t = transport.type === 'stdio'
      ? new StdioClientTransport({ command: transport.command, args: transport.args ?? [] })
      : new StreamableHTTPClientTransport(new URL(transport.url));
    await this.client.connect(t);
  }

  async disconnect(): Promise<void> {
    await this.client.close();
  }

  async getFileEvents(since: Date, severity?: string): Promise<SentinelEvent[]> {
    return this.callTool('get_file_access_events', { since: since.toISOString(), severity });
  }

  async getProcessEvents(since: Date): Promise<SentinelEvent[]> {
    return this.callTool('get_process_events', { since: since.toISOString() });
  }

  async getNetworkEvents(since: Date, severity?: string): Promise<SentinelEvent[]> {
    return this.callTool('get_network_events', { since: since.toISOString(), severity });
  }

  async getAllEvents(since: Date, severity?: string, limit = 200): Promise<SentinelEvent[]> {
    return this.callTool('get_all_events', { since: since.toISOString(), severity, limit });
  }

  async getCriticalEvents(since: Date): Promise<SentinelEvent[]> {
    return this.callTool('get_critical_events', { since: since.toISOString() });
  }

  private async callTool(name: string, args: Record<string, unknown>): Promise<SentinelEvent[]> {
    const cleanArgs = Object.fromEntries(
      Object.entries(args).filter(([, v]) => v !== undefined),
    );
    type ToolContent = { type: string; text?: string };
    const result = await this.client.callTool({ name, arguments: cleanArgs }) as { content: ToolContent[] };
    const first = result.content[0];
    const text = first?.type === 'text' ? (first.text ?? '[]') : '[]';
    try {
      return JSON.parse(text) ?? [];
    } catch {
      return [];
    }
  }
}
