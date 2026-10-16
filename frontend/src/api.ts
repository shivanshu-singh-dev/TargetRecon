import {
  HealthStatus,
  RunSummary,
  RunDetails,
  BenchmarkResult,
  InventoryData,
  GraphData,
  ConsistencyFinding,
} from './types';

const API_BASE = '/api';

export async function fetchHealth(): Promise<HealthStatus> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Failed to fetch health status');
  return res.json();
}

export async function fetchRuns(): Promise<RunSummary[]> {
  const res = await fetch(`${API_BASE}/runs`);
  if (!res.ok) throw new Error('Failed to fetch runs');
  return res.json();
}

export async function fetchRunDetails(runId: string): Promise<RunDetails> {
  const res = await fetch(`${API_BASE}/runs/${runId}`);
  if (!res.ok) throw new Error(`Failed to fetch run details for ${runId}`);
  return res.json();
}

export async function fetchRunStatus(runId: string): Promise<{
  run_id: string;
  status: string;
  progress_message: string;
  error_message?: string;
}> {
  const res = await fetch(`${API_BASE}/runs/${runId}/status`);
  if (!res.ok) throw new Error(`Failed to fetch status for ${runId}`);
  return res.json();
}

export async function cancelRun(runId: string): Promise<{ message: string }> {
  const res = await fetch(`${API_BASE}/runs/${runId}/cancel`, { method: 'POST' });
  if (!res.ok) throw new Error(`Failed to cancel run ${runId}`);
  return res.json();
}

export async function createRun(data: {
  target_domain: string;
  mode: 'demo' | 'passive' | 'active';
  budget?: number;
  confirm_active?: boolean;
  scope_rules?: string[];
  enable_zone_transfer?: boolean;
}): Promise<{
  run_id: string;
  target_domain: string;
  mode: string;
  status: string;
  message: string;
}> {
  const res = await fetch(`${API_BASE}/runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Network request failed' }));
    throw new Error(err.detail || 'Failed to dispatch run');
  }
  return res.json();
}

export async function fetchRunAssets(runId: string): Promise<InventoryData> {
  const res = await fetch(`${API_BASE}/runs/${runId}/assets`);
  if (!res.ok) throw new Error('Failed to fetch run assets');
  return res.json();
}

export async function fetchRunGraph(runId: string): Promise<GraphData> {
  const res = await fetch(`${API_BASE}/runs/${runId}/graph`);
  if (!res.ok) throw new Error('Failed to fetch run graph');
  return res.json();
}

export async function fetchRunFindings(runId: string): Promise<ConsistencyFinding[]> {
  const res = await fetch(`${API_BASE}/runs/${runId}/findings`);
  if (!res.ok) throw new Error('Failed to fetch run findings');
  return res.json();
}

export function getReportDownloadUrl(runId: string, format: 'json' | 'markdown'): string {
  return `${API_BASE}/runs/${runId}/reports/${format}`;
}

export async function fetchBenchmarks(): Promise<BenchmarkResult> {
  const res = await fetch(`${API_BASE}/benchmarks/results`);
  if (!res.ok) throw new Error('Failed to fetch benchmark results');
  return res.json();
}

export async function triggerBenchmark(target: 'scheduler' | 'matcher' | 'graph' | 'all'): Promise<{ message: string }> {
  const res = await fetch(`${API_BASE}/benchmarks/${target}`, { method: 'POST' });
  if (!res.ok) throw new Error(`Failed to trigger benchmark ${target}`);
  return res.json();
}

export async function matchBanner(banner: string, caseSensitive: boolean = false): Promise<any> {
  const res = await fetch(`${API_BASE}/algorithms/match-banner`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ banner, case_sensitive: caseSensitive }),
  });
  if (!res.ok) throw new Error('Failed to execute banner matching');
  return res.json();
}

export async function testScheduler(budget: number, candidateCount: number): Promise<any> {
  const res = await fetch(`${API_BASE}/algorithms/schedule`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ budget, candidate_count: candidateCount }),
  });
  if (!res.ok) throw new Error('Failed to execute scheduler comparison');
  return res.json();
}

export async function traverseGraph(runId: string, algorithm: 'bfs' | 'dfs', startNodeId: string): Promise<{
  algorithm: string;
  start_node_id: string;
  traversal_order: string[];
  visited_count: number;
  total_graph_nodes: number;
}> {
  const res = await fetch(`${API_BASE}/algorithms/graph-traverse`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ run_id: runId, algorithm, start_node_id: startNodeId }),
  });
  if (!res.ok) throw new Error('Failed to execute graph traversal');
  return res.json();
}
