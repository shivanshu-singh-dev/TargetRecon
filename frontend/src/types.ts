export interface HealthStatus {
  status: string;
  timestamp: string;
  version: string;
  external_tools: Record<string, boolean>;
  signatures_count: number;
}

export interface RunSummary {
  run_id: string;
  target_domain: string;
  mode: 'demo' | 'passive' | 'active';
  budget: number;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  start_time: string;
  end_time?: string;
  progress_message: string;
  asset_count: number;
  error_count: number;
}

export interface DNSRecord {
  record_type: string;
  host: string;
  value: string;
  source: string;
  timestamp?: string;
  ttl?: number;
}

export interface ServiceEndpoint {
  endpoint_id: string;
  host: string;
  port: number;
  protocol: string;
  service_name?: string;
  product?: string;
  version?: string;
  banner?: string;
  confidence: number;
  source: string;
  timestamp?: string;
}

export interface Observation {
  asset_id: string;
  source: string;
  method: string;
  raw_value: string;
  normalized_value: string;
  timestamp: string;
  confidence: number;
  status: string;
  error_message?: string;
}

export interface ConsistencyFinding {
  finding_type: string;
  asset_id: string;
  description: string;
  evidence_sources: string[];
  timestamp: string;
}

export interface GraphNode {
  node_id: string;
  node_type: string;
  properties?: Record<string, any>;
}

export interface GraphEdge {
  source_id: string;
  target_id: string;
  relationship_type: string;
  properties?: Record<string, any>;
}

export interface GraphMetrics {
  total_nodes: number;
  total_edges: number;
  node_distribution: Record<string, number>;
  relationship_distribution: Record<string, number>;
  connected_components_count: number;
}

export interface GraphData {
  metrics: GraphMetrics;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ProbeCandidate {
  probe_id: string;
  host: string;
  port: number;
  protocol: string;
  cost: number;
  value: number;
  reason: string;
  selected: boolean;
}

export interface SchedulerResult {
  strategy: string;
  selected_count: number;
  candidate_count: number;
  total_cost: number;
  total_value: number;
  budget: number;
  is_optimal: boolean;
  runtime_seconds: number;
  selected_probe_ids: string[];
}

export interface InventoryData {
  subdomains: string[];
  ip_addresses: string[];
  dns_records: DNSRecord[];
  services: ServiceEndpoint[];
  observations: Observation[];
  errors: { source: string; message: string; timestamp?: string }[];
}

export interface RunDetails {
  run_id: string;
  target_domain: string;
  mode: 'demo' | 'passive' | 'active';
  budget: number;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  start_time: string;
  end_time?: string;
  progress_message: string;
  error_message?: string;
  report_data?: {
    metadata: {
      target_domain: string;
      mode: string;
      timestamp: string;
      framework: string;
      version: string;
      settings: Record<string, any>;
      external_tools_status: Record<string, boolean>;
    };
    authorization_scope: {
      active_mode_confirmed: boolean;
      scope_rules: string[];
    };
    inventory: InventoryData;
    scheduler: Record<string, SchedulerResult>;
    graph: GraphData;
    consistency_findings: ConsistencyFinding[];
    benchmarks?: Record<string, any>;
  };
}

export interface BenchmarkResult {
  scheduler: any[];
  matcher: any[];
  graph: any[];
}
