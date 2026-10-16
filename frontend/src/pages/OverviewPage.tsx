import React from 'react';
import {
  Globe,
  Server,
  Network,
  Cpu,
  AlertTriangle,
  Clock,
  ArrowRight,
  Shield,
  FileText,
  Activity,
  Layers,
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { RunDetails, RunSummary } from '../types';

interface OverviewPageProps {
  currentRun: RunDetails | null;
  runs: RunSummary[];
  onNavigate: (pageId: any) => void;
  onSelectRun: (runId: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  currentRun,
  runs,
  onNavigate,
  onSelectRun,
}) => {
  if (!currentRun || !currentRun.report_data) {
    return (
      <div className="p-8 max-w-6xl mx-auto">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center max-w-xl mx-auto shadow-xl">
          <div className="w-16 h-16 bg-cyan-500/10 text-cyan-400 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-cyan-500/20">
            <Activity className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">No Active Intelligence Run Selected</h2>
          <p className="text-slate-400 text-sm mb-6 leading-relaxed">
            Dispatch a simulated offline demonstration, execute passive OSINT reconnaissance, or configure an authorized active scan to inspect real targets.
          </p>
          <div className="flex justify-center gap-3">
            <button
              onClick={() => onNavigate('new-run')}
              className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-all shadow-lg shadow-cyan-500/20 cursor-pointer"
            >
              Configure New Run
            </button>
          </div>
        </div>
      </div>
    );
  }

  const report = currentRun.report_data;
  const inv = report.inventory || { subdomains: [], ip_addresses: [], services: [], observations: [], errors: [] };
  const graph = report.graph || { metrics: { total_nodes: 0, total_edges: 0 } };
  const findings = report.consistency_findings || [];
  const meta = report.metadata || { target_domain: currentRun.target_domain, mode: currentRun.mode, timestamp: currentRun.start_time };

  // Calculate Source Distribution
  const sourceCounts: Record<string, number> = {};
  for (const obs of inv.observations || []) {
    const src = obs.source || 'unknown';
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  }
  const sourceChartData = Object.entries(sourceCounts).map(([name, count]) => ({
    name,
    count,
  }));

  const chartColors = ['#06b6d4', '#10b981', '#6366f1', '#f59e0b', '#ec4899', '#3b82f6'];

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Target Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-navy-900 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute right-0 top-0 w-96 h-full bg-gradient-to-l from-cyan-500/5 to-transparent pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xs uppercase tracking-wider font-semibold text-cyan-400 font-mono">
                Target Scope Intelligence
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-xs text-slate-400 font-mono flex items-center gap-1">
                <Clock className="w-3.5 h-3.5" />
                {new Date(meta.timestamp).toUTCString()}
              </span>
            </div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
              <span>{meta.target_domain}</span>
              <span
                className={`text-xs uppercase font-bold tracking-wider px-2.5 py-1 rounded-md border ${
                  meta.mode === 'active'
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                    : meta.mode === 'demo'
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                }`}
              >
                {meta.mode} MODE
              </span>
            </h1>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigate('inventory')}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-all flex items-center gap-2 cursor-pointer"
            >
              View Inventory
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => onNavigate('reports')}
              className="px-4 py-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 text-xs font-semibold border border-cyan-500/30 transition-all flex items-center gap-2 cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5" />
              Audit Report
            </button>
          </div>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* Subdomains */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Subdomains</span>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">{inv.subdomains.length}</div>
          <div className="text-[11px] text-slate-400 mt-1">Passive / Active</div>
        </div>

        {/* Resolved IPs */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">IP Addresses</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">{inv.ip_addresses.length}</div>
          <div className="text-[11px] text-slate-400 mt-1">Unique IPv4 / IPv6</div>
        </div>

        {/* Identified Services */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Services</span>
            <Layers className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">{inv.services.length}</div>
          <div className="text-[11px] text-slate-400 mt-1">Banners Matched</div>
        </div>

        {/* Graph Vertices */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Graph Nodes</span>
            <Network className="w-4 h-4 text-teal-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">{graph.metrics?.total_nodes || 0}</div>
          <div className="text-[11px] text-slate-400 mt-1">{graph.metrics?.total_edges || 0} Directed Edges</div>
        </div>

        {/* Knapsack Optimum */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Knapsack Val</span>
            <Cpu className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">
            {report.scheduler?.knapsack_dp?.total_value || 0}
          </div>
          <div className="text-[11px] text-emerald-400 mt-1">Optimal Subset</div>
        </div>

        {/* Discrepancies */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Discrepancies</span>
            <AlertTriangle className={`w-4 h-4 ${findings.length > 0 ? 'text-amber-400' : 'text-emerald-400'}`} />
          </div>
          <div className="text-2xl font-black text-white font-mono">{findings.length}</div>
          <div className="text-[11px] text-slate-400 mt-1">Audit Findings</div>
        </div>
      </div>

      {/* Middle Grid: Source Breakdown & Graph Topology Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Source Telemetry Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-bold text-white mb-1 flex items-center justify-between">
            <span>Observation Provenance by Source</span>
            <span className="text-xs font-normal text-slate-400 font-mono">
              {inv.observations?.length || 0} Total Records
            </span>
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Corroborating observation counts preserved across passive collectors and active probes.
          </p>

          <div className="h-64 w-full">
            {sourceChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sourceChartData} layout="vertical" margin={{ left: 20, right: 20, top: 10, bottom: 10 }}>
                  <XAxis type="number" stroke="#475569" fontSize={11} />
                  <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={11} width={90} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {sourceChartData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">
                No observation data available.
              </div>
            )}
          </div>
        </div>

        {/* Quick Correlation Graph Summary */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-sm font-bold text-white">Asset Correlation Graph Topology</h3>
              <button
                onClick={() => onNavigate('graph')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 cursor-pointer"
              >
                Open Full Graph
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Structural relationships correlated via Adjacency-List representation with BFS / DFS traversals.
            </p>

            <div className="grid grid-cols-2 gap-3 mb-4">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-xs text-slate-400">Node Types</div>
                <div className="text-sm font-bold text-slate-200 mt-1 font-mono">
                  {Object.keys(graph.metrics?.node_distribution || {}).length} Categories
                </div>
                <div className="text-[11px] text-slate-400 truncate mt-0.5">
                  {Object.keys(graph.metrics?.node_distribution || {}).join(', ')}
                </div>
              </div>

              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-xs text-slate-400">Relationships</div>
                <div className="text-sm font-bold text-slate-200 mt-1 font-mono">
                  {Object.keys(graph.metrics?.relationship_distribution || {}).length} Edge Types
                </div>
                <div className="text-[11px] text-slate-400 truncate mt-0.5">
                  {Object.keys(graph.metrics?.relationship_distribution || {}).join(', ')}
                </div>
              </div>
            </div>
          </div>

          <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-400">Connected Components:</span>
            <span className="font-mono text-cyan-400 font-bold">
              {graph.metrics?.connected_components_count || 1} Isolated Groups
            </span>
          </div>
        </div>
      </div>

      {/* Recent Reconnaissance Runs Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-white">Recent Reconnaissance Runs</h3>
            <p className="text-xs text-slate-400">Audit trail of completed and active sessions.</p>
          </div>
          <button
            onClick={() => onNavigate('reports')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 cursor-pointer"
          >
            All Reports
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <th className="py-2.5 px-3">Run ID</th>
                <th className="py-2.5 px-3">Target Domain</th>
                <th className="py-2.5 px-3">Mode</th>
                <th className="py-2.5 px-3">Budget</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {runs.slice(0, 5).map((r) => (
                <tr key={r.run_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-2.5 px-3 text-slate-300 font-medium truncate max-w-[140px]">{r.run_id}</td>
                  <td className="py-2.5 px-3 text-cyan-400">{r.target_domain}</td>
                  <td className="py-2.5 px-3">
                    <span className="uppercase text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {r.mode}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">{r.budget}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full border ${
                        r.status === 'completed'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : r.status === 'running'
                          ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse'
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}
                    >
                      {r.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">{new Date(r.start_time).toLocaleDateString()}</td>
                  <td className="py-2.5 px-3 text-right">
                    <button
                      onClick={() => onSelectRun(r.run_id)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-sans font-semibold cursor-pointer"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
