import React, { useState } from 'react';
import { FileText, Download, Eye, ExternalLink, Calendar, CheckCircle2, Clock } from 'lucide-react';
import { RunDetails, RunSummary } from '../types';
import { getReportDownloadUrl } from '../api';

interface ReportsPageProps {
  currentRun: RunDetails | null;
  runs: RunSummary[];
  onSelectRun: (runId: string) => void;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({
  currentRun,
  runs,
  onSelectRun,
}) => {
  const [previewFormat, setPreviewFormat] = useState<'markdown' | 'json'>('markdown');

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <FileText className="w-6 h-6 text-cyan-400" />
          Audit Reports & Run History
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Historical reconnaissance runs, complete audit trails, and exportable reports.
        </p>
      </div>

      {/* Historical Runs Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-slate-800 font-bold text-sm text-white flex items-center justify-between">
          <span>Reconnaissance Run History</span>
          <span className="text-xs text-slate-400 font-mono">{runs.length} Recorded Runs</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Run Identifier</th>
                <th className="py-3 px-4">Target Domain</th>
                <th className="py-3 px-4">Mode</th>
                <th className="py-3 px-4">Budget</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Assets</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Downloads</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {runs.map((r) => {
                const isSelected = currentRun?.run_id === r.run_id;
                return (
                  <tr
                    key={r.run_id}
                    onClick={() => onSelectRun(r.run_id)}
                    className={`hover:bg-slate-800/40 transition-colors cursor-pointer ${
                      isSelected ? 'bg-cyan-500/5 border-l-2 border-cyan-400' : ''
                    }`}
                  >
                    <td className="py-3 px-4 text-white font-bold">{r.run_id}</td>
                    <td className="py-3 px-4 text-cyan-400">{r.target_domain}</td>
                    <td className="py-3 px-4">
                      <span className="uppercase text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {r.mode}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{r.budget}</td>
                    <td className="py-3 px-4">
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
                    <td className="py-3 px-4 text-slate-300">{r.asset_count}</td>
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(r.start_time).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2 font-sans" onClick={(e) => e.stopPropagation()}>
                      <a
                        href={getReportDownloadUrl(r.run_id, 'json')}
                        download
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] text-cyan-400 border border-slate-700 inline-flex items-center gap-1"
                        title="Download JSON Report"
                      >
                        <Download className="w-3 h-3" /> JSON
                      </a>
                      <a
                        href={getReportDownloadUrl(r.run_id, 'markdown')}
                        download
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] text-cyan-400 border border-slate-700 inline-flex items-center gap-1"
                        title="Download Markdown Report"
                      >
                        <Download className="w-3 h-3" /> MD
                      </a>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Report Live Preview Pane */}
      {currentRun?.report_data && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>Selected Run Report Preview</span>
                <span className="font-mono text-xs text-cyan-400">({currentRun.run_id})</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Exact report outputs rendered from backend data models.
              </p>
            </div>

            <div className="flex items-center gap-2 bg-slate-950 p-1 rounded-lg border border-slate-800">
              <button
                onClick={() => setPreviewFormat('markdown')}
                className={`px-3 py-1 text-xs font-semibold rounded cursor-pointer ${
                  previewFormat === 'markdown'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Markdown View
              </button>
              <button
                onClick={() => setPreviewFormat('json')}
                className={`px-3 py-1 text-xs font-semibold rounded cursor-pointer ${
                  previewFormat === 'json'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Raw JSON Schema
              </button>
            </div>
          </div>

          <div className="bg-slate-950 p-5 rounded-lg border border-slate-800 max-h-[500px] overflow-y-auto">
            {previewFormat === 'json' ? (
              <pre className="text-xs font-mono text-cyan-200 whitespace-pre-wrap">
                {JSON.stringify(currentRun.report_data, null, 2)}
              </pre>
            ) : (
              <div className="text-xs text-slate-300 space-y-3 font-mono leading-relaxed">
                <div className="text-sm font-bold text-white border-b border-slate-800 pb-2">
                  # Algorithm-Optimized Reconnaissance Framework — Audit Report
                </div>
                <div><strong>Target Domain:</strong> `{currentRun.report_data.metadata?.target_domain}`</div>
                <div><strong>Execution Mode:</strong> `{currentRun.report_data.metadata?.mode?.toUpperCase()}`</div>
                <div><strong>Timestamp (UTC):</strong> `{currentRun.report_data.metadata?.timestamp}`</div>
                <div className="pt-2">
                  <strong>Discovered Subdomains:</strong> {currentRun.report_data.inventory?.subdomains?.length || 0}
                </div>
                <div>
                  <strong>Identified Services:</strong> {currentRun.report_data.inventory?.services?.length || 0}
                </div>
                <div>
                  <strong>Graph Nodes:</strong> {currentRun.report_data.graph?.metrics?.total_nodes || 0} (Edges: {currentRun.report_data.graph?.metrics?.total_edges || 0})
                </div>
                <div>
                  <strong>0/1 Knapsack Optimal Value:</strong> {currentRun.report_data.scheduler?.knapsack_dp?.total_value || 0} (Cost: {currentRun.report_data.scheduler?.knapsack_dp?.total_cost || 0})
                </div>
                <div className="text-slate-400 pt-2 border-t border-slate-800/80">
                  Use the download buttons above to retrieve the complete comprehensive markdown file formatted with full asset tables and mermaid graph topology.
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
