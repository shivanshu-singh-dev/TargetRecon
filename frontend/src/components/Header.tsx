import React from 'react';
import { Shield, RefreshCw, Terminal, CheckCircle2, AlertCircle } from 'lucide-react';
import { HealthStatus, RunSummary } from '../types';

interface HeaderProps {
  health?: HealthStatus | null;
  runs: RunSummary[];
  selectedRunId?: string;
  onSelectRun: (runId: string) => void;
  onRefresh: () => void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  runs,
  selectedRunId,
  onSelectRun,
  onRefresh,
  isRefreshing = false,
}) => {
  const currentRun = runs.find((r) => r.run_id === selectedRunId) || runs[0];

  return (
    <header className="h-16 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between px-6 shrink-0 backdrop-blur z-10">
      {/* Run Selector Context */}
      <div className="flex items-center gap-3">
        <div className="text-xs uppercase font-semibold text-slate-400 flex items-center gap-1.5">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          Active Target Context:
        </div>
        {runs.length > 0 ? (
          <select
            value={selectedRunId || ''}
            onChange={(e) => onSelectRun(e.target.value)}
            className="bg-slate-950 border border-slate-700/80 rounded-md px-3 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all cursor-pointer"
          >
            {runs.map((r) => (
              <option key={r.run_id} value={r.run_id}>
                {r.target_domain} [{r.mode.toUpperCase()}] — {new Date(r.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </option>
            ))}
          </select>
        ) : (
          <span className="text-xs text-slate-400 italic">No runs available yet</span>
        )}

        {currentRun && (
          <span
            className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full border ${
              currentRun.status === 'completed'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : currentRun.status === 'running'
                ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse'
                : currentRun.status === 'failed'
                ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
          >
            {currentRun.status}
          </span>
        )}
      </div>

      {/* Right Controls: Health & Actions */}
      <div className="flex items-center gap-4">
        {/* Tool badges */}
        {health && (
          <div className="hidden lg:flex items-center gap-2 text-xs text-slate-400">
            <span className="flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${health.external_tools.nmap ? 'bg-emerald-400' : 'bg-slate-600'}`} />
              Nmap
            </span>
            <span className="flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${health.external_tools.whois ? 'bg-emerald-400' : 'bg-slate-600'}`} />
              WHOIS
            </span>
            <span className="flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${health.external_tools.theHarvester ? 'bg-emerald-400' : 'bg-slate-600'}`} />
              theHarvester
            </span>
          </div>
        )}

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors border border-slate-700 cursor-pointer disabled:opacity-50"
          title="Refresh run status"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>
    </header>
  );
};
