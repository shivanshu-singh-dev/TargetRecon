import React from 'react';
import { Shield, RefreshCw, Terminal, Sun, Moon, ArrowLeft } from 'lucide-react';
import { HealthStatus, RunSummary } from '../types';
import { PageId } from './Sidebar';

interface HeaderProps {
  health?: HealthStatus | null;
  runs: RunSummary[];
  selectedRunId?: string;
  onSelectRun: (runId: string) => void;
  onRefresh: () => void;
  isRefreshing?: boolean;
  isDark: boolean;
  onToggleTheme: () => void;
  activePage: PageId;
  onNavigate: (page: PageId) => void;
  canGoBack: boolean;
  onGoBack: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  runs,
  selectedRunId,
  onSelectRun,
  onRefresh,
  isRefreshing = false,
  isDark,
  onToggleTheme,
  activePage,
  onNavigate,
  canGoBack,
  onGoBack,
}) => {
  const currentRun = runs.find((r) => r.run_id === selectedRunId) || runs[0];

  return (
    <header className="h-16 bg-white dark:bg-slate-900/80 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-6 shrink-0 z-10">
      {/* Run Selector Context & Navigation */}
      <div className="flex items-center gap-3">
        {/* Back Navigation Button to previous page */}
        {canGoBack && (
          <button
            onClick={onGoBack}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-700 transition-all cursor-pointer shadow-sm mr-1"
            title="Go back to previous page"
          >
            <ArrowLeft className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
            <span>Back</span>
          </button>
        )}

        <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
          <Terminal className="w-3.5 h-3.5 text-cyan-500 dark:text-cyan-400" />
          Target:
        </div>
        {runs.length > 0 ? (
          <select
            value={selectedRunId || ''}
            onChange={(e) => onSelectRun(e.target.value)}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 rounded-md px-3 py-1.5 text-xs font-mono text-cyan-700 dark:text-cyan-300 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all cursor-pointer"
          >
            {runs.map((r, idx) => (
              <option key={r.run_id} value={r.run_id}>
                Run #{r.run_number || idx + 1}: {r.target_domain} [{r.mode.toUpperCase()}] —{' '}
                {new Date(r.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
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
                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                : currentRun.status === 'running'
                ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30 animate-pulse'
                : currentRun.status === 'failed'
                ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-700'
            }`}
          >
            {currentRun.status}
          </span>
        )}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Tool badges */}
        {health && (
          <div className="hidden lg:flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span className="flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${health.external_tools.nmap ? 'bg-emerald-400' : 'bg-slate-400 dark:bg-slate-600'}`} />
              Nmap
            </span>
            <span className="flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${health.external_tools.whois ? 'bg-emerald-400' : 'bg-slate-400 dark:bg-slate-600'}`} />
              WHOIS
            </span>
            <span className="flex items-center gap-1">
              <span className={`w-2 h-2 rounded-full ${health.external_tools.theHarvester ? 'bg-emerald-400' : 'bg-slate-400 dark:bg-slate-600'}`} />
              theHarvester
            </span>
          </div>
        )}

        {/* Theme Toggle */}
        <button
          onClick={onToggleTheme}
          className="p-2 rounded-md bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 transition-colors border border-slate-200 dark:border-slate-700 cursor-pointer"
          title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-xs font-medium text-slate-700 dark:text-slate-300 transition-colors border border-slate-200 dark:border-slate-700 cursor-pointer disabled:opacity-50"
          title="Refresh run status"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-500 dark:text-cyan-400' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>
    </header>
  );
};
