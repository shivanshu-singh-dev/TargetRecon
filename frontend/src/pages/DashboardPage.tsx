import React from 'react';
import {
  Globe,
  Server,
  Layers,
  Database,
  AlertTriangle,
  Clock,
  ArrowRight,
  FileText,
  Activity,
  PlayCircle,
  Wifi,
  Target,
  Shield,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import { RunDetails, RunSummary } from '../types';

interface DashboardPageProps {
  currentRun: RunDetails | null;
  runs: RunSummary[];
  onNavigate: (page: any) => void;
  onSelectRun: (runId: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  currentRun,
  runs,
  onNavigate,
  onSelectRun,
}) => {
  if (runs.length === 0) {
    return (
      <div className="p-8 max-w-6xl mx-auto">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-12 text-center max-w-xl mx-auto shadow-xl">
          <div className="w-16 h-16 bg-cyan-500/10 text-cyan-500 dark:text-cyan-400 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-cyan-500/20">
            <Activity className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
            No Reconnaissance Targets Yet
          </h2>
          <p className="text-slate-500 dark:text-slate-400 text-sm mb-6 leading-relaxed">
            Execute active or passive reconnaissance on an authorized target (e.g. <span className="font-mono text-cyan-600 dark:text-cyan-400 font-semibold">scanme.nmap.org</span>) to discover subdomains, open ports, and services.
          </p>
          <button
            onClick={() => onNavigate('recon-run')}
            className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-all shadow-lg shadow-cyan-500/20 cursor-pointer flex items-center gap-2 mx-auto"
          >
            <PlayCircle className="w-4 h-4" />
            Start Reconnaissance
          </button>
        </div>
      </div>
    );
  }

  // Calculate Global Aggregate Stats across all runs
  const totalTargets = new Set(runs.map((r) => r.target_domain)).size;
  const totalAssetsAcrossRuns = runs.reduce((acc, r) => acc + (r.asset_count || 0), 0);
  const activeRunsCount = runs.filter((r) => r.mode === 'active').length;
  const passiveRunsCount = runs.filter((r) => r.mode === 'passive').length;

  const report = currentRun?.report_data;
  const inv = report?.inventory || {
    subdomains: [],
    ip_addresses: [],
    services: [],
    dns_records: [],
    observations: [],
    errors: [],
  };
  const meta = report?.metadata || {
    target_domain: currentRun?.target_domain || runs[0]?.target_domain,
    mode: currentRun?.mode || runs[0]?.mode,
    timestamp: currentRun?.start_time || runs[0]?.start_time,
  };

  // Source coverage chart data
  const sourceCounts: Record<string, number> = {};
  for (const obs of inv.observations || []) {
    const src = obs.source || 'unknown';
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  }
  const sourceChartData = Object.entries(sourceCounts).map(([name, count]) => ({ name, count }));
  const chartColors = ['#06b6d4', '#10b981', '#6366f1', '#f59e0b', '#ec4899', '#3b82f6'];

  const openPortsCount = inv.services.length;
  const dnsCount = inv.dns_records?.length || 0;
  const errorsCount = inv.errors?.length || 0;

  const modeBadgeClass =
    meta.mode === 'active'
      ? 'bg-rose-500/10 text-rose-500 dark:text-rose-400 border-rose-500/30'
      : meta.mode === 'simulation'
      ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30'
      : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';

  const handleFocusTarget = (runId: string) => {
    onSelectRun(runId);
    setTimeout(() => {
      const el = document.getElementById('target-intelligence-drilldown');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }, 60);
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* ================================================================= */}
      {/* 1. Global Multi-Target Enterprise Overview                        */}
      {/* ================================================================= */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Target className="w-6 h-6 text-cyan-600 dark:text-cyan-400" />
              Reconnaissance Overview & Intelligence Hub
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Comprehensive telemetry aggregated across all surveyed network targets.
            </p>
          </div>

          <button
            onClick={() => onNavigate('recon-run')}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all shadow-md shadow-cyan-500/20 cursor-pointer flex items-center gap-2 self-start sm:self-auto"
          >
            <PlayCircle className="w-4 h-4" />
            New Recon Scan
          </button>
        </div>

        {/* Global Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-1">
              <span className="text-xs font-medium">Surveyed Targets</span>
              <Target className="w-4 h-4 text-cyan-500" />
            </div>
            <div className="text-2xl font-black text-slate-900 dark:text-white font-mono">{totalTargets}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Unique Root Domains</div>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-1">
              <span className="text-xs font-medium">Total Recorded Runs</span>
              <Activity className="w-4 h-4 text-emerald-500" />
            </div>
            <div className="text-2xl font-black text-slate-900 dark:text-white font-mono">{runs.length}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              {activeRunsCount} Active • {passiveRunsCount} Passive
            </div>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-1">
              <span className="text-xs font-medium">Discovered Assets</span>
              <Server className="w-4 h-4 text-indigo-500" />
            </div>
            <div className="text-2xl font-black text-slate-900 dark:text-white font-mono">{totalAssetsAcrossRuns}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Subdomains & IPs Tracked</div>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-1">
              <span className="text-xs font-medium">Engine Status</span>
              <Shield className="w-4 h-4 text-teal-500" />
            </div>
            <div className="text-2xl font-black text-emerald-600 dark:text-emerald-400 font-mono">ONLINE</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Ready for scanning</div>
          </div>
        </div>
      </div>

      {/* ================================================================= */}
      {/* 2. Target Directory Grid (Select Target to Drilldown)             */}
      {/* ================================================================= */}
      <div className="space-y-3">
        <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider text-xs">
          Surveyed Targets Directory (Click to Focus)
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {runs.map((r, idx) => {
            const isFocused = currentRun?.run_id === r.run_id;
            return (
              <div
                key={r.run_id}
                onClick={() => handleFocusTarget(r.run_id)}
                className={`p-4 rounded-xl border transition-all cursor-pointer relative ${
                  isFocused
                    ? 'bg-cyan-50/50 dark:bg-cyan-950/20 border-cyan-500 ring-2 ring-cyan-500/20 shadow-md'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 shadow-sm'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-700">
                    Run #{r.run_number || idx + 1}
                  </span>
                  <span
                    className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                      r.mode === 'active'
                        ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
                        : r.mode === 'simulation'
                        ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30'
                        : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                    }`}
                  >
                    {r.mode}
                  </span>
                </div>

                <div className="font-mono font-bold text-base text-slate-900 dark:text-white truncate">
                  {r.target_domain}
                </div>

                <div className="flex items-center gap-4 mt-3 pt-3 border-t border-slate-100 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                  <div>
                    <span className="font-bold text-slate-900 dark:text-white font-mono">{r.asset_count}</span> Assets
                  </div>
                  <div>•</div>
                  <div>
                    <span className="font-bold text-slate-900 dark:text-white font-mono">
                      {new Date(r.start_time).toLocaleDateString()}
                    </span>
                  </div>
                </div>

                {isFocused && (
                  <div className="mt-2 text-[11px] font-bold text-cyan-600 dark:text-cyan-400 flex items-center gap-1">
                    <span>Currently Focused Target</span>
                    <ChevronRight className="w-3 h-3" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ================================================================= */}
      {/* 3. Focused Target Intelligence Report                             */}
      {/* ================================================================= */}
      {currentRun && currentRun.report_data && (
        <div id="target-intelligence-drilldown" className="space-y-6 pt-4 border-t border-slate-200 dark:border-slate-800">
          {/* Target Banner */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-sm relative overflow-hidden">
            <div className="absolute right-0 top-0 w-96 h-full bg-gradient-to-l from-cyan-500/5 to-transparent pointer-events-none" />
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs uppercase tracking-wider font-semibold text-cyan-600 dark:text-cyan-400 font-mono">
                    Target Intelligence Drilldown
                  </span>
                  <span className="text-slate-300 dark:text-slate-600">•</span>
                  <span className="text-xs text-slate-500 dark:text-slate-400 font-mono flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    {new Date(meta.timestamp).toUTCString()}
                  </span>
                </div>
                <h2 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight flex items-center gap-3 flex-wrap">
                  <span className="font-mono text-cyan-600 dark:text-cyan-400 text-xl font-bold bg-cyan-50 dark:bg-cyan-950 px-2.5 py-1 rounded-md border border-cyan-200 dark:border-cyan-800">
                    Run #{currentRun.run_number || 1}
                  </span>
                  <span>{meta.target_domain}</span>
                  <span className={`text-xs uppercase font-bold tracking-wider px-2.5 py-1 rounded-md border ${modeBadgeClass}`}>
                    {meta.mode} MODE
                  </span>
                </h2>
              </div>

              <div className="flex items-center gap-3 flex-wrap">
                <button
                  onClick={() => onNavigate('subdomains')}
                  className="px-4 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-all flex items-center gap-2 cursor-pointer shadow-sm"
                >
                  View All Subdomains
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => onNavigate('service-map')}
                  className="px-4 py-2 rounded-lg bg-indigo-50 dark:bg-indigo-950/40 hover:bg-indigo-100 text-indigo-700 dark:text-indigo-300 text-xs font-semibold border border-indigo-200 dark:border-indigo-800 transition-all flex items-center gap-2 cursor-pointer shadow-sm"
                >
                  View Service Map
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => onNavigate('reports')}
                  className="px-4 py-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 text-xs font-semibold border border-cyan-500/30 transition-all flex items-center gap-2 cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5" />
                  Full Report
                </button>
              </div>
            </div>
          </div>

          {/* Focused KPI Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
            {[
              {
                label: 'Subdomains',
                value: inv.subdomains.length,
                sub: 'Discovered',
                icon: Globe,
                color: 'text-cyan-500 dark:text-cyan-400',
                onClick: () => onNavigate('subdomains'),
              },
              {
                label: 'IP Addresses',
                value: inv.ip_addresses.length,
                sub: 'Unique IPs',
                icon: Server,
                color: 'text-emerald-500 dark:text-emerald-400',
              },
              {
                label: 'Open Ports',
                value: openPortsCount,
                sub: 'Services Found',
                icon: Wifi,
                color: 'text-indigo-500 dark:text-indigo-400',
                onClick: () => onNavigate('service-map'),
              },
              {
                label: 'Services',
                value: inv.services.length,
                sub: 'Banners Matched',
                icon: Layers,
                color: 'text-violet-500 dark:text-violet-400',
                onClick: () => onNavigate('service-map'),
              },
              {
                label: 'DNS Records',
                value: dnsCount,
                sub: 'Zone Records',
                icon: Database,
                color: 'text-teal-500 dark:text-teal-400',
                onClick: () => onNavigate('dns-records'),
              },
              {
                label: 'Errors',
                value: errorsCount,
                sub: 'Scan Errors',
                icon: AlertTriangle,
                color: errorsCount > 0 ? 'text-amber-500 dark:text-amber-400' : 'text-slate-400',
              },
            ].map((kpi) => {
              const Icon = kpi.icon;
              return (
                <div
                  key={kpi.label}
                  onClick={kpi.onClick}
                  className={`bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-300 dark:hover:border-slate-700 transition-all ${kpi.onClick ? 'cursor-pointer' : ''}`}
                >
                  <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
                    <span className="text-xs font-medium">{kpi.label}</span>
                    <Icon className={`w-4 h-4 ${kpi.color}`} />
                  </div>
                  <div className="text-2xl font-black text-slate-900 dark:text-white font-mono">{kpi.value}</div>
                  <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">{kpi.sub}</div>
                </div>
              );
            })}
          </div>

          {/* Subdomains & Services Quick Tables */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Subdomains Preview */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Subdomains Discovered ({inv.subdomains.length})
                </h3>
                <button
                  onClick={() => onNavigate('subdomains')}
                  className="text-xs text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 font-medium flex items-center gap-1 cursor-pointer"
                >
                  View All <ArrowRight className="w-3 h-3" />
                </button>
              </div>
              {inv.subdomains.length === 0 ? (
                <div className="text-xs text-slate-400 italic py-6 text-center">
                  No subdomains discovered for this host.
                </div>
              ) : (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-400 uppercase tracking-wider">
                      <th className="py-2 text-left font-semibold">Subdomain</th>
                      <th className="py-2 text-left font-semibold">Has IPs</th>
                      <th className="py-2 text-left font-semibold">Sources</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
                    {inv.subdomains.slice(0, 5).map((sub) => {
                      const ips = (inv.dns_records || []).filter(
                        (r) => r.host === sub && r.record_type === 'A'
                      );
                      const sources = [...new Set(
                        (inv.observations || [])
                          .filter((o) => o.asset_id === sub)
                          .map((o) => o.source)
                      )];
                      return (
                        <tr key={sub} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                          <td className="py-2 text-cyan-600 dark:text-cyan-400 truncate max-w-[180px]">{sub}</td>
                          <td className="py-2">
                            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${ips.length > 0 ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400' : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-500'}`}>
                              {ips.length > 0 ? 'Yes' : 'No'}
                            </span>
                          </td>
                          <td className="py-2">
                            <div className="flex gap-1 flex-wrap">
                              {sources.slice(0, 2).map((src) => (
                                <span key={src} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                                  {src}
                                </span>
                              ))}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Services Preview */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Identified Services ({inv.services.length})
                </h3>
                <button
                  onClick={() => onNavigate('service-map')}
                  className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 font-medium flex items-center gap-1 cursor-pointer"
                >
                  View All <ArrowRight className="w-3 h-3" />
                </button>
              </div>
              {inv.services.length === 0 ? (
                <div className="text-xs text-slate-400 italic py-6 text-center">
                  No active services found yet. Run an Active Scan to discover open ports.
                </div>
              ) : (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-400 uppercase tracking-wider">
                      <th className="py-2 text-left font-semibold">Port</th>
                      <th className="py-2 text-left font-semibold">Product & Stack</th>
                      <th className="py-2 text-left font-semibold">Security</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
                    {inv.services.slice(0, 5).map((svc) => (
                      <tr key={svc.endpoint_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <td className="py-2 font-bold text-slate-900 dark:text-white">
                          {svc.port}/{svc.protocol.toUpperCase()}
                        </td>
                        <td className="py-2">
                          <span className="text-indigo-600 dark:text-indigo-400 font-bold">
                            {svc.product || svc.protocol || '—'}{svc.version ? ` v${svc.version}` : ''}
                          </span>
                          {svc.detected_frameworks && svc.detected_frameworks.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-0.5 font-sans">
                              {svc.detected_frameworks.slice(0, 2).map((f) => (
                                <span key={f} className="text-[9px] px-1.5 py-0.2 rounded bg-violet-50 dark:bg-violet-950/40 text-violet-600 dark:text-violet-300 border border-violet-200 dark:border-violet-800/50">
                                  {f}
                                </span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="py-2">
                          {svc.security_score ? (
                            <span className="text-[10px] font-sans font-bold px-1.5 py-0.5 rounded bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30">
                              Grade {svc.security_score}
                            </span>
                          ) : (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                              {svc.source}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Source Coverage Chart */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-1 flex items-center justify-between">
              <span>Source Observation Coverage</span>
              <span className="text-xs font-normal text-slate-400 font-mono">
                {inv.observations?.length || 0} Total Observations
              </span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              Observation counts by data collector — illustrates how passive resolvers and active socket probes contribute to this target.
            </p>
            <div className="h-44 w-full">
              {sourceChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={sourceChartData} layout="vertical" margin={{ left: 20, right: 20, top: 5, bottom: 5 }}>
                    <XAxis
                      type="number"
                      stroke="#94a3b8"
                      fontSize={11}
                      tick={{ fill: '#94a3b8' }}
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      stroke="#94a3b8"
                      fontSize={11}
                      width={100}
                      tick={{ fill: '#94a3b8' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
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
        </div>
      )}

      {/* ================================================================= */}
      {/* 4. Complete Runs Audit Table with Clean Run Numbers               */}
      {/* ================================================================= */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Audit History of All Runs</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Chronological ledger of executed sessions.</p>
          </div>
          <button
            onClick={() => onNavigate('reports')}
            className="text-xs text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 font-medium flex items-center gap-1 cursor-pointer"
          >
            All Reports <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <th className="py-2.5 px-3">Run #</th>
                <th className="py-2.5 px-3">Target Domain</th>
                <th className="py-2.5 px-3">Mode</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Assets</th>
                <th className="py-2.5 px-3">Date</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
              {runs.map((r, idx) => {
                const isSelected = currentRun?.run_id === r.run_id;
                return (
                  <tr
                    key={r.run_id}
                    onClick={() => handleFocusTarget(r.run_id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-50 dark:bg-cyan-950/40 border-l-4 border-cyan-500 font-semibold'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-2.5 px-3 font-bold text-cyan-700 dark:text-cyan-300">
                      Run #{r.run_number || idx + 1}
                    </td>
                    <td className="py-2.5 px-3 text-slate-900 dark:text-white font-bold">{r.target_domain}</td>
                    <td className="py-2.5 px-3">
                      <span className="uppercase text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                        {r.mode}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full border ${
                          r.status === 'completed'
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                            : r.status === 'running'
                            ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30 animate-pulse'
                            : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
                        }`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-600 dark:text-slate-300">{r.asset_count}</td>
                    <td className="py-2.5 px-3 text-slate-400">{new Date(r.start_time).toLocaleDateString()}</td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleFocusTarget(r.run_id);
                        }}
                        className={`text-xs font-sans px-2.5 py-1 rounded transition-colors ${
                          isSelected
                            ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm'
                            : 'text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 font-semibold'
                        }`}
                      >
                        {isSelected ? 'Focused ✓' : 'Focus Target →'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
