import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  StopCircle,
  Terminal,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import { createRun, fetchRunStatus, cancelRun } from '../api';

interface ReconRunPageProps {
  onRunCreated: (runId: string) => void;
}

interface LogEntry {
  timestamp: string;
  message: string;
}

export const ReconRunPage: React.FC<ReconRunPageProps> = ({ onRunCreated }) => {
  const [targetDomain, setTargetDomain] = useState('scanme.nmap.org');
  const [mode, setMode] = useState<'simulation' | 'passive' | 'active'>('active');
  const [budget, setBudget] = useState(100);
  const [scopeText, setScopeText] = useState('');
  const [enableZoneTransfer, setEnableZoneTransfer] = useState(false);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Live log tracking
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<string>('idle');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const lastProgressRef = useRef<string>('');
  const logContainerRef = useRef<HTMLDivElement | null>(null);

  // Poll run status
  useEffect(() => {
    if (!activeJobId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetchRunStatus(activeJobId);
        setJobStatus(res.status);

        if (res.progress_message && res.progress_message !== lastProgressRef.current) {
          lastProgressRef.current = res.progress_message;
          const timeStr = new Date().toLocaleTimeString();
          setLogs((prev) => [...prev, { timestamp: timeStr, message: res.progress_message }]);
        }

        if (res.status === 'completed' || res.status === 'failed' || res.status === 'cancelled') {
          clearInterval(interval);
          if (res.status === 'completed') {
            const timeStr = new Date().toLocaleTimeString();
            setLogs((prev) => [
              ...prev,
              { timestamp: timeStr, message: 'Reconnaissance completed successfully. Results ready.' },
            ]);
          }
        }
      } catch (err) {
        console.error('Error polling status:', err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [activeJobId]);

  // Auto-scroll logs
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const cleanDomain = targetDomain.trim().toLowerCase();
    if (!cleanDomain) {
      setErrorMessage('Target domain is required.');
      return;
    }

    const scopeRules = scopeText
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));

    try {
      setIsSubmitting(true);
      const res = await createRun({
        target_domain: cleanDomain,
        mode,
        budget,
        confirm_active: true,
        scope_rules: scopeRules,
        enable_zone_transfer: enableZoneTransfer,
      });

      setActiveJobId(res.run_id);
      setJobStatus('running');
      setLogs([
        {
          timestamp: new Date().toLocaleTimeString(),
          message: `Dispatched ${mode.toUpperCase()} reconnaissance job (${res.run_id}) on ${cleanDomain}`,
        },
      ]);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to dispatch reconnaissance run.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = async () => {
    if (!activeJobId) return;
    try {
      await cancelRun(activeJobId);
      setJobStatus('cancelled');
      setLogs((prev) => [
        ...prev,
        { timestamp: new Date().toLocaleTimeString(), message: 'Run cancelled by user request.' },
      ]);
    } catch (err: any) {
      console.error('Failed to cancel run:', err);
    }
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Sliders className="w-6 h-6 text-cyan-600 dark:text-cyan-400" />
          Run Reconnaissance
        </h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          Execute OSINT collection, DNS enumeration, active port discovery, and service fingerprinting.
        </p>
      </div>

      {errorMessage && (
        <div className="bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-300 p-4 rounded-xl flex items-start gap-3 text-sm">
          <AlertTriangle className="w-5 h-5 text-rose-500 dark:text-rose-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold">Execution Error</div>
            <div className="text-xs text-rose-700 dark:text-rose-200 mt-0.5">{errorMessage}</div>
          </div>
        </div>
      )}

      {/* Live Stream / Terminal Panel */}
      {activeJobId && (
        <div className="bg-white dark:bg-slate-900 border border-cyan-500/40 rounded-xl p-6 shadow-xl relative overflow-hidden space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span
                className={`w-3 h-3 rounded-full ${
                  jobStatus === 'completed'
                    ? 'bg-emerald-400'
                    : jobStatus === 'running'
                    ? 'bg-cyan-400 animate-ping'
                    : 'bg-rose-400'
                }`}
              />
              <h3 className="font-bold text-slate-900 dark:text-white text-base font-mono flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-500 dark:text-cyan-400" />
                Live Recon Session: {activeJobId}
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`text-xs font-bold uppercase px-2.5 py-0.5 rounded-full border ${
                  jobStatus === 'completed'
                    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                    : jobStatus === 'running'
                    ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30 animate-pulse'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-700'
                }`}
              >
                {jobStatus}
              </span>
              {jobStatus === 'running' && (
                <button
                  onClick={handleCancel}
                  className="px-3 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-600 dark:text-rose-400 text-xs font-medium rounded border border-rose-500/30 flex items-center gap-1.5 cursor-pointer"
                >
                  <StopCircle className="w-3.5 h-3.5" />
                  Cancel
                </button>
              )}
            </div>
          </div>

          {/* Terminal log output */}
          <div
            ref={logContainerRef}
            className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 h-48 overflow-y-auto space-y-1.5"
          >
            {logs.length === 0 ? (
              <div className="text-slate-600 italic">Waiting for engine output...</div>
            ) : (
              logs.map((log, index) => (
                <div key={index} className="flex items-start gap-2">
                  <span className="text-slate-500 shrink-0">[{log.timestamp}]</span>
                  <span className="text-cyan-400 font-bold shrink-0">&gt;</span>
                  <span className="text-slate-200">{log.message}</span>
                </div>
              ))
            )}
          </div>

          {jobStatus === 'completed' && (
            <div className="flex justify-end pt-2">
              <button
                onClick={() => onRunCreated(activeJobId)}
                className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg shadow-md cursor-pointer flex items-center gap-2"
              >
                <span>View Full Results</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* Main Recon Configuration Form */}
      <form
        onSubmit={handleSubmit}
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-sm space-y-6"
      >
        {/* Domain Input */}
        <div>
          <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-2">
            Target Domain
          </label>
          <input
            type="text"
            value={targetDomain}
            onChange={(e) => setTargetDomain(e.target.value)}
            placeholder="example.com"
            disabled={isSubmitting || jobStatus === 'running'}
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-sm font-mono text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all disabled:opacity-50"
          />
        {/* Target Recommendations */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
          <span className="text-slate-500 dark:text-slate-400 font-medium">Safe Targets:</span>
          {['scanme.nmap.org', 'testphp.vulnweb.com', 'example.com', 'hackthissite.org', 'owasp.org'].map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTargetDomain(t)}
              className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 hover:bg-cyan-50 dark:hover:bg-cyan-950 text-cyan-700 dark:text-cyan-400 border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer font-mono text-[11px]"
            >
              {t}
            </button>
          ))}
        </div>
        </div>

        {/* Execution Mode Selector */}
        <div>
          <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-2">
            Reconnaissance Mode
          </label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Simulation Option */}
            <div
              onClick={() => setMode('simulation')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                mode === 'simulation'
                  ? 'bg-cyan-500/10 border-cyan-500/60 shadow-md shadow-cyan-500/10'
                  : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-slate-900 dark:text-white">Simulation</span>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">
                  Offline
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Zero network requests. Evaluates full pipeline using saved test fixtures for offline demonstration.
              </p>
            </div>

            {/* Passive Option */}
            <div
              onClick={() => setMode('passive')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                mode === 'passive'
                  ? 'bg-emerald-500/10 border-emerald-500/60 shadow-md shadow-emerald-500/10'
                  : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-slate-900 dark:text-white">Passive Recon</span>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                  Safe OSINT
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Queries public databases (crt.sh Certificate Transparency, DNS servers, WHOIS) without touching target hosts.
              </p>
            </div>

            {/* Active Option */}
            <div
              onClick={() => setMode('active')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                mode === 'active'
                  ? 'bg-rose-500/10 border-rose-500/60 shadow-md shadow-rose-500/10'
                  : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-slate-900 dark:text-white">Active Scan</span>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/30">
                  Port Probing
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Active socket connections to discover open ports, grab raw service banners, and match application signatures.
              </p>
            </div>
          </div>
        </div>

        {/* Probe Budget */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
              Active Probe Allowance (Cost Units)
            </label>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Default: 100 units
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <input
                type="number"
                min={1}
                max={10000}
                value={budget}
                onChange={(e) => {
                  const val = parseInt(e.target.value, 10);
                  setBudget(isNaN(val) ? 1 : Math.max(1, Math.min(10000, val)));
                }}
                className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-sm font-mono font-bold text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-colors"
                placeholder="100"
              />
              <span className="absolute right-3 top-2.5 text-xs text-slate-400 font-mono pointer-events-none">
                units
              </span>
            </div>

            {/* Quick Presets */}
            <div className="flex items-center gap-1.5 flex-wrap">
              {[25, 50, 100, 250, 500, 1000].map((preset) => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => setBudget(preset)}
                  className={`px-3 py-1.5 text-xs font-mono font-semibold rounded-md border transition-all cursor-pointer ${
                    budget === preset
                      ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/40 shadow-sm'
                      : 'bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {preset}
                </button>
              ))}
            </div>
          </div>

          <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
            Controls maximum probe volume and network overhead (default: 100). The scheduler selects the highest-priority attack surfaces to maximize intelligence extraction while preventing WAF bans.
          </p>
        </div>

        {/* Optional Scope Rules when Active */}
        {mode === 'active' && (
          <div className="bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2 text-rose-500 dark:text-rose-400 font-bold text-sm">
              <ShieldAlert className="w-4 h-4" />
              <span>Target Scope Filter (Optional)</span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Leave blank to automatically authorize the target domain and all discovered subdomains. Only enter specific CIDRs if you need to restrict IP ranges.
            </p>
            <textarea
              rows={2}
              value={scopeText}
              onChange={(e) => setScopeText(e.target.value)}
              className="w-full bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-900 dark:text-slate-200 focus:outline-none focus:border-cyan-400"
              placeholder="Leave blank for automatic target scope"
            />
          </div>
        )}

        {/* Submit */}
        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting || jobStatus === 'running'}
            className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-sm rounded-lg shadow-lg shadow-cyan-500/20 transition-all flex items-center gap-2 cursor-pointer"
          >
            <Play className="w-4 h-4 fill-slate-950" />
            <span>{isSubmitting ? 'Starting Scan...' : 'Start Reconnaissance'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
