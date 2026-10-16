import React, { useState, useEffect } from 'react';
import {
  Play,
  ShieldAlert,
  Sliders,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  Clock,
  StopCircle,
} from 'lucide-react';
import { createRun, fetchRunStatus, cancelRun } from '../api';

interface NewRunPageProps {
  onRunCreated: (runId: string) => void;
}

export const NewRunPage: React.FC<NewRunPageProps> = ({ onRunCreated }) => {
  const [targetDomain, setTargetDomain] = useState('example.com');
  const [mode, setMode] = useState<'demo' | 'passive' | 'active'>('demo');
  const [budget, setBudget] = useState(15);
  const [scopeText, setScopeText] = useState('example.com\n93.184.216.0/24\napi.example.com');
  const [confirmActive, setConfirmActive] = useState(false);
  const [enableZoneTransfer, setEnableZoneTransfer] = useState(false);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Active Job Status Poller
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<any>(null);

  useEffect(() => {
    if (!activeJobId) return;

    const interval = setInterval(async () => {
      try {
        const status = await fetchRunStatus(activeJobId);
        setJobStatus(status);

        if (status.status === 'completed' || status.status === 'failed' || status.status === 'cancelled') {
          clearInterval(interval);
          if (status.status === 'completed') {
            onRunCreated(activeJobId);
          }
        }
      } catch (err) {
        console.error('Error polling status:', err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [activeJobId, onRunCreated]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const cleanDomain = targetDomain.trim().toLowerCase();
    if (!cleanDomain) {
      setErrorMessage('Target domain is required.');
      return;
    }

    if (mode === 'active') {
      if (!confirmActive) {
        setErrorMessage('Active network scanning requires explicit user confirmation of scope authorization.');
        return;
      }
      const rules = scopeText
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'));
      if (rules.length === 0) {
        setErrorMessage('Active scanning requires at least one authorization rule (hostname or CIDR).');
        return;
      }
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
        confirm_active: confirmActive,
        scope_rules: scopeRules,
        enable_zone_transfer: enableZoneTransfer,
      });

      setActiveJobId(res.run_id);
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
    } catch (err: any) {
      console.error('Failed to cancel:', err);
    }
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Sliders className="w-6 h-6 text-cyan-400" />
          Configure Reconnaissance Run
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Select target domain, execution mode, optimization budget, and safety boundaries.
        </p>
      </div>

      {errorMessage && (
        <div className="bg-rose-500/10 border border-rose-500/30 text-rose-300 p-4 rounded-xl flex items-start gap-3 text-sm">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold">Configuration Validation Error</div>
            <div className="text-xs text-rose-200 mt-0.5">{errorMessage}</div>
          </div>
        </div>
      )}

      {/* Active Run Live Tracker Card */}
      {activeJobId && jobStatus && (
        <div className="bg-slate-900 border border-cyan-500/40 rounded-xl p-6 shadow-xl relative overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <span
                className={`w-3 h-3 rounded-full ${
                  jobStatus.status === 'completed'
                    ? 'bg-emerald-400'
                    : jobStatus.status === 'running'
                    ? 'bg-cyan-400 animate-ping'
                    : 'bg-rose-400'
                }`}
              />
              <h3 className="font-bold text-white text-base font-mono">
                Run: {activeJobId}
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                {jobStatus.status}
              </span>
              {jobStatus.status === 'running' && (
                <button
                  onClick={handleCancel}
                  className="px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-400 text-xs font-medium rounded border border-rose-500/30 flex items-center gap-1.5 cursor-pointer"
                >
                  <StopCircle className="w-3.5 h-3.5" />
                  Cancel
                </button>
              )}
            </div>
          </div>

          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 flex items-center gap-2">
            <span className="text-cyan-400 font-bold">&gt;</span>
            <span>{jobStatus.progress_message}</span>
          </div>

          {jobStatus.status === 'completed' && (
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => onRunCreated(activeJobId)}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg shadow-md cursor-pointer"
              >
                Open Completed Audit Dashboard
              </button>
            </div>
          )}
        </div>
      )}

      {/* Main Form */}
      <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg space-y-6">
        {/* Domain Input */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
            Target Root Domain
          </label>
          <input
            type="text"
            value={targetDomain}
            onChange={(e) => setTargetDomain(e.target.value)}
            placeholder="example.com"
            disabled={isSubmitting || (activeJobId !== null && jobStatus?.status === 'running')}
            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm font-mono text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all disabled:opacity-50"
          />
          <p className="text-xs text-slate-400 mt-1.5">
            Normalized automatically (lowercased, whitespace and trailing dots stripped).
          </p>
        </div>

        {/* Execution Mode Selector */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
            Reconnaissance Strategy Mode
          </label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Demo Option */}
            <div
              onClick={() => setMode('demo')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                mode === 'demo'
                  ? 'bg-cyan-500/10 border-cyan-500/60 shadow-md shadow-cyan-500/10'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-white">Demo Mode</span>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  Offline
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Zero network traffic. Loads offline test fixtures for instant algorithmic evaluation and reproducible reports.
              </p>
            </div>

            {/* Passive Option */}
            <div
              onClick={() => setMode('passive')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                mode === 'passive'
                  ? 'bg-emerald-500/10 border-emerald-500/60 shadow-md shadow-emerald-500/10'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-white">Passive Recon</span>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Safe OSINT
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Queries public databases (crt.sh, DNS resolvers, WHOIS) without directly sending active packets to target hosts.
              </p>
            </div>

            {/* Active Option */}
            <div
              onClick={() => setMode('active')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                mode === 'active'
                  ? 'bg-rose-500/10 border-rose-500/60 shadow-md shadow-rose-500/10'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-white">Authorized Active</span>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  Gated Scope
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Active banner grabbing & service scan. Strictly gated by authorization allowlist and explicit confirmation.
              </p>
            </div>
          </div>
        </div>

        {/* DAA Probe Budget */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
            0/1 Knapsack Probe Budget (Cost Units)
          </label>
          <div className="flex items-center gap-4">
            <input
              type="range"
              min={5}
              max={100}
              step={5}
              value={budget}
              onChange={(e) => setBudget(Number(e.target.value))}
              className="flex-1 accent-cyan-500"
            />
            <span className="w-16 text-center font-mono font-bold text-sm bg-slate-950 border border-slate-800 py-1.5 rounded text-cyan-400">
              {budget}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Controls max probe overhead. The 0/1 Knapsack DP algorithm selects the subset of probes that maximizes estimated information value within this budget.
          </p>
        </div>

        {/* Scope File & Confirmation (Only shown when mode == active) */}
        {mode === 'active' && (
          <div className="bg-rose-950/20 border border-rose-500/30 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
              <ShieldAlert className="w-4 h-4" />
              <span>Strict Authorization Scope Enforcement</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Scope Allowlist (One hostname, CIDR block, or IP per line):
              </label>
              <textarea
                rows={4}
                value={scopeText}
                onChange={(e) => setScopeText(e.target.value)}
                className="w-full bg-slate-950 border border-rose-500/30 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-rose-400"
                placeholder="example.com&#10;93.184.216.0/24"
              />
              <p className="text-[11px] text-slate-400 mt-1">
                Subdomains are NOT scanned merely because they share a root domain. Each candidate host and resolved IP must strictly match this allowlist.
              </p>
            </div>

            <div className="space-y-2 pt-2">
              <label className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-200">
                <input
                  type="checkbox"
                  checked={confirmActive}
                  onChange={(e) => setConfirmActive(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-950 border-slate-700 text-rose-500 focus:ring-rose-500"
                />
                <span>
                  I confirm that I have written legal authorization to probe the targets listed in the scope allowlist.
                </span>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-400">
                <input
                  type="checkbox"
                  checked={enableZoneTransfer}
                  onChange={(e) => setEnableZoneTransfer(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-950 border-slate-700 text-rose-500 focus:ring-rose-500"
                />
                <span>
                  Enable DNS Zone-Transfer (AXFR) test (strictly restricted to authorized nameservers).
                </span>
              </label>
            </div>
          </div>
        )}

        {/* Submit Control */}
        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting || (activeJobId !== null && jobStatus?.status === 'running')}
            className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-sm rounded-lg shadow-lg shadow-cyan-500/20 transition-all flex items-center gap-2 cursor-pointer"
          >
            <Play className="w-4 h-4 fill-slate-950" />
            <span>{isSubmitting ? 'Dispatching...' : 'Dispatch Reconnaissance Run'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
