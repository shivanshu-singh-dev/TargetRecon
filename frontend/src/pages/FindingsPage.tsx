import React from 'react';
import { AlertTriangle, ShieldCheck, Info, CheckCircle2, AlertCircle } from 'lucide-react';
import { RunDetails, ConsistencyFinding } from '../types';

interface FindingsPageProps {
  currentRun: RunDetails | null;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({ currentRun }) => {
  if (!currentRun || !currentRun.report_data) {
    return (
      <div className="p-8 text-center text-slate-400">
        No active run data loaded.
      </div>
    );
  }

  const findings = currentRun.report_data.consistency_findings || [];
  const errors = currentRun.report_data.inventory?.errors || [];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-6 h-6 text-amber-400" />
          Evidence Consistency & Discrepancy Findings
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Identifies corroboration conflicts, unconfirmed historical records, and missing infrastructure resolutions.
        </p>
      </div>

      {/* Defensive Security Notice */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-start gap-3">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 leading-relaxed">
          <strong>Academic Caveat:</strong> Evidence discrepancies represent contradictions between passive historical records and active observations. They are highlighted for asset correlation and network auditing; they do <em>not</em> automatically represent exploitable security vulnerabilities.
        </div>
      </div>

      {/* Main Findings List */}
      <div className="space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
          Consistency Discrepancies ({findings.length})
        </h2>

        {findings.length > 0 ? (
          <div className="space-y-3">
            {findings.map((f: ConsistencyFinding, idx: number) => {
              let badgeColor = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
              let verificationStep = 'Perform active DNS query against authoritative nameservers.';

              if (f.finding_type === 'FINGERPRINT_DISAGREEMENT') {
                badgeColor = 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30';
                verificationStep = 'Inspect raw HTTP response headers and TCP banner exchange manually.';
              } else if (f.finding_type === 'INDEXED_SERVICE_UNCONFIRMED') {
                badgeColor = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
                verificationStep = 'Verify if firewall policy has closed this port since historical indexing.';
              } else if (f.finding_type === 'CONFLICTING_OBSERVATIONS') {
                badgeColor = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
                verificationStep = 'Check TTL expiration and compare multi-CDN DNS responses.';
              }

              return (
                <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                    <div className="flex items-center gap-2.5">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${badgeColor}`}>
                        {f.finding_type}
                      </span>
                      <span className="font-mono text-sm font-bold text-white">
                        {f.asset_id}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">
                      {new Date(f.timestamp).toUTCString()}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {f.description}
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                    <div>
                      <span className="text-slate-500 font-semibold block mb-0.5">Originating Sources:</span>
                      <div className="flex flex-wrap gap-1 font-mono text-[11px]">
                        {(f.evidence_sources || []).map((src) => (
                          <span key={src} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            {src}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 font-semibold block mb-0.5">Recommended Audit Action:</span>
                      <span className="text-slate-300 text-[11px]">{verificationStep}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            <div className="text-sm font-bold text-white">No Structural Discrepancies Detected</div>
            <div className="text-xs text-slate-500 mt-1">All passive subdomains and recorded services corroborate consistently.</div>
          </div>
        )}
      </div>

      {/* Collection Errors and Incomplete Sources */}
      {errors.length > 0 && (
        <div className="space-y-4 pt-4 border-t border-slate-800">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-slate-400" />
            Collection Notices & Missing External Tools ({errors.length})
          </h2>
          <div className="space-y-2">
            {errors.map((err, idx) => (
              <div key={idx} className="bg-slate-900 border border-slate-800 p-3.5 rounded-lg flex items-center justify-between text-xs">
                <div>
                  <span className="font-bold text-cyan-400 uppercase font-mono mr-2">{err.source}:</span>
                  <span className="text-slate-300">{err.message}</span>
                </div>
                {err.timestamp && (
                  <span className="text-[10px] text-slate-500 font-mono shrink-0 ml-4">
                    {new Date(err.timestamp).toLocaleTimeString()}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
