import React, { useState, useMemo } from 'react';
import {
  Layers,
  Search,
  Download,
  Wifi,
  ChevronDown,
  ChevronUp,
  Terminal,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Server,
  Lock,
  Globe,
  CheckCircle2,
  XCircle,
  Cpu,
} from 'lucide-react';
import { RunDetails, ServiceEndpoint } from '../types';

interface ServiceMapPageProps {
  currentRun: RunDetails | null;
}

export const ServiceMapPage: React.FC<ServiceMapPageProps> = ({ currentRun }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedBanners, setExpandedBanners] = useState<Record<string, boolean>>({});
  const [expandedDetails, setExpandedDetails] = useState<Record<string, boolean>>({});

  if (!currentRun || !currentRun.report_data) {
    return (
      <div className="p-8 text-center text-slate-500 dark:text-slate-400">
        No active reconnaissance run loaded. Start or select a run first.
      </div>
    );
  }

  const inv = currentRun.report_data.inventory || {
    subdomains: [],
    ip_addresses: [],
    dns_records: [],
    services: [],
    observations: [],
    errors: [],
  };

  // Group services by host
  const groupedByHost = useMemo(() => {
    const map: Record<string, ServiceEndpoint[]> = {};
    for (const svc of inv.services || []) {
      const h = svc.host || 'Unknown Host';
      if (!map[h]) map[h] = [];
      map[h].push(svc);
    }
    return map;
  }, [inv.services]);

  // Filtered hosts based on search query
  const filteredHosts = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return Object.entries(groupedByHost);

    return Object.entries(groupedByHost).filter(([host, svcs]) => {
      if (host.toLowerCase().includes(q)) return true;
      return svcs.some(
        (s) =>
          String(s.port).includes(q) ||
          (s.product || '').toLowerCase().includes(q) ||
          (s.banner || '').toLowerCase().includes(q) ||
          (s.protocol || '').toLowerCase().includes(q) ||
          (s.detected_frameworks || []).some((f) => f.toLowerCase().includes(q)) ||
          (s.security_score || '').toLowerCase().includes(q)
      );
    });
  }, [groupedByHost, searchQuery]);

  const toggleBanner = (endpointId: string) => {
    setExpandedBanners((prev) => ({
      ...prev,
      [endpointId]: !prev[endpointId],
    }));
  };

  const toggleDetails = (endpointId: string) => {
    setExpandedDetails((prev) => ({
      ...prev,
      [endpointId]: !prev[endpointId],
    }));
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(inv.services, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `services_${currentRun.run_id}.json`;
    link.click();
  };

  const getScoreBadgeClass = (score: string) => {
    if (score.startsWith('A')) {
      return 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-300 dark:border-emerald-500/30';
    }
    if (score.startsWith('B')) {
      return 'bg-cyan-50 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-300 dark:border-cyan-500/30';
    }
    if (score.startsWith('C')) {
      return 'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-300 dark:border-amber-500/30';
    }
    if (score.startsWith('D')) {
      return 'bg-orange-50 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-300 dark:border-orange-500/30';
    }
    return 'bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-300 dark:border-rose-500/30';
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Layers className="w-6 h-6 text-indigo-500 dark:text-indigo-400" />
            Service & Port Map
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Host-centric port enumeration with tech stack identification, security header auditing, and TLS certificate inspection.
          </p>
        </div>

        <button
          onClick={exportJSON}
          className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-medium border border-slate-200 dark:border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm self-start sm:self-auto"
        >
          <Download className="w-3.5 h-3.5" />
          Export Services JSON
        </button>
      </div>

      {/* Search Input */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="relative w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by host IP/domain, open port number, product, tech stack, or banner content..."
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Host Cards */}
      {filteredHosts.length === 0 ? (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-12 text-center text-slate-500 dark:text-slate-400 text-sm">
          No services or open ports found. Try running an Active Scan to probe network ports.
        </div>
      ) : (
        <div className="space-y-4">
          {filteredHosts.map(([host, services]) => (
            <div
              key={host}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm space-y-4"
            >
              {/* Host Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800 gap-2">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-emerald-500" />
                  <span className="font-mono font-bold text-sm text-slate-900 dark:text-white">
                    {host}
                  </span>
                  <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20">
                    Host
                  </span>
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  <span className="font-bold text-indigo-600 dark:text-indigo-400 font-mono">
                    {services.length}
                  </span>{' '}
                  open {services.length === 1 ? 'port' : 'ports'} identified
                </div>
              </div>

              {/* Service list for this host */}
              <div className="divide-y divide-slate-100 dark:divide-slate-800/80 font-mono text-xs">
                {services.map((svc) => {
                  const epId = svc.endpoint_id || `${svc.host}:${svc.port}`;
                  const isExpanded = !!expandedBanners[epId];
                  const isDetailsExpanded = !!expandedDetails[epId];
                  const hasDetails = !!(svc.security_headers || svc.tls_cert_info || (svc.detected_frameworks && svc.detected_frameworks.length > 0));

                  return (
                    <div key={epId} className="py-4 space-y-3">
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                        {/* Port and Protocol */}
                        <div className="flex items-center flex-wrap gap-2">
                          <span className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-white font-bold text-xs border border-slate-200 dark:border-slate-700">
                            {svc.port}/{svc.protocol.toUpperCase()}
                          </span>
                          <span className="font-bold text-indigo-600 dark:text-indigo-400 font-sans">
                            {svc.product || svc.service_name || 'Generic TCP Service'}
                          </span>
                          {svc.version && (
                            <span className="text-slate-500 dark:text-slate-400 text-xs font-sans">
                              v{svc.version}
                            </span>
                          )}

                          {/* Security Posture Score Badge */}
                          {svc.security_score && (
                            <span
                              className={`text-[10px] font-sans font-bold px-2 py-0.5 rounded border uppercase tracking-wide flex items-center gap-1 ${getScoreBadgeClass(
                                svc.security_score
                              )}`}
                            >
                              <Shield className="w-3 h-3" />
                              Grade {svc.security_score}
                            </span>
                          )}

                          {/* Detected Frameworks / Tech Stacks */}
                          {svc.detected_frameworks &&
                            svc.detected_frameworks.map((fw) => (
                              <span
                                key={fw}
                                className="text-[10px] font-sans px-2 py-0.5 rounded bg-violet-50 dark:bg-violet-500/10 text-violet-600 dark:text-violet-300 border border-violet-200 dark:border-violet-500/20 font-medium"
                              >
                                {fw}
                              </span>
                            ))}
                        </div>

                        {/* Badges and action buttons */}
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-sans px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                            via {svc.source}
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20">
                            {(svc.confidence * 100).toFixed(0)}% conf
                          </span>

                          {hasDetails && (
                            <button
                              onClick={() => toggleDetails(epId)}
                              className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-indigo-600 dark:text-indigo-400 text-[11px] font-sans font-medium flex items-center gap-1 cursor-pointer transition-colors"
                            >
                              <ShieldCheck className="w-3 h-3" />
                              {isDetailsExpanded ? 'Hide Security Audit' : 'Security Audit'}
                            </button>
                          )}

                          {svc.banner && (
                            <button
                              onClick={() => toggleBanner(epId)}
                              className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-cyan-600 dark:text-cyan-400 text-[11px] font-sans font-medium flex items-center gap-1 cursor-pointer transition-colors"
                            >
                              <Terminal className="w-3 h-3" />
                              {isExpanded ? 'Hide Banner' : 'Show Banner'}
                              {isExpanded ? (
                                <ChevronUp className="w-3 h-3" />
                              ) : (
                                <ChevronDown className="w-3 h-3" />
                              )}
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Security Audit Drawer */}
                      {isDetailsExpanded && (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 bg-slate-50 dark:bg-slate-950/60 p-4 rounded-xl border border-slate-200 dark:border-slate-800 font-sans text-xs">
                          {/* HTTP Security Headers */}
                          {svc.security_headers && (
                            <div className="space-y-2">
                              <div className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 text-xs">
                                <Shield className="w-3.5 h-3.5 text-cyan-500" />
                                HTTP Security Headers Audit
                              </div>
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                                {Object.entries(svc.security_headers).map(([hdr, present]) => (
                                  <div
                                    key={hdr}
                                    className={`flex items-center justify-between px-2.5 py-1.5 rounded border text-[11px] ${
                                      present
                                        ? 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800/40 text-emerald-700 dark:text-emerald-300'
                                        : 'bg-rose-50/50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-800/40 text-rose-700 dark:text-rose-300'
                                    }`}
                                  >
                                    <span className="font-mono">{hdr}</span>
                                    {present ? (
                                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                                    ) : (
                                      <XCircle className="w-3.5 h-3.5 text-rose-500" />
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* TLS Certificate Telemetry */}
                          {svc.tls_cert_info && (
                            <div className="space-y-2">
                              <div className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 text-xs">
                                <Lock className="w-3.5 h-3.5 text-indigo-500" />
                                Deep TLS / SSL Certificate Inspector
                              </div>
                              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-2.5 space-y-1.5 text-[11px]">
                                <div className="flex justify-between">
                                  <span className="text-slate-400">Issuer:</span>
                                  <span className="font-medium text-slate-800 dark:text-slate-200">
                                    {svc.tls_cert_info.issuer || 'Unknown'}
                                  </span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-slate-400">Subject CN:</span>
                                  <span className="font-mono text-slate-800 dark:text-slate-200">
                                    {svc.tls_cert_info.subject || svc.host}
                                  </span>
                                </div>
                                <div className="flex justify-between items-center">
                                  <span className="text-slate-400">Validity:</span>
                                  <span
                                    className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-bold ${
                                      svc.tls_cert_info.is_expired
                                        ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400'
                                        : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
                                    }`}
                                  >
                                    {svc.tls_cert_info.is_expired
                                      ? 'EXPIRED'
                                      : `${svc.tls_cert_info.days_remaining} days left`}
                                  </span>
                                </div>
                                {svc.tls_cert_info.sans && svc.tls_cert_info.sans.length > 0 && (
                                  <div className="pt-1 border-t border-slate-100 dark:border-slate-800 space-y-1">
                                    <span className="text-slate-400 text-[10px] block">
                                      Discovered SANs ({svc.tls_cert_info.sans.length}):
                                    </span>
                                    <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                                      {svc.tls_cert_info.sans.map((san) => (
                                        <span
                                          key={san}
                                          className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300"
                                        >
                                          {san}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Expandable banner greeting */}
                      {isExpanded && svc.banner && (
                        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-cyan-300 text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                          {svc.banner}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
