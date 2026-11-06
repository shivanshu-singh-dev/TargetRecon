import React, { useState, useMemo } from 'react';
import {
  Globe,
  Search,
  Download,
  Server,
  Database,
  CheckCircle2,
  XCircle,
  ChevronRight,
  X,
  ExternalLink,
} from 'lucide-react';
import { RunDetails, DNSRecord, Observation } from '../types';

interface SubdomainPageProps {
  currentRun: RunDetails | null;
}

export const SubdomainPage: React.FC<SubdomainPageProps> = ({ currentRun }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSubdomain, setSelectedSubdomain] = useState<string | null>(null);

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

  // Compile detailed subdomain intelligence
  const subdomainList = useMemo(() => {
    return (inv.subdomains || []).map((sub) => {
      // Find DNS records for this subdomain
      const relatedDNS = (inv.dns_records || []).filter(
        (r) => r.host.toLowerCase() === sub.toLowerCase()
      );

      // Resolved IPv4 addresses
      const resolvedIPs = relatedDNS
        .filter((r) => r.record_type === 'A')
        .map((r) => r.value);

      // Distinct DNS record types (e.g., A, AAAA, MX, TXT)
      const dnsTypes = Array.from(new Set(relatedDNS.map((r) => r.record_type)));

      // Provenance / sources that observed this subdomain
      const sources = Array.from(
        new Set(
          (inv.observations || [])
            .filter((o) => o.asset_id.toLowerCase() === sub.toLowerCase())
            .map((o) => o.source)
        )
      );

      return {
        subdomain: sub,
        sources: sources.length > 0 ? sources : ['dns_resolver'],
        resolvedIPs,
        dnsTypes,
        isResolved: resolvedIPs.length > 0,
        dnsRecords: relatedDNS,
      };
    });
  }, [inv]);

  // Filtered by search query
  const filteredSubdomains = useMemo(() => {
    if (!searchQuery.trim()) return subdomainList;
    const q = searchQuery.toLowerCase();
    return subdomainList.filter(
      (item) =>
        item.subdomain.toLowerCase().includes(q) ||
        item.resolvedIPs.some((ip) => ip.includes(q)) ||
        item.sources.some((s) => s.toLowerCase().includes(q))
    );
  }, [subdomainList, searchQuery]);

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredSubdomains, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `subdomains_${currentRun.run_id}.json`;
    link.click();
  };

  const exportCSV = () => {
    const headers = ['Subdomain', 'Status', 'Resolved IPs', 'DNS Types', 'Sources'];
    const rows = filteredSubdomains.map((item) => [
      `"${item.subdomain}"`,
      `"${item.isResolved ? 'Resolved' : 'Unresolved'}"`,
      `"${item.resolvedIPs.join('; ')}"`,
      `"${item.dnsTypes.join('; ')}"`,
      `"${item.sources.join('; ')}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `subdomains_${currentRun.run_id}.csv`;
    link.click();
  };

  const activeSubDetails = subdomainList.find((s) => s.subdomain === selectedSubdomain);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header and Export */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Globe className="w-6 h-6 text-cyan-600 dark:text-cyan-400" />
            Subdomain Intelligence
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Target: <span className="font-mono font-bold text-cyan-600 dark:text-cyan-400">{currentRun.target_domain}</span> — {subdomainList.length} total subdomains discovered
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportJSON}
            className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-medium border border-slate-200 dark:border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            JSON
          </button>
          <button
            onClick={exportCSV}
            className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-medium border border-slate-200 dark:border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            CSV
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="relative w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search subdomains by name, resolved IP, or discovery source..."
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Subdomains Table */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-950/80 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 uppercase tracking-wider font-semibold">
                <th className="py-3 px-4">Subdomain</th>
                <th className="py-3 px-4">Discovery Sources</th>
                <th className="py-3 px-4">Resolved IP(s)</th>
                <th className="py-3 px-4">DNS Types</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
              {filteredSubdomains.length > 0 ? (
                filteredSubdomains.map((item) => (
                  <tr
                    key={item.subdomain}
                    onClick={() => setSelectedSubdomain(item.subdomain)}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4 font-bold text-cyan-600 dark:text-cyan-400 group-hover:underline">
                      {item.subdomain}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {item.sources.map((src) => (
                          <span
                            key={src}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-sans"
                          >
                            {src}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-700 dark:text-slate-300">
                      {item.resolvedIPs.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {item.resolvedIPs.map((ip) => (
                            <span key={ip} className="text-emerald-600 dark:text-emerald-400 font-medium">
                              {ip}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-slate-400 italic">No A record</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {item.dnsTypes.length > 0 ? (
                          item.dnsTypes.map((type) => (
                            <span
                              key={type}
                              className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border border-cyan-200 dark:border-cyan-500/20 font-bold"
                            >
                              {type}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-400 italic">—</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <span
                        className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full border ${
                          item.isResolved
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                            : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700'
                        }`}
                      >
                        {item.isResolved ? (
                          <>
                            <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                            Resolved
                          </>
                        ) : (
                          <>
                            <XCircle className="w-3 h-3 text-slate-400" />
                            Unresolved
                          </>
                        )}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 transition-colors inline" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400 font-sans">
                    No subdomains matched the current search criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Slide-out Drawer */}
      {activeSubDetails && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-lg bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 h-full p-6 overflow-y-auto space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
              <div>
                <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
                  Subdomain Profile
                </span>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white mt-2 font-mono break-all">
                  {activeSubDetails.subdomain}
                </h2>
              </div>
              <button
                onClick={() => setSelectedSubdomain(null)}
                className="p-1 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 dark:hover:text-white cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Resolved IPs card */}
            <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200 dark:border-slate-800 space-y-2">
              <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400 tracking-wider flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-emerald-500" />
                Resolved IP Addresses ({activeSubDetails.resolvedIPs.length})
              </div>
              {activeSubDetails.resolvedIPs.length > 0 ? (
                <div className="space-y-1">
                  {activeSubDetails.resolvedIPs.map((ip) => (
                    <div
                      key={ip}
                      className="font-mono text-xs font-semibold text-emerald-600 dark:text-emerald-400 bg-white dark:bg-slate-900 px-2.5 py-1.5 rounded border border-slate-200 dark:border-slate-800"
                    >
                      {ip}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-400 italic">No direct A records resolved.</div>
              )}
            </div>

            {/* Complete DNS Records List */}
            <div className="space-y-3">
              <div className="text-xs uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-cyan-500" />
                All Discovered DNS Records ({activeSubDetails.dnsRecords.length})
              </div>
              {activeSubDetails.dnsRecords.length > 0 ? (
                <div className="space-y-2">
                  {activeSubDetails.dnsRecords.map((rec: DNSRecord, index: number) => (
                    <div
                      key={index}
                      className="bg-slate-50 dark:bg-slate-950 p-3 rounded-lg border border-slate-200 dark:border-slate-800 text-xs space-y-1 font-mono"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyan-600 dark:text-cyan-400">
                          {rec.record_type}
                        </span>
                        <span className="text-[10px] text-slate-400 font-sans">{rec.source}</span>
                      </div>
                      <div className="text-slate-700 dark:text-slate-200 break-all text-[11px]">
                        {rec.value}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-400 italic">No DNS records stored.</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
