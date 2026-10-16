import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  Download,
  Server,
  Globe,
  Radio,
  FileCode,
  Shield,
  Layers,
  ChevronRight,
  X,
  ExternalLink,
} from 'lucide-react';
import { RunDetails, ServiceEndpoint, Observation } from '../types';

interface AssetInventoryPageProps {
  currentRun: RunDetails | null;
}

export const AssetInventoryPage: React.FC<AssetInventoryPageProps> = ({ currentRun }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedSource, setSelectedSource] = useState<string>('all');
  const [selectedAsset, setSelectedAsset] = useState<any | null>(null);

  if (!currentRun || !currentRun.report_data) {
    return (
      <div className="p-8 text-center text-slate-400">
        No run data loaded. Please select or execute a run first.
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

  // Build unified asset list
  const unifiedAssets = useMemo(() => {
    const list: any[] = [];

    // Subdomains
    for (const sub of inv.subdomains || []) {
      const obsList = (inv.observations || []).filter((o) => o.asset_id === sub);
      const sources = Array.from(new Set(obsList.map((o) => o.source)));
      list.push({
        id: sub,
        type: 'Subdomain',
        name: sub,
        sources,
        details: `${sources.join(', ')}`,
        observations: obsList,
        confidence: 0.95,
      });
    }

    // IP Addresses
    for (const ip of inv.ip_addresses || []) {
      const obsList = (inv.observations || []).filter((o) => o.asset_id === ip);
      const sources = Array.from(new Set(obsList.map((o) => o.source)));
      list.push({
        id: ip,
        type: 'IP Address',
        name: ip,
        sources,
        details: `${sources.join(', ')}`,
        observations: obsList,
        confidence: 1.0,
      });
    }

    // Services
    for (const svc of inv.services || []) {
      const ep = svc.endpoint_id || `${svc.host}:${svc.port}`;
      const obsList = (inv.observations || []).filter((o) => o.asset_id === ep);
      list.push({
        id: ep,
        type: 'Service Endpoint',
        name: ep,
        port: svc.port,
        protocol: svc.protocol,
        product: svc.product || svc.service_name || 'Unknown',
        version: svc.version || 'N/A',
        banner: svc.banner,
        sources: [svc.source],
        details: `${svc.product || svc.service_name || 'Service'} on port ${svc.port}`,
        observations: obsList,
        confidence: svc.confidence,
      });
    }

    return list;
  }, [inv]);

  // Unique sources
  const allSources = useMemo(() => {
    const s = new Set<string>();
    unifiedAssets.forEach((a) => a.sources?.forEach((src: string) => s.add(src)));
    return Array.from(s);
  }, [unifiedAssets]);

  // Filtered assets
  const filteredAssets = useMemo(() => {
    return unifiedAssets.filter((a) => {
      if (selectedType !== 'all' && a.type !== selectedType) return false;
      if (selectedSource !== 'all' && !a.sources?.includes(selectedSource)) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchesName = a.name.toLowerCase().includes(q);
        const matchesDetails = (a.details || '').toLowerCase().includes(q);
        const matchesProduct = (a.product || '').toLowerCase().includes(q);
        if (!matchesName && !matchesDetails && !matchesProduct) return false;
      }
      return true;
    });
  }, [unifiedAssets, selectedType, selectedSource, searchQuery]);

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredAssets, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `inventory_${currentRun.run_id}.json`;
    link.click();
  };

  const exportCSV = () => {
    const headers = ['Type', 'Identifier', 'Sources', 'Confidence', 'Details'];
    const rows = filteredAssets.map((a) => [
      `"${a.type}"`,
      `"${a.name}"`,
      `"${(a.sources || []).join(', ')}"`,
      `"${(a.confidence * 100).toFixed(0)}%"`,
      `"${(a.details || '').replace(/"/g, '""')}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `inventory_${currentRun.run_id}.csv`;
    link.click();
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header & Export Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Server className="w-6 h-6 text-cyan-400" />
            Discovered Asset Inventory
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Normalized assets with complete provenance and observation audit trail.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportJSON}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            JSON
          </button>
          <button
            onClick={exportCSV}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            CSV
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center gap-4">
        {/* Search */}
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search assets by domain, IP, port, or product..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Type Filter */}
        <div className="flex items-center gap-2 w-full md:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Asset Types</option>
            <option value="Subdomain">Subdomains</option>
            <option value="IP Address">IP Addresses</option>
            <option value="Service Endpoint">Service Endpoints</option>
          </select>
        </div>

        {/* Source Filter */}
        <div className="flex items-center gap-2 w-full md:w-auto">
          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Sources</option>
            {allSources.map((s) => (
              <option key={s} value={s}>
                Source: {s}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Asset Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Normalized Asset Identifier</th>
                <th className="py-3 px-4">Corroborating Sources</th>
                <th className="py-3 px-4">Details / Metadata</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredAssets.length > 0 ? (
                filteredAssets.map((asset) => (
                  <tr
                    key={asset.id}
                    onClick={() => setSelectedAsset(asset)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4 font-sans font-medium text-slate-400">
                      <span className="flex items-center gap-1.5">
                        {asset.type === 'Subdomain' && <Globe className="w-3.5 h-3.5 text-cyan-400" />}
                        {asset.type === 'IP Address' && <Server className="w-3.5 h-3.5 text-emerald-400" />}
                        {asset.type === 'Service Endpoint' && <Layers className="w-3.5 h-3.5 text-indigo-400" />}
                        {asset.type}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-bold text-white group-hover:text-cyan-400 transition-colors">
                      {asset.name}
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-sans">
                      <div className="flex flex-wrap gap-1">
                        {(asset.sources || []).map((src: string) => (
                          <span
                            key={src}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-300"
                          >
                            {src}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-sans max-w-xs truncate">
                      {asset.details}
                    </td>
                    <td className="py-3 px-4 text-slate-300 font-mono">
                      {(asset.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-4 text-right">
                      <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-colors inline" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                    No assets matching the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-in Detail Drawer */}
      {selectedAsset && (
        <div className="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-lg bg-slate-900 border-l border-slate-800 h-full p-6 overflow-y-auto space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  {selectedAsset.type}
                </span>
                <h2 className="text-lg font-bold text-white mt-2 font-mono break-all">
                  {selectedAsset.name}
                </h2>
              </div>
              <button
                onClick={() => setSelectedAsset(null)}
                className="p-1 rounded-md hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Service Specific Info */}
            {selectedAsset.type === 'Service Endpoint' && (
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="text-xs uppercase font-semibold text-slate-400 tracking-wider">Service Detection</div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-slate-500">Port:</span>{' '}
                    <span className="font-mono text-cyan-300">{selectedAsset.port} ({selectedAsset.protocol})</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Product:</span>{' '}
                    <span className="font-mono text-white">{selectedAsset.product}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Version:</span>{' '}
                    <span className="font-mono text-slate-300">{selectedAsset.version}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Confidence:</span>{' '}
                    <span className="font-mono text-emerald-400">{(selectedAsset.confidence * 100).toFixed(0)}%</span>
                  </div>
                </div>

                {selectedAsset.banner && (
                  <div className="mt-3">
                    <span className="text-slate-500 text-[11px] block mb-1">Raw Banner Greeting:</span>
                    <pre className="bg-slate-900 p-2.5 rounded text-[11px] font-mono text-cyan-200 overflow-x-auto whitespace-pre-wrap border border-slate-800">
                      {selectedAsset.banner}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* Provenance Observations List */}
            <div className="space-y-3">
              <h3 className="text-xs uppercase font-bold text-slate-400 tracking-wider">
                Corroborating Provenance ({selectedAsset.observations?.length || 0})
              </h3>
              {selectedAsset.observations && selectedAsset.observations.length > 0 ? (
                <div className="space-y-2">
                  {selectedAsset.observations.map((obs: Observation, idx: number) => (
                    <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs space-y-1">
                      <div className="flex items-center justify-between text-slate-400">
                        <span className="font-semibold text-cyan-400">{obs.source}</span>
                        <span className="text-[10px] text-slate-500">{new Date(obs.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <div className="text-slate-300 font-mono text-[11px] truncate">
                        Raw: {obs.raw_value}
                      </div>
                      <div className="text-slate-500 text-[10px]">Method: {obs.method}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 italic">No detailed raw observations linked.</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
