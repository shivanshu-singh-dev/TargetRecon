import React, { useState, useMemo } from 'react';
import {
  Database,
  Search,
  Filter,
  Download,
  ArrowUpDown,
} from 'lucide-react';
import { RunDetails, DNSRecord } from '../types';

interface DNSRecordsPageProps {
  currentRun: RunDetails | null;
}

export const DNSRecordsPage: React.FC<DNSRecordsPageProps> = ({ currentRun }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState('ALL');
  const [sortField, setSortField] = useState<'host' | 'record_type'>('host');
  const [sortAsc, setSortAsc] = useState(true);

  if (!currentRun || !currentRun.report_data) {
    return (
      <div className="p-8 text-center text-slate-500 dark:text-slate-400">
        No active reconnaissance run loaded. Start or select a run first.
      </div>
    );
  }

  const dnsRecords: DNSRecord[] = currentRun.report_data.inventory?.dns_records || [];

  // Get distinct record types
  const distinctTypes = useMemo(() => {
    const set = new Set<string>();
    dnsRecords.forEach((r) => set.add(r.record_type));
    return Array.from(set).sort();
  }, [dnsRecords]);

  // Filter and sort records
  const filteredRecords = useMemo(() => {
    return dnsRecords
      .filter((r) => {
        if (selectedType !== 'ALL' && r.record_type !== selectedType) return false;
        if (searchQuery) {
          const q = searchQuery.toLowerCase();
          return (
            r.host.toLowerCase().includes(q) ||
            r.value.toLowerCase().includes(q) ||
            r.source.toLowerCase().includes(q)
          );
        }
        return true;
      })
      .sort((a, b) => {
        const valA = a[sortField].toLowerCase();
        const valB = b[sortField].toLowerCase();
        if (valA < valB) return sortAsc ? -1 : 1;
        if (valA > valB) return sortAsc ? 1 : -1;
        return 0;
      });
  }, [dnsRecords, selectedType, searchQuery, sortField, sortAsc]);

  const toggleSort = (field: 'host' | 'record_type') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  const getRecordTypeBadge = (type: string) => {
    switch (type.toUpperCase()) {
      case 'A':
        return 'bg-cyan-100 text-cyan-800 dark:bg-cyan-500/10 dark:text-cyan-400 border-cyan-200 dark:border-cyan-500/20';
      case 'AAAA':
        return 'bg-purple-100 text-purple-800 dark:bg-purple-500/10 dark:text-purple-400 border-purple-200 dark:border-purple-500/20';
      case 'MX':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-500/10 dark:text-amber-400 border-amber-200 dark:border-amber-500/20';
      case 'NS':
        return 'bg-teal-100 text-teal-800 dark:bg-teal-500/10 dark:text-teal-400 border-teal-200 dark:border-teal-500/20';
      case 'TXT':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-500/10 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20';
      case 'CNAME':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20';
      case 'SOA':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-500/10 dark:text-rose-400 border-rose-200 dark:border-rose-500/20';
      default:
        return 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700';
    }
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredRecords, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `dns_${currentRun.run_id}.json`;
    link.click();
  };

  const exportCSV = () => {
    const headers = ['Record Type', 'Host', 'Value', 'Source'];
    const rows = filteredRecords.map((r) => [
      `"${r.record_type}"`,
      `"${r.host}"`,
      `"${r.value.replace(/"/g, '""')}"`,
      `"${r.source}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `dns_${currentRun.run_id}.csv`;
    link.click();
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Database className="w-6 h-6 text-teal-500 dark:text-teal-400" />
            DNS Records
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Complete inventory of parsed zone records (A, AAAA, MX, NS, TXT, SOA) for{' '}
            <span className="font-mono font-bold text-teal-600 dark:text-teal-400">
              {currentRun.target_domain}
            </span>.
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

      {/* Filter and Search Bar */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center gap-4 shadow-sm">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by host, record value, or discovery source..."
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-teal-500"
          />
        </div>

        {/* Type filter */}
        <div className="flex items-center gap-2 w-full md:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-teal-500 cursor-pointer"
          >
            <option value="ALL">All Record Types ({dnsRecords.length})</option>
            {distinctTypes.map((t) => (
              <option key={t} value={t}>
                {t} Records ({dnsRecords.filter((r) => r.record_type === t).length})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* DNS Records Table */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-950/80 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 uppercase tracking-wider font-semibold">
                <th
                  onClick={() => toggleSort('record_type')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-900 dark:hover:text-white transition-colors"
                >
                  <div className="flex items-center gap-1.5">
                    <span>Type</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => toggleSort('host')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-900 dark:hover:text-white transition-colors"
                >
                  <div className="flex items-center gap-1.5">
                    <span>Host / FQDN</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-4">Value / Target</th>
                <th className="py-3 px-4">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
              {filteredRecords.length > 0 ? (
                filteredRecords.map((record, index) => (
                  <tr
                    key={index}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3 px-4">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getRecordTypeBadge(
                          record.record_type
                        )}`}
                      >
                        {record.record_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-cyan-600 dark:text-cyan-400 font-bold max-w-xs truncate">
                      {record.host}
                    </td>
                    <td className="py-3 px-4 text-slate-700 dark:text-slate-300 break-all max-w-md">
                      {record.value}
                    </td>
                    <td className="py-3 px-4 text-slate-500 font-sans">
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700 text-[10px]">
                        {record.source}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-400 font-sans">
                    No DNS records matched the filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
