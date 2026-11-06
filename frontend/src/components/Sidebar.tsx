import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  PlayCircle,
  Globe,
  Layers,
  Database,
  Share2,
  Cpu,
  FileText,
  ShieldCheck,
  Clock,
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'recon-run'
  | 'subdomains'
  | 'service-map'
  | 'dns-records'
  | 'asset-graph'
  | 'algorithms'
  | 'reports';

interface SidebarProps {
  activePage: PageId;
  onSelectPage: (page: PageId) => void;
  activeRunCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activePage,
  onSelectPage,
  activeRunCount = 0,
}) => {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const reconItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'recon-run', label: 'Run Reconnaissance', icon: PlayCircle },
    { id: 'subdomains', label: 'Subdomains', icon: Globe },
    { id: 'service-map', label: 'Service Map', icon: Layers },
    { id: 'dns-records', label: 'DNS Records', icon: Database },
    { id: 'asset-graph', label: 'Asset Graph', icon: Share2 },
  ];

  const analysisItems = [
    { id: 'algorithms', label: 'Algorithm Performance', icon: Cpu },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  const renderNavItem = (item: { id: string; label: string; icon: any }) => {
    const Icon = item.icon;
    const isActive = activePage === item.id;
    return (
      <button
        key={item.id}
        onClick={() => onSelectPage(item.id as PageId)}
        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all cursor-pointer ${
          isActive
            ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10 dark:bg-cyan-500/10 dark:text-cyan-400 dark:border-cyan-500/30'
            : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-800/60'
        }`}
      >
        <Icon
          className={`w-4 h-4 shrink-0 ${
            isActive ? 'text-cyan-500 dark:text-cyan-400' : 'text-slate-400 dark:text-slate-500'
          }`}
        />
        <span className="truncate">{item.label}</span>
        {item.id === 'recon-run' && activeRunCount > 0 && (
          <span className="ml-auto flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
          </span>
        )}
      </button>
    );
  };

  return (
    <aside className="w-64 bg-white dark:bg-slate-900/95 border-r border-slate-200 dark:border-slate-800 flex flex-col shrink-0 select-none">
      {/* Brand */}
      <div className="h-16 flex items-center px-5 gap-3 border-b border-slate-200 dark:border-slate-800">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-teal-700 flex items-center justify-center text-slate-950 font-black shadow-lg shadow-cyan-500/20">
          <ShieldCheck className="w-5 h-5 text-slate-950" />
        </div>
        <div>
          <div className="font-bold text-sm tracking-wide text-slate-900 dark:text-white">
            TargetRecon
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">Cyber Reconnaissance Platform</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {/* Reconnaissance section */}
        <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-400 dark:text-slate-500 px-3 py-1.5">
          Reconnaissance
        </div>
        {reconItems.map(renderNavItem)}

        {/* Analysis section */}
        <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-400 dark:text-slate-500 px-3 py-1.5 mt-4">
          Analysis
        </div>
        {analysisItems.map(renderNavItem)}
      </nav>

      {/* Footer */}
      <div className="p-3 border-t border-slate-200 dark:border-slate-800 text-xs">
        <div className="bg-slate-50 dark:bg-slate-950/70 p-3 rounded-lg border border-slate-200 dark:border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-[11px]">
            <span>Local Engine:</span>
            <span className="font-mono text-cyan-600 dark:text-cyan-400">127.0.0.1:8000</span>
          </div>
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-[11px]">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              Time:
            </span>
            <span className="font-mono">{currentTime.toLocaleTimeString()}</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
