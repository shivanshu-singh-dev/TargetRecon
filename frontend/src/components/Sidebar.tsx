import React from 'react';
import {
  LayoutDashboard,
  PlayCircle,
  Server,
  Share2,
  Cpu,
  AlertTriangle,
  FileText,
  ShieldCheck,
} from 'lucide-react';

export type PageId =
  | 'overview'
  | 'new-run'
  | 'inventory'
  | 'graph'
  | 'algorithms'
  | 'findings'
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
  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'new-run', label: 'New Recon Run', icon: PlayCircle },
    { id: 'inventory', label: 'Asset Inventory', icon: Server },
    { id: 'graph', label: 'Asset Correlation Graph', icon: Share2 },
    { id: 'algorithms', label: 'Algorithm Laboratory', icon: Cpu },
    { id: 'findings', label: 'Findings & Discrepancies', icon: AlertTriangle },
    { id: 'reports', label: 'Reports & History', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-slate-900/95 border-r border-slate-800 flex flex-col shrink-0 select-none backdrop-blur">
      {/* Brand & Title */}
      <div className="h-16 flex items-center px-5 gap-3 border-b border-slate-800">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-teal-700 flex items-center justify-center text-slate-950 font-black shadow-lg shadow-cyan-500/20">
          <ShieldCheck className="w-5 h-5 text-slate-950" />
        </div>
        <div>
          <div className="font-bold text-sm tracking-wide text-white flex items-center gap-1.5">
            TargetRecon <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">DAA</span>
          </div>
          <div className="text-[11px] text-slate-400 font-mono">SOC Recon Platform</div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-400 px-3 py-1.5">
          Intelligence Console
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activePage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectPage(item.id as PageId)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span className="truncate">{item.label}</span>
              {item.id === 'new-run' && activeRunCount > 0 && (
                <span className="ml-auto flex h-2 w-2 relative">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* System Status Footprint */}
      <div className="p-3 border-t border-slate-800 text-xs">
        <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px]">
            <span>Active Policy:</span>
            <span className="text-emerald-400 font-medium">Scope Enforced</span>
          </div>
          <div className="flex items-center justify-between text-slate-400 text-[11px]">
            <span>Local Engine:</span>
            <span className="font-mono text-cyan-400">127.0.0.1:8000</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
