import React, { useState, useEffect } from 'react';
import { Sidebar, PageId } from './components/Sidebar';
import { Header } from './components/Header';
import { DashboardPage } from './pages/DashboardPage';
import { ReconRunPage } from './pages/ReconRunPage';
import { SubdomainPage } from './pages/SubdomainPage';
import { ServiceMapPage } from './pages/ServiceMapPage';
import { DNSRecordsPage } from './pages/DNSRecordsPage';
import { AssetGraphPage } from './pages/AssetGraphPage';
import { AlgorithmsPage } from './pages/AlgorithmsPage';
import { ReportsPage } from './pages/ReportsPage';
import { fetchHealth, fetchRuns, fetchRunDetails } from './api';
import { HealthStatus, RunSummary, RunDetails } from './types';

export const App: React.FC = () => {
  const [activePage, setActivePage] = useState<PageId>('dashboard');
  const [history, setHistory] = useState<PageId[]>(['dashboard']);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | undefined>(undefined);
  const [currentRun, setCurrentRun] = useState<RunDetails | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isDark, setIsDark] = useState(true);

  // Apply dark class to <html>
  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDark]);

  const toggleTheme = () => setIsDark((d) => !d);

  const handleNavigate = (nextPage: PageId) => {
    if (nextPage === activePage) return;
    setHistory((prev) => [...prev, nextPage]);
    setActivePage(nextPage);
  };

  const handleGoBack = () => {
    if (history.length > 1) {
      const newHistory = [...history];
      newHistory.pop();
      const prevPage = newHistory[newHistory.length - 1];
      setHistory(newHistory);
      setActivePage(prevPage);
    }
  };

  const canGoBack = history.length > 1;

  const loadInitialData = async () => {
    try {
      setIsRefreshing(true);
      const [h, r] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchRuns().catch(() => []),
      ]);
      setHealth(h);
      setRuns(r);

      if (r.length > 0 && !selectedRunId) {
        setSelectedRunId(r[0].run_id);
      }
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  useEffect(() => {
    if (!selectedRunId) return;
    fetchRunDetails(selectedRunId)
      .then((details) => setCurrentRun(details))
      .catch((err) => console.error('Failed to load run details:', err));
  }, [selectedRunId]);

  const handleSelectRun = (runId: string) => {
    setSelectedRunId(runId);
  };

  const handleRunCreated = async (newRunId: string) => {
    await loadInitialData();
    setSelectedRunId(newRunId);
    handleNavigate('dashboard');
  };

  const activeRunCount = runs.filter((r) => r.status === 'running').length;

  return (
    <div className="flex h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 overflow-hidden font-sans">
      <Sidebar
        activePage={activePage}
        onSelectPage={handleNavigate}
        activeRunCount={activeRunCount}
      />

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          health={health}
          runs={runs}
          selectedRunId={selectedRunId}
          onSelectRun={handleSelectRun}
          onRefresh={loadInitialData}
          isRefreshing={isRefreshing}
          isDark={isDark}
          onToggleTheme={toggleTheme}
          activePage={activePage}
          onNavigate={handleNavigate}
          canGoBack={canGoBack}
          onGoBack={handleGoBack}
        />

        <main className="flex-1 overflow-y-auto bg-slate-50 dark:bg-slate-950/90">
          {activePage === 'dashboard' && (
            <DashboardPage
              currentRun={currentRun}
              runs={runs}
              onNavigate={handleNavigate}
              onSelectRun={handleSelectRun}
            />
          )}

          {activePage === 'recon-run' && (
            <ReconRunPage onRunCreated={handleRunCreated} />
          )}

          {activePage === 'subdomains' && (
            <SubdomainPage currentRun={currentRun} />
          )}

          {activePage === 'service-map' && (
            <ServiceMapPage currentRun={currentRun} />
          )}

          {activePage === 'dns-records' && (
            <DNSRecordsPage currentRun={currentRun} />
          )}

          {activePage === 'asset-graph' && (
            <AssetGraphPage currentRun={currentRun} />
          )}

          {activePage === 'algorithms' && (
            <AlgorithmsPage />
          )}

          {activePage === 'reports' && (
            <ReportsPage
              currentRun={currentRun}
              runs={runs}
              onSelectRun={handleSelectRun}
            />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
