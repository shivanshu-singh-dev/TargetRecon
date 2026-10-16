import React, { useState, useEffect } from 'react';
import { Sidebar, PageId } from './components/Sidebar';
import { Header } from './components/Header';
import { OverviewPage } from './pages/OverviewPage';
import { NewRunPage } from './pages/NewRunPage';
import { AssetInventoryPage } from './pages/AssetInventoryPage';
import { GraphPage } from './pages/GraphPage';
import { AlgorithmsLabPage } from './pages/AlgorithmsLabPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportsPage } from './pages/ReportsPage';
import { fetchHealth, fetchRuns, fetchRunDetails } from './api';
import { HealthStatus, RunSummary, RunDetails } from './types';

export const App: React.FC = () => {
  const [activePage, setActivePage] = useState<PageId>('overview');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | undefined>(undefined);
  const [currentRun, setCurrentRun] = useState<RunDetails | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Load initial health and runs list
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

  // Fetch full details whenever selectedRunId changes
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
    setActivePage('overview');
  };

  const activeRunCount = runs.filter((r) => r.status === 'running').length;

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Sidebar */}
      <Sidebar
        activePage={activePage}
        onSelectPage={setActivePage}
        activeRunCount={activeRunCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          health={health}
          runs={runs}
          selectedRunId={selectedRunId}
          onSelectRun={handleSelectRun}
          onRefresh={loadInitialData}
          isRefreshing={isRefreshing}
        />

        <main className="flex-1 overflow-y-auto bg-slate-950/90">
          {activePage === 'overview' && (
            <OverviewPage
              currentRun={currentRun}
              runs={runs}
              onNavigate={setActivePage}
              onSelectRun={handleSelectRun}
            />
          )}

          {activePage === 'new-run' && (
            <NewRunPage onRunCreated={handleRunCreated} />
          )}

          {activePage === 'inventory' && (
            <AssetInventoryPage currentRun={currentRun} />
          )}

          {activePage === 'graph' && (
            <GraphPage currentRun={currentRun} />
          )}

          {activePage === 'algorithms' && (
            <AlgorithmsLabPage />
          )}

          {activePage === 'findings' && (
            <FindingsPage currentRun={currentRun} />
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
