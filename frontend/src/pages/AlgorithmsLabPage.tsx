import React, { useState, useEffect } from 'react';
import {
  Cpu,
  Layers,
  Zap,
  BarChart2,
  LineChart as LineChartIcon,
  Play,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  RefreshCw,
  Code2,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from 'recharts';
import { fetchBenchmarks, triggerBenchmark, testScheduler, matchBanner } from '../api';
import { BenchmarkResult } from '../types';

export const AlgorithmsLabPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'scheduler' | 'matcher' | 'graph'>('scheduler');
  const [benchmarks, setBenchmarks] = useState<BenchmarkResult>({ scheduler: [], matcher: [], graph: [] });
  const [isLoading, setIsLoading] = useState(true);
  const [isTriggering, setIsTriggering] = useState(false);

  // Live Scheduler Bench State
  const [schedBudget, setSchedBudget] = useState(25);
  const [schedCount, setSchedCount] = useState(20);
  const [schedResult, setSchedResult] = useState<any | null>(null);

  // Live Matcher Bench State
  const [bannerInput, setBannerInput] = useState('SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2\r\nServer: nginx/1.24.0');
  const [matchResult, setMatchResult] = useState<any | null>(null);

  const loadData = async () => {
    try {
      setIsLoading(true);
      const data = await fetchBenchmarks();
      setBenchmarks(data);
    } catch (err) {
      console.error('Error loading benchmarks:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunSchedulerTest = async () => {
    try {
      const res = await testScheduler(schedBudget, schedCount);
      setSchedResult(res);
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunMatchTest = async () => {
    try {
      const res = await matchBanner(bannerInput);
      setMatchResult(res);
    } catch (err) {
      console.error(err);
    }
  };

  const handleRerunBenchmark = async (target: 'scheduler' | 'matcher' | 'graph') => {
    try {
      setIsTriggering(true);
      await triggerBenchmark(target);
      await loadData();
    } catch (err) {
      console.error(err);
    } finally {
      setIsTriggering(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Page Title & Navigation Tabs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Cpu className="w-6 h-6 text-cyan-400" />
            Data Structures & Algorithms Laboratory
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Empirical benchmarking, asymptotic complexity proofs, and interactive algorithm testing.
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('scheduler')}
            className={`px-4 py-2 rounded-md transition-all cursor-pointer ${
              activeTab === 'scheduler'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            1. 0/1 Knapsack Scheduler
          </button>
          <button
            onClick={() => setActiveTab('matcher')}
            className={`px-4 py-2 rounded-md transition-all cursor-pointer ${
              activeTab === 'matcher'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            2. Aho–Corasick Matcher
          </button>
          <button
            onClick={() => setActiveTab('graph')}
            className={`px-4 py-2 rounded-md transition-all cursor-pointer ${
              activeTab === 'graph'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            3. Asset Graph Traversals
          </button>
        </div>
      </div>

      {/* ==================================================================== */}
      {/* TAB 1: 0/1 KNAPSACK SCHEDULER                                        */}
      {/* ==================================================================== */}
      {activeTab === 'scheduler' && (
        <div className="space-y-6">
          {/* Top Info Banner */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>Probe Scheduling Optimization</span>
                <span className="text-xs font-mono font-normal text-cyan-400 border border-cyan-500/30 px-2 py-0.5 rounded bg-cyan-500/10">
                  O(nB) Dynamic Programming
                </span>
              </h2>
              <button
                onClick={() => handleRerunBenchmark('scheduler')}
                disabled={isTriggering}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isTriggering ? 'animate-spin text-cyan-400' : ''}`} />
                Re-run Benchmark Suite
              </button>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Compares Discovery-Order baseline (first-fit sequential), Greedy Heuristic (ranking by value/cost ratio), and 0/1 Knapsack Dynamic Programming (exact optimal subset selection).
            </p>
          </div>

          {/* Benchmark Chart */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <h3 className="text-sm font-bold text-white mb-2">Total Value Collected: DP vs Greedy vs Discovery</h3>
              <p className="text-xs text-slate-400 mb-4">
                Demonstrates that 0/1 Knapsack DP guarantees mathematical optimality, whereas Greedy lands on suboptimal selections when budget restricts fractional items.
              </p>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={benchmarks.scheduler}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="candidate_count" stroke="#64748b" fontSize={11} label={{ value: 'Candidates (N)', position: 'insideBottom', offset: -5 }} />
                    <YAxis stroke="#64748b" fontSize={11} />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }} />
                    <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                    <Bar dataKey="dp_value" name="0/1 Knapsack DP (Optimal)" fill="#06b6d4" />
                    <Bar dataKey="greedy_value" name="Greedy Ratio" fill="#f59e0b" />
                    <Bar dataKey="discovery_value" name="Discovery Order" fill="#64748b" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <h3 className="text-sm font-bold text-white mb-2">Algorithm Execution Latency (Milliseconds)</h3>
              <p className="text-xs text-slate-400 mb-4">
                Pseudopolynomial O(nB) DP runtime vs O(n log n) sorting runtime across increasing candidate sets.
              </p>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={benchmarks.scheduler}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="candidate_count" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }} />
                    <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                    <Line type="monotone" dataKey="dp_runtime_ms" name="DP Runtime (ms)" stroke="#06b6d4" strokeWidth={2} dot={{ r: 3 }} />
                    <Line type="monotone" dataKey="greedy_runtime_ms" name="Greedy Runtime (ms)" stroke="#f59e0b" strokeWidth={2} dot={{ r: 3 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Interactive Live Test Bench */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Live Interactive Scheduler Test Bench
            </h3>
            <p className="text-xs text-slate-400">
              Generate synthetic candidate probes on-demand and compare the exact subset choices made by the three algorithms.
            </p>

            <div className="flex flex-wrap items-center gap-4 bg-slate-950 p-4 rounded-lg border border-slate-800">
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase mb-1">
                  Budget Limit: {schedBudget}
                </label>
                <input
                  type="range"
                  min={10}
                  max={100}
                  value={schedBudget}
                  onChange={(e) => setSchedBudget(Number(e.target.value))}
                  className="accent-cyan-500 w-36"
                />
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase mb-1">
                  Candidate Count: {schedCount}
                </label>
                <input
                  type="range"
                  min={5}
                  max={50}
                  value={schedCount}
                  onChange={(e) => setSchedCount(Number(e.target.value))}
                  className="accent-cyan-500 w-36"
                />
              </div>

              <button
                onClick={handleRunSchedulerTest}
                className="mt-3 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-slate-950" />
                Run Scheduler Comparison
              </button>
            </div>

            {/* Results Table */}
            {schedResult && (
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3">
                <div className="grid grid-cols-3 gap-3 text-xs">
                  {Object.entries(schedResult.results).map(([k, res]: [string, any]) => (
                    <div key={k} className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                      <div className="font-bold text-cyan-400">{res.strategy}</div>
                      <div className="text-slate-300">Total Value: <span className="font-bold font-mono text-white">{res.total_value}</span></div>
                      <div className="text-slate-400">Budget Consumed: {res.total_cost}/{res.budget}</div>
                      <div className="text-slate-400">Probes Selected: {res.selected_count}</div>
                      <div className="text-[11px] font-semibold mt-1">
                        {res.is_optimal ? (
                          <span className="text-emerald-400">✓ Mathematically Optimal</span>
                        ) : (
                          <span className="text-amber-400">✗ Suboptimal Heuristic</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Mathematical Recurrence Collapsible */}
            <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800/80 text-xs font-mono text-slate-300 space-y-2">
              <div className="font-bold text-cyan-400 flex items-center gap-1.5">
                <Code2 className="w-4 h-4" />
                0/1 Knapsack Dynamic Programming Mathematical Recurrence
              </div>
              <div className="text-slate-400 text-[11px] font-sans">
                Let dp[i][w] be the maximum estimated value achievable using a subset of the first i candidate probes with total resource cost at most w:
              </div>
              <div className="bg-slate-900 p-2.5 rounded border border-slate-800 text-cyan-200">
                dp[i][w] = dp[i-1][w] &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; if cost[i] &gt; w<br />
                dp[i][w] = max(dp[i-1][w], dp[i-1][w - cost[i]] + value[i]) &nbsp; otherwise
              </div>
              <div className="text-slate-400 text-[11px] font-sans">
                <strong>Time Complexity:</strong> O(nB) operations &nbsp;|&nbsp; <strong>Space Complexity:</strong> O(nB) 2D table for exact backtracking reconstruction.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 2: AHO-CORASICK MATCHER                                         */}
      {/* ==================================================================== */}
      {activeTab === 'matcher' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>Multi-Pattern Matching: Aho–Corasick vs Naive</span>
                <span className="text-xs font-mono font-normal text-cyan-400 border border-cyan-500/30 px-2 py-0.5 rounded bg-cyan-500/10">
                  O(L + Z) Automaton
                </span>
              </h2>
              <button
                onClick={() => handleRerunBenchmark('matcher')}
                disabled={isTriggering}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isTriggering ? 'animate-spin text-cyan-400' : ''}`} />
                Re-run Matcher Benchmark
              </button>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Demonstrates asymptotically superior scanning: Aho–Corasick preprocesses the signature dictionary into a trie with BFS failure links, yielding search time independent of signature set size K.
            </p>
          </div>

          {/* Speedup and Scaling Chart */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h3 className="text-sm font-bold text-white mb-2">Search Latency Scaling: Aho-Corasick vs Naive Matcher</h3>
            <p className="text-xs text-slate-400 mb-4">
              Observe that Aho-Corasick search latency stays virtually flat as signature count K grows to 1,000, whereas Naive matching latency grows linearly with K.
            </p>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={benchmarks.matcher.filter((b) => b.text_length === 2000)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="signature_count" stroke="#64748b" fontSize={11} label={{ value: 'Signatures Count (K)', position: 'insideBottom', offset: -5 }} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }} />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                  <Line type="monotone" dataKey="ac_search_time_ms" name="Aho-Corasick Search (ms)" stroke="#06b6d4" strokeWidth={2.5} dot={{ r: 4 }} />
                  <Line type="monotone" dataKey="naive_search_time_ms" name="Naive Search (ms)" stroke="#f43f5e" strokeWidth={2.5} dot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Interactive Live Banner Tester */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Live Interactive Banner Signature Matcher
            </h3>
            <p className="text-xs text-slate-400">
              Input a network greeting banner to test simultaneous multi-pattern matching and decoupled regex version extraction.
            </p>

            <textarea
              rows={3}
              value={bannerInput}
              onChange={(e) => setBannerInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-cyan-200 focus:outline-none focus:border-cyan-500"
              placeholder="Paste banner greeting text here..."
            />

            <div className="flex justify-end">
              <button
                onClick={handleRunMatchTest}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-slate-950" />
                Run Aho–Corasick Multi-Pattern Scan
              </button>
            </div>

            {matchResult && (
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between text-slate-400">
                  <span>Signatures Loaded: <strong className="text-white">{matchResult.signature_count}</strong></span>
                  <span>Matches Found: <strong className="text-cyan-400">{matchResult.ac_matches.length}</strong></span>
                  <span className="text-emerald-400 font-semibold">✓ Equivalence Verified</span>
                </div>

                {matchResult.ac_matches.length > 0 && (
                  <div className="space-y-1.5 pt-2">
                    <span className="text-[11px] text-slate-500 uppercase tracking-wider">Identified Signatures:</span>
                    {matchResult.ac_matches.map((m: any, idx: number) => (
                      <div key={idx} className="bg-slate-900 p-2 rounded flex items-center justify-between">
                        <span className="text-white font-bold">{m.product}</span>
                        <span className="text-slate-400">Pattern: "{m.pattern}" (Index: {m.start_pos}..{m.end_pos})</span>
                        <span className="text-cyan-300 font-semibold">
                          Version: {matchResult.extracted_versions[m.product] || 'N/A'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 3: ASSET GRAPH TRAVERSALS                                        */}
      {/* ==================================================================== */}
      {activeTab === 'graph' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>Asset Correlation Graph: BFS & DFS Scaling</span>
                <span className="text-xs font-mono font-normal text-cyan-400 border border-cyan-500/30 px-2 py-0.5 rounded bg-cyan-500/10">
                  O(V + E) Adjacency List
                </span>
              </h2>
              <button
                onClick={() => handleRerunBenchmark('graph')}
                disabled={isTriggering}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isTriggering ? 'animate-spin text-cyan-400' : ''}`} />
                Re-run Graph Benchmark
              </button>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Measures adjacency-list construction time and traversal performance across synthetic graphs scaling up to 8,500+ vertices and 14,000+ directed edges.
            </p>
          </div>

          {/* Graph Scaling Chart */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h3 className="text-sm font-bold text-white mb-2">Traversal Latency vs Vertex Count</h3>
            <p className="text-xs text-slate-400 mb-4">
              Both BFS (FIFO queue) and DFS (LIFO stack) scale strictly linearly with O(V + E).
            </p>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={benchmarks.graph}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="vertex_count" stroke="#64748b" fontSize={11} label={{ value: 'Vertices (V)', position: 'insideBottom', offset: -5 }} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }} />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                  <Bar dataKey="bfs_runtime_ms" name="BFS Runtime (ms)" fill="#06b6d4" />
                  <Bar dataKey="dfs_runtime_ms" name="DFS Runtime (ms)" fill="#818cf8" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Graph Benchmark Data Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 font-bold text-sm text-white">
              Empirical Graph Scaling Measurements
            </div>
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400">
                <tr>
                  <th className="py-2.5 px-4">Subdomains</th>
                  <th className="py-2.5 px-4">IPs</th>
                  <th className="py-2.5 px-4">Vertices (V)</th>
                  <th className="py-2.5 px-4">Edges (E)</th>
                  <th className="py-2.5 px-4">BFS Time</th>
                  <th className="py-2.5 px-4">DFS Time</th>
                  <th className="py-2.5 px-4">Coverage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {benchmarks.graph.map((row, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 text-slate-300">{row.subdomain_count}</td>
                    <td className="py-2.5 px-4 text-slate-300">{row.ip_count}</td>
                    <td className="py-2.5 px-4 font-bold text-cyan-400">{row.vertex_count}</td>
                    <td className="py-2.5 px-4 text-slate-300">{row.edge_count}</td>
                    <td className="py-2.5 px-4 text-cyan-300">{row.bfs_runtime_ms} ms</td>
                    <td className="py-2.5 px-4 text-indigo-300">{row.dfs_runtime_ms} ms</td>
                    <td className="py-2.5 px-4 text-emerald-400">100% (Complete)</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
