import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Share2,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Filter,
  Play,
  RotateCcw,
  Search,
  CheckCircle,
  Layers,
  Server,
  Globe,
  Radio,
} from 'lucide-react';
import { RunDetails, GraphNode, GraphEdge } from '../types';
import { traverseGraph } from '../api';

interface GraphPageProps {
  currentRun: RunDetails | null;
}

export const GraphPage: React.FC<GraphPageProps> = ({ currentRun }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedTypeFilter, setSelectedTypeFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Traversal state
  const [traversalAlgo, setTraversalAlgo] = useState<'bfs' | 'dfs'>('bfs');
  const [traversalSequence, setTraversalSequence] = useState<string[]>([]);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(-1);
  const [isTraversing, setIsTraversing] = useState(false);

  // Pan & Zoom
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const graphData = currentRun?.report_data?.graph;

  // Node layout calculation
  const layoutNodes = useMemo(() => {
    if (!graphData || !graphData.nodes) return [];

    const nodes = graphData.nodes;
    const count = nodes.length;
    const width = 800;
    const height = 600;
    const centerX = width / 2;
    const centerY = height / 2;

    // Group nodes by type to arrange hierarchically / concentrically
    const domains = nodes.filter((n) => n.node_type === 'Domain');
    const subdomains = nodes.filter((n) => n.node_type === 'Subdomain');
    const ips = nodes.filter((n) => n.node_type === 'IPAddress');
    const endpoints = nodes.filter((n) => n.node_type === 'Endpoint');
    const services = nodes.filter((n) => n.node_type === 'Service');
    const others = nodes.filter(
      (n) => !['Domain', 'Subdomain', 'IPAddress', 'Endpoint', 'Service'].includes(n.node_type)
    );

    const positions: Record<string, { x: number; y: number }> = {};

    // Center root domains
    domains.forEach((d, idx) => {
      positions[d.node_id] = {
        x: centerX + (idx - (domains.length - 1) / 2) * 120,
        y: centerY - 180,
      };
    });

    // Subdomains ring
    subdomains.forEach((s, idx) => {
      const angle = (idx / Math.max(1, subdomains.length)) * Math.PI * 1.5 - Math.PI * 0.75;
      const radius = 180;
      positions[s.node_id] = {
        x: centerX + Math.cos(angle) * radius,
        y: centerY - 80 + Math.sin(angle) * 80,
      };
    });

    // IPs layer
    ips.forEach((ip, idx) => {
      positions[ip.node_id] = {
        x: centerX + (idx - (ips.length - 1) / 2) * 140,
        y: centerY + 60,
      };
    });

    // Endpoints & Services
    endpoints.forEach((ep, idx) => {
      positions[ep.node_id] = {
        x: centerX + (idx - (endpoints.length - 1) / 2) * 90,
        y: centerY + 160,
      };
    });

    services.forEach((svc, idx) => {
      positions[svc.node_id] = {
        x: centerX + (idx - (services.length - 1) / 2) * 100,
        y: centerY + 240,
      };
    });

    others.forEach((o, idx) => {
      positions[o.node_id] = {
        x: centerX + (idx - (others.length - 1) / 2) * 100,
        y: centerY - 250,
      };
    });

    return nodes.map((n) => ({
      ...n,
      x: positions[n.node_id]?.x || centerX + (Math.random() - 0.5) * 300,
      y: positions[n.node_id]?.y || centerY + (Math.random() - 0.5) * 300,
    }));
  }, [graphData]);

  // Color mapping by node type
  const getNodeColor = (type: string) => {
    switch (type) {
      case 'Domain':
        return '#06b6d4'; // Cyan
      case 'Subdomain':
        return '#38bdf8'; // Sky blue
      case 'IPAddress':
        return '#10b981'; // Emerald
      case 'Endpoint':
        return '#f59e0b'; // Amber
      case 'Service':
        return '#818cf8'; // Indigo
      default:
        return '#94a3b8'; // Slate
    }
  };

  // Canvas drawing loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.save();
    ctx.translate(pan.x, pan.y);
    ctx.scale(zoom, zoom);

    if (!graphData || !graphData.edges) {
      ctx.restore();
      return;
    }

    const nodeMap = new Map<string, any>();
    layoutNodes.forEach((n) => nodeMap.set(n.node_id, n));

    // 1. Draw Edges
    graphData.edges.forEach((edge) => {
      const source = nodeMap.get(edge.source_id);
      const target = nodeMap.get(edge.target_id);
      if (!source || !target) return;

      const isTraversed =
        traversalSequence.slice(0, currentStepIndex + 1).includes(edge.source_id) &&
        traversalSequence.slice(0, currentStepIndex + 1).includes(edge.target_id);

      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = isTraversed ? '#06b6d4' : '#334155';
      ctx.lineWidth = isTraversed ? 2.5 : 1;
      ctx.stroke();

      // Draw arrow
      const angle = Math.atan2(target.y - source.y, target.x - source.x);
      const arrowRadius = 14;
      const arrowX = target.x - Math.cos(angle) * arrowRadius;
      const arrowY = target.y - Math.sin(angle) * arrowRadius;

      ctx.beginPath();
      ctx.moveTo(arrowX, arrowY);
      ctx.lineTo(arrowX - 6 * Math.cos(angle - Math.PI / 6), arrowY - 6 * Math.sin(angle - Math.PI / 6));
      ctx.lineTo(arrowX - 6 * Math.cos(angle + Math.PI / 6), arrowY - 6 * Math.sin(angle + Math.PI / 6));
      ctx.fillStyle = isTraversed ? '#06b6d4' : '#475569';
      ctx.fill();
    });

    // 2. Draw Nodes
    layoutNodes.forEach((node) => {
      if (selectedTypeFilter !== 'all' && node.node_type !== selectedTypeFilter) {
        return;
      }

      const isSelected = node.node_id === selectedNodeId;
      const isSearchMatch =
        searchQuery && node.node_id.toLowerCase().includes(searchQuery.toLowerCase());
      const isVisited = traversalSequence.slice(0, currentStepIndex + 1).includes(node.node_id);
      const isCurrentStep = traversalSequence[currentStepIndex] === node.node_id;

      // Glow halo if active or matched
      if (isSelected || isCurrentStep || isSearchMatch) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, 18, 0, Math.PI * 2);
        ctx.fillStyle = isCurrentStep ? 'rgba(34, 211, 238, 0.4)' : 'rgba(6, 182, 212, 0.25)';
        ctx.fill();
      }

      // Main Circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, 10, 0, Math.PI * 2);
      ctx.fillStyle = isCurrentStep ? '#22d3ee' : isVisited ? '#06b6d4' : getNodeColor(node.node_type);
      ctx.fill();

      ctx.strokeStyle = isSelected ? '#ffffff' : '#0f172a';
      ctx.lineWidth = isSelected ? 2.5 : 1.5;
      ctx.stroke();

      // Label text
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.fillStyle = isSelected ? '#ffffff' : '#94a3b8';
      ctx.textAlign = 'center';

      // Truncate label for clean visual density
      const label = node.node_id.length > 20 ? node.node_id.slice(0, 18) + '...' : node.node_id;
      ctx.fillText(label, node.x, node.y + 20);
    });

    ctx.restore();
  }, [layoutNodes, graphData, zoom, pan, selectedNodeId, selectedTypeFilter, searchQuery, traversalSequence, currentStepIndex]);

  // Handle canvas interactions
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!isDragging) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  // Node click detection
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const clickX = (e.clientX - rect.left - pan.x) / zoom;
    const clickY = (e.clientY - rect.top - pan.y) / zoom;

    // Find clicked node within radius 15
    const clicked = layoutNodes.find(
      (n) => Math.hypot(n.x - clickX, n.y - clickY) <= 15
    );

    if (clicked) {
      setSelectedNodeId(clicked.node_id);
    } else {
      setSelectedNodeId(null);
    }
  };

  // Run Traversal Animation
  const handleRunTraversal = async () => {
    if (!currentRun) return;
    const startNode = selectedNodeId || layoutNodes[0]?.node_id;
    if (!startNode) return;

    try {
      setIsTraversing(true);
      const res = await traverseGraph(currentRun.run_id, traversalAlgo, startNode);
      setTraversalSequence(res.traversal_order);
      setCurrentStepIndex(0);

      // Step-by-step playback
      let idx = 0;
      const interval = setInterval(() => {
        idx++;
        if (idx < res.traversal_order.length) {
          setCurrentStepIndex(idx);
        } else {
          clearInterval(interval);
          setIsTraversing(false);
        }
      }, 300);
    } catch (err) {
      console.error('Traversal error:', err);
      setIsTraversing(false);
    }
  };

  const selectedNode = layoutNodes.find((n) => n.node_id === selectedNodeId);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Share2 className="w-6 h-6 text-cyan-400" />
            Asset Correlation Graph
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Visual multi-relational topology with real-time BFS/DFS graph traversals.
          </p>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-3 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-xs font-mono">
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Domain
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" /> Subdomain
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> IP
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" /> Endpoint
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-400" /> Service
          </span>
        </div>
      </div>

      {/* Control Bar: Search, Filters, and Traversal Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        {/* Left: Search & Filter */}
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search or highlight node..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <select
            value={selectedTypeFilter}
            onChange={(e) => setSelectedTypeFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Node Types</option>
            <option value="Domain">Domains</option>
            <option value="Subdomain">Subdomains</option>
            <option value="IPAddress">IP Addresses</option>
            <option value="Service">Services</option>
          </select>
        </div>

        {/* Right: DAA Traversal Dispatcher */}
        <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 px-3 py-1.5 rounded-lg">
          <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
            DAA Traversal:
          </span>
          <select
            value={traversalAlgo}
            onChange={(e: any) => setTraversalAlgo(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-cyan-400 font-mono focus:outline-none cursor-pointer"
          >
            <option value="bfs">BFS (Breadth-First)</option>
            <option value="dfs">DFS (Depth-First)</option>
          </select>

          <button
            onClick={handleRunTraversal}
            disabled={isTraversing}
            className="px-3 py-1 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded flex items-center gap-1.5 transition-all cursor-pointer"
          >
            <Play className="w-3 h-3 fill-slate-950" />
            <span>{isTraversing ? 'Exploring...' : 'Execute Traversal'}</span>
          </button>
        </div>
      </div>

      {/* Main Canvas & Details Panel Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Graph Canvas Container */}
        <div className="lg:col-span-3 bg-slate-950 border border-slate-800 rounded-xl relative overflow-hidden h-[580px] shadow-2xl flex items-center justify-center">
          <canvas
            ref={canvasRef}
            width={850}
            height={580}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onClick={handleCanvasClick}
            className="cursor-grab active:cursor-grabbing w-full h-full"
          />

          {/* Floating Canvas Controls */}
          <div className="absolute bottom-4 right-4 bg-slate-900/90 border border-slate-800 rounded-lg p-1.5 flex items-center gap-1 backdrop-blur shadow-lg">
            <button
              onClick={() => setZoom((z) => Math.min(2.5, z + 0.2))}
              className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-white"
              title="Zoom In"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.4, z - 0.2))}
              className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-white"
              title="Zoom Out"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
              }}
              className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-white"
              title="Reset View"
            >
              <Maximize2 className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Selected Node Details & Traversal Step Log */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div>
            <h3 className="text-sm font-bold text-white mb-2">Node Inspector</h3>
            {selectedNode ? (
              <div className="space-y-3">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs space-y-1">
                  <div className="text-[10px] uppercase font-bold text-cyan-400">{selectedNode.node_type}</div>
                  <div className="font-mono text-white font-bold break-all">{selectedNode.node_id}</div>
                </div>

                {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                  <div className="space-y-1.5">
                    <span className="text-[11px] font-semibold text-slate-400">Node Properties:</span>
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1 max-h-48 overflow-y-auto">
                      {Object.entries(selectedNode.properties).map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-2">
                          <span className="text-slate-500 truncate">{k}:</span>
                          <span className="text-slate-200 truncate">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-xs text-slate-500 italic py-6 text-center">
                Click any node on the graph canvas to inspect its metadata and connections.
              </div>
            )}
          </div>

          {/* Traversal Order Log */}
          {traversalSequence.length > 0 && (
            <div className="border-t border-slate-800 pt-3">
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="font-bold text-cyan-400 uppercase font-mono">
                  {traversalAlgo.toUpperCase()} Visited Sequence:
                </span>
                <span className="text-slate-400 font-mono text-[11px]">
                  {currentStepIndex + 1}/{traversalSequence.length}
                </span>
              </div>
              <div className="bg-slate-950 p-2 rounded-lg border border-slate-800 max-h-40 overflow-y-auto space-y-1 font-mono text-[11px]">
                {traversalSequence.map((nodeId, idx) => (
                  <div
                    key={idx}
                    className={`px-2 py-0.5 rounded flex items-center justify-between ${
                      idx === currentStepIndex
                        ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                        : idx < currentStepIndex
                        ? 'text-slate-400'
                        : 'text-slate-600'
                    }`}
                  >
                    <span className="truncate">{idx + 1}. {nodeId}</span>
                    {idx <= currentStepIndex && <CheckCircle className="w-3 h-3 text-cyan-400 shrink-0" />}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
