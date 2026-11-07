import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Share2,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Filter,
  Play,
  Search,
  CheckCircle,
} from 'lucide-react';
import { RunDetails, GraphNode, GraphEdge } from '../types';
import { traverseGraph } from '../api';

interface AssetGraphPageProps {
  currentRun: RunDetails | null;
}

export const AssetGraphPage: React.FC<AssetGraphPageProps> = ({ currentRun }) => {
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
    const width = 850;
    const height = 580;
    const centerX = width / 2;
    const centerY = height / 2;

    const domains = nodes.filter((n) => n.node_type === 'Domain');
    const subdomains = nodes.filter((n) => n.node_type === 'Subdomain');
    const ips = nodes.filter((n) => n.node_type === 'IPAddress');
    const endpoints = nodes.filter((n) => n.node_type === 'Endpoint');
    const services = nodes.filter((n) => n.node_type === 'Service');
    const others = nodes.filter(
      (n) => !['Domain', 'Subdomain', 'IPAddress', 'Endpoint', 'Service'].includes(n.node_type)
    );

    const positions: Record<string, { x: number; y: number }> = {};

    domains.forEach((d, idx) => {
      positions[d.node_id] = {
        x: centerX + (idx - (domains.length - 1) / 2) * 120,
        y: centerY - 180,
      };
    });

    subdomains.forEach((s, idx) => {
      const angle = (idx / Math.max(1, subdomains.length)) * Math.PI * 1.5 - Math.PI * 0.75;
      const radius = 180;
      positions[s.node_id] = {
        x: centerX + Math.cos(angle) * radius,
        y: centerY - 80 + Math.sin(angle) * 80,
      };
    });

    ips.forEach((ip, idx) => {
      positions[ip.node_id] = {
        x: centerX + (idx - (ips.length - 1) / 2) * 140,
        y: centerY + 60,
      };
    });

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

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'Domain':
        return '#06b6d4';
      case 'Subdomain':
        return '#38bdf8';
      case 'IPAddress':
        return '#10b981';
      case 'Endpoint':
        return '#f59e0b';
      case 'Service':
        return '#818cf8';
      default:
        return '#94a3b8';
    }
  };

  const getNodeDescription = (type: string) => {
    switch (type) {
      case 'Domain':
        return 'Authoritative root domain targeted for reconnaissance.';
      case 'Subdomain':
        return 'Subordinate hostname discovered via DNS enumeration, crt.sh logs, or TLS SANs.';
      case 'IPAddress':
        return 'Network host IP address hosting infrastructure and resolving DNS records.';
      case 'Endpoint':
        return 'Layer-4 transport port exposed on the host machine.';
      case 'Service':
        return 'Application software or protocol service identified by banner matching.';
      default:
        return 'Network reconnaissance entity node.';
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
      ctx.strokeStyle = isTraversed ? '#06b6d4' : '#475569';
      ctx.lineWidth = isTraversed ? 2.5 : 1;
      ctx.stroke();

      // Arrowhead
      const angle = Math.atan2(target.y - source.y, target.x - source.x);
      const arrowRadius = 14;
      const arrowX = target.x - Math.cos(angle) * arrowRadius;
      const arrowY = target.y - Math.sin(angle) * arrowRadius;

      ctx.beginPath();
      ctx.moveTo(arrowX, arrowY);
      ctx.lineTo(
        arrowX - 6 * Math.cos(angle - Math.PI / 6),
        arrowY - 6 * Math.sin(angle - Math.PI / 6)
      );
      ctx.lineTo(
        arrowX - 6 * Math.cos(angle + Math.PI / 6),
        arrowY - 6 * Math.sin(angle + Math.PI / 6)
      );
      ctx.fillStyle = isTraversed ? '#06b6d4' : '#64748b';
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

      // Glow halo
      if (isSelected || isCurrentStep || isSearchMatch) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, 18, 0, Math.PI * 2);
        ctx.fillStyle = isCurrentStep ? 'rgba(34, 211, 238, 0.4)' : 'rgba(6, 182, 212, 0.25)';
        ctx.fill();
      }

      // Main Circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, 10, 0, Math.PI * 2);
      ctx.fillStyle = isCurrentStep
        ? '#22d3ee'
        : isVisited
        ? '#06b6d4'
        : getNodeColor(node.node_type);
      ctx.fill();

      ctx.strokeStyle = isSelected ? '#ffffff' : '#0f172a';
      ctx.lineWidth = isSelected ? 2.5 : 1.5;
      ctx.stroke();

      // Label text
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.fillStyle = isSelected ? '#38bdf8' : '#94a3b8';
      ctx.textAlign = 'center';

      const label = node.node_id.length > 20 ? node.node_id.slice(0, 18) + '...' : node.node_id;
      ctx.fillText(label, node.x, node.y + 20);
    });

    ctx.restore();
  }, [
    layoutNodes,
    graphData,
    zoom,
    pan,
    selectedNodeId,
    selectedTypeFilter,
    searchQuery,
    traversalSequence,
    currentStepIndex,
  ]);

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

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const clickX = ((e.clientX - rect.left) * scaleX - pan.x) / zoom;
    const clickY = ((e.clientY - rect.top) * scaleY - pan.y) / zoom;

    const clicked = layoutNodes.find((n) => Math.hypot(n.x - clickX, n.y - clickY) <= 22);
    if (clicked) {
      setSelectedNodeId(clicked.node_id);
    } else {
      setSelectedNodeId(null);
    }
  };

  const connectedEdges = useMemo(() => {
    if (!selectedNodeId || !graphData?.edges) return [];
    return graphData.edges.filter(
      (e) => e.source_id === selectedNodeId || e.target_id === selectedNodeId
    );
  }, [selectedNodeId, graphData]);

  const handleRunTraversal = async () => {
    if (!currentRun) return;
    const startNode = selectedNodeId || layoutNodes[0]?.node_id;
    if (!startNode) return;

    try {
      setIsTraversing(true);
      const res = await traverseGraph(currentRun.run_id, traversalAlgo, startNode);
      setTraversalSequence(res.traversal_order);
      setCurrentStepIndex(0);

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
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Share2 className="w-6 h-6 text-cyan-600 dark:text-cyan-400" />
            Asset Correlation Graph
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Visual multi-relational topology with real-time BFS/DFS graph traversals.
          </p>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-3 py-1.5 rounded-lg text-xs font-mono shadow-sm">
          <span className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Domain
          </span>
          <span className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" /> Subdomain
          </span>
          <span className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> IP
          </span>
          <span className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" /> Endpoint
          </span>
          <span className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-400" /> Service
          </span>
        </div>
      </div>

      {/* Control Bar */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm">
        {/* Search & Filter */}
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search or highlight node..."
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <select
            value={selectedTypeFilter}
            onChange={(e) => setSelectedTypeFilter(e.target.value)}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Node Types</option>
            <option value="Domain">Domains</option>
            <option value="Subdomain">Subdomains</option>
            <option value="IPAddress">IP Addresses</option>
            <option value="Service">Services</option>
          </select>
        </div>

        {/* Traversal Dispatcher */}
        <div className="flex items-center gap-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3 py-1.5 rounded-lg">
          <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider font-mono">
            Graph Traversal:
          </span>
          <select
            value={traversalAlgo}
            onChange={(e: any) => setTraversalAlgo(e.target.value)}
            className="bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded px-2 py-1 text-xs text-cyan-600 dark:text-cyan-400 font-mono focus:outline-none cursor-pointer"
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

      {/* Main Canvas & Details Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Canvas Container */}
        <div className="lg:col-span-3 bg-slate-950 border border-slate-800 rounded-xl relative overflow-hidden h-[580px] shadow-lg flex items-center justify-center">
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

          {/* Floating Controls */}
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

        {/* Selected Node Details */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4 shadow-sm">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Node Inspector</h3>
              {selectedNode && (
                <button
                  onClick={() => setSelectedNodeId(null)}
                  className="text-[11px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 font-medium cursor-pointer"
                >
                  Clear Selection
                </button>
              )}
            </div>

            {selectedNode ? (
              <div className="space-y-4">
                <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-lg border border-slate-200 dark:border-slate-800 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold text-cyan-600 dark:text-cyan-400">
                      {selectedNode.node_type}
                    </span>
                    <span
                      className="w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: getNodeColor(selectedNode.node_type) }}
                    />
                  </div>
                  <div className="font-mono text-slate-900 dark:text-white font-bold break-all text-sm">
                    {selectedNode.node_id}
                  </div>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400 pt-1.5 border-t border-slate-200 dark:border-slate-800/80 leading-relaxed">
                    {getNodeDescription(selectedNode.node_type)}
                  </p>
                </div>

                {/* Connected Relationships */}
                <div className="space-y-1.5">
                  <div className="flex justify-between items-center text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                    <span>Connected Relationships:</span>
                    <span className="font-mono text-cyan-600 dark:text-cyan-400 font-bold">
                      {connectedEdges.length} {connectedEdges.length === 1 ? 'edge' : 'edges'}
                    </span>
                  </div>
                  {connectedEdges.length > 0 ? (
                    <div className="bg-slate-50 dark:bg-slate-950 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 text-[11px] font-mono space-y-1.5 max-h-36 overflow-y-auto">
                      {connectedEdges.map((e, idx) => {
                        const isOutgoing = e.source_id === selectedNode.node_id;
                        const otherNode = isOutgoing ? e.target_id : e.source_id;
                        return (
                          <div key={idx} className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
                            <span className="text-cyan-500 font-bold shrink-0">{isOutgoing ? '→' : '←'}</span>
                            <span className="text-slate-400 text-[10px] uppercase shrink-0">
                              {e.relationship_type.replace(/_/g, ' ')}
                            </span>
                            <span className="text-slate-900 dark:text-white truncate font-medium">{otherNode}</span>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="text-[11px] text-slate-400 italic py-1">No direct connections recorded.</div>
                  )}
                </div>

                {/* Node Metadata / Properties */}
                {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                  <div className="space-y-1.5">
                    <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                      Node Properties:
                    </span>
                    <div className="bg-slate-50 dark:bg-slate-950 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-700 dark:text-slate-300 space-y-1 max-h-36 overflow-y-auto">
                      {Object.entries(selectedNode.properties).map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-2">
                          <span className="text-slate-400 truncate">{k}:</span>
                          <span className="text-slate-900 dark:text-slate-200 truncate">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Quick Action */}
                <button
                  onClick={handleRunTraversal}
                  className="w-full py-2 px-3 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 font-bold text-xs border border-cyan-500/30 flex items-center justify-center gap-2 cursor-pointer transition-colors"
                >
                  <Play className="w-3.5 h-3.5 fill-cyan-500" />
                  Traverse {traversalAlgo.toUpperCase()} from this node
                </button>
              </div>
            ) : (
              <div className="text-xs text-slate-400 italic py-8 text-center space-y-2">
                <div>Click any node on the graph canvas to inspect its metadata, relationships, and connections.</div>
                <div className="text-[11px] text-slate-500">Tip: Click and drag to pan, scroll to zoom.</div>
              </div>
            )}
          </div>

          {/* Traversal Order Log */}
          {traversalSequence.length > 0 && (
            <div className="border-t border-slate-100 dark:border-slate-800 pt-3">
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="font-bold text-cyan-600 dark:text-cyan-400 uppercase font-mono">
                  {traversalAlgo.toUpperCase()} Visited:
                </span>
                <span className="text-slate-500 dark:text-slate-400 font-mono text-[11px]">
                  {currentStepIndex + 1}/{traversalSequence.length}
                </span>
              </div>
              <div className="bg-slate-50 dark:bg-slate-950 p-2 rounded-lg border border-slate-200 dark:border-slate-800 max-h-40 overflow-y-auto space-y-1 font-mono text-[11px]">
                {traversalSequence.map((nodeId, idx) => (
                  <div
                    key={idx}
                    className={`px-2 py-0.5 rounded flex items-center justify-between ${
                      idx === currentStepIndex
                        ? 'bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 font-bold'
                        : idx < currentStepIndex
                        ? 'text-slate-600 dark:text-slate-400'
                        : 'text-slate-400 dark:text-slate-600'
                    }`}
                  >
                    <span className="truncate">
                      {idx + 1}. {nodeId}
                    </span>
                    {idx <= currentStepIndex && (
                      <CheckCircle className="w-3 h-3 text-cyan-500 shrink-0" />
                    )}
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
