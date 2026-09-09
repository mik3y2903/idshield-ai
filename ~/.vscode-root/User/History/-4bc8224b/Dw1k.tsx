import React, { useState } from 'react';
import { EvidenceRegion } from '../types';
import { Layers, ZoomIn, Eye, AlertTriangle } from 'lucide-react';

export const EvidenceViewer: React.FC<{ regions: EvidenceRegion[] }> = ({ regions }) => {
  const [activeRegion, setActiveRegion] = useState<string | null>(regions[0]?.id || null);
  const [showOverlays, setShowOverlays] = useState<boolean>(true);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <div className="px-5 py-3.5 bg-slate-850 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">Side-by-Side Computer Vision Evidence Inspector</h3>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowOverlays(!showOverlays)}
            className={`flex items-center gap-1.5 px-3 py-1 text-xs rounded-lg border transition ${
              showOverlays 
                ? 'bg-cyan-950/60 border-cyan-700 text-cyan-300' 
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
          >
            <Eye className="w-3.5 h-3.5" />
            {showOverlays ? 'Overlays Active' : 'Overlays Hidden'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 p-5">
        {/* Left: Original Scan */}
        <div className="flex flex-col gap-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            Original Uploaded Document Scan (Pre-Inspection)
          </span>
          <div className="relative aspect-[16/10] bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-center overflow-hidden">
            <div className="w-[90%] h-[82%] bg-gradient-to-br from-slate-900 via-slate-850 to-slate-900 rounded border border-slate-700/80 p-4 flex flex-col justify-between shadow-2xl">
              <div className="flex items-center justify-between border-b border-slate-700/60 pb-2">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-orange-600/30 border border-orange-500/50 flex items-center justify-center text-[10px] text-orange-300">ID</div>
                  <span className="text-xs font-bold tracking-wider text-slate-300">GOVERNMENT OF INDIA</span>
                </div>
                <span className="text-[10px] text-slate-400 uppercase">Universal ID Authority</span>
              </div>
              <div className="flex gap-4 items-center">
                <div className="w-16 h-20 bg-slate-800 border border-slate-700 rounded flex items-center justify-center text-[10px] text-slate-500">
                  PHOTO
                </div>
                <div className="space-y-1.5 flex-1">
                  <div className="h-3 w-32 bg-slate-800 rounded"></div>
                  <div className="h-2.5 w-24 bg-slate-800 rounded"></div>
                  <div className="h-2.5 w-28 bg-slate-800 rounded"></div>
                </div>
                <div className="w-14 h-14 bg-slate-800 border border-slate-700 rounded grid grid-cols-3 gap-0.5 p-1">
                  <div className="bg-slate-600"></div><div className="bg-slate-700"></div><div className="bg-slate-600"></div>
                  <div className="bg-slate-700"></div><div className="bg-slate-500"></div><div className="bg-slate-700"></div>
                  <div className="bg-slate-600"></div><div className="bg-slate-700"></div><div className="bg-slate-600"></div>
                </div>
              </div>
              <div className="pt-2 border-t border-slate-800 text-center font-mono text-xs tracking-widest text-slate-400">
                [Aadhaar Redacted]
              </div>
            </div>
          </div>
        </div>

        {/* Right: AI Analysis Overlay */}
        <div className="flex flex-col gap-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400 flex items-center justify-between">
            <span>AI Neural Inference Overlay</span>
            <span className="text-[11px] text-slate-500 font-normal">Model: ResNet50-ELA-v4.2</span>
          </span>
          <div className="relative aspect-[16/10] bg-slate-950 rounded-lg border border-cyan-900/40 flex items-center justify-center overflow-hidden">
            {/* Base replica */}
            <div className="w-[90%] h-[82%] bg-gradient-to-br from-slate-900 via-slate-850 to-slate-900 rounded border border-slate-700/80 p-4 flex flex-col justify-between shadow-2xl relative">
              <div className="flex items-center justify-between border-b border-slate-700/60 pb-2">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-orange-600/30 border border-orange-500/50 flex items-center justify-center text-[10px] text-orange-300">ID</div>
                  <span className="text-xs font-bold tracking-wider text-slate-300">GOVERNMENT OF INDIA</span>
                </div>
                <span className="text-[10px] text-slate-400 uppercase">Universal ID Authority</span>
              </div>
              <div className="flex gap-4 items-center">
                <div className="w-16 h-20 bg-slate-800 border border-slate-700 rounded flex items-center justify-center text-[10px] text-slate-500">
                  PHOTO
                </div>
                <div className="space-y-1.5 flex-1">
                  <div className="h-3 w-32 bg-slate-800 rounded"></div>
                  <div className="h-2.5 w-24 bg-slate-800 rounded"></div>
                  <div className="h-2.5 w-28 bg-slate-800 rounded"></div>
                </div>
                <div className="w-14 h-14 bg-slate-800 border border-slate-700 rounded grid grid-cols-3 gap-0.5 p-1">
                  <div className="bg-slate-600"></div><div className="bg-slate-700"></div><div className="bg-slate-600"></div>
                  <div className="bg-slate-700"></div><div className="bg-slate-500"></div><div className="bg-slate-700"></div>
                  <div className="bg-slate-600"></div><div className="bg-slate-700"></div><div className="bg-slate-600"></div>
                </div>
              </div>
              <div className="pt-2 border-t border-slate-800 text-center font-mono text-xs tracking-widest text-slate-400">
                [Aadhaar Redacted]
              </div>

              {/* Dynamic Bounding Box Highlights */}
              {showOverlays && regions.map((region) => {
                const isSelected = activeRegion === region.id;
                return (
                  <div
                    key={region.id}
                    onClick={() => setActiveRegion(region.id)}
                    style={{
                      left: `${region.x}%`,
                      top: `${region.y}%`,
                      width: `${region.width}%`,
                      height: `${region.height}%`
                    }}
                    className={`absolute cursor-pointer border-2 transition-all duration-150 ${
                      isSelected 
                        ? 'border-rose-500 bg-rose-500/20 ring-2 ring-rose-400/40 shadow-lg shadow-rose-950' 
                        : 'border-amber-400 bg-amber-400/15 hover:border-rose-400'
                    }`}
                  >
                    <span className="absolute -top-5 left-0 px-1.5 py-0.2 bg-rose-900 border border-rose-600 text-rose-200 text-[9px] font-mono font-bold uppercase rounded whitespace-nowrap">
                      {region.label} ({region.confidence}%)
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Region Explanatory Panel */}
      <div className="border-t border-slate-850 p-4 bg-slate-900/60">
        <div className="text-xs font-semibold uppercase text-slate-400 mb-2.5 flex items-center justify-between">
          <span>Detected Evidence Regions ({regions.length})</span>
          <span className="text-[11px] text-slate-500">Click a flagged anomaly to view forensic rationale</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {regions.map((region) => {
            const isSelected = activeRegion === region.id;
            return (
              <div
                key={region.id}
                onClick={() => setActiveRegion(region.id)}
                className={`p-3 rounded-lg border cursor-pointer transition text-left ${
                  isSelected
                    ? 'bg-slate-800/90 border-rose-500/70'
                    : 'bg-slate-950/40 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold text-xs text-white flex items-center gap-1.5">
                    <AlertTriangle className="w-3 h-3 text-rose-400" />
                    {region.label}
                  </span>
                  <span className="text-[10px] font-mono text-rose-400 font-bold">{region.confidence}% Conf.</span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">{region.explanation}</p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};