import { useState, useEffect, FC } from 'react';
import { ShieldAlert, FileText, Cpu, AlertTriangle, Inbox } from 'lucide-react';

interface AnalyticsData {
  totalQuarantined: number;
  mostForged: string;
  topVector: string;
  avgInference: string;
  tamperingVectors: { technique: string; count: number; pct: number }[];
  typeDistribution: { type: string; count: number; share: number }[];
}

export const AnalyticsPage: FC = () => {
  const [data, setData] = useState<AnalyticsData>({
    totalQuarantined: 0,
    mostForged: 'None (0%)',
    topVector: 'None',
    avgInference: '0.0s',
    tamperingVectors: [],
    typeDistribution: []
  });

  useEffect(() => {
    let isMounted = true;
    const fetchAnalytics = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/analytics');
        if (res.ok) {
          const json = await res.json();
          if (isMounted) setData(json);
        }
      } catch {
        // Backend not reached, keeps defaults
      }
    };
    fetchAnalytics();
    return () => { isMounted = false; };
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Fraud Analytics & Detection Patterns</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Macro analysis of synthetic fraud attacks, forgery mechanisms, and geographical screening loads.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase">Total Forgeries Quarantined</span>
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white mb-1">{data.totalQuarantined}</div>
          <div className="text-[11px] text-slate-500">Live flagged count</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase">Most Forged Credential</span>
            <FileText className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white mb-1">{data.mostForged}</div>
          <div className="text-[11px] text-slate-500">Primary threat vector</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase">Top Tampering Technique</span>
            <AlertTriangle className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white mb-1">{data.topVector}</div>
          <div className="text-[11px] text-slate-500">Dominant manipulation style</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase">Engine Inference Avg</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white mb-1">{data.avgInference}</div>
          <div className="text-[11px] text-slate-500">Local pipeline latency</div>
        </div>
      </div>

      {data.tamperingVectors.length === 0 && data.typeDistribution.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center flex flex-col items-center justify-center">
          <Inbox className="w-10 h-10 text-slate-600 mb-2" />
          <h4 className="text-sm font-semibold text-white">No Telemetry Recorded</h4>
          <p className="text-xs text-slate-400 max-w-sm">
            Statistical charts will generate dynamically once documents are screened through the engine.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-white mb-1">Detected Tampering Vectors</h3>
            <p className="text-xs text-slate-400 mb-4">Breakdown by detected alteration techniques</p>

            <div className="space-y-3 text-xs">
              {data.tamperingVectors.map((row, i) => (
                <div key={i} className="space-y-1">
                  <div className="flex justify-between text-slate-300">
                    <span>{row.technique} ({row.count})</span>
                    <span className="font-mono font-bold text-cyan-400">{row.pct}%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div style={{ width: `${row.pct}%` }} className="bg-cyan-500 h-full rounded-full transition-all" />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-white mb-1">Document Classification Distribution</h3>
            <p className="text-xs text-slate-400 mb-4">Volume processed by credential category</p>

            <div className="space-y-3 text-xs">
              {data.typeDistribution.map((row, i) => (
                <div key={i} className="space-y-1">
                  <div className="flex justify-between text-slate-300">
                    <span>{row.type} ({row.count})</span>
                    <span className="font-mono font-bold text-emerald-400">{row.share}%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div style={{ width: `${row.share}%` }} className="bg-emerald-500 h-full rounded-full transition-all" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};