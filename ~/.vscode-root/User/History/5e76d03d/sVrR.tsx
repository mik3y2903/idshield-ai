import React from 'react';
import { BarChart3, ShieldAlert, FileText, Cpu, AlertTriangle } from 'lucide-react';

export const AnalyticsPage: React.FC = () => {
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
        {[
          { label: 'Total Forgeries Quarantined', val: '1,592', change: '+12.4%', icon: ShieldAlert },
          { label: 'Most Forged Credential', val: 'Aadhaar (54%)', change: 'Primary vector', icon: FileText },
          { label: 'Top Tampering Technique', val: 'Font Splice (42%)', change: 'Text modification', icon: AlertTriangle },
          { label: 'Engine Inference Avg', val: '1.42s', change: '99.98% SLA', icon: Cpu },
        ].map((item, idx) => {
          const Icon = item.icon;
          return (
            <div key={idx} className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
              <div className="flex items-center justify-between text-slate-400 mb-2">
                <span className="text-xs font-semibold uppercase">{item.label}</span>
                <Icon className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-xl font-bold text-white mb-1">{item.val}</div>
              <div className="text-[11px] text-slate-500">{item.change}</div>
            </div>
          );
        })}
      </div>

      {/* Breakdown grids */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-1">Most Common Tampering Vectors</h3>
          <p className="text-xs text-slate-400 mb-4">Breakdown by detected alteration techniques</p>

          <div className="space-y-3 text-xs">
            {[
              { technique: 'Font & Typographical Weight Inconsistency', pct: 42 },
              { technique: 'Cryptographic QR Code Invalid / Forged', pct: 28 },
              { technique: 'DOB / Text Error Level Analysis Splice', pct: 16 },
              { technique: 'Facial Photo Border Digital Cut-and-Paste', pct: 9 },
              { technique: 'Hologram & Microprint Displacement', pct: 5 },
            ].map((row, i) => (
              <div key={i} className="space-y-1">
                <div className="flex justify-between text-slate-300">
                  <span>{row.technique}</span>
                  <span className="font-mono font-bold text-cyan-400">{row.pct}%</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div style={{ width: `${row.pct}%` }} className="bg-cyan-500 h-full rounded-full" />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-1">Document Classification Distribution</h3>
          <p className="text-xs text-slate-400 mb-4">Volume processed by credential category</p>

          <div className="space-y-3 text-xs">
            {[
              { type: 'Aadhaar Card', count: '6,934', share: 54 },
              { type: 'Permanent Account Number (PAN)', count: '3,210', share: 25 },
              { type: 'Driving License', count: '1,412', share: 11 },
              { type: 'Passport Credentials', count: '772', share: 6 },
              { type: 'Voter Identification', count: '514', share: 4 },
            ].map((row, i) => (
              <div key={i} className="space-y-1">
                <div className="flex justify-between text-slate-300">
                  <span>{row.type} ({row.count})</span>
                  <span className="font-mono font-bold text-emerald-400">{row.share}%</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div style={{ width: `${row.share}%` }} className="bg-emerald-500 h-full rounded-full" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};