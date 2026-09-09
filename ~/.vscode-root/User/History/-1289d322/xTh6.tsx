import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

interface KpiCardProps {
  label: string;
  value: string;
  change: string;
  isPositive: boolean;
  subtext: string;
  icon: React.ReactNode;
}

export const KpiCard: React.FC<KpiCardProps> = ({ label, value, change, isPositive, subtext, icon }) => {
  return (
    <div className="bg-slate-900/90 border border-slate-800 hover:border-slate-700/80 rounded-xl p-4 transition-all duration-200">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</span>
        <div className="p-2 rounded-lg bg-slate-800/80 text-cyan-400">{icon}</div>
      </div>
      <div className="text-2xl font-bold tracking-tight text-white mb-2">{value}</div>
      <div className="flex items-center gap-1.5 text-xs">
        <span className={`inline-flex items-center font-medium ${isPositive ? 'text-emerald-400' : 'text-rose-400'}`}>
          {isPositive ? <TrendingUp className="w-3.5 h-3.5 mr-0.5" /> : <TrendingDown className="w-3.5 h-3.5 mr-0.5" />}
          {change}
        </span>
        <span className="text-slate-500">{subtext}</span>
      </div>
    </div>
  );
};