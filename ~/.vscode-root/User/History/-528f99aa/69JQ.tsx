import React, { useState } from 'react';
import { KpiCard } from '../components/KpiCard';
import { StatusBadge } from '../components/StatusBadge';
import { KPI_METRICS, RECENT_DOCUMENTS } from '../data/mockData';
import { 
  FileCheck2, 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  Timer, 
  CheckCircle2, 
  ArrowUpRight,
  Filter
} from 'lucide-react';

export const OverviewPage: React.FC<{ onNavigateToInspection: () => void }> = ({ onNavigateToInspection }) => {
  const [timeRange, setTimeRange] = useState<'7' | '30' | '90'>('30');

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 p-5 rounded-2xl border border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Identity Fraud Intelligence Dashboard</h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time neural document classification, OCR validation, and synthetic forgery prevention network.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {(['7', '30', '90'] as const).map((days) => (
            <button
              key={days}
              onClick={() => setTimeRange(days)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg border transition ${
                timeRange === days
                  ? 'bg-cyan-950 border-cyan-700 text-cyan-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              Last {days} Days
            </button>
          ))}
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          label="Documents Scanned"
          value={KPI_METRICS.scanned.value}
          change={KPI_METRICS.scanned.change}
          isPositive={KPI_METRICS.scanned.isPositive}
          subtext="vs previous cycle"
          icon={<FileCheck2 className="w-5 h-5" />}
        />
        <KpiCard
          label="Verified Legitimate"
          value={KPI_METRICS.verified.value}
          change={KPI_METRICS.verified.change}
          isPositive={KPI_METRICS.verified.isPositive}
          subtext="96.2% confidence"
          icon={<CheckCircle2 className="w-5 h-5" />}
        />
        <KpiCard
          label="Suspicious Documents"
          value={KPI_METRICS.suspicious.value}
          change={KPI_METRICS.suspicious.change}
          isPositive={KPI_METRICS.suspicious.isPositive}
          subtext="flagged for audit"
          icon={<ShieldAlert className="w-5 h-5" />}
        />
        <KpiCard
          label="Critical / High Risk"
          value={KPI_METRICS.highRisk.value}
          change={KPI_METRICS.highRisk.change}
          isPositive={KPI_METRICS.highRisk.isPositive}
          subtext="immediate quarantine"
          icon={<AlertTriangle className="w-5 h-5" />}
        />
      </div>

      {/* Secondary Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <KpiCard
          label="Average Risk Score"
          value={KPI_METRICS.avgRiskScore.value}
          change={KPI_METRICS.avgRiskScore.change}
          isPositive={KPI_METRICS.avgRiskScore.isPositive}
          subtext="aggregate index"
          icon={<Activity className="w-4 h-4" />}
        />
        <KpiCard
          label="Detection Accuracy"
          value={KPI_METRICS.accuracy.value}
          change={KPI_METRICS.accuracy.change}
          isPositive={KPI_METRICS.accuracy.isPositive}
          subtext="benchmark validation"
          icon={<CheckCircle2 className="w-4 h-4" />}
        />
        <KpiCard
          label="Average Processing Time"
          value={KPI_METRICS.processingTime.value}
          change={KPI_METRICS.processingTime.change}
          isPositive={KPI_METRICS.processingTime.isPositive}
          subtext="per document inference"
          icon={<Timer className="w-4 h-4" />}
        />
      </div>

      {/* Visual Analytics Split Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Donut Visualization */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white">Risk Tier Breakdown</h3>
              <span className="text-[11px] text-slate-400">Total: 12,842</span>
            </div>
            {/* Donut representation */}
            <div className="flex items-center justify-center my-4">
              <div className="relative w-44 h-44 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                  {/* Low Risk 74% */}
                  <path stroke="#10b981" strokeWidth="4.5" strokeDasharray="74, 100" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                  {/* Medium Risk 14% */}
                  <path stroke="#f59e0b" strokeWidth="4.5" strokeDasharray="14, 100" strokeDashoffset="-74" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                  {/* High Risk 9% */}
                  <path stroke="#f43f5e" strokeWidth="4.5" strokeDasharray="9, 100" strokeDashoffset="-88" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                  {/* Critical 3% */}
                  <path stroke="#dc2626" strokeWidth="4.5" strokeDasharray="3, 100" strokeDashoffset="-97" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                </svg>
                <div className="absolute text-center">
                  <span className="text-xl font-bold text-white">99.4%</span>
                  <span className="block text-[10px] text-slate-400 uppercase">Coverage</span>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-2 pt-3 border-t border-slate-800 text-xs">
            <div className="flex justify-between items-center text-slate-300">
              <span className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>Low Risk (0-30)</span>
              <span className="font-mono font-medium">9,503 (74%)</span>
            </div>
            <div className="flex justify-between items-center text-slate-300">
              <span className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>Medium Risk (31-60)</span>
              <span className="font-mono font-medium">1,797 (14%)</span>
            </div>
            <div className="flex justify-between items-center text-slate-300">
              <span className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>High Risk (61-80)</span>
              <span className="font-mono font-medium">1,155 (9%)</span>
            </div>
            <div className="flex justify-between items-center text-slate-300">
              <span className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-red-600"></span>Critical (81-100)</span>
              <span className="font-mono font-medium">387 (3%)</span>
            </div>
          </div>
        </div>

        {/* Temporal Detection Trends Bar/Line Representation */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-2 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Verification & Tampering Trajectory</h3>
              <p className="text-xs text-slate-400">Verified vs. Suspicious and Altered IDs recorded over period</p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1.5 text-slate-300">
                <span className="w-3 h-3 rounded bg-cyan-500"></span> Verified
              </span>
              <span className="flex items-center gap-1.5 text-slate-300">
                <span className="w-3 h-3 rounded bg-rose-500"></span> Forged / Altered
              </span>
            </div>
          </div>

          {/* Graphic Bar Display */}
          <div className="h-48 flex items-end justify-between gap-3 pt-6 px-2 border-b border-slate-800">
            {[
              { day: 'Mon', verified: 78, forged: 12 },
              { day: 'Tue', verified: 85, forged: 9 },
              { day: 'Wed', verified: 65, forged: 22 },
              { day: 'Thu', verified: 92, forged: 15 },
              { day: 'Fri', verified: 104, forged: 28 },
              { day: 'Sat', verified: 60, forged: 8 },
              { day: 'Sun', verified: 48, forged: 5 },
            ].map((bar, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end">
                <div className="w-full max-w-[28px] flex items-end gap-1 h-full">
                  <div 
                    style={{ height: `${(bar.verified / 110) * 100}%` }} 
                    className="w-1/2 bg-cyan-500/80 hover:bg-cyan-400 rounded-t transition" 
                  />
                  <div 
                    style={{ height: `${(bar.forged / 110) * 100}%` }} 
                    className="w-1/2 bg-rose-500/90 hover:bg-rose-400 rounded-t transition" 
                  />
                </div>
                <span className="text-[10px] font-medium text-slate-400">{bar.day}</span>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between pt-3 text-xs text-slate-400">
            <span>Peak anomaly detection window: <strong>Friday 14:00 - 18:00 IST</strong></span>
            <span className="text-cyan-400 cursor-pointer hover:underline">Download raw CSV log</span>
          </div>
        </div>
      </div>

      {/* Recent Screenings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Recent Document Screenings</h3>
            <p className="text-xs text-slate-400">Active screening telemetry across regional edge inference nodes</p>
          </div>
          <button className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-800 border border-slate-700 rounded-lg text-slate-300 hover:text-white">
            <Filter className="w-3.5 h-3.5" /> Filter Criteria
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Document ID</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Subject Identifier</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">OCR Conf.</th>
                <th className="py-3 px-4">Tampering</th>
                <th className="py-3 px-4">QR Check</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {RECENT_DOCUMENTS.map((doc) => (
                <tr key={doc.id} className="hover:bg-slate-850/50 transition">
                  <td className="py-3 px-4 font-mono font-medium text-cyan-300">{doc.id}</td>
                  <td className="py-3 px-4 text-slate-200">{doc.docType}</td>
                  <td className="py-3 px-4 font-mono text-slate-400">{doc.subjectMaskedId}</td>
                  <td className="py-3 px-4">
                    <span className={`font-mono font-bold ${
                      doc.riskScore > 70 ? 'text-rose-400' : doc.riskScore > 30 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {doc.riskScore}/100
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300">{doc.ocrConfidence}%</td>
                  <td className="py-3 px-4">
                    {doc.tamperingDetected ? (
                      <span className="text-rose-400 font-medium">Detected</span>
                    ) : (
                      <span className="text-slate-400">Clean</span>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                      doc.qrStatus === 'VERIFIED' 
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50' 
                        : 'bg-rose-950 text-rose-300 border border-rose-800/50'
                    }`}>
                      {doc.qrStatus}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <StatusBadge status={doc.status} />
                  </td>
                  <td className="py-3 px-4 text-slate-400 whitespace-nowrap">{doc.timestamp}</td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={onNavigateToInspection}
                      className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium"
                    >
                      Audit <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};