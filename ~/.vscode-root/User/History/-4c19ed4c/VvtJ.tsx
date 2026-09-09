import React, { useState } from 'react';
import { DashboardLayout } from './layout/DashboardLayout';
import { OverviewPage } from './pages/OverviewPage';
import { ScreeningPage } from './pages/ScreeningPage';
import { AnalysisResultPage } from './pages/AnalysisResultPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { ReportModal } from './pages/ReportModal';
import { CURRENT_INSPECTION } from './data/mockData';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('overview');
  const [isReportOpen, setIsReportOpen] = useState<boolean>(false);

  return (
    <DashboardLayout currentTab={currentTab} setCurrentTab={setCurrentTab}>
      {currentTab === 'overview' && (
        <OverviewPage onNavigateToInspection={() => setCurrentTab('analysis')} />
      )}

      {currentTab === 'screen' && (
        <ScreeningPage onCompleteAnalysis={() => setCurrentTab('analysis')} />
      )}

      {currentTab === 'analysis' && (
        <AnalysisResultPage
          onBack={() => setCurrentTab('overview')}
          onOpenReport={() => setIsReportOpen(true)}
        />
      )}

      {currentTab === 'analytics' && <AnalyticsPage />}

      {/* Fallback for other tab options */}
      {(currentTab === 'suspicious' || currentTab === 'evidence' || currentTab === 'history') && (
        <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-base font-bold text-white capitalize">{currentTab} Queue</h3>
          <p className="text-xs text-slate-400">
            Telemetry filter active for {currentTab}. Click below to view the inspected suspicious candidate.
          </p>
          <button
            onClick={() => setCurrentTab('analysis')}
            className="px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 text-xs font-bold"
          >
            Open Active Suspicious Dossier
          </button>
        </div>
      )}

      {currentTab === 'settings' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-bold text-white uppercase">System Heuristic Configuration</h3>
          <div className="space-y-2 text-xs text-slate-400">
            <div className="flex justify-between p-3 bg-slate-950 rounded border border-slate-800">
              <span>Tampering Threshold Sensitivity</span>
              <span className="font-mono text-cyan-400">0.85 (Strict)</span>
            </div>
            <div className="flex justify-between p-3 bg-slate-950 rounded border border-slate-800">
              <span>Cryptographic QR Validation</span>
              <span className="font-mono text-emerald-400">Enforced</span>
            </div>
            <div className="flex justify-between p-3 bg-slate-950 rounded border border-slate-800">
              <span>Inference Engine Worker Threads</span>
              <span className="font-mono text-slate-200">16 CUDA Cores</span>
            </div>
          </div>
        </div>
      )}

      {/* Forensic Report Modal */}
      {isReportOpen && (
        <ReportModal
          doc={CURRENT_INSPECTION}
          onClose={() => setIsReportOpen(false)}
        />
      )}
    </DashboardLayout>
  );
};

export default App;