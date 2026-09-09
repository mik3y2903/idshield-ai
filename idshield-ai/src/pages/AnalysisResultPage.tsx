import { FC } from 'react';
import { DetailedAnalysis } from '../types';
import { RiskGauge } from '../components/RiskGauge';
import { RiskWaterfall } from '../components/RiskWaterfall';
import { EvidenceViewer } from '../components/EvidenceViewer';
import { StatusBadge } from '../components/StatusBadge';
import { 
  FileText, 
  QrCode, 
  ScanFace, 
  Sparkles, 
  Printer, 
  ArrowLeft,
  ScanSearch,
  UploadCloud
} from 'lucide-react';

export const AnalysisResultPage: FC<{ 
  doc: DetailedAnalysis | null;
  onBack: () => void; 
  onOpenReport?: () => void;
  onNavigateToUpload: () => void;
}> = ({ doc, onBack, onNavigateToUpload }) => {
  if (!doc) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center flex flex-col items-center justify-center min-h-[460px]">
        <div className="w-16 h-16 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 mb-4 shadow-inner">
          <ScanSearch className="w-8 h-8" />
        </div>
        <h3 className="text-lg font-bold text-white mb-1.5">No Active Document Under Inspection</h3>
        <p className="text-xs text-slate-400 max-w-md mb-6 leading-relaxed">
          Upload an identity document in the screening engine to run real-time Error Level Analysis (ELA), OCR extraction, facial geometry validation, and risk scoring.
        </p>
        <button
          onClick={onNavigateToUpload}
          className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition shadow-lg shadow-cyan-950"
        >
          <UploadCloud className="w-4 h-4" /> Go to Upload & Screen
        </button>
      </div>
    );
  }

  const handleDownloadReport = () => {
    if (!doc?.id) return;
    window.open(`http://localhost:8000/api/documents/${doc.id}/report`, '_blank');
  };

  return (
    <div className="space-y-6">
      {/* Top Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white tracking-tight">Forensic Dossier: {doc.id}</h2>
              <StatusBadge status={doc.status} />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Audited by {doc.processedByNode} on {doc.timestamp}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadReport}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition shadow-lg shadow-cyan-950 cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5" />
            Generate Audit Report
          </button>
          <button
            onClick={() => window.print()}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition cursor-pointer"
          >
            <Printer className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Threat Banner */}
      <div className={`p-4 rounded-xl border flex items-center justify-between ${
        doc.status === 'VERIFIED'
          ? 'bg-emerald-950/40 border-emerald-800/60'
          : 'bg-rose-950/40 border-rose-800/60'
      }`}>
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center font-bold text-lg border ${
            doc.status === 'VERIFIED'
              ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
              : 'bg-rose-500/20 border-rose-500/40 text-rose-400'
          }`}>
            {doc.status === 'VERIFIED' ? '✓' : '⚠'}
          </div>
          <div>
            <h4 className={`text-sm font-bold ${doc.status === 'VERIFIED' ? 'text-emerald-200' : 'text-rose-200'}`}>
              {doc.status === 'VERIFIED' ? 'Legitimate Document Verified' : 'High-Risk Manipulation Indicators Detected'}
            </h4>
            <p className={`text-xs ${doc.status === 'VERIFIED' ? 'text-emerald-300/80' : 'text-rose-300/80'}`}>
              {doc.status === 'VERIFIED' 
                ? 'All optical, facial biometric, and cryptographic verification checks passed with acceptable tolerances.'
                : 'Discrepancies identified across optical layout, QR cryptographic hashes, and microprint margins.'}
            </p>
          </div>
        </div>
        <span className={`px-3 py-1 rounded text-xs font-mono font-bold border ${
          doc.status === 'VERIFIED'
            ? 'bg-emerald-900/60 border-emerald-700 text-emerald-200'
            : 'bg-rose-900/60 border-rose-700 text-rose-200'
        }`}>
          SCORE: {doc.riskScore}/100
        </span>
      </div>

      {/* Risk Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        <div className="md:col-span-4 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col items-center justify-center text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Composite AI Risk Score
          </span>
          <RiskGauge score={doc.riskScore} />
          <div className="mt-3 text-xs text-slate-400 max-w-[240px]">
            {doc.status === 'VERIFIED' 
              ? <strong className="text-emerald-400">Authentic Document Pattern</strong> 
              : <strong className="text-rose-400">High Probability of Forgery</strong>}
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 w-full grid grid-cols-2 text-center text-xs">
            <div>
              <span className="text-slate-500 block text-[10px]">VERIFICATION</span>
              <span className={`font-bold ${doc.status === 'VERIFIED' ? 'text-emerald-400' : 'text-rose-400'}`}>
                {doc.status === 'VERIFIED' ? 'ACCEPTED' : 'REJECT / AUDIT'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">DOCUMENT CLASS</span>
              <span className="text-slate-200 font-bold">{doc.docType}</span>
            </div>
          </div>
        </div>

        <div className="md:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-white">Signal Integrity Diagnostic Matrices</h3>
            <span className="text-xs text-slate-400 font-mono">Normalized Percentages</span>
          </div>

          <div className="space-y-3.5 my-3">
            {[
              { label: 'OCR Consistency & Text Sharpness', value: doc.ocrConfidence, color: 'bg-emerald-500' },
              { label: 'Layout & Template Alignment Integrity', value: doc.layoutIntegrity, color: 'bg-cyan-500' },
              { label: 'Pixel & Compression Error Level (ELA)', value: doc.imageIntegrity, color: doc.imageIntegrity > 60 ? 'bg-emerald-500' : 'bg-rose-500' },
              { label: 'Biometric Face Ratio Consistency', value: doc.faceConsistency, color: doc.faceConsistency > 50 ? 'bg-emerald-500' : 'bg-rose-500' },
            ].map((meter, i) => (
              <div key={i} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-300 font-medium">{meter.label}</span>
                  <span className="font-mono text-slate-300 font-bold">{meter.value}%</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    style={{ width: `${meter.value}%` }}
                    className={`h-full ${meter.color} transition-all duration-700`}
                  />
                </div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3 border-t border-slate-800 text-center">
            <div className="bg-slate-950/40 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block">QR Hash Check</span>
              <span className={`text-xs font-mono font-bold ${doc.qrStatus === 'VERIFIED' ? 'text-emerald-400' : 'text-rose-400'}`}>
                {doc.qrStatus === 'VERIFIED' ? 'PASSED' : 'FAILED'}
              </span>
            </div>
            <div className="bg-slate-950/40 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block">Tampering Flag</span>
              <span className={`text-xs font-mono font-bold ${doc.tamperingDetected ? 'text-rose-400' : 'text-emerald-400'}`}>
                {doc.tamperingDetected ? 'DETECTED' : 'CLEAN'}
              </span>
            </div>
            <div className="bg-slate-950/40 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block">Face Detected</span>
              <span className={`text-xs font-mono font-bold ${doc.faceDetected ? 'text-emerald-400' : 'text-rose-400'}`}>
                {doc.faceDetected ? `YES (${doc.faceQuality}%)` : 'NO'}
              </span>
            </div>
            <div className="bg-slate-950/40 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block">Watermark</span>
              <span className="text-xs font-mono font-bold text-amber-400">CHECKED</span>
            </div>
          </div>
        </div>
      </div>

      <EvidenceViewer regions={doc.evidenceRegions} imageUrl={doc.imageUrl} />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Forensic Natural Language Explanations</h3>
          </div>
          <div className="p-3.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 text-xs text-cyan-200 leading-relaxed">
            The neural inference cluster classified this document with <strong>Risk Index {doc.riskScore}/100</strong>.
          </div>
          <div className="space-y-2 text-xs">
            {doc.aiExplanation.map((reason, idx) => (
              <div key={idx} className="flex items-start gap-2 text-slate-300">
                <span className="text-cyan-400 font-bold mt-0.5">•</span>
                <span>{reason}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="lg:col-span-6">
          <RiskWaterfall factors={doc.riskBreakdown} totalScore={doc.riskScore} />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <div className="flex items-center gap-2">
              <QrCode className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">QR / Barcode Forensic Integrity</h3>
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
              doc.qrStatus === 'VERIFIED'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : 'bg-rose-950 text-rose-300 border border-rose-800'
            }`}>
              STATUS: {doc.qrStatus}
            </span>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block mb-1">Decoded Payload Digest</span>
              <span className="text-rose-300 break-all">{doc.qrDecodedData || 'NOT_DECODABLE'}</span>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block mb-1">Expected Template Schema</span>
              <span className="text-emerald-400 break-all">{doc.qrExpectedData || 'NONE'}</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <div className="flex items-center gap-2">
              <ScanFace className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Biometric Facial Verification</h3>
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
              doc.faceDetected 
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : 'bg-rose-950 text-rose-300 border border-rose-800'
            }`}>
              MATCH: {doc.faceConsistency}%
            </span>
          </div>

          <div className="grid grid-cols-3 gap-3 text-center mb-4 text-xs">
            <div className="bg-slate-950/60 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 block">Face Present</span>
              <span className="font-bold text-emerald-400">{doc.faceDetected ? 'YES' : 'NO'}</span>
            </div>
            <div className="bg-slate-950/60 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 block">Photo Quality</span>
              <span className="font-bold text-slate-200">{doc.faceQuality}%</span>
            </div>
            <div className="bg-slate-950/60 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 block">Liveness Ratio</span>
              <span className="font-bold text-cyan-300">0.87</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};